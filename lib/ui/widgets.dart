// Small reusable pieces of the pink & black UI. All text is 15px or bigger.

import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../services/ip_utils.dart';
import '../theme.dart';

String levelLabel(RiskLevel level) => switch (level) {
      RiskLevel.safe => 'Looks safe',
      RiskLevel.suspicious => 'Suspicious',
      RiskLevel.dangerous => 'Danger!',
    };

/// The plain-words answer to "is it suspicious?".
String verdictHeadline(RiskLevel level) => switch (level) {
      RiskLevel.safe => 'No, this looks safe.',
      RiskLevel.suspicious => 'Yes, this looks suspicious.',
      RiskLevel.dangerous => 'Yes, this looks dangerous!',
    };

IconData levelIcon(RiskLevel level) => switch (level) {
      RiskLevel.safe => Icons.verified_user_rounded,
      RiskLevel.suspicious => Icons.warning_amber_rounded,
      RiskLevel.dangerous => Icons.gpp_bad_rounded,
    };

String ratingLabel(AiRating rating) => switch (rating) {
      AiRating.safe => 'Safe',
      AiRating.suspicious => 'Suspicious',
      AiRating.dangerous => 'Dangerous',
      AiRating.unknown => 'Not sure',
    };

IconData directionIcon(Direction d) => switch (d) {
      Direction.outgoing => Icons.north_east_rounded,
      Direction.incoming => Icons.south_west_rounded,
      Direction.listening => Icons.sensors_rounded,
      Direction.local => Icons.loop_rounded,
      Direction.other => Icons.hourglass_bottom_rounded,
    };

/// What a connection is doing, in plain words.
String directionWords(Direction d) => switch (d) {
      Direction.outgoing => 'Talking to',
      Direction.incoming => 'Connected from',
      Direction.listening => 'Waiting for others to connect',
      Direction.local => 'Talking to another program on this PC',
      Direction.other => 'Closing a connection to',
    };

IconData reasonIcon(ReasonKind kind) => switch (kind) {
      ReasonKind.folder => Icons.folder_special_rounded,
      ReasonKind.signature => Icons.gpp_maybe_rounded,
      ReasonKind.disguise => Icons.theater_comedy_rounded,
      ReasonKind.tool => Icons.build_circle_rounded,
      ReasonKind.command => Icons.terminal_rounded,
      ReasonKind.port => Icons.door_front_door_rounded,
      ReasonKind.network => Icons.public_rounded,
      ReasonKind.country => Icons.flag_rounded,
      ReasonKind.file => Icons.insert_drive_file_rounded,
    };

/// Where the other side of a connection is, like "Germany · Tor exit relay".
String placeOf(ConnectionRow row, {required bool lookupOn}) {
  final c = row.connection;
  if (row.direction == Direction.listening) {
    if (isUnspecified(c.localAddress)) return 'anyone on your network can connect';
    if (isLoopback(c.localAddress)) return 'only this PC can connect';
    return 'on ${c.localAddress}';
  }
  final ip = c.remoteAddress;
  if (ip.isEmpty) return '';
  if (isLoopback(ip) || ip == c.localAddress) return 'this PC';
  if (!isPublicIp(ip)) return 'a device on your home network';
  final g = row.geo;
  if (g == null) return lookupOn ? 'looking up who owns it...' : '';
  return [g.country, g.owner]
      .whereType<String>()
      .where((s) => s.isNotEmpty)
      .join('  ·  ');
}

/// The address part of a connection.
String endpointOf(ConnectionRow row) {
  final c = row.connection;
  if (row.direction == Direction.listening) return 'port ${c.localPort}';
  if (c.remoteAddress.isEmpty) return '';
  return formatEndpoint(c.remoteAddress, c.remotePort);
}

/// Signature in plain words, plus a color.
(String, Color) signatureWords(ProgramGroup g, {bool checking = false}) {
  final file = g.file;
  if (g.isWindowsCore) return ('Part of Windows', AppColors.safe);
  if (g.path == null) return ('Unknown (folder hidden)', AppColors.muted);
  if (file == null) {
    return (checking ? 'Checking...' : 'Not checked yet', AppColors.muted);
  }
  if (!file.exists) return ('File is missing', AppColors.danger);
  return switch (file.signature) {
    SignatureStatus.valid => (
        'Signed by ${file.signer ?? 'a trusted company'}',
        AppColors.safe
      ),
    SignatureStatus.notSigned => ('Not signed', AppColors.pink),
    SignatureStatus.hashMismatch => (
        'Broken (changed after signing)',
        AppColors.danger
      ),
    SignatureStatus.notTrusted => ('Signed, but not trusted', AppColors.pink),
    SignatureStatus.unknownError => ("Couldn't be confirmed", AppColors.pink),
    SignatureStatus.notSupported ||
    SignatureStatus.unknown =>
      ('No information', AppColors.muted),
  };
}

/// The "Danger!" / "Suspicious" / "Looks safe" badge.
class RiskBadge extends StatelessWidget {
  const RiskBadge({super.key, required this.level, this.large = false});

  final RiskLevel level;
  final bool large;

  @override
  Widget build(BuildContext context) {
    final safe = level == RiskLevel.safe;
    final gradient = switch (level) {
      RiskLevel.safe => null,
      RiskLevel.suspicious => AppColors.pinkGradient,
      RiskLevel.dangerous => const LinearGradient(
          colors: [Color(0xFFFF3D6E), Color(0xFFE0115F)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
    };
    final fg = safe ? AppColors.safe : Colors.white;
    return Container(
      padding: EdgeInsets.symmetric(
          horizontal: large ? 16 : 14, vertical: large ? 10 : 8),
      decoration: BoxDecoration(
        gradient: gradient,
        color: safe ? AppColors.panel : null,
        borderRadius: BorderRadius.circular(999),
        border: safe ? Border.all(color: AppColors.border) : null,
        boxShadow: level == RiskLevel.dangerous
            ? [
                BoxShadow(
                  color: AppColors.danger.withValues(alpha: 0.45),
                  blurRadius: 16,
                  spreadRadius: -2,
                ),
              ]
            : null,
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(levelIcon(level), size: large ? 20 : 18, color: fg),
          const SizedBox(width: 6),
          Text(
            levelLabel(level),
            style: TextStyle(
                color: fg,
                fontSize: large ? 17 : 16,
                fontWeight: FontWeight.w800),
          ),
        ],
      ),
    );
  }
}

/// Rounded program "icon" with the first letter of its name.
class ProgramAvatar extends StatelessWidget {
  const ProgramAvatar(
      {super.key, required this.name, required this.level, this.windows = false, this.size = 46});

  final String name;
  final RiskLevel level;
  final bool windows;
  final double size;

  @override
  Widget build(BuildContext context) {
    final risky = level != RiskLevel.safe;
    final letter = name.isEmpty ? '?' : name.characters.first.toUpperCase();
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        gradient: risky
            ? (level == RiskLevel.dangerous
                ? const LinearGradient(
                    colors: [Color(0xFFFF3D6E), Color(0xFF9E0B46)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight)
                : AppColors.pinkGradient)
            : null,
        color: risky ? null : AppColors.cardHigh,
        borderRadius: BorderRadius.circular(size * 0.32),
        border: risky ? null : Border.all(color: AppColors.border),
      ),
      child: windows
          ? Icon(Icons.desktop_windows_rounded,
              size: size * 0.48, color: risky ? Colors.white : AppColors.softPink)
          : Text(
              letter,
              style: TextStyle(
                fontSize: size * 0.42,
                fontWeight: FontWeight.w800,
                color: risky ? Colors.white : AppColors.softPink,
              ),
            ),
    );
  }
}

/// Text with a pink gradient.
class GradientText extends StatelessWidget {
  const GradientText(this.text, {super.key, required this.style});

  final String text;
  final TextStyle style;

  @override
  Widget build(BuildContext context) {
    return ShaderMask(
      blendMode: BlendMode.srcIn,
      shaderCallback: (bounds) => const LinearGradient(
        colors: [Color(0xFFFFC2E0), AppColors.pink, Color(0xFFFF2E88)],
        stops: [0, 0.55, 1],
      ).createShader(Rect.fromLTWH(0, 0, bounds.width, bounds.height)),
      child: Text(text, style: style),
    );
  }
}

/// A small "NEW" tag for programs that just started connecting.
class NewTag extends StatelessWidget {
  const NewTag({super.key});

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: 'Started connecting in the last minute',
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 1),
        decoration: BoxDecoration(
          gradient: AppColors.pinkGradient,
          borderRadius: BorderRadius.circular(7),
        ),
        child: const Text(
          'NEW',
          style: TextStyle(
            fontSize: 15,
            fontWeight: FontWeight.w900,
            color: Colors.white,
            letterSpacing: 0.6,
          ),
        ),
      ),
    );
  }
}

/// Shows a pink-bordered message at the bottom of the window.
void showToast(BuildContext context, String message,
    {bool ok = true, String? actionLabel, VoidCallback? onAction}) {
  final messenger = ScaffoldMessenger.maybeOf(context);
  if (messenger == null) return;
  messenger
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(
      content: Row(
        children: [
          Icon(ok ? Icons.favorite_rounded : Icons.error_outline_rounded,
              color: ok ? AppColors.pink : AppColors.danger, size: 20),
          const SizedBox(width: 10),
          Expanded(child: Text(message)),
        ],
      ),
      action: actionLabel == null
          ? null
          : SnackBarAction(label: actionLabel, onPressed: onAction ?? () {}),
      duration: const Duration(seconds: 4),
    ));
}
