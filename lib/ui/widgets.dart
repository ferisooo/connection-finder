// Small reusable pieces of the pink & black UI.

import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../services/ip_utils.dart';
import '../theme.dart';

String levelLabel(RiskLevel level) => switch (level) {
      RiskLevel.safe => 'Looks safe',
      RiskLevel.suspicious => 'Suspicious',
      RiskLevel.dangerous => 'Danger!',
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

String directionLabel(Direction d) => switch (d) {
      Direction.outgoing => 'Outgoing',
      Direction.incoming => 'Incoming',
      Direction.listening => 'Listening',
      Direction.local => 'This PC only',
      Direction.other => 'Closing',
    };

String directionHelp(Direction d) => switch (d) {
      Direction.outgoing => 'Your PC connected out to this IP.',
      Direction.incoming => 'This IP connected in to your PC.',
      Direction.listening =>
        'The program is waiting for others to connect (an open door).',
      Direction.local => 'Both ends are on this PC.',
      Direction.other => 'This connection is closing.',
    };

IconData directionIcon(Direction d) => switch (d) {
      Direction.outgoing => Icons.north_east_rounded,
      Direction.incoming => Icons.south_west_rounded,
      Direction.listening => Icons.sensors_rounded,
      Direction.local => Icons.loop_rounded,
      Direction.other => Icons.hourglass_bottom_rounded,
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

/// (text, color, icon) describing a program's signature.
(String, Color, IconData) signatureLook(ConnectionRow row, {bool checking = false}) {
  final file = row.file;
  if (row.isWindowsCore) {
    return ('Part of Windows', AppColors.safe, Icons.verified_rounded);
  }
  if (row.path == null) {
    return ('Signature unknown', AppColors.muted, Icons.help_outline_rounded);
  }
  if (file == null) {
    return (
      checking ? 'Checking signature...' : 'Signature not checked yet',
      AppColors.muted,
      Icons.hourglass_top_rounded,
    );
  }
  if (!file.exists) {
    return ('File missing', AppColors.danger, Icons.report_rounded);
  }
  return switch (file.signature) {
    SignatureStatus.valid => (
        'Signed by ${file.signer ?? 'a trusted company'}',
        AppColors.safe,
        Icons.verified_rounded,
      ),
    SignatureStatus.notSigned => (
        'Not signed',
        AppColors.pink,
        Icons.gpp_maybe_rounded,
      ),
    SignatureStatus.hashMismatch => (
        'Broken signature',
        AppColors.danger,
        Icons.gpp_bad_rounded,
      ),
    SignatureStatus.notTrusted => (
        'Untrusted signature',
        AppColors.pink,
        Icons.gpp_maybe_rounded,
      ),
    SignatureStatus.unknownError => (
        'Unverified signature',
        AppColors.pink,
        Icons.gpp_maybe_rounded,
      ),
    SignatureStatus.notSupported || SignatureStatus.unknown => (
        'No signature info',
        AppColors.muted,
        Icons.help_outline_rounded,
      ),
  };
}

/// Second line under the remote address: country, city and owner.
String remoteSubtitle(ConnectionRow row, {required bool lookupOn}) {
  final c = row.connection;
  if (row.direction == Direction.listening) {
    if (isUnspecified(c.localAddress)) return 'Open to your whole network';
    if (isLoopback(c.localAddress)) return 'Only this PC can connect';
    return 'Waiting on ${c.localAddress}';
  }
  final ip = c.remoteAddress;
  if (ip.isEmpty) return '';
  if (isLoopback(ip) || ip == c.localAddress) return 'This PC';
  if (!isPublicIp(ip)) return 'A device on your home network';
  final g = row.geo;
  if (g == null) return lookupOn ? 'Looking up who owns it...' : 'IP lookup is off';
  return [g.countryCode, g.city, g.owner]
      .whereType<String>()
      .where((s) => s.isNotEmpty)
      .join('  ·  ');
}

String remoteTitle(ConnectionRow row) {
  final c = row.connection;
  if (row.direction == Direction.listening) {
    return '${c.protocol} port ${c.localPort}';
  }
  if (c.remoteAddress.isEmpty) return '-';
  return formatEndpoint(c.remoteAddress, c.remotePort);
}

/// Small rounded label.
class Pill extends StatelessWidget {
  const Pill({
    super.key,
    required this.text,
    this.icon,
    this.color = AppColors.muted,
    this.filled = false,
    this.tooltip,
    this.monospace = false,
  });

  final String text;
  final IconData? icon;
  final Color color;
  final bool filled;
  final String? tooltip;
  final bool monospace;

  @override
  Widget build(BuildContext context) {
    final style = monospace
        ? mono(12, color: color, weight: FontWeight.w500)
        : TextStyle(
            color: color, fontSize: 12, fontWeight: FontWeight.w600, height: 1.2);
    Widget pill = Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: filled ? color.withValues(alpha: 0.16) : AppColors.panel,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
            color: filled ? color.withValues(alpha: 0.45) : AppColors.border),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 14, color: color),
            const SizedBox(width: 5),
          ],
          Flexible(
            child: Text(text,
                style: style, overflow: TextOverflow.ellipsis, maxLines: 1),
          ),
        ],
      ),
    );
    if (tooltip != null) pill = Tooltip(message: tooltip!, child: pill);
    return pill;
  }
}

/// The "Danger! 85/100" badge.
class RiskBadge extends StatelessWidget {
  const RiskBadge({super.key, required this.level, required this.score, this.large = false});

  final RiskLevel level;
  final int score;
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
    return Tooltip(
      message: 'Risk score $score out of 100. 20+ is suspicious, 50+ is dangerous.',
      child: Container(
        width: large ? 150 : 118,
        padding: EdgeInsets.symmetric(horizontal: 12, vertical: large ? 12 : 9),
        decoration: BoxDecoration(
          gradient: gradient,
          color: safe ? AppColors.panel : null,
          borderRadius: BorderRadius.circular(14),
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
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(levelIcon(level), size: large ? 18 : 16, color: fg),
                const SizedBox(width: 6),
                Flexible(
                  child: Text(
                    levelLabel(level),
                    style: TextStyle(
                        color: fg,
                        fontSize: large ? 15 : 13,
                        fontWeight: FontWeight.w800),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 2),
            Text(
              'risk $score/100',
              style: TextStyle(
                color: safe ? AppColors.faint : Colors.white.withValues(alpha: 0.85),
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Rounded program "icon" with the first letter of its name.
class ProgramAvatar extends StatelessWidget {
  const ProgramAvatar({super.key, required this.row, this.size = 44});

  final ConnectionRow row;
  final double size;

  @override
  Widget build(BuildContext context) {
    final level = row.risk.level;
    final risky = level != RiskLevel.safe;
    final name = row.fileName;
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
      child: row.isWindowsCore
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

/// A warning clue chip like "Runs from a Temp folder +40".
class ReasonChip extends StatelessWidget {
  const ReasonChip({super.key, required this.reason, required this.color});

  final RiskReason reason;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: reason.detail,
      child: Container(
        padding: const EdgeInsets.fromLTRB(8, 5, 6, 5),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.10),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withValues(alpha: 0.35)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(reasonIcon(reason.kind), size: 14, color: color),
            const SizedBox(width: 6),
            Flexible(
              child: Text(
                reason.title,
                style: TextStyle(
                    color: AppColors.blush,
                    fontSize: 12,
                    fontWeight: FontWeight.w600),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            const SizedBox(width: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.22),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                '+${reason.points}',
                style: TextStyle(
                    color: color, fontSize: 11, fontWeight: FontWeight.w800),
              ),
            ),
          ],
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
              color: ok ? AppColors.pink : AppColors.danger, size: 18),
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
