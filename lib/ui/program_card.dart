// One program, shown as a card: what it is, where it lives, who it talks to,
// and the answer to "is it suspicious?" with the reasons why (or why not).

import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../services/risk_engine.dart';
import '../state/app_controller.dart';
import '../theme.dart';
import 'widgets.dart';

class ProgramCard extends StatefulWidget {
  const ProgramCard({
    super.key,
    required this.group,
    required this.status,
    required this.lookupOn,
    required this.isAdmin,
    required this.onAskAi,
    required this.onOpenFolder,
    required this.onDetails,
    required this.onStop,
    required this.onRestartAsAdmin,
    this.verdict,
    this.asking = false,
  });

  final ProgramGroup group;
  final ProgramStatus status;
  final bool isAdmin;
  final VoidCallback onRestartAsAdmin;
  final AiVerdict? verdict;
  final bool asking;
  final bool lookupOn;
  final VoidCallback onAskAi;
  final VoidCallback onOpenFolder;
  final VoidCallback onDetails;
  final VoidCallback onStop;

  @override
  State<ProgramCard> createState() => _ProgramCardState();
}

class _ProgramCardState extends State<ProgramCard> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final g = widget.group;
    final level = g.level;
    final risky = level != RiskLevel.safe;
    final color = risky ? AppColors.forLevel(level) : AppColors.safe;

    final card = AnimatedContainer(
      duration: const Duration(milliseconds: 160),
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: _hover ? AppColors.cardHigh : AppColors.card,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: color.withValues(alpha: _hover ? 0.85 : (risky ? 0.55 : 0.35)),
          width: risky ? 1.3 : 1,
        ),
        boxShadow: [
          if (level == RiskLevel.dangerous)
            BoxShadow(
              color: AppColors.danger.withValues(alpha: _hover ? 0.38 : 0.26),
              blurRadius: 30,
              spreadRadius: -6,
            ),
          if (level == RiskLevel.suspicious)
            BoxShadow(
              color: AppColors.pink.withValues(alpha: _hover ? 0.22 : 0.12),
              blurRadius: 24,
              spreadRadius: -8,
            ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(18),
        child: Stack(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 18, 18, 10),
              child: _content(g, level, color),
            ),
            Positioned(
              left: 0,
              top: 0,
              bottom: 0,
              child: Container(
                width: 5,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [color, color.withValues(alpha: 0.35)],
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );

    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: card,
    );
  }

  Widget _content(ProgramGroup g, RiskLevel level, Color color) {
    final risky = level != RiskLevel.safe;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            ProgramAvatar(name: g.fileName, level: level, windows: g.isWindowsCore),
            const SizedBox(width: 14),
            Expanded(child: _nameAndFolder(g)),
            const SizedBox(width: 12),
            RiskBadge(level: level, unchecked: widget.status == ProgramStatus.unchecked),
          ],
        ),
        const SizedBox(height: 12),
        _TalkingLine(group: g, lookupOn: widget.lookupOn),
        const SizedBox(height: 12),
        if (risky)
          _WhyRisky(group: g, color: color)
        else
          _WhyUnchecked(group: g, isAdmin: widget.isAdmin),
        if (widget.asking || widget.verdict != null) ...[
          const SizedBox(height: 12),
          AiVerdictBox(verdict: widget.verdict, asking: widget.asking),
        ],
        const SizedBox(height: 6),
        Wrap(
          spacing: 4,
          runSpacing: 2,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            if (!risky && !widget.isAdmin && g.path == null)
              _ActionButton(
                icon: Icons.admin_panel_settings_rounded,
                label: 'Restart as admin to check it',
                onPressed: widget.onRestartAsAdmin,
                highlight: true,
              ),
            if (risky)
              _ActionButton(
                icon: Icons.auto_awesome_rounded,
                label: widget.verdict == null || widget.verdict!.isError
                    ? 'Ask AI'
                    : 'Ask AI again',
                onPressed: widget.asking ? null : widget.onAskAi,
                highlight: true,
              ),
            if (g.path != null)
              _ActionButton(
                icon: Icons.folder_open_rounded,
                label: 'Open folder',
                onPressed: widget.onOpenFolder,
              ),
            _ActionButton(
              icon: Icons.info_outline_rounded,
              label: 'Details',
              onPressed: widget.onDetails,
            ),
            if (risky)
              _ActionButton(
                icon: Icons.power_settings_new_rounded,
                label: 'Stop program',
                onPressed: g.isWindowsCore ? null : widget.onStop,
                danger: true,
              ),
          ],
        ),
      ],
    );
  }

  Widget _nameAndFolder(ProgramGroup g) {
    final folder = g.folder;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Flexible(
              child: Text(
                g.fileName,
                style: const TextStyle(
                    fontSize: 18, fontWeight: FontWeight.w800, color: AppColors.text),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            if (g.isNew) ...[
              const SizedBox(width: 8),
              const NewTag(),
            ],
          ],
        ),
        const SizedBox(height: 3),
        Tooltip(
          message: g.path ?? 'Windows is hiding this folder',
          child: Row(
            children: [
              Icon(folder == null ? Icons.folder_off_outlined : Icons.folder_outlined,
                  size: 17, color: AppColors.faint),
              const SizedBox(width: 6),
              Flexible(
                child: Text(
                  folder ??
                      (g.isWindowsCore
                          ? 'Windows itself'
                          : 'Folder hidden by Windows'),
                  style: mono(15, color: AppColors.muted),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

/// "Talking to 185.220.101.47 · Germany · Tor exit relay  + 2 more".
class _TalkingLine extends StatelessWidget {
  const _TalkingLine({required this.group, required this.lookupOn});

  final ProgramGroup group;
  final bool lookupOn;

  @override
  Widget build(BuildContext context) {
    final talking = group.talking;
    final row = talking.isNotEmpty ? talking.first : group.listening.first;
    final others = group.rows.length - 1;
    final place = placeOf(row, lookupOn: lookupOn);
    final endpoint = endpointOf(row);
    final isListening = row.direction == Direction.listening;

    return Row(
      children: [
        Icon(directionIcon(row.direction), size: 18, color: AppColors.pink),
        const SizedBox(width: 8),
        Expanded(
          child: Text.rich(
            TextSpan(children: [
              TextSpan(
                text: isListening
                    ? '${directionWords(row.direction)} on '
                    : '${directionWords(row.direction)} ',
                style: const TextStyle(color: AppColors.muted),
              ),
              TextSpan(text: endpoint, style: mono(15, weight: FontWeight.w700)),
              if (place.isNotEmpty)
                TextSpan(
                  text: isListening ? '  ($place)' : '  ·  $place',
                  style: const TextStyle(color: AppColors.muted),
                ),
              if (others > 0)
                TextSpan(
                  text: '   + $others more',
                  style: const TextStyle(
                      color: AppColors.softPink, fontWeight: FontWeight.w600),
                ),
            ]),
            style: const TextStyle(fontSize: 15, color: AppColors.text),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}

/// "Why it looks suspicious:" with the top reasons in plain words.
class _WhyRisky extends StatelessWidget {
  const _WhyRisky({required this.group, required this.color});

  final ProgramGroup group;
  final Color color;

  static const int shown = 3;

  @override
  Widget build(BuildContext context) {
    final reasons = group.reasons;
    final more = reasons.length - shown;
    return Container(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.28)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            group.level == RiskLevel.dangerous
                ? 'Why it looks dangerous:'
                : 'Why it looks suspicious:',
            style: TextStyle(color: color, fontSize: 16, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 6),
          for (final r in reasons.take(shown))
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 3),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 1),
                    child: Icon(reasonIcon(r.kind), size: 18, color: color),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text.rich(
                      TextSpan(children: [
                        TextSpan(
                          text: r.title,
                          style: const TextStyle(
                              fontWeight: FontWeight.w700, color: AppColors.text),
                        ),
                        TextSpan(
                          text: '  ${r.detail}',
                          style: const TextStyle(color: AppColors.muted),
                        ),
                      ]),
                      style: const TextStyle(fontSize: 15, height: 1.35),
                    ),
                  ),
                ],
              ),
            ),
          if (more > 0)
            Padding(
              padding: const EdgeInsets.only(top: 4, left: 28),
              child: Text(
                '+ $more more reason${more == 1 ? '' : 's'} in Details',
                style: const TextStyle(color: AppColors.softPink, fontSize: 15),
              ),
            ),
        ],
      ),
    );
  }
}

/// Plain-words reason why a program couldn't be checked.
String uncheckedReason(ProgramGroup g, {required bool isAdmin}) {
  final file = g.file;
  final parts = <String>[];
  if (g.path == null) {
    parts.add(isAdmin
        ? "Even with admin rights, Windows won't share this program's folder."
        : 'Windows hides this program because it runs with higher rights than Connection Finder.');
    if (windowsSystemNames.contains(g.fileName.toLowerCase())) {
      parts.add("It has a Windows program's name, so it's probably part of Windows, but that can't be confirmed.");
    }
  } else if (file != null && !file.exists) {
    parts.add("Its program file couldn't be found in its folder.");
  } else {
    parts.add("Windows couldn't check its digital signature.");
  }
  if (g.services.isNotEmpty) {
    final shown = g.services.take(3).join(', ');
    final more = g.services.length - 3;
    parts.add('It runs these Windows services: $shown${more > 0 ? ' and $more more' : ''}.');
  }
  return parts.join(' ');
}

/// "Why it couldn't be checked:" for programs Windows hides.
class _WhyUnchecked extends StatelessWidget {
  const _WhyUnchecked({required this.group, required this.isAdmin});

  final ProgramGroup group;
  final bool isAdmin;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
      decoration: BoxDecoration(
        color: AppColors.safe.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppColors.safe.withValues(alpha: 0.25)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Padding(
            padding: EdgeInsets.only(top: 1),
            child: Icon(Icons.help_outline_rounded, size: 18, color: AppColors.safe),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text.rich(
              TextSpan(children: [
                const TextSpan(
                  text: "Why it couldn't be checked:  ",
                  style: TextStyle(fontWeight: FontWeight.w700, color: AppColors.text),
                ),
                TextSpan(
                  text: uncheckedReason(group, isAdmin: isAdmin),
                  style: const TextStyle(color: AppColors.muted),
                ),
              ]),
              style: const TextStyle(fontSize: 15, height: 1.4),
            ),
          ),
        ],
      ),
    );
  }
}

class _ActionButton extends StatelessWidget {
  const _ActionButton({
    required this.icon,
    required this.label,
    required this.onPressed,
    this.highlight = false,
    this.danger = false,
  });

  final IconData icon;
  final String label;
  final VoidCallback? onPressed;
  final bool highlight;
  final bool danger;

  @override
  Widget build(BuildContext context) {
    final color = danger
        ? AppColors.danger
        : (highlight ? AppColors.pink : AppColors.softPink);
    return TextButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, size: 18),
      label: Text(label,
          style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w700)),
      style: TextButton.styleFrom(
        foregroundColor: color,
        disabledForegroundColor: AppColors.faint,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
        minimumSize: const Size(0, 40),
      ),
    );
  }
}

/// The AI's opinion (or a spinner while it thinks).
class AiVerdictBox extends StatelessWidget {
  const AiVerdictBox({super.key, required this.verdict, this.asking = false});

  final AiVerdict? verdict;
  final bool asking;

  @override
  Widget build(BuildContext context) {
    final v = verdict;
    final color = asking || v == null
        ? AppColors.softPink
        : (v.isError ? AppColors.danger : AppColors.forRating(v.rating));

    Widget body;
    if (asking) {
      body = const Row(
        children: [
          SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          SizedBox(width: 12),
          Text('Asking your AI helper...',
              style: TextStyle(color: AppColors.softPink, fontSize: 15)),
        ],
      );
    } else if (v == null) {
      body = const SizedBox.shrink();
    } else if (v.isError) {
      body = Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.error_outline_rounded, size: 20, color: AppColors.danger),
          const SizedBox(width: 10),
          Expanded(
            child: Text(v.error!,
                style: const TextStyle(color: AppColors.blush, fontSize: 15)),
          ),
        ],
      );
    } else {
      body = Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.auto_awesome_rounded, size: 20, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text.rich(
                  TextSpan(children: [
                    TextSpan(
                        text: '${v.provider} says: ',
                        style: const TextStyle(color: AppColors.muted)),
                    TextSpan(
                      text: ratingLabel(v.rating),
                      style: TextStyle(color: color, fontWeight: FontWeight.w800),
                    ),
                  ]),
                  style: const TextStyle(fontSize: 15),
                ),
                if (v.summary.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(v.summary,
                      style: const TextStyle(
                          color: AppColors.text,
                          fontSize: 16,
                          fontWeight: FontWeight.w600)),
                ],
                if (v.advice.isNotEmpty) ...[
                  const SizedBox(height: 3),
                  Text(v.advice,
                      style: const TextStyle(color: AppColors.muted, fontSize: 15)),
                ],
              ],
            ),
          ),
        ],
      );
    }

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.panel,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.45)),
      ),
      child: body,
    );
  }
}
