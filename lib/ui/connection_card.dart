// One connection, shown as a card: program, folder, remote IP, risk, clues,
// the AI's opinion and quick actions.

import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../theme.dart';
import 'widgets.dart';

class ConnectionCard extends StatefulWidget {
  const ConnectionCard({
    super.key,
    required this.row,
    required this.lookupOn,
    required this.onAskAi,
    required this.onOpenFolder,
    required this.onCopy,
    required this.onDetails,
    required this.onStop,
    this.verdict,
    this.asking = false,
    this.checkingFile = false,
  });

  final ConnectionRow row;
  final AiVerdict? verdict;
  final bool asking;
  final bool checkingFile;
  final bool lookupOn;
  final VoidCallback onAskAi;
  final VoidCallback onOpenFolder;
  final VoidCallback onCopy;
  final VoidCallback onDetails;
  final VoidCallback onStop;

  @override
  State<ConnectionCard> createState() => _ConnectionCardState();
}

class _ConnectionCardState extends State<ConnectionCard> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final row = widget.row;
    final level = row.risk.level;
    final color = AppColors.forLevel(level);
    final risky = level != RiskLevel.safe;

    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 160),
        margin: const EdgeInsets.only(bottom: 12),
        decoration: BoxDecoration(
          color: _hover ? AppColors.cardHigh : AppColors.card,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: risky
                ? color.withValues(alpha: _hover ? 0.85 : 0.5)
                : (_hover ? AppColors.border : AppColors.borderSoft),
            width: risky ? 1.2 : 1,
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
                padding: const EdgeInsets.fromLTRB(22, 16, 16, 10),
                child: _content(row, level, color),
              ),
              Positioned(
                left: 0,
                top: 0,
                bottom: 0,
                child: Container(
                  width: 5,
                  decoration: BoxDecoration(
                    gradient: risky
                        ? LinearGradient(
                            colors: [color, color.withValues(alpha: 0.35)],
                            begin: Alignment.topCenter,
                            end: Alignment.bottomCenter,
                          )
                        : null,
                    color: risky ? null : AppColors.border,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _content(ConnectionRow row, RiskLevel level, Color color) {
    final c = row.connection;
    final (sigText, sigColor, sigIcon) =
        signatureLook(row, checking: widget.checkingFile);
    final folder = row.folder;
    final hasRemote = c.remoteAddress.isNotEmpty;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            ProgramAvatar(row: row),
            const SizedBox(width: 14),
            Expanded(
              flex: 5,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          row.fileName,
                          style: const TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.w700,
                              color: AppColors.text),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (row.isNew) ...[
                        const SizedBox(width: 8),
                        const _NewTag(),
                      ],
                    ],
                  ),
                  const SizedBox(height: 3),
                  Tooltip(
                    message: row.path ?? 'Folder hidden by Windows',
                    child: Row(
                      children: [
                        Icon(
                          folder == null
                              ? Icons.folder_off_outlined
                              : Icons.folder_outlined,
                          size: 14,
                          color: AppColors.faint,
                        ),
                        const SizedBox(width: 5),
                        Flexible(
                          child: Text(
                            folder ??
                                (row.isWindowsCore
                                    ? 'Windows system core'
                                    : 'Folder hidden (run as admin to see it)'),
                            style: mono(12, color: AppColors.muted),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              flex: 4,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Tooltip(
                        message: directionHelp(row.direction),
                        child: Icon(directionIcon(row.direction),
                            size: 16, color: AppColors.pink),
                      ),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Text(
                          remoteTitle(row),
                          style: mono(14, weight: FontWeight.w700),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    remoteSubtitle(row, lookupOn: widget.lookupOn),
                    style:
                        const TextStyle(fontSize: 12, color: AppColors.muted),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),
            RiskBadge(level: level, score: row.risk.score),
          ],
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 6,
          runSpacing: 6,
          children: [
            Pill(
              text: directionLabel(row.direction),
              icon: directionIcon(row.direction),
              color: AppColors.softPink,
              tooltip: directionHelp(row.direction),
            ),
            Pill(text: '${c.protocol} · ${c.state}'),
            Pill(text: 'PID ${c.pid}', monospace: true),
            if (hasRemote) Pill(text: 'local :${c.localPort}', monospace: true),
            if (row.geo?.proxy == true)
              const Pill(
                text: 'VPN / proxy / Tor',
                icon: Icons.vpn_lock_rounded,
                color: AppColors.pink,
                filled: true,
              ),
            Pill(text: sigText, icon: sigIcon, color: sigColor, filled: sigColor != AppColors.muted),
          ],
        ),
        if (row.risk.reasons.isNotEmpty) ...[
          const SizedBox(height: 10),
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: [
              for (final r in row.risk.reasons)
                ReasonChip(
                    reason: r,
                    color: level == RiskLevel.dangerous && r.points >= 30
                        ? AppColors.danger
                        : AppColors.pink),
            ],
          ),
        ],
        if (widget.asking || widget.verdict != null) ...[
          const SizedBox(height: 12),
          AiVerdictBox(verdict: widget.verdict, asking: widget.asking),
        ],
        const SizedBox(height: 6),
        Row(
          children: [
            _ActionButton(
              icon: Icons.auto_awesome_rounded,
              label: widget.verdict == null || widget.verdict!.isError
                  ? 'Ask AI'
                  : 'Ask AI again',
              onPressed: widget.asking ? null : widget.onAskAi,
              highlight: level != RiskLevel.safe,
            ),
            _ActionButton(
              icon: Icons.folder_open_rounded,
              label: 'Open folder',
              onPressed: row.path == null ? null : widget.onOpenFolder,
            ),
            _ActionButton(
              icon: Icons.content_copy_rounded,
              label: hasRemote ? 'Copy IP' : 'Copy path',
              onPressed: widget.onCopy,
            ),
            _ActionButton(
              icon: Icons.info_outline_rounded,
              label: 'Details',
              onPressed: widget.onDetails,
            ),
            const Spacer(),
            _ActionButton(
              icon: Icons.power_settings_new_rounded,
              label: 'Stop program',
              onPressed: row.isWindowsCore ? null : widget.onStop,
              danger: true,
            ),
          ],
        ),
      ],
    );
  }
}

class _NewTag extends StatelessWidget {
  const _NewTag();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
      decoration: BoxDecoration(
        gradient: AppColors.pinkGradient,
        borderRadius: BorderRadius.circular(6),
      ),
      child: const Text(
        'NEW',
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w900,
          color: Colors.white,
          letterSpacing: 0.8,
        ),
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
      icon: Icon(icon, size: 16),
      label: Text(label,
          style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
      style: TextButton.styleFrom(
        foregroundColor: color,
        disabledForegroundColor: AppColors.faint,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        minimumSize: const Size(0, 36),
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
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          SizedBox(width: 12),
          Text('Asking your AI helper...',
              style: TextStyle(color: AppColors.softPink, fontSize: 13)),
        ],
      );
    } else if (v == null) {
      body = const SizedBox.shrink();
    } else if (v.isError) {
      body = Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.error_outline_rounded,
              size: 18, color: AppColors.danger),
          const SizedBox(width: 10),
          Expanded(
            child: Text(v.error!,
                style: const TextStyle(color: AppColors.blush, fontSize: 13)),
          ),
        ],
      );
    } else {
      body = Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.auto_awesome_rounded, size: 18, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text.rich(
                  TextSpan(children: [
                    const TextSpan(
                        text: 'AI says: ',
                        style: TextStyle(color: AppColors.muted)),
                    TextSpan(
                      text: ratingLabel(v.rating),
                      style:
                          TextStyle(color: color, fontWeight: FontWeight.w800),
                    ),
                    if (v.confidence > 0)
                      TextSpan(
                        text: '  ·  ${v.confidence}% sure',
                        style: const TextStyle(color: AppColors.muted),
                      ),
                  ]),
                  style: const TextStyle(fontSize: 13),
                ),
                if (v.summary.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(v.summary,
                      style: const TextStyle(
                          color: AppColors.text,
                          fontSize: 13.5,
                          fontWeight: FontWeight.w600)),
                ],
                if (v.advice.isNotEmpty) ...[
                  const SizedBox(height: 3),
                  Text(v.advice,
                      style: const TextStyle(
                          color: AppColors.muted, fontSize: 12.5)),
                ],
              ],
            ),
          ),
          const SizedBox(width: 10),
          Text(v.provider,
              style: const TextStyle(color: AppColors.faint, fontSize: 11)),
        ],
      );
    }

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.panel,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.45)),
      ),
      child: body,
    );
  }
}
