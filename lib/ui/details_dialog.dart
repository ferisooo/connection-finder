// Everything known about one program, answer first: is it suspicious, and
// why (or why not)? Technical details are folded away at the bottom.

import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../services/ip_utils.dart';
import '../state/app_controller.dart';
import '../theme.dart';
import 'program_card.dart';
import 'widgets.dart';

class DetailsDialog extends StatelessWidget {
  const DetailsDialog({
    super.key,
    required this.controller,
    required this.initialGroup,
    required this.onAskAi,
    required this.onOpenFolder,
    required this.onCopy,
    required this.onStop,
  });

  final AppController controller;
  final ProgramGroup initialGroup;
  final void Function(ProgramGroup group) onAskAi;
  final void Function(ProgramGroup group) onOpenFolder;
  final void Function(String text) onCopy;
  final void Function(ProgramGroup group) onStop;

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.sizeOf(context);
    return Dialog(
      insetPadding: const EdgeInsets.all(28),
      child: ConstrainedBox(
        constraints:
            BoxConstraints(maxWidth: 800, maxHeight: size.height * 0.9),
        child: ListenableBuilder(
          listenable: controller,
          builder: (context, _) {
            final live = controller.groupByKey(initialGroup.key);
            return _body(context, live ?? initialGroup, live != null);
          },
        ),
      ),
    );
  }

  Widget _body(BuildContext context, ProgramGroup g, bool stillOpen) {
    final verdict = controller.verdictFor(g);
    final asking = controller.isAsking(g);
    final level = g.level;
    final color = AppColors.forLevel(level);
    final (sigText, sigColor) =
        signatureWords(g, checking: controller.isCheckingFile(g));
    final file = g.file;
    final lookupOn = controller.settings.geoLookup;

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // ---- header --------------------------------------------------
        Padding(
          padding: const EdgeInsets.fromLTRB(24, 22, 14, 16),
          child: Row(
            children: [
              ProgramAvatar(
                  name: g.fileName, level: level, windows: g.isWindowsCore, size: 54),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(g.fileName,
                        style: const TextStyle(
                            fontSize: 22, fontWeight: FontWeight.w800)),
                    const SizedBox(height: 3),
                    Text(
                      stillOpen
                          ? '${g.rows.length} connection${g.rows.length == 1 ? '' : 's'} right now'
                          : 'This program has no connections anymore.',
                      style: const TextStyle(color: AppColors.muted, fontSize: 15),
                    ),
                  ],
                ),
              ),
              RiskBadge(level: level, large: true),
              const SizedBox(width: 6),
              IconButton(
                tooltip: 'Close',
                onPressed: () => Navigator.of(context).pop(),
                icon: const Icon(Icons.close_rounded, color: AppColors.muted, size: 26),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        // ---- body ----------------------------------------------------
        Flexible(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(24, 18, 24, 18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _Section(
                  title: 'Is it suspicious?',
                  icon: levelIcon(level),
                  color: color,
                  children: [
                    Text(verdictHeadline(level),
                        style: TextStyle(
                            color: color, fontSize: 19, fontWeight: FontWeight.w800)),
                    const SizedBox(height: 10),
                    if (g.reasons.isNotEmpty) ...[
                      const _Label('Why:'),
                      for (final r in g.reasons) _ReasonLine(reason: r, color: color),
                      const SizedBox(height: 8),
                    ],
                    if (g.goodSigns.isNotEmpty) ...[
                      _Label(g.reasons.isEmpty ? 'Why not:' : 'Good signs:'),
                      for (final s in g.goodSigns)
                        _IconLine(icon: Icons.check_circle_rounded, color: AppColors.safe, text: s),
                    ],
                    for (final n in g.notes)
                      _IconLine(icon: Icons.info_outline_rounded, color: AppColors.softPink, text: n),
                  ],
                ),
                _Section(
                  title: 'AI opinion',
                  icon: Icons.auto_awesome_rounded,
                  children: [
                    if (verdict == null && !asking)
                      const Text(
                        'Not asked yet. Press "Ask AI" below for a second opinion from your AI helper.',
                        style: TextStyle(color: AppColors.muted, fontSize: 15),
                      )
                    else
                      AiVerdictBox(verdict: verdict, asking: asking),
                  ],
                ),
                _Section(
                  title: 'The program',
                  icon: Icons.apps_rounded,
                  children: [
                    _Field('Name', g.fileName),
                    _Field('Folder', g.folder ?? 'Hidden by Windows', isMono: true),
                    _Field('Made by', file?.company ?? file?.signer),
                    _Field('Signature', sigText, color: sigColor),
                    _Field('What it is', file?.description ?? file?.product),
                    _Field('Running copies', g.pids.length > 1 ? '${g.pids.length}' : null),
                    _Field('File created', _date(file?.created)),
                  ],
                ),
                _Section(
                  title: 'Where it connects',
                  icon: Icons.public_rounded,
                  children: [
                    for (final r in g.rows) _ConnectionLine(row: r, lookupOn: lookupOn, onCopy: onCopy),
                  ],
                ),
                _TechnicalDetails(group: g),
              ],
            ),
          ),
        ),
        const Divider(height: 1),
        // ---- actions -------------------------------------------------
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 14),
          child: Wrap(
            spacing: 10,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: asking ? null : () => onAskAi(g),
                icon: const Icon(Icons.auto_awesome_rounded, size: 20),
                label: const Text('Ask AI'),
              ),
              OutlinedButton.icon(
                onPressed: g.path == null ? null : () => onOpenFolder(g),
                icon: const Icon(Icons.folder_open_rounded, size: 20),
                label: const Text('Open folder'),
              ),
              OutlinedButton.icon(
                onPressed: g.path == null ? null : () => onCopy(g.path!),
                icon: const Icon(Icons.content_copy_rounded, size: 20),
                label: const Text('Copy path'),
              ),
              TextButton.icon(
                onPressed: g.isWindowsCore || !stillOpen ? null : () => onStop(g),
                style: TextButton.styleFrom(
                  foregroundColor: AppColors.danger,
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                ),
                icon: const Icon(Icons.power_settings_new_rounded, size: 20),
                label: const Text('Stop program',
                    style: TextStyle(fontSize: 15, fontWeight: FontWeight.w700)),
              ),
            ],
          ),
        ),
      ],
    );
  }

  static String? _date(DateTime? d) {
    if (d == null) return null;
    final l = d.toLocal();
    String two(int v) => v.toString().padLeft(2, '0');
    final ago = DateTime.now().difference(l);
    final when = ago.inDays >= 1
        ? '${ago.inDays} day${ago.inDays == 1 ? '' : 's'} ago'
        : '${ago.inHours} hour${ago.inHours == 1 ? '' : 's'} ago';
    return '${l.year}-${two(l.month)}-${two(l.day)}  ($when)';
  }
}

class _Section extends StatelessWidget {
  const _Section({
    required this.title,
    required this.icon,
    required this.children,
    this.color = AppColors.pink,
  });

  final String title;
  final IconData icon;
  final Color color;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 14),
      decoration: BoxDecoration(
        color: AppColors.card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.borderSoft),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Icon(icon, size: 20, color: color),
              const SizedBox(width: 8),
              Text(title,
                  style: const TextStyle(
                      fontSize: 17, fontWeight: FontWeight.w800, color: AppColors.text)),
            ],
          ),
          const SizedBox(height: 12),
          ...children,
        ],
      ),
    );
  }
}

class _Label extends StatelessWidget {
  const _Label(this.text);
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 4),
        child: Text(text,
            style: const TextStyle(
                color: AppColors.text, fontSize: 15, fontWeight: FontWeight.w700)),
      );
}

class _IconLine extends StatelessWidget {
  const _IconLine({required this.icon, required this.color, required this.text});

  final IconData icon;
  final Color color;
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.only(top: 1),
              child: Icon(icon, size: 18, color: color),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(text,
                  style: const TextStyle(color: AppColors.muted, fontSize: 15)),
            ),
          ],
        ),
      );
}

class _ReasonLine extends StatelessWidget {
  const _ReasonLine({required this.reason, required this.color});
  final RiskReason reason;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(9),
            ),
            child: Icon(reasonIcon(reason.kind), size: 18, color: color),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(reason.title,
                    style: const TextStyle(
                        fontWeight: FontWeight.w700, fontSize: 15.5, color: AppColors.text)),
                const SizedBox(height: 2),
                Text(reason.detail,
                    style: const TextStyle(color: AppColors.muted, fontSize: 15)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _Field extends StatelessWidget {
  const _Field(this.label, this.value, {this.isMono = false, this.color});

  final String label;
  final String? value;
  final bool isMono;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final v = value;
    if (v == null || v.trim().isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 150,
            child: Text(label,
                style: const TextStyle(color: AppColors.muted, fontSize: 15)),
          ),
          Expanded(
            child: SelectableText(
              v,
              style: isMono
                  ? mono(15, color: color ?? AppColors.text)
                  : TextStyle(color: color ?? AppColors.text, fontSize: 15),
            ),
          ),
        ],
      ),
    );
  }
}

class _ConnectionLine extends StatelessWidget {
  const _ConnectionLine({required this.row, required this.lookupOn, required this.onCopy});

  final ConnectionRow row;
  final bool lookupOn;
  final void Function(String text) onCopy;

  @override
  Widget build(BuildContext context) {
    final place = placeOf(row, lookupOn: lookupOn);
    final ip = row.connection.remoteAddress;
    final risky = row.risk.level != RiskLevel.safe;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(directionIcon(row.direction),
              size: 18, color: risky ? AppColors.pink : AppColors.softPink),
          const SizedBox(width: 10),
          Expanded(
            child: Text.rich(
              TextSpan(children: [
                TextSpan(
                  text: row.direction == Direction.listening
                      ? '${directionWords(row.direction)} on '
                      : '${directionWords(row.direction)} ',
                  style: const TextStyle(color: AppColors.muted),
                ),
                TextSpan(text: endpointOf(row), style: mono(15, weight: FontWeight.w700)),
                if (place.isNotEmpty)
                  TextSpan(
                    text: '  ·  $place',
                    style: const TextStyle(color: AppColors.muted),
                  ),
              ]),
              style: const TextStyle(fontSize: 15, color: AppColors.text),
            ),
          ),
          if (ip.isNotEmpty)
            IconButton(
              tooltip: 'Copy IP address',
              onPressed: () => onCopy(ip),
              icon: const Icon(Icons.content_copy_rounded, size: 18, color: AppColors.faint),
            ),
        ],
      ),
    );
  }
}

/// PIDs, start command, ports and other techy bits, folded away.
class _TechnicalDetails extends StatelessWidget {
  const _TechnicalDetails({required this.group});

  final ProgramGroup group;

  @override
  Widget build(BuildContext context) {
    final file = group.file;
    final process = group.process;
    return Material(
      color: AppColors.card,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: AppColors.borderSoft),
      ),
      child: Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 2),
          childrenPadding: const EdgeInsets.fromLTRB(18, 0, 18, 14),
          iconColor: AppColors.pink,
          collapsedIconColor: AppColors.muted,
          leading: const Icon(Icons.build_rounded, color: AppColors.muted, size: 20),
          title: const Text('Technical details',
              style: TextStyle(fontSize: 17, fontWeight: FontWeight.w800)),
          subtitle: const Text('For experts: process IDs, ports, start command',
              style: TextStyle(color: AppColors.muted, fontSize: 15)),
          children: [
            _Field('Risk score', '${group.score} / 100 for its riskiest connection (20+ suspicious, 50+ dangerous)'),
            _Field('Process IDs', (group.pids.toList()..sort()).join(', '), isMono: true),
            _Field('Started by', process?.parentPid == null ? null : 'process ${process!.parentPid}', isMono: true),
            _Field('Full path', group.path, isMono: true),
            _Field('Start command', process?.commandLine, isMono: true),
            _Field('Product', file?.product),
            _Field('File size', _size(file?.size)),
            _Field('Check error', file?.checkError),
            const SizedBox(height: 6),
            for (final r in group.rows)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 2),
                child: SelectableText(
                  '${r.connection.protocol}  ${r.connection.state.padRight(11)}  '
                  '${formatEndpoint(r.connection.localAddress, r.connection.localPort)}'
                  '${r.connection.remoteAddress.isEmpty ? '' : '  ->  ${formatEndpoint(r.connection.remoteAddress, r.connection.remotePort)}'}'
                  '   (PID ${r.pid})',
                  style: mono(15, color: AppColors.muted),
                ),
              ),
          ],
        ),
      ),
    );
  }

  static String? _size(int? bytes) {
    if (bytes == null) return null;
    if (bytes < 1024) return '$bytes bytes';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}
