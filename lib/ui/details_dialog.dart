// Everything known about one connection, in a big pink-and-black window.

import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../services/ip_utils.dart';
import '../state/app_controller.dart';
import '../theme.dart';
import 'connection_card.dart';
import 'widgets.dart';

class DetailsDialog extends StatelessWidget {
  const DetailsDialog({
    super.key,
    required this.controller,
    required this.initialRow,
    required this.onAskAi,
    required this.onOpenFolder,
    required this.onCopyPath,
    required this.onStop,
  });

  final AppController controller;
  final ConnectionRow initialRow;
  final void Function(ConnectionRow row) onAskAi;
  final void Function(ConnectionRow row) onOpenFolder;
  final void Function(ConnectionRow row) onCopyPath;
  final void Function(ConnectionRow row) onStop;

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.sizeOf(context);
    return Dialog(
      insetPadding: const EdgeInsets.all(32),
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: 780, maxHeight: size.height * 0.88),
        child: ListenableBuilder(
          listenable: controller,
          builder: (context, _) {
            final key = initialRow.connection.key;
            final row = controller.allRows.firstWhere(
                (r) => r.connection.key == key,
                orElse: () => initialRow);
            final stillOpen = controller.allRows.any((r) => r.connection.key == key);
            return _body(context, row, stillOpen);
          },
        ),
      ),
    );
  }

  Widget _body(BuildContext context, ConnectionRow row, bool stillOpen) {
    final c = row.connection;
    final file = row.file;
    final geo = row.geo;
    final verdict = controller.verdictFor(row);
    final asking = controller.isAsking(row);
    final (sigText, _, _) =
        signatureLook(row, checking: controller.isCheckingFile(row));

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(24, 22, 16, 14),
          child: Row(
            children: [
              ProgramAvatar(row: row, size: 52),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(row.fileName,
                        style: const TextStyle(
                            fontSize: 21, fontWeight: FontWeight.w800)),
                    const SizedBox(height: 4),
                    Text(
                      stillOpen
                          ? '${directionLabel(row.direction)} · ${remoteTitle(row)}'
                          : 'This connection has closed.',
                      style: mono(13, color: AppColors.muted),
                    ),
                  ],
                ),
              ),
              RiskBadge(level: row.risk.level, score: row.risk.score, large: true),
              const SizedBox(width: 8),
              IconButton(
                tooltip: 'Close',
                onPressed: () => Navigator.of(context).pop(),
                icon: const Icon(Icons.close_rounded, color: AppColors.muted),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Flexible(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(24, 18, 24, 18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _Section(
                  icon: Icons.warning_amber_rounded,
                  title: 'Why this score?',
                  children: [
                    if (row.risk.reasons.isEmpty)
                      const _Plain('No warning signs found.',
                          icon: Icons.favorite_rounded),
                    for (final r in row.risk.reasons) _ReasonLine(reason: r),
                    for (final n in row.risk.notes)
                      _Plain(n, icon: Icons.info_outline_rounded),
                  ],
                ),
                _Section(
                  icon: Icons.auto_awesome_rounded,
                  title: 'AI opinion',
                  children: [
                    if (verdict == null && !asking)
                      const _Plain(
                          'Not asked yet. Press "Ask AI" for a second opinion from your AI helper.')
                    else
                      AiVerdictBox(verdict: verdict, asking: asking),
                  ],
                ),
                _Section(
                  icon: Icons.apps_rounded,
                  title: 'Program',
                  children: [
                    _Field('File', row.fileName),
                    _Field('Folder', row.folder ?? 'Hidden by Windows', isMono: true),
                    _Field('Full path', row.path, isMono: true),
                    _Field('Start command', row.process?.commandLine, isMono: true),
                    _Field('Process ID (PID)', '${row.pid}', isMono: true),
                    _Field('Started by PID', row.process?.parentPid?.toString(), isMono: true),
                    _Field('Signature', sigText),
                    _Field('Company', file?.company),
                    _Field('Product', file?.product),
                    _Field('Description', file?.description),
                    _Field('File created', _date(file?.created)),
                    _Field('File size', _size(file?.size)),
                  ],
                ),
                _Section(
                  icon: Icons.swap_horiz_rounded,
                  title: 'Connection',
                  children: [
                    _Field('Direction', '${directionLabel(row.direction)} — ${directionHelp(row.direction)}'),
                    _Field('Protocol / state', '${c.protocol} · ${c.state}'),
                    _Field('This PC', formatEndpoint(c.localAddress, c.localPort), isMono: true),
                    if (c.remoteAddress.isNotEmpty)
                      _Field('Other side', formatEndpoint(c.remoteAddress, c.remotePort), isMono: true),
                  ],
                ),
                if (c.remoteAddress.isNotEmpty)
                  _Section(
                    icon: Icons.public_rounded,
                    title: 'Who is on the other side',
                    children: [
                      if (!isPublicIp(c.remoteAddress))
                        const _Plain('This is a device on your own network (or this PC), so there is nothing to look up.')
                      else if (geo == null)
                        const _Plain('No owner info yet (IP lookup may be off or still loading).')
                      else ...[
                        _Field('Country', [geo.country, geo.countryCode].whereType<String>().join(' · ')),
                        _Field('City', geo.city),
                        _Field('Owner', geo.org),
                        _Field('Internet provider', geo.isp),
                        _Field('Network', geo.asName),
                        _Field('VPN / proxy / Tor', geo.proxy ? 'Yes' : 'No'),
                        _Field('Data center', geo.hosting ? 'Yes' : 'No'),
                      ],
                    ],
                  ),
              ],
            ),
          ),
        ),
        const Divider(height: 1),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 14),
          child: Row(
            children: [
              FilledButton.icon(
                onPressed: asking ? null : () => onAskAi(row),
                icon: const Icon(Icons.auto_awesome_rounded, size: 18),
                label: const Text('Ask AI'),
              ),
              const SizedBox(width: 10),
              OutlinedButton.icon(
                onPressed: row.path == null ? null : () => onOpenFolder(row),
                icon: const Icon(Icons.folder_open_rounded, size: 18),
                label: const Text('Open folder'),
              ),
              const SizedBox(width: 10),
              OutlinedButton.icon(
                onPressed: row.path == null ? null : () => onCopyPath(row),
                icon: const Icon(Icons.content_copy_rounded, size: 18),
                label: const Text('Copy path'),
              ),
              const Spacer(),
              TextButton.icon(
                onPressed: row.isWindowsCore || !stillOpen ? null : () => onStop(row),
                style: TextButton.styleFrom(foregroundColor: AppColors.danger),
                icon: const Icon(Icons.power_settings_new_rounded, size: 18),
                label: const Text('Stop program'),
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
    return '${l.year}-${two(l.month)}-${two(l.day)} ${two(l.hour)}:${two(l.minute)}  ($when)';
  }

  static String? _size(int? bytes) {
    if (bytes == null) return null;
    if (bytes < 1024) return '$bytes bytes';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}

class _Section extends StatelessWidget {
  const _Section({required this.icon, required this.title, required this.children});

  final IconData icon;
  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 12),
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
              Icon(icon, size: 18, color: AppColors.pink),
              const SizedBox(width: 8),
              Text(title,
                  style: const TextStyle(
                      fontSize: 15, fontWeight: FontWeight.w800, color: AppColors.text)),
            ],
          ),
          const SizedBox(height: 10),
          ...children,
        ],
      ),
    );
  }
}

class _Field extends StatelessWidget {
  const _Field(this.label, this.value, {this.isMono = false});

  final String label;
  final String? value;
  final bool isMono;

  @override
  Widget build(BuildContext context) {
    final v = value;
    if (v == null || v.trim().isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 150,
            child: Text(label,
                style: const TextStyle(color: AppColors.muted, fontSize: 13)),
          ),
          Expanded(
            child: SelectableText(
              v,
              style: isMono
                  ? mono(13)
                  : const TextStyle(color: AppColors.text, fontSize: 13.5),
            ),
          ),
        ],
      ),
    );
  }
}

class _Plain extends StatelessWidget {
  const _Plain(this.text, {this.icon});
  final String text;
  final IconData? icon;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (icon != null) ...[
              Padding(
                padding: const EdgeInsets.only(top: 1),
                child: Icon(icon, size: 16, color: AppColors.softPink),
              ),
              const SizedBox(width: 8),
            ],
            Expanded(
              child: Text(text,
                  style:
                      const TextStyle(color: AppColors.muted, fontSize: 13.5)),
            ),
          ],
        ),
      );
}

class _ReasonLine extends StatelessWidget {
  const _ReasonLine({required this.reason});
  final RiskReason reason;

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
              color: AppColors.pink.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(9),
            ),
            child: Icon(reasonIcon(reason.kind), size: 16, color: AppColors.pink),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(reason.title,
                    style: const TextStyle(
                        fontWeight: FontWeight.w700, fontSize: 14, color: AppColors.text)),
                const SizedBox(height: 2),
                Text(reason.detail,
                    style: const TextStyle(color: AppColors.muted, fontSize: 13)),
              ],
            ),
          ),
          const SizedBox(width: 10),
          Text('+${reason.points}',
              style: const TextStyle(
                  color: AppColors.pink, fontWeight: FontWeight.w900, fontSize: 14)),
        ],
      ),
    );
  }
}
