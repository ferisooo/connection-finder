// The main window: header, numbers, search & filters, and the list of
// connection cards.

import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../state/app_controller.dart';
import '../theme.dart';
import 'connection_card.dart';
import 'details_dialog.dart';
import 'settings_screen.dart';
import 'widgets.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.controller});

  final AppController controller;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _search = TextEditingController();
  final _scroll = ScrollController();

  AppController get c => widget.controller;

  @override
  void dispose() {
    _search.dispose();
    _scroll.dispose();
    super.dispose();
  }

  // ---- actions ----------------------------------------------------------

  void _openSettings() {
    Navigator.of(context).push(MaterialPageRoute<void>(
      builder: (_) => SettingsScreen(settings: c.settings, ai: c.ai),
    ));
  }

  Future<void> _askAi(ConnectionRow row) async {
    final msg = await c.askAi(row);
    if (msg != null && mounted) {
      showToast(context, msg,
          ok: false, actionLabel: 'Settings', onAction: _openSettings);
    }
  }

  Future<void> _askAiAll() async {
    if (!c.settings.aiReady) {
      showToast(context, 'Add your AI key in Settings first.',
          ok: false, actionLabel: 'Settings', onAction: _openSettings);
      return;
    }
    final pending = c.pendingAiRows;
    if (pending.isEmpty) {
      showToast(context, 'No risky connections are waiting for the AI.');
      return;
    }
    final provider = c.settings.provider;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        icon: const Icon(Icons.auto_awesome_rounded,
            color: AppColors.pink, size: 34),
        title: Text(
            'Ask ${provider.shortName} about ${pending.length} connection${pending.length == 1 ? '' : 's'}?'),
        content: SizedBox(
          width: 440,
          child: Text(
            'This sends each connection\'s IP address, program folder and file name, '
            'start command and the app\'s clues to ${provider.label}. '
            'It uses a little of your API credits.',
            style: const TextStyle(color: AppColors.muted, height: 1.4),
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton.icon(
            onPressed: () => Navigator.pop(ctx, true),
            icon: const Icon(Icons.auto_awesome_rounded, size: 18),
            label: const Text('Ask AI'),
          ),
        ],
      ),
    );
    if (ok == true) unawaited(c.askAiAboutPending());
  }

  Future<void> _openFolder(ConnectionRow row) async {
    final res = await c.revealInExplorer(row);
    if (!res.ok && mounted) showToast(context, res.message, ok: false);
  }

  void _copy(ConnectionRow row) {
    final ip = row.connection.remoteAddress;
    final text = ip.isNotEmpty ? ip : (row.path ?? row.fileName);
    Clipboard.setData(ClipboardData(text: text));
    showToast(context, 'Copied $text');
  }

  void _copyPath(ConnectionRow row) {
    final text = row.path ?? row.fileName;
    Clipboard.setData(ClipboardData(text: text));
    showToast(context, 'Copied the program path');
  }

  Future<void> _stop(ConnectionRow row) async {
    final folder = (row.folder ?? '').toLowerCase();
    final isWindowsFile = RegExp(r'^[a-z]:\\windows(\\|$)').hasMatch(folder);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        icon: const Icon(Icons.power_settings_new_rounded,
            color: AppColors.danger, size: 36),
        title: Text('Stop ${row.fileName}?'),
        content: SizedBox(
          width: 440,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'This force-closes the program (PID ${row.pid}) and all of its connections. '
                'Anything unsaved in it will be lost.',
                style: const TextStyle(color: AppColors.muted, height: 1.4),
              ),
              if (isWindowsFile) ...[
                const SizedBox(height: 12),
                const Text(
                  'Careful: this is part of Windows. Stopping it could make your PC unstable or restart it.',
                  style: TextStyle(
                      color: AppColors.danger,
                      fontWeight: FontWeight.w600,
                      height: 1.4),
                ),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton.icon(
            style: FilledButton.styleFrom(backgroundColor: AppColors.danger),
            onPressed: () => Navigator.pop(ctx, true),
            icon: const Icon(Icons.power_settings_new_rounded, size: 18),
            label: const Text('Stop it'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final res = await c.stopProgram(row);
    if (mounted) showToast(context, res.message, ok: res.ok);
  }

  void _details(ConnectionRow row) {
    showDialog<void>(
      context: context,
      builder: (_) => DetailsDialog(
        controller: c,
        initialRow: row,
        onAskAi: _askAi,
        onOpenFolder: _openFolder,
        onCopyPath: _copyPath,
        onStop: _stop,
      ),
    );
  }

  Future<void> _relaunchAsAdmin() async {
    final ok = await c.relaunchAsAdmin();
    if (ok) {
      exit(0);
    } else if (mounted) {
      showToast(context, 'Windows did not allow it (the prompt was cancelled).',
          ok: false);
    }
  }

  // ---- layout -------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          const _BackgroundGlow(),
          ListenableBuilder(
            listenable: c,
            builder: (context, _) => Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _Header(
                  controller: c,
                  onSettings: _openSettings,
                ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 4, 24, 0),
                  child: _StatsRow(
                    stats: c.stats,
                    onSuspicious: () => c.filter = RowFilter.suspicious,
                    onAll: () => c.filter = RowFilter.all,
                    onConnected: () => c.filter = RowFilter.connected,
                  ),
                ),
                ..._banners(),
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 14, 24, 6),
                  child: _toolbar(),
                ),
                Expanded(child: _list()),
              ],
            ),
          ),
        ],
      ),
    );
  }

  List<Widget> _banners() {
    final out = <Widget>[];
    void add(Widget w) => out.add(Padding(
        padding: const EdgeInsets.fromLTRB(24, 12, 24, 0), child: w));

    if (c.demoMode) {
      add(const _Banner(
        icon: Icons.science_rounded,
        text:
            "Demo mode: this computer isn't Windows, so you're seeing made-up sample connections.",
      ));
    } else if (c.firstScanDone && !c.isAdmin) {
      add(_Banner(
        icon: Icons.admin_panel_settings_rounded,
        text:
            'Some program folders may be hidden because the app is not running as administrator.',
        actionLabel: 'Restart as admin',
        onAction: _relaunchAsAdmin,
      ));
    }
    if (c.error != null) {
      add(_Banner(
        icon: Icons.error_outline_rounded,
        text: c.error!,
        danger: true,
        actionLabel: 'Try again',
        onAction: c.refresh,
      ));
    }
    if (c.usingNetstatFallback) {
      add(const _Banner(
        icon: Icons.info_outline_rounded,
        text: 'Using the backup method (netstat) to read connections.',
      ));
    }
    final warn = c.settings.storageWarning;
    if (warn != null) add(_Banner(icon: Icons.key_off_rounded, text: warn));
    return out;
  }

  Widget _toolbar() {
    final pending = c.pendingAiRows.length;
    final visible = c.visibleRows.length;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: TextField(
                controller: _search,
                onChanged: (v) => c.search = v,
                style: const TextStyle(fontSize: 14),
                decoration: InputDecoration(
                  hintText: 'Search IP, program, folder, country, port...',
                  prefixIcon:
                      const Icon(Icons.search_rounded, color: AppColors.pink),
                  suffixIcon: c.search.isEmpty
                      ? null
                      : IconButton(
                          tooltip: 'Clear',
                          icon: const Icon(Icons.close_rounded,
                              color: AppColors.muted),
                          onPressed: () {
                            _search.clear();
                            c.search = '';
                          },
                        ),
                ),
              ),
            ),
            const SizedBox(width: 12),
            SizedBox(
              height: 50,
              child: DecoratedBox(
                decoration: BoxDecoration(
                  gradient: c.aiBatchRunning ? null : AppColors.pinkGradient,
                  color: c.aiBatchRunning ? AppColors.cardHigh : null,
                  borderRadius: BorderRadius.circular(14),
                  boxShadow: [
                    if (!c.aiBatchRunning)
                      BoxShadow(
                        color: AppColors.pink.withValues(alpha: 0.35),
                        blurRadius: 18,
                        spreadRadius: -6,
                      ),
                  ],
                ),
                child: TextButton.icon(
                  onPressed: c.aiBatchRunning ? null : _askAiAll,
                  style: TextButton.styleFrom(
                    foregroundColor: Colors.white,
                    disabledForegroundColor: AppColors.softPink,
                    padding: const EdgeInsets.symmetric(horizontal: 18),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14)),
                  ),
                  icon: c.aiBatchRunning
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.auto_awesome_rounded, size: 18),
                  label: Text(
                    c.aiBatchRunning
                        ? 'Asking AI... ${c.aiBatchDone}/${c.aiBatchTotal}'
                        : pending > 0
                            ? 'Ask AI about risky ones ($pending)'
                            : 'Ask AI about risky ones',
                    style: const TextStyle(
                        fontWeight: FontWeight.w700, fontSize: 14),
                  ),
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
            for (final f in RowFilter.values)
              _FilterChip(
                label: switch (f) {
                  RowFilter.all => 'All',
                  RowFilter.suspicious => 'Suspicious only',
                  RowFilter.connected => 'Connected IPs',
                  RowFilter.listening => 'Open doors',
                },
                icon: switch (f) {
                  RowFilter.all => Icons.all_inclusive_rounded,
                  RowFilter.suspicious => Icons.warning_amber_rounded,
                  RowFilter.connected => Icons.swap_horiz_rounded,
                  RowFilter.listening => Icons.sensors_rounded,
                },
                selected: c.filter == f,
                onTap: () => c.filter = f,
              ),
            _FilterChip(
              label: 'Show local & closing',
              icon: c.settings.showLocal
                  ? Icons.check_box_rounded
                  : Icons.check_box_outline_blank_rounded,
              selected: c.settings.showLocal,
              onTap: () => c.settings.showLocal = !c.settings.showLocal,
              subtle: true,
            ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            Padding(
              padding: const EdgeInsets.only(top: 9),
              child: Text(
                '$visible shown',
                style: const TextStyle(color: AppColors.faint, fontSize: 12.5),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _list() {
    if (!c.firstScanDone && c.error == null) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
                width: 42,
                height: 42,
                child: CircularProgressIndicator(strokeWidth: 3)),
            SizedBox(height: 18),
            Text('Looking for connections...',
                style: TextStyle(color: AppColors.softPink, fontSize: 15)),
            SizedBox(height: 6),
            Text('This takes a few seconds the first time.',
                style: TextStyle(color: AppColors.faint, fontSize: 13)),
          ],
        ),
      );
    }
    final rows = c.visibleRows;
    if (rows.isEmpty) {
      final filtered = c.search.isNotEmpty || c.filter != RowFilter.all;
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.favorite_border_rounded,
                size: 46, color: AppColors.pink),
            const SizedBox(height: 14),
            Text(
              filtered ? 'Nothing matches' : 'No connections right now',
              style: const TextStyle(
                  fontSize: 17, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            Text(
              filtered
                  ? 'Try another search or filter.'
                  : 'When a program talks to the internet, it shows up here.',
              style: const TextStyle(color: AppColors.muted),
            ),
          ],
        ),
      );
    }
    return Scrollbar(
      controller: _scroll,
      child: ListView.builder(
        controller: _scroll,
        padding: const EdgeInsets.fromLTRB(24, 8, 24, 28),
        itemCount: rows.length,
        itemBuilder: (context, i) {
          final row = rows[i];
          return ConnectionCard(
            key: ValueKey(row.connection.key),
            row: row,
            verdict: c.verdictFor(row),
            asking: c.isAsking(row),
            checkingFile: c.isCheckingFile(row),
            lookupOn: c.settings.geoLookup,
            onAskAi: () => _askAi(row),
            onOpenFolder: () => _openFolder(row),
            onCopy: () => _copy(row),
            onDetails: () => _details(row),
            onStop: () => _stop(row),
          );
        },
      ),
    );
  }
}

// ---------------------------------------------------------------------------

class _BackgroundGlow extends StatelessWidget {
  const _BackgroundGlow();

  @override
  Widget build(BuildContext context) {
    return Positioned.fill(
      child: IgnorePointer(
        child: DecoratedBox(
          decoration: BoxDecoration(
            gradient: RadialGradient(
              center: const Alignment(-0.95, -1.05),
              radius: 1.1,
              colors: [
                AppColors.pink.withValues(alpha: 0.16),
                AppColors.magenta.withValues(alpha: 0.05),
                Colors.transparent,
              ],
              stops: const [0, 0.45, 1],
            ),
          ),
        ),
      ),
    );
  }
}

class _Header extends StatelessWidget {
  const _Header({required this.controller, required this.onSettings});

  final AppController controller;
  final VoidCallback onSettings;

  @override
  Widget build(BuildContext context) {
    final settings = controller.settings;
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 20, 24, 14),
      child: Row(
        children: [
          Container(
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(14),
              boxShadow: [
                BoxShadow(
                  color: AppColors.pink.withValues(alpha: 0.45),
                  blurRadius: 22,
                  spreadRadius: -6,
                ),
              ],
            ),
            child: Image.asset('assets/icon.png', width: 50, height: 50),
          ),
          const SizedBox(width: 16),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                GradientText(
                  'Connection Finder',
                  style: TextStyle(
                      fontSize: 26,
                      fontWeight: FontWeight.w900,
                      letterSpacing: -0.3),
                ),
                SizedBox(height: 2),
                Text(
                  "See who's connected to your PC, and which program and folder it comes from.",
                  style: TextStyle(color: AppColors.muted, fontSize: 13.5),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 16),
          _LiveStatus(controller: controller),
          const SizedBox(width: 10),
          _RoundButton(
            icon: settings.autoRefresh
                ? Icons.pause_rounded
                : Icons.play_arrow_rounded,
            tooltip: settings.autoRefresh
                ? 'Pause live updates'
                : 'Resume live updates',
            onPressed: () => settings.autoRefresh = !settings.autoRefresh,
          ),
          const SizedBox(width: 8),
          _RoundButton(
            icon: Icons.refresh_rounded,
            tooltip: 'Scan now',
            busy: controller.scanning,
            onPressed: controller.refresh,
          ),
          const SizedBox(width: 8),
          _RoundButton(
            icon: Icons.settings_rounded,
            tooltip: 'Settings (AI key, IP lookup...)',
            onPressed: onSettings,
          ),
        ],
      ),
    );
  }
}

class _LiveStatus extends StatefulWidget {
  const _LiveStatus({required this.controller});
  final AppController controller;

  @override
  State<_LiveStatus> createState() => _LiveStatusState();
}

class _LiveStatusState extends State<_LiveStatus> {
  Timer? _tick;

  @override
  void initState() {
    super.initState();
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _tick?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.controller;
    final live = c.settings.autoRefresh;
    final last = c.lastUpdated;
    String when;
    if (last == null) {
      when = 'scanning...';
    } else {
      final s = DateTime.now().difference(last).inSeconds;
      when = s <= 1 ? 'updated just now' : 'updated ${s}s ago';
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
      decoration: BoxDecoration(
        color: AppColors.panel,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
            color: live
                ? AppColors.pink.withValues(alpha: 0.5)
                : AppColors.border),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 9,
            height: 9,
            decoration: BoxDecoration(
              color: live ? AppColors.pink : AppColors.faint,
              shape: BoxShape.circle,
              boxShadow: live
                  ? [
                      BoxShadow(
                          color: AppColors.pink.withValues(alpha: 0.8),
                          blurRadius: 8)
                    ]
                  : null,
            ),
          ),
          const SizedBox(width: 8),
          Text(
            live ? 'Live' : 'Paused',
            style: TextStyle(
                color: live ? AppColors.text : AppColors.muted,
                fontWeight: FontWeight.w700,
                fontSize: 13),
          ),
          Text('  ·  $when',
              style: const TextStyle(color: AppColors.muted, fontSize: 13)),
        ],
      ),
    );
  }
}

class _RoundButton extends StatelessWidget {
  const _RoundButton({
    required this.icon,
    required this.tooltip,
    required this.onPressed,
    this.busy = false,
  });

  final IconData icon;
  final String tooltip;
  final VoidCallback onPressed;
  final bool busy;

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: tooltip,
      child: Material(
        color: AppColors.panel,
        shape: const CircleBorder(side: BorderSide(color: AppColors.border)),
        child: InkWell(
          customBorder: const CircleBorder(),
          onTap: busy ? null : onPressed,
          child: SizedBox(
            width: 42,
            height: 42,
            child: Center(
              child: busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : Icon(icon, size: 20, color: AppColors.softPink),
            ),
          ),
        ),
      ),
    );
  }
}

class _StatsRow extends StatelessWidget {
  const _StatsRow({
    required this.stats,
    required this.onSuspicious,
    required this.onAll,
    required this.onConnected,
  });

  final Stats stats;
  final VoidCallback onSuspicious;
  final VoidCallback onAll;
  final VoidCallback onConnected;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: _StatCard(
            icon: Icons.hub_rounded,
            value: stats.connections,
            label: 'Connections',
            onTap: onAll,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _StatCard(
            icon: Icons.public_rounded,
            value: stats.remoteIps,
            label: 'Internet IPs',
            onTap: onConnected,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _StatCard(
            icon: Icons.apps_rounded,
            value: stats.programs,
            label: 'Programs',
            onTap: onAll,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _StatCard(
            icon: Icons.warning_amber_rounded,
            value: stats.suspicious,
            label: 'Suspicious',
            accent: stats.suspicious > 0 ? AppColors.pink : null,
            onTap: onSuspicious,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _StatCard(
            icon: Icons.gpp_bad_rounded,
            value: stats.dangerous,
            label: 'Dangerous',
            accent: stats.dangerous > 0 ? AppColors.danger : null,
            glow: stats.dangerous > 0,
            onTap: onSuspicious,
          ),
        ),
      ],
    );
  }
}

class _StatCard extends StatelessWidget {
  const _StatCard({
    required this.icon,
    required this.value,
    required this.label,
    required this.onTap,
    this.accent,
    this.glow = false,
  });

  final IconData icon;
  final int value;
  final String label;
  final VoidCallback onTap;
  final Color? accent;
  final bool glow;

  @override
  Widget build(BuildContext context) {
    final color = accent ?? AppColors.softPink;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: Ink(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          decoration: BoxDecoration(
            color: accent != null
                ? Color.alphaBlend(
                    accent!.withValues(alpha: 0.10), AppColors.card)
                : AppColors.card,
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
                color: accent != null
                    ? accent!.withValues(alpha: 0.55)
                    : AppColors.borderSoft),
            boxShadow: glow
                ? [
                    BoxShadow(
                      color: AppColors.danger.withValues(alpha: 0.3),
                      blurRadius: 24,
                      spreadRadius: -6,
                    ),
                  ]
                : null,
          ),
          child: Row(
            children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(icon, color: color, size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '$value',
                      style: TextStyle(
                        fontSize: 24,
                        fontWeight: FontWeight.w900,
                        color: accent ?? AppColors.text,
                        height: 1.1,
                      ),
                    ),
                    Text(
                      label,
                      style: const TextStyle(
                          color: AppColors.muted, fontSize: 12.5),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  const _FilterChip({
    required this.label,
    required this.icon,
    required this.selected,
    required this.onTap,
    this.subtle = false,
  });

  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;
  final bool subtle;

  @override
  Widget build(BuildContext context) {
    final strong = selected && !subtle;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(999),
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            gradient: strong ? AppColors.pinkGradient : null,
            color: strong ? null : AppColors.panel,
            borderRadius: BorderRadius.circular(999),
            border: Border.all(
                color: strong
                    ? Colors.transparent
                    : (selected ? AppColors.pink : AppColors.border)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon,
                  size: 15,
                  color: strong
                      ? Colors.white
                      : (selected ? AppColors.pink : AppColors.muted)),
              const SizedBox(width: 6),
              Text(
                label,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: strong ? Colors.white : AppColors.text,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _Banner extends StatelessWidget {
  const _Banner({
    required this.icon,
    required this.text,
    this.actionLabel,
    this.onAction,
    this.danger = false,
  });

  final IconData icon;
  final String text;
  final String? actionLabel;
  final VoidCallback? onAction;
  final bool danger;

  @override
  Widget build(BuildContext context) {
    final color = danger ? AppColors.danger : AppColors.pink;
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 10, 10, 10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Row(
        children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Text(text,
                style: const TextStyle(color: AppColors.blush, fontSize: 13.5)),
          ),
          if (actionLabel != null)
            FilledButton(
              onPressed: onAction,
              style: FilledButton.styleFrom(
                backgroundColor: color,
                padding:
                    const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              ),
              child: Text(actionLabel!),
            ),
        ],
      ),
    );
  }
}
