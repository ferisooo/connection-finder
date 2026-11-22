// The main window: a one-sentence summary at the top, a search box with two
// simple tabs, and one card per program.

import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../models.dart';
import '../state/app_controller.dart';
import '../theme.dart';
import '../version.dart';
import 'details_dialog.dart';
import 'program_card.dart';
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

  void _openHelp() {
    showDialog<void>(context: context, builder: (_) => const HelpDialog());
  }

  Future<void> _askAi(ProgramGroup group) async {
    final msg = await c.askAi(group);
    if (msg != null && mounted) {
      showToast(context, msg,
          ok: false, actionLabel: 'Open Settings', onAction: _openSettings);
    }
  }

  Future<void> _askAiAll() async {
    if (!c.settings.aiReady) {
      showToast(context, 'First add your AI key in Settings.',
          ok: false, actionLabel: 'Open Settings', onAction: _openSettings);
      return;
    }
    final pending = c.pendingAiGroups;
    if (pending.isEmpty) {
      showToast(context, 'The AI already checked every suspicious program.');
      return;
    }
    final provider = c.settings.provider;
    final n = pending.length;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        icon: const Icon(Icons.auto_awesome_rounded, color: AppColors.pink, size: 36),
        title: Text('Ask ${provider.shortName} about $n program${n == 1 ? '' : 's'}?'),
        content: SizedBox(
          width: 460,
          child: Text(
            'The app will send each program\'s name, folder, start command, the IPs it talks to '
            'and the warning signs to ${provider.label}. This uses a little of your API credits.',
            style: const TextStyle(color: AppColors.muted, height: 1.45, fontSize: 15),
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton.icon(
            onPressed: () => Navigator.pop(ctx, true),
            icon: const Icon(Icons.auto_awesome_rounded, size: 20),
            label: const Text('Ask AI'),
          ),
        ],
      ),
    );
    if (ok == true) unawaited(c.askAiAboutPending());
  }

  Future<void> _openFolder(ProgramGroup group) async {
    final res = await c.revealInExplorer(group);
    if (!res.ok && mounted) showToast(context, res.message, ok: false);
  }

  void _copy(String text) {
    Clipboard.setData(ClipboardData(text: text));
    showToast(context, 'Copied: $text');
  }

  Future<void> _stop(ProgramGroup group) async {
    final folder = (group.folder ?? '').toLowerCase();
    final isWindowsFile = RegExp(r'^[a-z]:\\windows(\\|$)').hasMatch(folder);
    final copies = group.pids.length;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        icon: const Icon(Icons.power_settings_new_rounded,
            color: AppColors.danger, size: 38),
        title: Text('Stop ${group.fileName}?'),
        content: SizedBox(
          width: 460,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                copies > 1
                    ? 'This closes all $copies running copies of the program right away. Anything unsaved in it will be lost.'
                    : 'This closes the program right away. Anything unsaved in it will be lost.',
                style: const TextStyle(color: AppColors.muted, height: 1.45, fontSize: 15),
              ),
              if (isWindowsFile) ...[
                const SizedBox(height: 12),
                const Text(
                  'Careful: this is part of Windows. Stopping it could make your PC unstable or restart it.',
                  style: TextStyle(
                      color: AppColors.danger,
                      fontWeight: FontWeight.w700,
                      height: 1.45,
                      fontSize: 15),
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
            icon: const Icon(Icons.power_settings_new_rounded, size: 20),
            label: const Text('Stop it'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final res = await c.stopProgram(group);
    if (mounted) showToast(context, res.message, ok: res.ok);
  }

  void _details(ProgramGroup group) {
    showDialog<void>(
      context: context,
      builder: (_) => DetailsDialog(
        controller: c,
        initialGroup: group,
        onAskAi: _askAi,
        onOpenFolder: _openFolder,
        onCopy: _copy,
        onStop: _stop,
      ),
    );
  }

  Future<void> _relaunchAsAdmin() async {
    final ok = await c.relaunchAsAdmin();
    if (ok) {
      exit(0);
    } else if (mounted) {
      showToast(context, 'Windows did not allow it (the question was cancelled).',
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
                _Header(controller: c, onSettings: _openSettings, onHelp: _openHelp),
                if (c.firstScanDone)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(24, 2, 24, 0),
                    child: _Summary(
                      stats: c.stats,
                      aiRunning: c.aiBatchRunning,
                      aiDone: c.aiBatchDone,
                      aiTotal: c.aiBatchTotal,
                      onAskAi: _askAiAll,
                    ),
                  ),
                ..._banners(),
                if (c.firstScanDone)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(24, 16, 24, 8),
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
    void add(Widget w) => out.add(
        Padding(padding: const EdgeInsets.fromLTRB(24, 12, 24, 0), child: w));

    if (c.demoMode) {
      add(const _Banner(
        icon: Icons.science_rounded,
        text: "Demo: this computer isn't Windows, so these are made-up examples.",
      ));
    } else if (c.firstScanDone && !c.isAdmin) {
      add(_Banner(
        icon: Icons.admin_panel_settings_rounded,
        text: "Windows hides some programs' folders. Restart as admin to see everything.",
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
    final warn = c.settings.storageWarning;
    if (warn != null) add(_Banner(icon: Icons.key_off_rounded, text: warn));
    return out;
  }

  Widget _toolbar() {
    final stats = c.stats;
    return Row(
      children: [
        Expanded(
          child: TextField(
            controller: _search,
            onChanged: (v) => c.search = v,
            style: const TextStyle(fontSize: 16),
            decoration: InputDecoration(
              hintText: 'Search a program, folder, IP or country...',
              prefixIcon: const Icon(Icons.search_rounded, color: AppColors.pink),
              suffixIcon: c.search.isEmpty
                  ? null
                  : IconButton(
                      tooltip: 'Clear search',
                      icon: const Icon(Icons.close_rounded, color: AppColors.muted),
                      onPressed: () {
                        _search.clear();
                        c.search = '';
                      },
                    ),
            ),
          ),
        ),
        const SizedBox(width: 12),
        _Tab(
          label: 'Everything (${stats.programs})',
          selected: c.filter == ViewFilter.everything,
          onTap: () => c.filter = ViewFilter.everything,
        ),
        const SizedBox(width: 8),
        _Tab(
          label: 'Only suspicious (${stats.riskyPrograms})',
          selected: c.filter == ViewFilter.suspicious,
          onTap: () => c.filter = ViewFilter.suspicious,
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
                width: 44,
                height: 44,
                child: CircularProgressIndicator(strokeWidth: 3)),
            SizedBox(height: 18),
            Text('Checking what is connected to your PC...',
                style: TextStyle(color: AppColors.softPink, fontSize: 17)),
            SizedBox(height: 6),
            Text('This takes a few seconds.',
                style: TextStyle(color: AppColors.muted, fontSize: 15)),
          ],
        ),
      );
    }
    final groups = c.visibleGroups;
    if (groups.isEmpty) {
      final filtered = c.search.isNotEmpty || c.filter != ViewFilter.everything;
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.favorite_border_rounded, size: 48, color: AppColors.pink),
            const SizedBox(height: 14),
            Text(
              c.filter == ViewFilter.suspicious && c.search.isEmpty
                  ? 'Nothing suspicious right now'
                  : filtered
                      ? 'Nothing matches your search'
                      : 'No programs are using the network right now',
              style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            Text(
              filtered
                  ? 'Try "Everything" or a different search.'
                  : 'When a program connects, it shows up here.',
              style: const TextStyle(color: AppColors.muted, fontSize: 15),
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
        itemCount: groups.length,
        itemBuilder: (context, i) {
          final g = groups[i];
          return ProgramCard(
            key: ValueKey(g.key),
            group: g,
            verdict: c.verdictFor(g),
            asking: c.isAsking(g),
            lookupOn: c.settings.geoLookup,
            onAskAi: () => _askAi(g),
            onOpenFolder: () => _openFolder(g),
            onDetails: () => _details(g),
            onStop: () => _stop(g),
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
  const _Header({required this.controller, required this.onSettings, required this.onHelp});

  final AppController controller;
  final VoidCallback onSettings;
  final VoidCallback onHelp;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 20, 24, 16),
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
            child: Image.asset('assets/icon.png', width: 52, height: 52),
          ),
          const SizedBox(width: 16),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                GradientText(
                  'Connection Finder',
                  style: TextStyle(
                      fontSize: 28, fontWeight: FontWeight.w900, letterSpacing: -0.3),
                ),
                SizedBox(height: 2),
                Text(
                  'Shows which programs on your PC use the internet, and warns you if one looks suspicious.',
                  style: TextStyle(color: AppColors.muted, fontSize: 15),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 16),
          _LiveStatus(controller: controller),
          const SizedBox(width: 8),
          _HeaderButton(
            icon: Icons.refresh_rounded,
            tooltip: 'Check again now',
            busy: controller.scanning,
            onPressed: controller.refresh,
          ),
          const SizedBox(width: 8),
          _HeaderButton(
            icon: Icons.help_outline_rounded,
            label: 'Help',
            tooltip: 'How does this work?',
            onPressed: onHelp,
          ),
          const SizedBox(width: 8),
          _HeaderButton(
            icon: Icons.settings_rounded,
            label: 'Settings',
            tooltip: 'AI key, IP lookup and more',
            onPressed: onSettings,
          ),
        ],
      ),
    );
  }
}

/// "● Live · updated 2s ago" - click it to pause or resume.
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
    final settings = c.settings;
    final live = settings.autoRefresh;
    final last = c.lastUpdated;
    String when;
    if (last == null) {
      when = 'checking...';
    } else {
      final s = DateTime.now().difference(last).inSeconds;
      when = s <= 1 ? 'just now' : '${s}s ago';
    }
    return Tooltip(
      message: live
          ? 'Updates by itself every ${settings.refreshSeconds} seconds. Click to pause.'
          : 'Paused. Click to update by itself again.',
      child: Material(
        color: AppColors.panel,
        shape: StadiumBorder(
            side: BorderSide(
                color: live ? AppColors.pink.withValues(alpha: 0.5) : AppColors.border)),
        child: InkWell(
          customBorder: const StadiumBorder(),
          onTap: () => settings.autoRefresh = !live,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                    color: live ? AppColors.pink : AppColors.faint,
                    shape: BoxShape.circle,
                    boxShadow: live
                        ? [BoxShadow(color: AppColors.pink.withValues(alpha: 0.8), blurRadius: 8)]
                        : null,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  live ? 'Live' : 'Paused',
                  style: TextStyle(
                      color: live ? AppColors.text : AppColors.muted,
                      fontWeight: FontWeight.w800,
                      fontSize: 15),
                ),
                Text('  ·  $when',
                    style: const TextStyle(color: AppColors.muted, fontSize: 15)),
                const SizedBox(width: 8),
                Icon(live ? Icons.pause_rounded : Icons.play_arrow_rounded,
                    size: 20, color: AppColors.softPink),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _HeaderButton extends StatelessWidget {
  const _HeaderButton({
    required this.icon,
    required this.tooltip,
    required this.onPressed,
    this.label,
    this.busy = false,
  });

  final IconData icon;
  final String? label;
  final String tooltip;
  final VoidCallback onPressed;
  final bool busy;

  @override
  Widget build(BuildContext context) {
    final iconWidget = busy
        ? const SizedBox(
            width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
        : Icon(icon, size: 21, color: AppColors.softPink);
    return Tooltip(
      message: tooltip,
      child: Material(
        color: AppColors.panel,
        shape: const StadiumBorder(side: BorderSide(color: AppColors.border)),
        child: InkWell(
          customBorder: const StadiumBorder(),
          onTap: busy ? null : onPressed,
          child: Padding(
            padding: EdgeInsets.symmetric(horizontal: label == null ? 11 : 14, vertical: 10),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                iconWidget,
                if (label != null) ...[
                  const SizedBox(width: 7),
                  Text(label!,
                      style: const TextStyle(
                          fontSize: 15, fontWeight: FontWeight.w700, color: AppColors.text)),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// One friendly sentence that says what's going on.
class _Summary extends StatelessWidget {
  const _Summary({
    required this.stats,
    required this.aiRunning,
    required this.aiDone,
    required this.aiTotal,
    required this.onAskAi,
  });

  final Stats stats;
  final bool aiRunning;
  final int aiDone;
  final int aiTotal;
  final VoidCallback onAskAi;

  String _programs(int n) => '$n program${n == 1 ? '' : 's'}';

  @override
  Widget build(BuildContext context) {
    final d = stats.dangerousPrograms;
    final s = stats.suspiciousPrograms;
    final risky = d + s > 0;
    final color = d > 0 ? AppColors.danger : (s > 0 ? AppColors.pink : AppColors.safe);

    final String headline;
    if (d > 0 && s > 0) {
      headline = '${_programs(d)} look${d == 1 ? 's' : ''} dangerous and $s more look${s == 1 ? 's' : ''} suspicious.';
    } else if (d > 0) {
      headline = '${_programs(d)} look${d == 1 ? 's' : ''} dangerous.';
    } else if (s > 0) {
      headline = '${_programs(s)} look${s == 1 ? 's' : ''} suspicious.';
    } else {
      headline = 'Everything looks safe right now.';
    }
    final sub = risky
        ? "They're at the top of the list. Each card tells you why."
        : '${_programs(stats.programs)} ${stats.programs == 1 ? 'is' : 'are'} using the network, and none of them look suspicious.';

    return Container(
      padding: const EdgeInsets.fromLTRB(18, 16, 16, 16),
      decoration: BoxDecoration(
        color: Color.alphaBlend(color.withValues(alpha: 0.09), AppColors.card),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: color.withValues(alpha: 0.5)),
        boxShadow: d > 0
            ? [
                BoxShadow(
                  color: AppColors.danger.withValues(alpha: 0.25),
                  blurRadius: 26,
                  spreadRadius: -8,
                ),
              ]
            : null,
      ),
      child: Row(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.16),
              shape: BoxShape.circle,
            ),
            child: Icon(
              d > 0
                  ? Icons.gpp_bad_rounded
                  : (s > 0 ? Icons.warning_amber_rounded : Icons.favorite_rounded),
              color: color,
              size: 26,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(headline,
                    style: const TextStyle(
                        fontSize: 20, fontWeight: FontWeight.w800, color: AppColors.text)),
                const SizedBox(height: 3),
                Text(sub, style: const TextStyle(fontSize: 15, color: AppColors.muted)),
              ],
            ),
          ),
          if (risky) ...[
            const SizedBox(width: 12),
            DecoratedBox(
              decoration: BoxDecoration(
                gradient: aiRunning ? null : AppColors.pinkGradient,
                color: aiRunning ? AppColors.cardHigh : null,
                borderRadius: BorderRadius.circular(14),
              ),
              child: TextButton.icon(
                onPressed: aiRunning ? null : onAskAi,
                style: TextButton.styleFrom(
                  foregroundColor: Colors.white,
                  disabledForegroundColor: AppColors.softPink,
                  padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                ),
                icon: aiRunning
                    ? const SizedBox(
                        width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.auto_awesome_rounded, size: 20),
                label: Text(
                  aiRunning ? 'Asking AI... $aiDone/$aiTotal' : 'Ask AI to double-check',
                  style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 15),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _Tab extends StatelessWidget {
  const _Tab({required this.label, required this.selected, required this.onTap});

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(999),
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 13),
          decoration: BoxDecoration(
            gradient: selected ? AppColors.pinkGradient : null,
            color: selected ? null : AppColors.panel,
            borderRadius: BorderRadius.circular(999),
            border: Border.all(color: selected ? Colors.transparent : AppColors.border),
          ),
          child: Text(
            label,
            style: TextStyle(
              fontSize: 15,
              fontWeight: FontWeight.w700,
              color: selected ? Colors.white : AppColors.text,
            ),
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
          Icon(icon, color: color, size: 22),
          const SizedBox(width: 12),
          Expanded(
            child: Text(text, style: const TextStyle(color: AppColors.blush, fontSize: 15)),
          ),
          if (actionLabel != null)
            FilledButton(
              onPressed: onAction,
              style: FilledButton.styleFrom(
                backgroundColor: color,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              ),
              child: Text(actionLabel!),
            ),
        ],
      ),
    );
  }
}

/// A short, friendly explanation of the app for first-time users.
class HelpDialog extends StatelessWidget {
  const HelpDialog({super.key});

  @override
  Widget build(BuildContext context) {
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 620),
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(26, 24, 26, 18),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const GradientText('How it works',
                  style: TextStyle(fontSize: 24, fontWeight: FontWeight.w900)),
              const SizedBox(height: 16),
              const _HelpItem(
                icon: Icons.apps_rounded,
                title: 'What you see',
                text: 'Each card is a program on your PC that is using the internet or your network, '
                    'with the folder it runs from and who it is talking to.',
              ),
              const _HelpItem(
                icon: Icons.palette_rounded,
                title: 'What the colors mean',
                text: 'Grey "Looks safe": nothing to worry about.\n'
                    'Pink "Suspicious": worth a closer look.\n'
                    'Glowing "Danger!": check it right away.',
              ),
              const _HelpItem(
                icon: Icons.lightbulb_rounded,
                title: 'Why something is suspicious',
                text: 'Every card says why in plain words, for example a program hiding in a Temp folder, '
                    'a program with no digital signature, or a fake Windows name.',
              ),
              const _HelpItem(
                icon: Icons.touch_app_rounded,
                title: 'What you can do',
                text: '"Ask AI" gets a second opinion from your AI (set it up in Settings).\n'
                    '"Open folder" shows the program file.\n'
                    '"Stop program" closes it.\n'
                    '"Details" shows everything the app knows.',
              ),
              const _HelpItem(
                icon: Icons.favorite_rounded,
                title: 'Good to know',
                text: 'A warning is a clue, not proof. If you are not sure, ask the AI, search the program\'s '
                    'name online, or scan it with Windows Security.',
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  const Text('Version $appVersion',
                      style: TextStyle(color: AppColors.muted, fontSize: 15)),
                  const Spacer(),
                  FilledButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('Got it'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _HelpItem extends StatelessWidget {
  const _HelpItem({required this.icon, required this.title, required this.text});

  final IconData icon;
  final String title;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 38,
            height: 38,
            decoration: BoxDecoration(
              gradient: AppColors.pinkGradient,
              borderRadius: BorderRadius.circular(11),
            ),
            child: Icon(icon, color: Colors.white, size: 20),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title,
                    style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800)),
                const SizedBox(height: 3),
                Text(text,
                    style: const TextStyle(
                        fontSize: 15, color: AppColors.muted, height: 1.45)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
