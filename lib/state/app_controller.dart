// The app's brain: scans on a timer, checks files and IPs in the background,
// scores every connection, groups them by program and keeps the AI verdicts.

import 'dart:async';
import 'dart:io' show pid;
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models.dart';
import '../services/ai_service.dart';
import '../services/bad_addresses.dart';
import '../services/geo_service.dart';
import '../services/ip_utils.dart';
import '../services/repeat_tracker.dart';
import '../services/risk_engine.dart';
import '../services/scanner.dart';
import '../services/seen_store.dart';
import '../services/settings.dart';
import '../services/system_actions.dart';

/// Where a program ends up in the app.
enum ProgramStatus {
  /// Has warning signs: shown.
  risky,

  /// Windows wouldn't let the app check it: shown, honestly marked.
  unchecked,

  /// Its file is still being checked: not shown yet.
  checking,

  /// Signed, normal and without warning signs: hidden.
  trusted,
}

class Stats {
  const Stats({
    required this.connections,
    required this.programs,
    required this.suspiciousPrograms,
    required this.dangerousPrograms,
    required this.uncheckedPrograms,
    required this.checkingPrograms,
    required this.trustedNames,
  });

  final int connections;
  final int programs;
  final int suspiciousPrograms;
  final int dangerousPrograms;
  final int uncheckedPrograms;
  final int checkingPrograms;

  /// Names of the busiest trusted programs, for the summary.
  final List<String> trustedNames;

  int get riskyPrograms => suspiciousPrograms + dangerousPrograms;
}

/// Works out which way a connection goes.
Direction directionOf(NetConnection c, Set<int> listeningPortsOfProcess) {
  if (c.isListening) return Direction.listening;
  if (c.remoteAddress.isEmpty) return Direction.other;
  if ((isLoopback(c.remoteAddress) && isLoopback(c.localAddress)) ||
      c.remoteAddress == c.localAddress) {
    return Direction.local;
  }
  if (c.pid == 0 || c.state == 'TimeWait' || c.state == 'Closed') {
    return Direction.other;
  }
  if (c.isTcp && listeningPortsOfProcess.contains(c.localPort)) {
    return Direction.incoming;
  }
  return Direction.outgoing;
}

const Map<Direction, int> _directionOrder = {
  Direction.incoming: 0,
  Direction.outgoing: 1,
  Direction.listening: 2,
  Direction.local: 3,
  Direction.other: 4,
};

int compareRows(ConnectionRow a, ConnectionRow b) {
  final byRisk = b.risk.score.compareTo(a.risk.score);
  if (byRisk != 0) return byRisk;
  final byDir =
      _directionOrder[a.direction]!.compareTo(_directionOrder[b.direction]!);
  if (byDir != 0) return byDir;
  return a.connection.key.compareTo(b.connection.key);
}

int compareGroups(ProgramGroup a, ProgramGroup b) {
  final byRisk = b.score.compareTo(a.score);
  if (byRisk != 0) return byRisk;
  final byTalking = b.talking.length.compareTo(a.talking.length);
  if (byTalking != 0) return byTalking;
  return a.fileName.toLowerCase().compareTo(b.fileName.toLowerCase());
}

/// Groups connections by the program behind them.
List<ProgramGroup> groupByProgram(Iterable<ConnectionRow> rows) {
  final map = <String, List<ConnectionRow>>{};
  for (final r in rows) {
    // Programs whose folder is hidden are grouped by name (for example all
    // the svchost.exe copies Windows runs).
    final key = r.path?.toLowerCase() ??
        (r.isWindowsCore ? 'pid:${r.pid}' : 'name:${r.fileName.toLowerCase()}');
    map.putIfAbsent(key, () => []).add(r);
  }
  return [
    for (final e in map.entries) ProgramGroup(e.key, e.value),
  ]..sort(compareGroups);
}

class AppController extends ChangeNotifier {
  AppController({
    required this.settings,
    required this.scanner,
    required this.geo,
    required this.ai,
    this.actions = const SystemActions(),
    this.engine = const RiskEngine(),
    BadAddressList? badAddresses,
    SharedPreferences? prefs,
  })  : badAddresses = badAddresses ?? FixedBadAddressList(),
        _seenPrograms = SeenStore('programs', prefs: prefs),
        _seenAutostarts = {
          for (final kind in const ['run', 'folder', 'task'])
            kind: SeenStore('autostart.$kind', prefs: prefs),
        };

  final AppSettings settings;
  final ConnectionScanner scanner;
  final AiService ai;
  final SystemActions actions;
  final RiskEngine engine;
  final GeoLookup geo;

  /// Public list of addresses reported for attacks.
  final BadAddressList badAddresses;

  /// Programs seen on the network before (to spot new ones).
  final SeenStore _seenPrograms;

  /// Startup entries seen before, per kind (to spot new ones).
  final Map<String, SeenStore> _seenAutostarts;
  final RepeatTracker _repeats = RepeatTracker();
  List<AutostartEntry> _autostarts = const [];
  DateTime? _autostartsAt;
  bool _autostartsBusy = false;

  static const int aiBatchSize = 6;
  static final DateTime _longAgo = DateTime.fromMillisecondsSinceEpoch(0);

  ScanResult? _last;
  List<ConnectionRow> _rows = const [];
  List<ProgramGroup> _groups = const [];
  List<ProgramGroup>? _visibleCache;
  bool _scanning = false;
  bool _firstScanDone = false;
  DateTime? _lastUpdated;
  String? _error;

  final Map<String, FileInfo> _files = {};
  final Set<String> _inspecting = {};
  final Map<String, DateTime> _retryInspectAfter = {};
  final Map<String, DateTime> _firstSeen = {};

  final Map<String, AiVerdict> _verdicts = {};
  final Set<String> _aiBusy = {};
  bool _aiBatchRunning = false;
  int _aiBatchTotal = 0;
  int _aiBatchDone = 0;

  String _search = '';

  Timer? _timer;
  bool? _timerAuto;
  int? _timerSeconds;
  bool _started = false;
  bool _disposed = false;

  // ---- read-only state for the UI --------------------------------------

  bool get scanning => _scanning;
  bool get firstScanDone => _firstScanDone;
  DateTime? get lastUpdated => _lastUpdated;
  String? get error => _error;
  bool get isAdmin => _last?.isAdmin ?? true;
  bool get demoMode => _last?.demo ?? false;
  bool get usingNetstatFallback => _last?.method == 'netstat';
  String get search => _search;
  bool get aiBatchRunning => _aiBatchRunning;
  int get aiBatchTotal => _aiBatchTotal;
  int get aiBatchDone => _aiBatchDone;

  /// Every connection (including local ones).
  List<ConnectionRow> get allRows => _rows;

  /// Programs shown in the list (local ones hidden unless asked for).
  List<ProgramGroup> get groups => _groups;

  ProgramGroup? groupByKey(String key) {
    for (final g in _groups) {
      if (g.key == key) return g;
    }
    return null;
  }

  AiVerdict? verdictFor(ProgramGroup g) => _verdicts[g.key];
  bool isAsking(ProgramGroup g) => _aiBusy.contains(g.key);
  bool isCheckingFile(ProgramGroup g) =>
      g.path != null && g.file == null &&
      _inspecting.contains(g.path!.toLowerCase());

  /// Decides whether a program is shown, and why.
  ProgramStatus statusOf(ProgramGroup g) {
    if (g.level != RiskLevel.safe) return ProgramStatus.risky;
    if (g.isWindowsCore || g.pids.contains(pid)) return ProgramStatus.trusted;
    final path = g.path;
    if (path == null) return ProgramStatus.unchecked;
    final file = g.file;
    if (file == null) {
      final key = path.toLowerCase();
      final failed = _retryInspectAfter.containsKey(key) && !_inspecting.contains(key);
      return failed ? ProgramStatus.unchecked : ProgramStatus.checking;
    }
    if (!file.exists ||
        file.signature == SignatureStatus.unknown ||
        file.signature == SignatureStatus.notSupported) {
      return ProgramStatus.unchecked;
    }
    return ProgramStatus.trusted;
  }

  /// Only programs that need a look: suspicious ones and ones the app
  /// couldn't check. Trusted programs are never shown.
  List<ProgramGroup> get visibleGroups =>
      _visibleCache ??= _groups.where(_passesFilters).toList(growable: false);

  /// How many programs need a look (before searching).
  int get attentionCount => _groups.where((g) {
        final st = statusOf(g);
        return st == ProgramStatus.risky || st == ProgramStatus.unchecked;
      }).length;

  Stats get stats {
    final trusted = _groups
        .where((g) => statusOf(g) == ProgramStatus.trusted && !g.isWindowsCore)
        .toList()
      ..sort((a, b) => b.rows.length.compareTo(a.rows.length));
    return Stats(
      connections: _groups.fold(0, (n, g) => n + g.rows.length),
      programs: _groups.length,
      suspiciousPrograms:
          _groups.where((g) => g.level == RiskLevel.suspicious).length,
      dangerousPrograms:
          _groups.where((g) => g.level == RiskLevel.dangerous).length,
      uncheckedPrograms:
          _groups.where((g) => statusOf(g) == ProgramStatus.unchecked).length,
      checkingPrograms:
          _groups.where((g) => statusOf(g) == ProgramStatus.checking).length,
      trustedNames: [
        for (final g in trusted.take(3)) g.fileName.replaceAll(RegExp(r'\.exe$', caseSensitive: false), ''),
      ],
    );
  }

  /// Risky programs the AI hasn't judged yet.
  List<ProgramGroup> get pendingAiGroups => [
        for (final g in _groups)
          if (g.level != RiskLevel.safe &&
              (_verdicts[g.key] == null || _verdicts[g.key]!.isError))
            g,
      ];

  // ---- filters -----------------------------------------------------------

  set search(String value) {
    if (value == _search) return;
    _search = value;
    _visibleCache = null;
    notifyListeners();
  }

  bool _passesLocalFilter(ConnectionRow r) {
    if (settings.showLocal) return true;
    if (r.direction == Direction.local || r.direction == Direction.other) {
      return false;
    }
    if (r.direction == Direction.listening &&
        isLoopback(r.connection.localAddress)) {
      return false;
    }
    return true;
  }

  bool _passesFilters(ProgramGroup g) {
    final status = statusOf(g);
    if (status != ProgramStatus.risky && status != ProgramStatus.unchecked) {
      return false;
    }
    final q = _search.trim().toLowerCase();
    if (q.isEmpty) return true;
    bool has(String? s) => s != null && s.toLowerCase().contains(q);
    if (has(g.fileName) ||
        has(g.path) ||
        has(g.file?.signer) ||
        has(g.file?.company) ||
        has(g.file?.product)) {
      return true;
    }
    for (final r in g.rows) {
      final c = r.connection;
      if (has(c.remoteAddress) ||
          has('${c.remotePort}') ||
          has('${c.localPort}') ||
          has(r.geo?.country) ||
          has(r.geo?.city) ||
          has(r.geo?.owner)) {
        return true;
      }
    }
    return false;
  }

  // ---- scanning ----------------------------------------------------------

  void start() {
    if (_started) return;
    _started = true;
    settings.addListener(_onSettingsChanged);
    _syncTimer();
    unawaited(refresh());
  }

  void _onSettingsChanged() {
    _syncTimer();
    _rebuild();
    if (settings.geoLookup) unawaited(_resolveGeo());
    notifyListeners();
  }

  void _syncTimer() {
    final auto = settings.autoRefresh;
    final secs = settings.refreshSeconds;
    if (_timerAuto == auto && _timerSeconds == secs) return;
    _timer?.cancel();
    _timer = null;
    _timerAuto = auto;
    _timerSeconds = secs;
    if (auto) {
      _timer = Timer.periodic(Duration(seconds: secs), (_) => refresh());
    }
  }

  Future<void> refresh() async {
    if (_scanning || _disposed) return;
    _scanning = true;
    notifyListeners();
    try {
      final result = await scanner.scan();
      if (_disposed) return;
      _last = result;
      _error = null;
      _lastUpdated = DateTime.now();
      _observe(result, _lastUpdated!);
      _rebuild();
      _firstScanDone = true;
      unawaited(_inspectNewFiles());
      unawaited(_resolveGeo());
      unawaited(_loadAutostarts());
      unawaited(_loadBadAddresses());
    } catch (e) {
      _error = e is ScanException ? e.message : 'Scan failed: $e';
    } finally {
      _scanning = false;
      if (!_disposed) notifyListeners();
    }
  }

  Duration get _scanInterval => Duration(seconds: settings.refreshSeconds);

  static Map<int, Set<int>> _listeningPorts(ScanResult result) {
    final listening = <int, Set<int>>{};
    for (final c in result.connections) {
      if (c.isTcp && c.state == 'Listen') {
        listening.putIfAbsent(c.pid, () => <int>{}).add(c.localPort);
      }
    }
    return listening;
  }

  static String _programKey(ProcessInfo? p, int pid) =>
      p?.path?.toLowerCase() ?? p?.name.toLowerCase() ?? 'pid:$pid';

  /// Remembers what was seen in a fresh scan: which programs are on the
  /// network, and when new internet connections appear.
  void _observe(ScanResult result, DateTime now) {
    final listening = _listeningPorts(result);
    final programs = <String>{};
    final outgoing = <(String, String, String, int)>[];
    for (final c in result.connections) {
      final process = result.processes[c.pid];
      final path = process?.path;
      if (path != null) programs.add(path.toLowerCase());
      if (directionOf(c, listening[c.pid] ?? const <int>{}) ==
              Direction.outgoing &&
          isPublicIp(c.remoteAddress)) {
        outgoing.add((
          c.key,
          _programKey(process, c.pid),
          c.remoteAddress,
          c.remotePort,
        ));
      }
    }
    _seenPrograms.observe(programs, now);
    _repeats.observe(outgoing, now, scanInterval: _scanInterval);
  }

  /// Reads what starts with Windows (every couple of minutes).
  Future<void> _loadAutostarts() async {
    final at = _autostartsAt;
    if (_autostartsBusy ||
        (at != null &&
            DateTime.now().difference(at) < const Duration(minutes: 2))) {
      return;
    }
    _autostartsBusy = true;
    try {
      final scan = await scanner.autostarts();
      final now = DateTime.now();
      _autostarts = scan.entries;
      _autostartsAt = now;
      for (final kind in scan.completeKinds) {
        _seenAutostarts[kind]?.observe(
            [for (final e in scan.entries) if (e.kind == kind) e.key], now);
      }
      if (_disposed) return;
      _rebuild();
      notifyListeners();
    } catch (_) {
      // Try again in a while; the other clues still work.
      _autostartsAt = DateTime.now();
    } finally {
      _autostartsBusy = false;
    }
  }

  Future<void> _loadBadAddresses() async {
    if (!settings.badList) return;
    final changed = await badAddresses.refresh();
    if (changed && !_disposed) {
      _rebuild();
      notifyListeners();
    }
  }

  /// The programs that started [p]: parent first, then grandparent...
  static List<ProcessInfo> ancestorsOf(ProcessInfo? p, Map<int, ProcessInfo> all) {
    final out = <ProcessInfo>[];
    if (p == null) return out;
    final seen = <int>{p.pid};
    var cur = p;
    while (cur.parentPid != null && out.length < 5) {
      final parent = all[cur.parentPid!];
      if (parent == null || !seen.add(parent.pid)) break;
      // A "parent" that started later is a different program that got the
      // same number after the real parent closed.
      final ps = parent.started, cs = cur.started;
      if (ps != null && cs != null && ps.isAfter(cs.add(const Duration(seconds: 2)))) {
        break;
      }
      out.add(parent);
      cur = parent;
    }
    return out;
  }

  /// The startup entries that start [p].
  List<AutostartEntry> _autostartsFor(ProcessInfo? p, List<AutostartEntry> services) {
    if (p == null) return const [];
    final path = p.path?.toLowerCase();
    final name = p.fileName.toLowerCase();
    final cmd = (p.commandLine ?? '').toLowerCase();
    final isTool = abusedWindowsTools.containsKey(name);
    final out = <AutostartEntry>[];
    for (final e in [..._autostarts, ...services]) {
      if (isTool) {
        // Windows' own tasks use these tools all the time. Only count an
        // entry that runs the tool the same way this copy was started.
        if (e.kind == 'service' || e.name.toLowerCase().startsWith(r'\microsoft\')) {
          continue;
        }
        final sameTool =
            e.exeName == name && e.args.isNotEmpty && cmd.contains(e.args);
        final runsScript = e.exePath != null &&
            !e.exeName.endsWith('.exe') &&
            cmd.contains(e.exePath!.toLowerCase());
        if (sameTool || runsScript) out.add(e);
      } else if (path != null && e.exePath?.toLowerCase() == path) {
        out.add(e);
      }
    }
    return out;
  }

  void _rebuild() {
    final result = _last;
    if (result == null) return;
    final now = DateTime.now();

    final listening = _listeningPorts(result);
    final autostartCache = <int, List<AutostartEntry>>{};
    final ancestorCache = <int, List<ProcessInfo>>{};

    final rows = <ConnectionRow>[];
    final seen = <String>{};
    for (final c in result.connections) {
      final process = result.processes[c.pid];
      final path = process?.path;
      final file = path == null ? null : _files[path.toLowerCase()];
      final place = (c.remoteAddress.isEmpty || !settings.geoLookup)
          ? null
          : geo.cached(c.remoteAddress);
      final direction = directionOf(c, listening[c.pid] ?? const <int>{});
      final ancestors = ancestorCache.putIfAbsent(
          c.pid, () => ancestorsOf(process, result.processes));
      final autostarts = autostartCache.putIfAbsent(
          c.pid, () => _autostartsFor(process, result.services));
      final risk = engine.assess(RiskInput(
        connection: c,
        direction: direction,
        process: process,
        file: file,
        geo: place,
        flaggedCountries: settings.flaggedCountries,
        isAdmin: result.isAdmin,
        selfPid: pid,
        now: now,
        ancestors: ancestors,
        autostarts: autostarts,
        autostartIsNew: autostarts.any((e) =>
            _seenAutostarts[e.kind]
                ?.isNew(e.key, now, const Duration(days: 7)) ??
            false),
        repeat: direction == Direction.outgoing
            ? _repeats.infoFor(
                _programKey(process, c.pid), c.remoteAddress, c.remotePort,
                scanInterval: _scanInterval)
            : null,
        firstSeenRecently: path != null &&
            _seenPrograms.isNew(
                path.toLowerCase(), now, const Duration(hours: 24)),
        badAddress: settings.badList &&
            c.remoteAddress.isNotEmpty &&
            badAddresses.contains(c.remoteAddress),
      ));
      // Everything found by the very first scan was already there when the
      // app opened, so only later arrivals get the "NEW" tag.
      final first = _firstSeen.putIfAbsent(
          c.key, () => _firstScanDone ? now : _longAgo);
      seen.add(c.key);
      rows.add(ConnectionRow(
        connection: c,
        process: process,
        file: file,
        geo: place,
        risk: risk,
        direction: direction,
        firstSeen: first,
        isNew: now.difference(first) < const Duration(seconds: 60),
        ancestors: ancestors,
        autostarts: autostarts,
      ));
    }
    _firstSeen.removeWhere((key, _) => !seen.contains(key));
    rows.sort(compareRows);
    _rows = rows;
    _groups = groupByProgram(rows.where(_passesLocalFilter));
    _visibleCache = null;
  }

  Future<void> _inspectNewFiles() async {
    final result = _last;
    if (result == null) return;
    final now = DateTime.now();
    final todo = <String, String>{}; // lower-case key -> real path
    for (final c in result.connections) {
      final path = result.processes[c.pid]?.path;
      if (path == null) continue;
      final key = path.toLowerCase();
      if (_files.containsKey(key) || _inspecting.contains(key)) continue;
      final retry = _retryInspectAfter[key];
      if (retry != null && now.isBefore(retry)) continue;
      todo[key] = path;
    }
    if (todo.isEmpty) return;

    _inspecting.addAll(todo.keys);
    _visibleCache = null;
    notifyListeners();
    try {
      final infos = await scanner.inspectFiles(todo.values.toList());
      for (final entry in todo.entries) {
        final info = infos[entry.value];
        if (info != null) {
          _files[entry.key] = info;
        } else {
          _retryInspectAfter[entry.key] =
              DateTime.now().add(const Duration(minutes: 2));
        }
      }
    } catch (_) {
      for (final key in todo.keys) {
        _retryInspectAfter[key] =
            DateTime.now().add(const Duration(minutes: 1));
      }
    } finally {
      _inspecting.removeAll(todo.keys);
    }
    if (_disposed) return;
    _rebuild();
    notifyListeners();
  }

  Future<void> _resolveGeo() async {
    if (!settings.geoLookup) return;
    final ips = _rows
        .map((r) => r.connection.remoteAddress)
        .where((ip) => ip.isNotEmpty)
        .toSet();
    final learned = await geo.resolve(ips);
    if (learned && !_disposed) {
      _rebuild();
      notifyListeners();
    }
  }

  // ---- AI helper ----------------------------------------------------------

  /// Asks the AI about one program. Returns a message to show, or null.
  Future<String?> askAi(ProgramGroup group) async {
    if (!settings.aiReady) {
      return 'First add your AI key in Settings.';
    }
    final key = group.key;
    if (_aiBusy.contains(key)) return null;
    _aiBusy.add(key);
    notifyListeners();
    final config = settings.aiConfig;
    try {
      final res =
          await ai.analyze(config, [AiItem('p1', describeGroupForAi(group))]);
      _verdicts[key] = res['p1'] ??
          AiVerdict.failed("The AI didn't answer about this program.",
              provider: config.provider.shortName, model: config.model);
    } on AiException catch (e) {
      _verdicts[key] = AiVerdict.failed(e.message,
          provider: config.provider.shortName, model: config.model);
    } catch (e) {
      _verdicts[key] = AiVerdict.failed('Something went wrong: $e',
          provider: config.provider.shortName, model: config.model);
    } finally {
      _aiBusy.remove(key);
      if (!_disposed) notifyListeners();
    }
    return null;
  }

  /// Asks the AI about every risky program it hasn't judged yet.
  Future<void> askAiAboutPending() async {
    if (_aiBatchRunning || !settings.aiReady) return;
    final groups = pendingAiGroups;
    if (groups.isEmpty) return;

    _aiBatchRunning = true;
    _aiBatchTotal = groups.length;
    _aiBatchDone = 0;
    _aiBusy.addAll(groups.map((g) => g.key));
    notifyListeners();

    final config = settings.aiConfig;
    AiVerdict fail(String msg) => AiVerdict.failed(msg,
        provider: config.provider.shortName, model: config.model);

    try {
      for (var i = 0; i < groups.length; i += aiBatchSize) {
        final chunk =
            groups.sublist(i, math.min(i + aiBatchSize, groups.length));
        final items = [
          for (var j = 0; j < chunk.length; j++)
            AiItem('p${j + 1}', describeGroupForAi(chunk[j])),
        ];
        try {
          final res = await ai.analyze(config, items);
          for (var j = 0; j < chunk.length; j++) {
            _verdicts[chunk[j].key] =
                res['p${j + 1}'] ?? fail('The AI skipped this one. Try again.');
          }
        } on AiException catch (e) {
          // Problems like a wrong key affect every request, so stop here.
          for (final g in groups.sublist(i)) {
            _verdicts[g.key] = fail(e.message);
          }
          break;
        } catch (e) {
          for (final g in chunk) {
            _verdicts[g.key] = fail('Something went wrong: $e');
          }
        }
        _aiBatchDone += chunk.length;
        _aiBusy.removeAll(chunk.map((g) => g.key));
        if (_disposed) return;
        notifyListeners();
      }
    } finally {
      _aiBatchRunning = false;
      _aiBusy.removeAll(groups.map((g) => g.key));
      if (!_disposed) notifyListeners();
    }
  }

  // ---- actions --------------------------------------------------------------

  Future<ActionResult> revealInExplorer(ProgramGroup group) {
    final path = group.path;
    if (path == null) {
      return Future.value(const ActionResult(false,
          'Windows is hiding this folder. Try "Restart as admin".'));
    }
    return actions.revealInExplorer(path);
  }

  /// Stops every running copy of the program.
  Future<ActionResult> stopProgram(ProgramGroup group) async {
    final pids = group.pids.where((p) => p > 4 && p != pid).toList();
    if (pids.isEmpty) {
      return const ActionResult(false, "This one can't be stopped.");
    }
    var last = const ActionResult(true, 'Program stopped.');
    var stopped = 0;
    for (final p in pids) {
      final r = await actions.killProcess(p);
      if (r.ok) {
        stopped++;
      } else {
        last = r;
      }
    }
    await Future<void>.delayed(const Duration(milliseconds: 400));
    unawaited(refresh());
    if (stopped == pids.length) {
      return const ActionResult(true, 'Program stopped.');
    }
    return last;
  }

  Future<bool> relaunchAsAdmin() => actions.relaunchAsAdmin();

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    if (_started) settings.removeListener(_onSettingsChanged);
    super.dispose();
  }
}
