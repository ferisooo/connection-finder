// Notices programs that contact the same address again and again on a
// timer ("phoning home"), by remembering when new connections appear.

import '../models.dart';

class RepeatTracker {
  final Map<String, List<DateTime>> _events = {};
  final Map<String, DateTime> _lastActivity = {};
  Set<String> _previous = {};

  /// How many contacts are needed before calling it a pattern.
  static const int minEvents = 5;

  static String keyFor(String program, String ip, int port) =>
      '${program.toLowerCase()}|$ip|$port';

  /// Call once per scan with the outgoing internet connections:
  /// (connection key, program, remote IP, remote port).
  void observe(
    Iterable<(String, String, String, int)> connections,
    DateTime now, {
    required Duration scanInterval,
  }) {
    final gap = burstGap(scanInterval);
    final current = <String>{};
    for (final (connKey, program, ip, port) in connections) {
      current.add(connKey);
      if (_previous.contains(connKey)) continue; // still the same connection
      final key = keyFor(program, ip, port);
      final last = _lastActivity[key];
      _lastActivity[key] = now;
      // Several new connections close together count as one contact.
      if (last != null && now.difference(last) < gap) continue;
      final list = _events.putIfAbsent(key, () => []);
      list.add(now);
      if (list.length > 12) list.removeAt(0);
    }
    _previous = current;

    // Forget addresses that have been quiet for a long time.
    final stale = [
      for (final e in _lastActivity.entries)
        if (now.difference(e.value) > const Duration(minutes: 30)) e.key,
    ];
    for (final k in stale) {
      _lastActivity.remove(k);
      _events.remove(k);
    }
  }

  static Duration burstGap(Duration scanInterval) {
    final twice = scanInterval * 2;
    return twice > const Duration(seconds: 10) ? twice : const Duration(seconds: 10);
  }

  static Duration minInterval(Duration scanInterval) {
    final triple = scanInterval * 3;
    return triple > const Duration(seconds: 15) ? triple : const Duration(seconds: 15);
  }

  /// The repeat pattern for this program and address, if there is one.
  RepeatInfo? infoFor(String program, String ip, int port,
      {required Duration scanInterval}) {
    final events = _events[keyFor(program, ip, port)];
    if (events == null || events.length < minEvents) return null;
    final gaps = <int>[
      for (var i = 1; i < events.length; i++)
        events[i].difference(events[i - 1]).inMilliseconds,
    ];
    final sorted = [...gaps]..sort();
    final median = sorted[sorted.length ~/ 2];
    if (median < minInterval(scanInterval).inMilliseconds) return null;
    // The app only looks every few seconds, so allow that much wobble.
    final quarter = median ~/ 4;
    final wobble = scanInterval.inMilliseconds + 3000;
    final tolerance = quarter > wobble ? quarter : wobble;
    if (gaps.any((g) => (g - median).abs() > tolerance)) return null;
    return RepeatInfo(count: events.length, seconds: (median / 1000).round());
  }
}
