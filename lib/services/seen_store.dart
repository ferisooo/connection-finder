// Remembers which things (programs, startup entries) Connection Finder has
// seen before, so it can point out what is new.

import 'package:shared_preferences/shared_preferences.dart';

/// A small, stable hash so the saved list stays short and holds no paths.
String stableHash(String text) {
  var h = 0x811c9dc5;
  for (final unit in text.codeUnits) {
    h ^= unit;
    h = (h * 0x01000193) & 0xffffffff;
  }
  return h.toRadixString(16).padLeft(8, '0');
}

class SeenStore {
  SeenStore(this.name, {this.prefs}) {
    final p = prefs;
    if (p == null) return;
    _ready = p.getBool('seen.$name.ready') ?? false;
    _known.addAll(p.getStringList('seen.$name.known') ?? const []);
    for (final item in p.getStringList('seen.$name.recent') ?? const <String>[]) {
      final i = item.indexOf(':');
      final ms = i < 0 ? null : int.tryParse(item.substring(i + 1));
      if (ms != null) _recent[item.substring(0, i)] = ms;
    }
  }

  /// How long something counts as "new".
  static const Duration keepRecent = Duration(days: 14);

  final String name;

  /// Where the list is saved (null keeps it in memory only).
  final SharedPreferences? prefs;
  bool _ready = false;
  final Set<String> _known = {};
  final Map<String, int> _recent = {};

  /// False until the first look, when everything found becomes "known".
  bool get ready => _ready;

  /// Notes that [keys] exist right now. Everything seen on the very first
  /// call is treated as old; later arrivals are remembered as new.
  void observe(Iterable<String> keys, DateTime now) {
    var changed = false;
    if (!_ready) {
      _known.addAll(keys.map(stableHash));
      _ready = true;
      changed = true;
    } else {
      for (final key in keys) {
        final h = stableHash(key);
        if (_known.contains(h) || _recent.containsKey(h)) continue;
        _recent[h] = now.millisecondsSinceEpoch;
        changed = true;
      }
      final cutoff = now.subtract(keepRecent).millisecondsSinceEpoch;
      final old = [
        for (final e in _recent.entries)
          if (e.value < cutoff) e.key,
      ];
      for (final h in old) {
        _recent.remove(h);
        _known.add(h);
        changed = true;
      }
    }
    if (changed) _save();
  }

  /// When [key] first showed up, or null if it was there from the start
  /// (or has never been seen).
  DateTime? firstSeen(String key) {
    final ms = _recent[stableHash(key)];
    return ms == null ? null : DateTime.fromMillisecondsSinceEpoch(ms);
  }

  /// Did [key] first show up less than [within] ago?
  bool isNew(String key, DateTime now, Duration within) {
    final first = firstSeen(key);
    return first != null && now.difference(first) < within;
  }

  void _save() {
    final p = prefs;
    if (p == null) return;
    p.setBool('seen.$name.ready', _ready);
    p.setStringList('seen.$name.known', _known.toList());
    p.setStringList('seen.$name.recent',
        [for (final e in _recent.entries) '${e.key}:${e.value}']);
  }
}
