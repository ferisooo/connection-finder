// A public list of internet addresses that were reported for attacks
// ("IPsum", addresses found on 3 or more blacklists). It is downloaded at
// most once a day. Nothing about this PC is sent to get it.

import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'ip_utils.dart';

abstract class BadAddressList {
  /// Is this address on the list?
  bool contains(String ip);

  /// How many addresses are loaded.
  int get count;

  /// Loads or refreshes the list. Returns true if it changed.
  Future<bool> refresh();
}

/// Used when the list is switched off, and in tests.
class FixedBadAddressList implements BadAddressList {
  FixedBadAddressList([Iterable<String> ips = const []]) : _ips = ips.toSet();

  final Set<String> _ips;

  @override
  bool contains(String ip) => _ips.contains(ip);

  @override
  int get count => _ips.length;

  @override
  Future<bool> refresh() async => false;
}

/// Reads one address per line, ignoring comments and anything that isn't a
/// plain IPv4 address.
Set<String> parseAddressList(String text) {
  final out = <String>{};
  for (final raw in text.split('\n')) {
    final line = raw.trim();
    if (line.isEmpty || line.startsWith('#')) continue;
    final ip = line.split(RegExp(r'\s+')).first;
    if (parseIpv4(ip) != null) out.add(ip);
  }
  return out;
}

class IpsumBadAddressList implements BadAddressList {
  IpsumBadAddressList({http.Client? client, this.cacheFile})
      : _client = client ?? http.Client();

  static final Uri source = Uri.parse(
      'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt');
  static const Duration maxAge = Duration(hours: 24);

  final http.Client _client;

  /// Where the downloaded list is kept between runs.
  final File? cacheFile;

  Set<String> _ips = {};
  DateTime? _loadedAt;
  DateTime? _retryAfter;

  /// The usual place for the saved list on Windows.
  static File? defaultCacheFile() {
    final base = Platform.environment['LOCALAPPDATA'];
    if (base == null || base.isEmpty) return null;
    return File('$base\\ConnectionFinder\\bad-addresses.txt');
  }

  @override
  bool contains(String ip) => _ips.contains(ip);

  @override
  int get count => _ips.length;

  @override
  Future<bool> refresh() async {
    final now = DateTime.now();
    final loaded = _loadedAt;
    if (loaded != null && now.difference(loaded) < maxAge) return false;
    final retry = _retryAfter;
    if (retry != null && now.isBefore(retry)) return false;

    // 1. A saved copy from earlier today.
    final file = cacheFile;
    try {
      if (file != null && file.existsSync()) {
        final age = now.difference(file.lastModifiedSync());
        if (age < maxAge) {
          final ips = parseAddressList(await file.readAsString());
          if (ips.length >= 100) {
            _ips = ips;
            _loadedAt = file.lastModifiedSync();
            return true;
          }
        }
      }
    } catch (_) {}

    // 2. Download a fresh copy.
    try {
      final res =
          await _client.get(source).timeout(const Duration(seconds: 30));
      if (res.statusCode != 200) throw const HttpException('bad status');
      final ips = parseAddressList(res.body);
      // A real list has thousands of entries; ignore anything odd.
      if (ips.length < 100) throw const FormatException('list too short');
      _ips = ips;
      _loadedAt = now;
      try {
        if (file != null) {
          file.parent.createSync(recursive: true);
          await file.writeAsString(res.body);
        }
      } catch (_) {}
      return true;
    } catch (_) {
      _retryAfter = now.add(const Duration(minutes: 30));
      return false;
    }
  }
}
