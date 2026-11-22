// Looks up which country / company an IP address belongs to, using the free
// ip-api.com service (batched, cached, and rate-limit friendly).

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models.dart';
import 'ip_utils.dart';

abstract class GeoLookup {
  /// Returns what is already known about [ip], without any network access.
  GeoInfo? cached(String ip);

  /// Looks up any new public IPs. Returns true if something new was learned.
  Future<bool> resolve(Iterable<String> ips);
}

class IpApiGeoLookup implements GeoLookup {
  IpApiGeoLookup({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;
  final Map<String, GeoInfo> _cache = {};
  final Set<String> _failed = {};
  final Set<String> _inFlight = {};
  DateTime? _pausedUntil;

  static final Uri _endpoint = Uri.parse(
      'http://ip-api.com/batch?fields=status,message,country,countryCode,city,isp,org,as,proxy,hosting,query');

  @override
  GeoInfo? cached(String ip) => _cache[ip];

  @override
  Future<bool> resolve(Iterable<String> ips) async {
    final paused = _pausedUntil;
    if (paused != null && DateTime.now().isBefore(paused)) return false;

    final todo = ips
        .where(isPublicIp)
        .where((ip) =>
            !_cache.containsKey(ip) &&
            !_failed.contains(ip) &&
            !_inFlight.contains(ip))
        .toSet()
        .toList();
    if (todo.isEmpty) return false;

    var learned = false;
    for (var i = 0; i < todo.length; i += 100) {
      final batch =
          todo.sublist(i, i + 100 > todo.length ? todo.length : i + 100);
      _inFlight.addAll(batch);
      try {
        final res = await _client
            .post(_endpoint,
                headers: {'Content-Type': 'application/json'},
                body: jsonEncode(batch))
            .timeout(const Duration(seconds: 15));

        final remaining = int.tryParse(res.headers['x-rl'] ?? '');
        final resetIn = int.tryParse(res.headers['x-ttl'] ?? '');
        if (res.statusCode == 429 || remaining == 0) {
          _pausedUntil =
              DateTime.now().add(Duration(seconds: (resetIn ?? 60) + 1));
        }
        if (res.statusCode != 200) break;

        final data = jsonDecode(res.body);
        if (data is! List) break;
        for (final item in data) {
          if (item is! Map) continue;
          final ip = item['query']?.toString();
          if (ip == null) continue;
          if (item['status'] != 'success') {
            _failed.add(ip);
            continue;
          }
          _cache[ip] = GeoInfo(
            ip: ip,
            country: _s(item['country']),
            countryCode: _s(item['countryCode']),
            city: _s(item['city']),
            isp: _s(item['isp']),
            org: _s(item['org']),
            asName: _s(item['as']),
            proxy: item['proxy'] == true,
            hosting: item['hosting'] == true,
          );
          learned = true;
        }
      } catch (_) {
        // Offline or blocked: try again later.
        _pausedUntil = DateTime.now().add(const Duration(seconds: 30));
        break;
      } finally {
        _inFlight.removeAll(batch);
      }
      if (_pausedUntil != null && DateTime.now().isBefore(_pausedUntil!)) {
        break;
      }
    }
    return learned;
  }

  static String? _s(Object? v) {
    final s = v?.toString().trim();
    return (s == null || s.isEmpty) ? null : s;
  }
}

/// Lookup that never touches the network (used when IP lookup is switched
/// off, and in demo mode with made-up answers).
class OfflineGeoLookup implements GeoLookup {
  OfflineGeoLookup([this._known = const {}]);

  final Map<String, GeoInfo> _known;

  @override
  GeoInfo? cached(String ip) => _known[ip];

  @override
  Future<bool> resolve(Iterable<String> ips) async => false;
}
