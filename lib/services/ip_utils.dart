// Small helpers for looking at IP addresses without any network access.

/// Parses an IPv4 address into its four numbers, or returns null.
List<int>? parseIpv4(String ip) {
  final parts = ip.split('.');
  if (parts.length != 4) return null;
  final out = <int>[];
  for (final p in parts) {
    final n = int.tryParse(p);
    if (n == null || n < 0 || n > 255) return null;
    out.add(n);
  }
  return out;
}

String _stripZone(String ip) {
  final i = ip.indexOf('%');
  return (i >= 0 ? ip.substring(0, i) : ip).toLowerCase();
}

/// `0.0.0.0` or `::` - "any address".
bool isUnspecified(String ip) {
  final v = _stripZone(ip.trim());
  return v == '0.0.0.0' || v == '::' || v == '0:0:0:0:0:0:0:0' || v == '*';
}

bool isLoopback(String ip) {
  final v = _stripZone(ip.trim());
  if (v == '::1') return true;
  final v4 = parseIpv4(_mappedV4(v) ?? v);
  return v4 != null && v4[0] == 127;
}

/// Turns `::ffff:1.2.3.4` into `1.2.3.4`.
String? _mappedV4(String v) {
  const prefix = '::ffff:';
  if (v.startsWith(prefix) && v.contains('.')) return v.substring(prefix.length);
  return null;
}

/// True when the IP is on the public internet (not home network, not this
/// PC, not multicast, ...). Only public IPs are looked up and judged.
bool isPublicIp(String ip) {
  var v = _stripZone(ip.trim());
  if (v.isEmpty || isUnspecified(v)) return false;
  v = _mappedV4(v) ?? v;

  final v4 = parseIpv4(v);
  if (v4 != null) {
    final a = v4[0], b = v4[1];
    if (a == 0 || a == 10 || a == 127) return false;
    if (a == 169 && b == 254) return false; // link-local
    if (a == 172 && b >= 16 && b <= 31) return false; // private
    if (a == 192 && b == 168) return false; // private
    if (a == 100 && b >= 64 && b <= 127) return false; // carrier NAT
    if (a == 192 && b == 0 && v4[2] == 0) return false; // IETF
    if (a == 198 && (b == 18 || b == 19)) return false; // benchmarking
    if (a >= 224) return false; // multicast + reserved + broadcast
    return true;
  }

  if (!v.contains(':')) return false; // not an IP at all
  if (v == '::1') return false;
  if (v.startsWith('fe8') ||
      v.startsWith('fe9') ||
      v.startsWith('fea') ||
      v.startsWith('feb')) {
    return false; // link-local
  }
  if (v.startsWith('fc') || v.startsWith('fd')) return false; // unique local
  if (v.startsWith('ff')) return false; // multicast
  if (v.startsWith('2001:db8')) return false; // documentation
  return true;
}

/// Is this address only reachable from this PC?
bool isLocalOnlyBind(String ip) => isLoopback(ip);

/// Formats `ip:port`, wrapping IPv6 in brackets so it stays readable.
String formatEndpoint(String ip, int port) {
  final host = ip.contains(':') ? '[$ip]' : ip;
  return '$host:$port';
}
