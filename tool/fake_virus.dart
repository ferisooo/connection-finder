// A HARMLESS fake virus for testing Connection Finder.
//
// It does nothing bad: it reads nothing, logs nothing, saves nothing and
// sends nothing. For 3 minutes it only keeps *trying* to open connections
// to two addresses that are reserved for documentation and tests
// (RFC 5737). They belong to nobody, so no connection is ever made. Then it
// quits by itself.
//
// Connection Finder should flag it as dangerous because it
// - runs from the Temp folder (the app copies it there),
// - has no digital signature and is brand new,
// - talks on port 4444, a port used by hacking tools, and
// - "phones home" to the same address every 20 seconds, like clockwork.

import 'dart:async';
import 'dart:io';

/// Keeps trying [host]:[port] for [howLong]. Nobody answers, by design.
Future<void> tryFor(String host, int port, Duration howLong) async {
  final until = DateTime.now().add(howLong);
  while (true) {
    final left = until.difference(DateTime.now());
    if (left <= const Duration(milliseconds: 300)) return;
    try {
      final socket = await Socket.connect(host, port, timeout: left);
      socket.destroy();
    } catch (_) {
      // Expected: nobody is there.
    }
    await Future<void>.delayed(const Duration(milliseconds: 200));
  }
}

Future<void> main() async {
  const lifetime = Duration(minutes: 3);
  final stopAt = DateTime.now().add(lifetime);

  // 1. Always visible: keeps trying a "hacker" port.
  unawaited(tryFor('192.0.2.1', 4444, lifetime));

  // 2. Clockwork: every 20 seconds, tries a second address for 12 seconds.
  var tick = DateTime.now();
  while (DateTime.now().isBefore(stopAt)) {
    await tryFor('198.51.100.7', 443, const Duration(seconds: 12));
    tick = tick.add(const Duration(seconds: 20));
    final wait = tick.difference(DateTime.now());
    if (!wait.isNegative) await Future<void>.delayed(wait);
  }
  exit(0);
}
