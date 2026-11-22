// A HARMLESS fake virus for testing Connection Finder.
//
// It does nothing bad: it reads nothing, logs nothing, saves nothing and
// sends nothing. For 2 minutes it just keeps *trying* to open a connection
// to 192.0.2.1 on port 4444. That address is reserved for documentation
// and tests (RFC 5737) and belongs to nobody, so the attempt never reaches
// anyone. Then it quits by itself.
//
// Connection Finder should flag it as dangerous because it
// - runs from the Temp folder (the app copies it there),
// - has no digital signature,
// - is brand new, and
// - talks on port 4444, a port used by hacking tools.

import 'dart:io';

Future<void> main() async {
  final stopAt = DateTime.now().add(const Duration(minutes: 2));
  while (DateTime.now().isBefore(stopAt)) {
    try {
      final socket = await Socket.connect('192.0.2.1', 4444,
          timeout: const Duration(seconds: 20));
      socket.destroy();
    } catch (_) {
      // Expected: nobody is there.
    }
    await Future<void>.delayed(const Duration(milliseconds: 200));
  }
  exit(0);
}
