// Runs only on Windows (for example on the GitHub build machine): checks
// that the real PowerShell scan, the signature check and the kernel32 path
// lookup all work on an actual Windows PC.
@TestOn('windows')
library;

import 'dart:io';

import 'package:connection_finder/models.dart';
import 'package:connection_finder/services/process_path.dart';
import 'package:connection_finder/services/scanner.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('real scan finds connections and processes', () async {
    final result = await WindowsScanner().scan();
    // ignore: avoid_print
    print('method=${result.method} admin=${result.isAdmin} '
        'connections=${result.connections.length} processes=${result.processes.length}');
    for (final c in result.connections.take(8)) {
      final p = result.processes[c.pid];
      // ignore: avoid_print
      print('  ${c.protocol} ${c.state} ${c.localAddress}:${c.localPort} -> '
          '${c.remoteAddress}:${c.remotePort}  pid=${c.pid} ${p?.name} ${p?.path ?? '(hidden)'}');
    }
    expect(result.method, 'cim');
    expect(result.processes, isNotEmpty);
    expect(result.connections, isNotEmpty);
    expect(result.connections.any((c) => c.isListening), isTrue);
    expect(result.processes.values.where((p) => p.path != null), isNotEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('signature check works on Windows files', () async {
    final root = Platform.environment['SystemRoot'] ?? r'C:\Windows';
    final svchost = '$root\\System32\\svchost.exe';
    const missing = r'C:\definitely\not\here\nothing.exe';
    final infos = await WindowsScanner().inspectFiles([svchost, missing]);
    final info = infos[svchost]!;
    // ignore: avoid_print
    print('svchost: sig=${info.signature} signer=${info.signer} company=${info.company}');
    expect(info.exists, isTrue);
    expect(info.signature, SignatureStatus.valid);
    expect(info.signer, isNotNull);
    expect(infos[missing]!.exists, isFalse);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('kernel32 tells us the path of a running program', () {
    final path = queryProcessImagePath(pid);
    // ignore: avoid_print
    print('this test process: $path');
    expect(path, isNotNull);
    expect(path!.toLowerCase(), endsWith('.exe'));
  });
}
