// Runs only on Windows (for example on the GitHub build machine): checks
// that the real PowerShell scan, the signature check and the kernel32 path
// lookup all work on an actual Windows PC.
@TestOn('windows')
library;

import 'dart:io';

import 'package:connection_finder/models.dart';
import 'package:connection_finder/services/process_path.dart';
import 'package:connection_finder/services/risk_engine.dart';
import 'package:connection_finder/services/scanner.dart';
import 'package:connection_finder/state/app_controller.dart';
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
    final withServices =
        result.processes.values.where((p) => p.services.isNotEmpty).toList();
    // ignore: avoid_print
    print('processes running services: ${withServices.length}, e.g. '
        '${withServices.isEmpty ? '-' : '${withServices.first.name}: ${withServices.first.services.take(3).join(', ')}'}');
    expect(withServices, isNotEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('signature check works on Windows files', () async {
    final root = Platform.environment['SystemRoot'] ?? r'C:\Windows';
    final svchost = '$root\\System32\\svchost.exe';
    const missing = r'C:\definitely\not\here\nothing.exe';
    final infos = await WindowsScanner().inspectFiles([svchost, missing]);
    final info = infos[svchost]!;
    // ignore: avoid_print
    print('svchost: sig=${info.signature} signer=${info.signer} '
        'company=${info.company} error=${info.checkError}');
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

  test('the harmless fake virus is caught as dangerous', () async {
    final temp = Platform.environment['TEMP'] ?? Directory.systemTemp.path;
    final exe = '$temp\\ConnectionFinder-FakeVirus.exe';
    final build = await Process.run(
        'dart', ['compile', 'exe', 'tool/fake_virus.dart', '-o', exe],
        runInShell: true);
    expect(build.exitCode, 0, reason: '${build.stdout}\n${build.stderr}');

    final virus = await Process.start(exe, const []);
    try {
      final scanner = WindowsScanner();
      ScanResult? result;
      var conns = <NetConnection>[];
      for (var i = 0; i < 5 && conns.isEmpty; i++) {
        await Future<void>.delayed(const Duration(seconds: 2));
        result = await scanner.scan();
        conns = result.connections.where((c) => c.pid == virus.pid).toList();
      }
      // ignore: avoid_print
      print('fake virus connections: ${conns.map((c) => '${c.state} ${c.remoteAddress}:${c.remotePort}').toList()}');
      expect(conns, isNotEmpty, reason: 'the fake virus should be trying to connect');

      final process = result!.processes[virus.pid]!;
      expect(process.path, isNotNull);
      expect(process.path!.toLowerCase(), endsWith('connectionfinder-fakevirus.exe'));
      final files = await scanner.inspectFiles([process.path!]);
      // Judge all of its connections together, the way the app's card does.
      final rows = [
        for (final c in conns)
          ConnectionRow(
            connection: c,
            process: process,
            file: files[process.path!],
            direction: directionOf(c, const {}),
            firstSeen: DateTime.now(),
            risk: const RiskEngine().assess(RiskInput(
              connection: c,
              direction: directionOf(c, const {}),
              process: process,
              file: files[process.path!],
            )),
          ),
      ];
      final group = groupByProgram(rows).single;
      // ignore: avoid_print
      print('fake virus score ${group.score}: ${group.reasons.map((r) => r.title).toList()}');
      expect(group.level, RiskLevel.dangerous);
      expect(group.reasons.map((r) => r.title),
          containsAll(['Runs from a Temp folder', 'No digital signature', 'Suspicious port 4444']));
    } finally {
      virus.kill();
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
}
