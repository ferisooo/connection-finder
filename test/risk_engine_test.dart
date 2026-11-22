import 'package:connection_finder/models.dart';
import 'package:connection_finder/services/ip_utils.dart';
import 'package:connection_finder/services/risk_engine.dart';
import 'package:connection_finder/state/app_controller.dart';
import 'package:flutter_test/flutter_test.dart';

const engine = RiskEngine();
final now = DateTime(2026, 11, 22, 12);

NetConnection tcp({
  String remote = '142.250.80.46',
  int remotePort = 443,
  int localPort = 50000,
  String local = '192.168.1.5',
  String state = 'Established',
  int pid = 1234,
}) =>
    NetConnection(
      protocol: 'TCP',
      localAddress: local,
      localPort: localPort,
      remoteAddress: remote,
      remotePort: remotePort,
      state: state,
      pid: pid,
    );

FileInfo signedFile(String path, {String signer = 'Some Company'}) => FileInfo(
    path: path,
    exists: true,
    signature: SignatureStatus.valid,
    signer: signer,
    created: DateTime(2025, 1, 1));

FileInfo unsignedFile(String path, {DateTime? created}) => FileInfo(
    path: path,
    exists: true,
    signature: SignatureStatus.notSigned,
    created: created ?? DateTime(2025, 1, 1));

RiskAssessment assess(
  String path, {
  NetConnection? conn,
  FileInfo? file,
  String? cmd,
  GeoInfo? geo,
  Direction direction = Direction.outgoing,
  Set<String> flagged = const {},
}) {
  final c = conn ?? tcp();
  return engine.assess(RiskInput(
    connection: c,
    direction: direction,
    process: ProcessInfo(
        pid: c.pid, name: fileNameOf(path), path: path, commandLine: cmd),
    file: file,
    geo: geo,
    flaggedCountries: flagged,
    now: now,
  ));
}

Set<String> titles(RiskAssessment a) => a.reasons.map((r) => r.title).toSet();

void main() {
  test('normal signed app in Program Files is safe', () {
    const path = r'C:\Program Files\Google\Chrome\Application\chrome.exe';
    final a = assess(path, file: signedFile(path, signer: 'Google LLC'));
    expect(a.score, 0);
    expect(a.level, RiskLevel.safe);
  });

  test('real svchost in System32 is safe', () {
    const path = r'C:\Windows\System32\svchost.exe';
    final a = assess(path, file: signedFile(path));
    expect(a.level, RiskLevel.safe);
  });

  test('fake svchost in Temp is dangerous', () {
    const path = r'C:\Users\Mia\AppData\Local\Temp\svchost.exe';
    final a = assess(path, file: unsignedFile(path));
    expect(a.level, RiskLevel.dangerous);
    expect(titles(a), containsAll(['Pretends to be a Windows file', 'Runs from a Temp folder', 'No digital signature']));
  });

  test('look-alike names are caught', () {
    expect(lookAlikeWindowsName('svch0st'), 'svchost.exe');
    expect(lookAlikeWindowsName('scvhost'), 'svchost.exe');
    expect(lookAlikeWindowsName('lsasss'), 'lsass.exe');
    expect(lookAlikeWindowsName('svchost'), isNull, reason: 'the real name');
    expect(lookAlikeWindowsName('chrome'), isNull);
    expect(lookAlikeWindowsName('taskhost'), isNull, reason: 'legit on old Windows');
    expect(lookAlikeWindowsName('service'), isNull);
  });

  test('fake document name in Downloads is dangerous', () {
    const path = r'C:\Users\Mia\Downloads\invoice_2026.pdf.exe';
    final a = assess(path,
        conn: tcp(remote: '45.142.212.61', remotePort: 4444),
        file: unsignedFile(path, created: now.subtract(const Duration(hours: 3))));
    expect(a.level, RiskLevel.dangerous);
    expect(titles(a), containsAll(['Fake document name', 'Runs from Downloads', 'Suspicious port 4444', 'Brand-new program']));
  });

  test('PowerShell with an encoded hidden command is dangerous', () {
    const path = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';
    final a = assess(path,
        file: signedFile(path, signer: 'Microsoft Windows'),
        cmd: 'powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA');
    expect(a.level, RiskLevel.dangerous);
    expect(titles(a), containsAll(['Windows tool talking to the internet', 'Sneaky start-up command']));
  });

  test('PowerShell running a normal script is only suspicious', () {
    const path = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';
    final a = assess(path,
        file: signedFile(path), cmd: r'powershell.exe -File C:\Scripts\backup.ps1');
    expect(a.level, RiskLevel.suspicious);
    expect(titles(a), isNot(contains('Sneaky start-up command')));
  });

  test('unsigned server listening to everyone is suspicious', () {
    const path = r'C:\Games\BlockWorld\game_server.exe';
    final a = assess(path,
        conn: const NetConnection(
            protocol: 'TCP',
            localAddress: '0.0.0.0',
            localPort: 25565,
            remoteAddress: '',
            remotePort: 0,
            state: 'Listen',
            pid: 7788),
        direction: Direction.listening,
        file: unsignedFile(path));
    expect(a.level, RiskLevel.suspicious);
    expect(titles(a), contains('Open door to everyone'));
  });

  test('someone remote-desktopping in from the internet is flagged', () {
    const path = r'C:\Windows\System32\svchost.exe';
    final a = assess(path,
        conn: tcp(remote: '81.2.69.160', remotePort: 51515, localPort: 3389),
        direction: Direction.incoming,
        file: signedFile(path));
    expect(titles(a), contains('Someone is remote-accessing your PC'));
    expect(a.level, isNot(RiskLevel.safe));
  });

  test('Tor/proxy IP and flagged country add points', () {
    const path = r'C:\Program Files\App\app.exe';
    final a = assess(path,
        file: signedFile(path),
        geo: const GeoInfo(
            ip: '142.250.80.46', country: 'Narnia', countryCode: 'NA', proxy: true),
        flagged: {'NA'});
    expect(titles(a), containsAll(['VPN / proxy / Tor address', 'Flagged country: Narnia']));
    expect(a.score, 45);
  });

  test('Windows kernel (PID 4) is never flagged', () {
    final a = engine.assess(RiskInput(
        connection: tcp(pid: 4, remotePort: 4444), direction: Direction.outgoing));
    expect(a.score, 0);
    expect(a.notes, isNotEmpty);
  });

  test('hidden folder is a note, not points', () {
    final a = engine.assess(RiskInput(
      connection: tcp(),
      direction: Direction.outgoing,
      process: const ProcessInfo(pid: 1234, name: 'mystery.exe'),
      isAdmin: false,
    ));
    expect(a.score, 0);
    expect(a.notes.single, contains('Restart as admin'));
  });

  test('random-looking names', () {
    expect(looksRandomName('a8f3c2d9e7b1a4c6'), isTrue);
    expect(looksRandomName('xkqwzrtp'), isTrue);
    expect(looksRandomName('chrome'), isFalse);
    expect(looksRandomName('msedgewebview2'), isFalse);
    expect(looksRandomName('nvcontainer'), isFalse);
  });

  group('directionOf', () {
    test('incoming when the local port is a listening port', () {
      expect(directionOf(tcp(localPort: 3389), {3389}), Direction.incoming);
    });
    test('outgoing otherwise', () {
      expect(directionOf(tcp(), {3389}), Direction.outgoing);
    });
    test('loopback is local', () {
      expect(directionOf(tcp(remote: '127.0.0.1', local: '127.0.0.1'), {}),
          Direction.local);
    });
  });

  group('ip utils', () {
    test('public vs private', () {
      expect(isPublicIp('142.250.80.46'), isTrue);
      expect(isPublicIp('192.168.1.5'), isFalse);
      expect(isPublicIp('10.1.2.3'), isFalse);
      expect(isPublicIp('172.20.0.1'), isFalse);
      expect(isPublicIp('127.0.0.1'), isFalse);
      expect(isPublicIp('0.0.0.0'), isFalse);
      expect(isPublicIp('2606:4700::1111'), isTrue);
      expect(isPublicIp('fe80::1%12'), isFalse);
      expect(isPublicIp('::ffff:8.8.8.8'), isTrue);
      expect(isPublicIp('::1'), isFalse);
    });
    test('formatEndpoint wraps IPv6', () {
      expect(formatEndpoint('1.2.3.4', 80), '1.2.3.4:80');
      expect(formatEndpoint('::1', 80), '[::1]:80');
    });
  });
}
