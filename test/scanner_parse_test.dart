import 'package:connection_finder/models.dart';
import 'package:connection_finder/services/scanner.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('parseScanJson', () {
    test('reads connections, processes and admin flag', () {
      const raw = '\uFEFF{"admin":true,"method":"cim","conns":['
          '{"p":"TCP","la":"192.168.1.5","lp":50123,"ra":"142.250.80.46","rp":443,"s":"Established","id":9120},'
          '{"p":"TCP","la":"0.0.0.0","lp":135,"ra":"0.0.0.0","rp":0,"s":"Listen","id":1144},'
          '{"p":"UDP","la":"0.0.0.0","lp":5353,"ra":"","rp":0,"s":"Bound","id":2000}'
          '],"procs":['
          r'{"id":9120,"n":"chrome.exe","path":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","cmd":"chrome.exe --x","pp":100},'
          '{"id":1144,"n":"svchost.exe","path":"","cmd":"","pp":0}'
          '],"netstat":""}';
      final result = parseScanJson(raw);
      expect(result.isAdmin, isTrue);
      expect(result.connections, hasLength(3));

      final web = result.connections[0];
      expect(web.remoteAddress, '142.250.80.46');
      expect(web.remotePort, 443);
      expect(web.isEstablished, isTrue);

      final listen = result.connections[1];
      expect(listen.isListening, isTrue);
      expect(listen.remoteAddress, isEmpty, reason: 'listening has no remote');

      expect(result.connections[2].protocol, 'UDP');
      expect(result.connections[2].isListening, isTrue);

      final chrome = result.processes[9120]!;
      expect(chrome.path, r'C:\Program Files\Google\Chrome\Application\chrome.exe');
      expect(chrome.parentPid, 100);
      expect(result.processes[1144]!.path, isNull, reason: 'empty path = hidden');
    });

    test('accepts a single connection that is not wrapped in a list', () {
      const raw = '{"admin":false,"method":"cim",'
          '"conns":{"p":"TCP","la":"10.0.0.2","lp":1,"ra":"1.1.1.1","rp":53,"s":"Established","id":7},'
          '"procs":{"id":7,"n":"x.exe","path":"C:\\\\x.exe","cmd":"","pp":0}}';
      final result = parseScanJson(raw);
      expect(result.connections.single.remotePort, 53);
      expect(result.processes[7]!.name, 'x.exe');
    });

    test('falls back to netstat text', () {
      const raw = '{"admin":false,"method":"netstat","conns":[],"procs":[],'
          '"netstat":"\\r\\nActive Connections\\r\\n\\r\\n  Proto  Local Address          Foreign Address        State           PID\\r\\n'
          '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1144\\r\\n'
          '  TCP    192.168.1.5:50123      142.250.80.46:443      ESTABLISHED     9120\\r\\n'
          '  TCP    [::1]:49670            [::1]:49671            ESTABLISHED     3000\\r\\n'
          '  UDP    0.0.0.0:5353           *:*                                    2000\\r\\n"}';
      final result = parseScanJson(raw);
      expect(result.method, 'netstat');
      expect(result.connections, hasLength(4));
      expect(result.connections[0].state, 'Listen');
      expect(result.connections[0].remoteAddress, isEmpty);
      expect(result.connections[1].remoteAddress, '142.250.80.46');
      expect(result.connections[1].pid, 9120);
      expect(result.connections[2].localAddress, '::1');
      expect(result.connections[3].protocol, 'UDP');
      expect(result.connections[3].pid, 2000);
    });
  });

  test('parseInspectJson reads signature details', () {
    const raw = r'[{"path":"C:\\Windows\\System32\\svchost.exe","exists":true,"sig":"Valid","signer":"Microsoft Windows Publisher","company":"Microsoft Corporation","product":"Windows","desc":"Host Process","created":"2025-03-02T10:00:00.0000000Z","size":57360},'
        r'{"path":"C:\\Temp\\x.exe","exists":true,"sig":"NotSigned","signer":"","company":"","product":"","desc":"","created":"","size":0},'
        r'{"path":"C:\\gone.exe","exists":false,"sig":"Unknown","signer":"","company":"","product":"","desc":"","created":"","size":0}]';
    final files = parseInspectJson(raw);
    final svc = files[r'C:\Windows\System32\svchost.exe']!;
    expect(svc.signature, SignatureStatus.valid);
    expect(svc.isSigned, isTrue);
    expect(svc.signer, 'Microsoft Windows Publisher');
    expect(svc.created, DateTime.utc(2025, 3, 2, 10));
    expect(svc.size, 57360);
    expect(files[r'C:\Temp\x.exe']!.signature, SignatureStatus.notSigned);
    expect(files[r'C:\gone.exe']!.exists, isFalse);
  });

  test('folderOf / fileNameOf handle Windows paths', () {
    expect(folderOf(r'C:\Program Files\App\app.exe'), r'C:\Program Files\App');
    expect(fileNameOf(r'C:\Program Files\App\app.exe'), 'app.exe');
    expect(folderOf(r'C:\evil.exe'), r'C:\');
    expect(folderOf(null), isNull);
  });

  group('services', () {
    test('executableFromCommand finds the program file', () {
      const env = {'SystemRoot': r'C:\WINDOWS'};
      expect(executableFromCommand(r'C:\WINDOWS\system32\svchost.exe -k netsvcs -p', environment: env),
          r'C:\WINDOWS\system32\svchost.exe');
      expect(executableFromCommand(r'"C:\Program Files\App\app.exe" --service', environment: env),
          r'C:\Program Files\App\app.exe');
      expect(executableFromCommand(r'%SystemRoot%\System32\lsass.exe', environment: env),
          r'C:\WINDOWS\System32\lsass.exe');
      expect(executableFromCommand(r'\SystemRoot\System32\drivers\x.sys', environment: env), isNull);
      expect(executableFromCommand('', environment: env), isNull);
    });

    test('hidden folders are filled in from the service list', () {
      const raw = '{"admin":false,"method":"cim","conns":['
          '{"p":"TCP","la":"0.0.0.0","lp":5040,"ra":"0.0.0.0","rp":0,"s":"Listen","id":44},'
          '{"p":"TCP","la":"0.0.0.0","lp":7680,"ra":"0.0.0.0","rp":0,"s":"Listen","id":55}'
          '],"procs":['
          '{"id":44,"n":"svchost.exe","path":"","cmd":"","pp":0},'
          '{"id":55,"n":"evil.exe","path":"","cmd":"","pp":0}'
          '],"svcs":['
          r'{"id":44,"n":"CDPSvc","d":"Connected Devices Platform Service","path":"C:\\WINDOWS\\system32\\svchost.exe -k LocalService -p"},'
          r'{"id":44,"n":"DoSvc","d":"Delivery Optimization","path":"C:\\WINDOWS\\System32\\svchost.exe -k NetworkService -p"},'
          r'{"id":55,"n":"Fake","d":"Fake Service","path":"C:\\WINDOWS\\system32\\svchost.exe -k x"}'
          ']}';
      final result = parseScanJson(raw);
      final svchost = result.processes[44]!;
      expect(svchost.path, r'C:\WINDOWS\system32\svchost.exe');
      expect(svchost.services, ['Connected Devices Platform Service', 'Delivery Optimization']);
      expect(result.processes[55]!.path, isNull,
          reason: 'a service path is only trusted when the file name matches');
    });
  });
}
