// Tests for the "unusual behaviour" clues: who started a program, what
// starts with Windows, remote control, clockwork calls, new programs and
// addresses with a bad reputation.

import 'dart:convert';

import 'package:connection_finder/models.dart';
import 'package:connection_finder/services/ai_service.dart';
import 'package:connection_finder/services/bad_addresses.dart';
import 'package:connection_finder/services/demo_data.dart';
import 'package:connection_finder/services/repeat_tracker.dart';
import 'package:connection_finder/services/risk_engine.dart';
import 'package:connection_finder/services/scanner.dart';
import 'package:connection_finder/services/seen_store.dart';
import 'package:connection_finder/services/settings.dart';
import 'package:connection_finder/services/system_actions.dart';
import 'package:connection_finder/state/app_controller.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';

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

FileInfo signed(String path, [String signer = 'Some Company']) => FileInfo(
    path: path,
    exists: true,
    signature: SignatureStatus.valid,
    signer: signer,
    created: DateTime(2025));

FileInfo unsigned(String path) => FileInfo(
    path: path,
    exists: true,
    signature: SignatureStatus.notSigned,
    created: DateTime(2025));

ProcessInfo proc(String path, {int pid = 1234, String? cmd}) => ProcessInfo(
    pid: pid, name: fileNameOf(path), path: path, commandLine: cmd);

RiskAssessment assess(
  String path, {
  NetConnection? conn,
  FileInfo? file,
  String? cmd,
  GeoInfo? geo,
  Direction direction = Direction.outgoing,
  List<ProcessInfo> ancestors = const [],
  List<AutostartEntry> autostarts = const [],
  bool autostartIsNew = false,
  RepeatInfo? repeat,
  bool firstSeenRecently = false,
  bool badAddress = false,
}) {
  final c = conn ?? tcp();
  return engine.assess(RiskInput(
    connection: c,
    direction: direction,
    process: proc(path, pid: c.pid, cmd: cmd),
    file: file,
    geo: geo,
    now: now,
    ancestors: ancestors,
    autostarts: autostarts,
    autostartIsNew: autostartIsNew,
    repeat: repeat,
    firstSeenRecently: firstSeenRecently,
    badAddress: badAddress,
  ));
}

Set<String> titles(RiskAssessment a) => a.reasons.map((r) => r.title).toSet();

const word = r'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE';
const powershell = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';
const cmdExe = r'C:\Windows\System32\cmd.exe';
const chrome = r'C:\Program Files\Google\Chrome\Application\chrome.exe';
const tool = r'C:\Tools\helper.exe';

void main() {
  group('who started it', () {
    test('a document app starting PowerShell that goes online is dangerous', () {
      final a = assess(powershell,
          file: signed(powershell, 'Microsoft Windows'),
          ancestors: [proc(word, pid: 10), proc(r'C:\Windows\explorer.exe', pid: 5)]);
      expect(a.level, RiskLevel.dangerous);
      expect(titles(a), contains('Started by a document app'));
      expect(a.reasons.first.detail, contains('Word started "powershell.exe"'));
    });

    test('a document app starting a tool that starts a program is caught', () {
      final a = assess(tool,
          file: unsigned(tool),
          ancestors: [proc(cmdExe, pid: 11), proc(word, pid: 10)]);
      expect(titles(a), contains('Started by a document app'));
      expect(a.reasons.firstWhere((r) => r.kind == ReasonKind.behavior).detail,
          contains('Word started "cmd.exe"'));
    });

    test('an unsigned program started straight from a document is suspicious', () {
      final a = assess(tool, file: unsigned(tool), ancestors: [proc(word, pid: 10)]);
      expect(titles(a), contains('Started by Word'));
    });

    test('a signed browser opened from a document is fine', () {
      final a = assess(chrome,
          file: signed(chrome, 'Google LLC'), ancestors: [proc(word, pid: 10)]);
      expect(a.level, RiskLevel.safe);
    });

    test('PowerShell started normally gets no document clue', () {
      final a = assess(powershell,
          file: signed(powershell),
          ancestors: [proc(r'C:\Windows\explorer.exe', pid: 5)]);
      expect(titles(a), isNot(contains('Started by a document app')));
    });

    test('ancestorsOf walks up, and ignores a reused process number', () {
      final t0 = DateTime(2026, 11, 22, 10);
      final all = {
        1: ProcessInfo(pid: 1, name: 'explorer.exe', started: t0),
        2: ProcessInfo(pid: 2, name: 'WINWORD.EXE', parentPid: 1, started: t0.add(const Duration(minutes: 1))),
        3: ProcessInfo(pid: 3, name: 'powershell.exe', parentPid: 2, started: t0.add(const Duration(minutes: 2))),
        // Claims parent 9, but 9 started later, so it's a different program.
        4: ProcessInfo(pid: 4, name: 'old.exe', parentPid: 9, started: t0),
        9: ProcessInfo(pid: 9, name: 'newer.exe', started: t0.add(const Duration(hours: 1))),
      };
      expect(AppController.ancestorsOf(all[3], all).map((p) => p.name),
          ['WINWORD.EXE', 'explorer.exe']);
      expect(AppController.ancestorsOf(all[4], all), isEmpty);
    });
  });

  group('starts with Windows', () {
    const entry = AutostartEntry(
        kind: 'run', name: 'Updater', command: r'C:\Tools\helper.exe',
        exePath: r'C:\Tools\helper.exe', exeName: 'helper.exe');

    test('unsigned program that just added itself to startup', () {
      final a = assess(tool, file: unsigned(tool), autostarts: [entry], autostartIsNew: true);
      expect(titles(a), contains('Just set itself to start with Windows'));
      expect(a.level, RiskLevel.dangerous); // 25 unsigned + 25 startup
      expect(a.reasons.firstWhere((r) => r.kind == ReasonKind.startup).detail,
          contains('Windows startup list entry called "Updater"'));
    });

    test('unsigned program that has always started with Windows', () {
      final a = assess(tool, file: unsigned(tool), autostarts: [entry]);
      expect(titles(a), contains('Starts by itself with Windows'));
      expect(a.level, RiskLevel.suspicious);
    });

    test('signed apps that start with Windows are normal', () {
      final a = assess(chrome, file: signed(chrome), autostarts: [entry], autostartIsNew: true);
      expect(a.level, RiskLevel.safe);
    });

    test('a startup entry that runs a Windows tool is flagged', () {
      const task = AutostartEntry(
          kind: 'task', name: r'\Updates\Sync', command: 'powershell -w hidden -file x.ps1',
          exeName: 'powershell.exe', args: '-w hidden -file x.ps1');
      final a = assess(powershell, file: signed(powershell), autostarts: [task]);
      expect(titles(a), contains('Windows tool set to start by itself'));
      expect(a.reasons.firstWhere((r) => r.kind == ReasonKind.startup).detail,
          contains('scheduled task entry called "Sync"'));
    });
  });

  group('remote control', () {
    const anydesk = r'C:\Program Files (x86)\AnyDesk\AnyDesk.exe';

    test('a running remote-control app is shown, even when signed', () {
      final a = assess(anydesk, file: signed(anydesk, 'AnyDesk Software GmbH'));
      expect(a.level, RiskLevel.suspicious);
      expect(titles(a), {'Remote-control app is running'});
      expect(a.reasons.single.detail, contains('AnyDesk lets another person see and control this PC'));
    });

    test('Remote Desktop waiting for connections is pointed out', () {
      const svchost = r'C:\Windows\System32\svchost.exe';
      final a = assess(svchost,
          file: signed(svchost, 'Microsoft Windows'),
          direction: Direction.listening,
          conn: const NetConnection(
              protocol: 'TCP', localAddress: '0.0.0.0', localPort: 3389,
              remoteAddress: '', remotePort: 0, state: 'Listen', pid: 1234));
      expect(titles(a), {'Remote Desktop is switched on'});
      expect(a.level, RiskLevel.suspicious);
    });

    test('someone on the home network using Remote Desktop', () {
      const svchost = r'C:\Windows\System32\svchost.exe';
      final a = assess(svchost,
          file: signed(svchost),
          direction: Direction.incoming,
          conn: tcp(remote: '192.168.1.77', remotePort: 51000, localPort: 3389));
      expect(titles(a), contains('Remote access from your network'));
    });

    test('an ordinary program talking to a remote-control company', () {
      final a = assess(tool,
          file: signed(tool),
          geo: const GeoInfo(ip: '142.250.80.46', org: 'TeamViewer Germany GmbH'));
      expect(titles(a), {'Talks to a remote-control service'});
    });
  });

  group('clockwork calls', () {
    const interval = Duration(seconds: 5);

    void feed(RepeatTracker t, DateTime start, List<int> seconds, {String ip = '198.51.100.7'}) {
      var n = 0;
      for (final s in seconds) {
        t.observe([('conn${n++}', 'c:\\x.exe', ip, 443)],
            start.add(Duration(seconds: s)), scanInterval: interval);
      }
    }

    test('regular contacts are noticed', () {
      final t = RepeatTracker();
      feed(t, now, [0, 20, 41, 60, 82]);
      final info = t.infoFor('C:\\x.exe', '198.51.100.7', 443, scanInterval: interval);
      expect(info, isNotNull);
      expect(info!.count, 5);
      expect(info.seconds, inInclusiveRange(19, 22));
    });

    test('a burst of connections counts as one contact', () {
      final t = RepeatTracker();
      feed(t, now, [0, 7, 20, 27, 40, 47, 60, 67, 80, 87]);
      expect(t.infoFor('c:\\x.exe', '198.51.100.7', 443, scanInterval: interval)?.seconds, 20);
    });

    test('a steady stream of retries is not clockwork', () {
      final t = RepeatTracker();
      feed(t, now, [for (var i = 0; i < 30; i++) i * 7]);
      expect(t.infoFor('c:\\x.exe', '198.51.100.7', 443, scanInterval: interval), isNull);
    });

    test('irregular contacts and too few contacts are ignored', () {
      final t = RepeatTracker();
      feed(t, now, [0, 20, 95, 130, 300]);
      expect(t.infoFor('c:\\x.exe', '198.51.100.7', 443, scanInterval: interval), isNull);
      final few = RepeatTracker();
      feed(few, now, [0, 20, 40, 60]);
      expect(few.infoFor('c:\\x.exe', '198.51.100.7', 443, scanInterval: interval), isNull);
    });

    test('a connection that simply stays open is one contact', () {
      final t = RepeatTracker();
      for (var s = 0; s <= 120; s += 5) {
        t.observe([('same', 'c:\\x.exe', '1.2.3.4', 443)],
            now.add(Duration(seconds: s)), scanInterval: interval);
      }
      expect(t.infoFor('c:\\x.exe', '1.2.3.4', 443, scanInterval: interval), isNull);
    });

    test('the clue counts for unsigned programs, and is a note for signed ones', () {
      const repeat = RepeatInfo(count: 6, seconds: 60);
      final bad = assess(tool, file: unsigned(tool), repeat: repeat);
      expect(titles(bad), contains('Calls the same address like clockwork'));
      expect(bad.reasons.firstWhere((r) => r.points == 15).detail, contains('6 times, about every 60 seconds'));
      final good = assess(chrome, file: signed(chrome), repeat: repeat);
      expect(good.level, RiskLevel.safe);
      expect(good.notes.join(), contains('about every 60 seconds'));
    });
  });

  group('new things', () {
    test('SeenStore: the first look is the baseline, later arrivals are new', () {
      final s = SeenStore('t');
      expect(s.ready, isFalse);
      s.observe(['a', 'b'], now);
      expect(s.isNew('a', now, const Duration(days: 1)), isFalse);
      s.observe(['a', 'b', 'c'], now.add(const Duration(hours: 1)));
      expect(s.isNew('c', now.add(const Duration(hours: 2)), const Duration(days: 1)), isTrue);
      expect(s.isNew('c', now.add(const Duration(days: 3)), const Duration(days: 1)), isFalse);
      expect(s.isNew('never-seen', now, const Duration(days: 1)), isFalse);
    });

    test('SeenStore remembers between runs', () async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();
      SeenStore('programs', prefs: prefs)
        ..observe(['a'], now)
        ..observe(['a', 'fresh'], now.add(const Duration(minutes: 5)));
      final again = SeenStore('programs', prefs: prefs);
      expect(again.ready, isTrue);
      expect(again.isNew('fresh', now.add(const Duration(hours: 1)), const Duration(days: 1)), isTrue);
      expect(again.isNew('a', now.add(const Duration(hours: 1)), const Duration(days: 1)), isFalse);
    });

    test('an unsigned program seen online for the first time', () {
      final a = assess(tool, file: unsigned(tool), firstSeenRecently: true);
      expect(titles(a), contains('New on your network'));
      final b = assess(chrome, file: signed(chrome), firstSeenRecently: true);
      expect(b.level, RiskLevel.safe);
    });
  });

  group('addresses with a bad reputation', () {
    test('the clue depends on direction and signature', () {
      final out = assess(tool, file: unsigned(tool), badAddress: true);
      expect(titles(out), contains('Talks to a reported address'));
      expect(out.level, RiskLevel.dangerous);
      final incoming = assess(chrome,
          file: signed(chrome), badAddress: true, direction: Direction.incoming);
      expect(titles(incoming), contains('Reported address connected in'));
      final signedOut = assess(chrome, file: signed(chrome), badAddress: true);
      expect(signedOut.level, RiskLevel.safe);
      expect(signedOut.notes.join(), contains('reported for attacks'));
    });

    test('the list parser keeps only real addresses', () {
      expect(parseAddressList('# comment\n1.2.3.4\n5.6.7.8\t9\n\nnot-an-ip\n999.1.1.1\n'),
          {'1.2.3.4', '5.6.7.8'});
    });

    test('the list is downloaded once and ignores junk answers', () async {
      var calls = 0;
      final body = [for (var i = 0; i < 150; i++) '10.0.${i ~/ 250}.${i % 250}'].join('\n');
      final list = IpsumBadAddressList(client: MockClient((_) async {
        calls++;
        return http.Response(body, 200);
      }));
      expect(await list.refresh(), isTrue);
      expect(list.count, 150);
      expect(list.contains('10.0.0.7'), isTrue);
      expect(await list.refresh(), isFalse, reason: 'still fresh');
      expect(calls, 1);

      final junk = IpsumBadAddressList(
          client: MockClient((_) async => http.Response('<html>oops</html>', 200)));
      expect(await junk.refresh(), isFalse);
      expect(junk.count, 0);
    });
  });

  group('reading Windows data', () {
    test('processes carry their start time and parent', () {
      const raw = '{"admin":true,"method":"cim","conns":['
          '{"p":"TCP","la":"10.0.0.2","lp":1,"ra":"1.1.1.1","rp":443,"s":"Established","id":7}],'
          '"procs":['
          r'{"id":7,"n":"powershell.exe","path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","cmd":"","pp":6,"cd":"2026-11-22T10:02:00.0000000Z"},'
          r'{"id":6,"n":"WINWORD.EXE","path":"C:\\Office\\WINWORD.EXE","cmd":"","pp":0,"cd":"2026-11-22T10:00:00.0000000Z"}],'
          '"svcs":['
          r'{"id":7,"n":"Sync","d":"Sync Service","path":"\"C:\\Tools\\sync.exe\" --run","sm":"Auto"},'
          r'{"id":7,"n":"Manual","d":"Manual Service","path":"C:\\Tools\\manual.exe","sm":"Manual"}]}';
      final r = parseScanJson(raw);
      expect(r.processes[7]!.parentPid, 6);
      expect(r.processes[7]!.started, DateTime.utc(2026, 11, 22, 10, 2));
      expect(AppController.ancestorsOf(r.processes[7], r.processes).single.name, 'WINWORD.EXE');
      expect(r.services.single.name, 'Sync Service');
      expect(r.services.single.exePath, r'C:\Tools\sync.exe');
      expect(r.services.single.kind, 'service');
    });

    test('startup entries are parsed from the registry, folder and tasks', () {
      const env = {'SystemRoot': r'C:\WINDOWS', 'windir': r'C:\WINDOWS'};
      const raw = '{"items":['
          r'{"t":"run","n":"Discord","c":"\"C:\\Users\\Mia\\AppData\\Local\\Discord\\Update.exe\" --processStart Discord.exe"},'
          r'{"t":"run","n":"Sneaky","c":"powershell -w hidden -enc AAAA"},'
          r'{"t":"folder","n":"Notes.lnk","e":"C:\\Apps\\notes.exe","a":"--tray"},'
          r'{"t":"folder","n":"run.vbs","e":"C:\\Users\\Mia\\AppData\\Roaming\\run.vbs","a":""},'
          r'{"t":"task","n":"\\Vendor\\Updater","e":"%windir%\\system32\\rundll32.exe","a":"thing.dll,Start"}'
          '],"ok":["run","folder","task"]}';
      final scan = parseAutostartJson(raw, environment: env);
      expect(scan.completeKinds, {'run', 'folder', 'task'});
      final byName = {for (final e in scan.entries) e.name: e};
      expect(byName['Discord']!.exePath, r'C:\Users\Mia\AppData\Local\Discord\Update.exe');
      expect(byName['Discord']!.args, '--processstart discord.exe');
      expect(byName['Sneaky']!.exePath, isNull);
      expect(byName['Sneaky']!.exeName, 'powershell.exe');
      expect(byName['Sneaky']!.args, '-w hidden -enc aaaa');
      expect(byName['Notes.lnk']!.exePath, r'C:\Apps\notes.exe');
      expect(byName['run.vbs']!.exeName, 'run.vbs');
      expect(byName[r'\Vendor\Updater']!.exePath, r'C:\WINDOWS\system32\rundll32.exe');
      expect(byName[r'\Vendor\Updater']!.shortName, 'Updater');
      expect(byName[r'\Vendor\Updater']!.where, 'scheduled task');
    });

    test("Windows Defender's answer is read correctly", () {
      expect(readDefenderOutput(0, 'Scanning C:\\x.exe found no threats.').outcome, DefenderOutcome.clean);
      expect(readDefenderOutput(2, 'Scanning C:\\x.exe found 1 threats.').outcome, DefenderOutcome.threat);
      expect(readDefenderOutput(2, 'CmdTool: Failed with hr = 0x80508023.').outcome,
          DefenderOutcome.unavailable);
      expect(readDefenderOutput(1, '').outcome, DefenderOutcome.unavailable);
    });
  });

  test('the app shows the demo behaviours with their explanations', () async {
    SharedPreferences.setMockInitialValues({'scan.auto': false});
    final settings = AppSettings(keyStore: MemoryKeyStore());
    await settings.load();
    final c = AppController(
      settings: settings,
      scanner: DemoScanner(delay: Duration.zero),
      geo: demoGeoLookup(),
      ai: AiService(),
      badAddresses: FixedBadAddressList(['45.142.212.61']),
    );
    await c.refresh();
    await Future<void>.delayed(const Duration(milliseconds: 50));

    ProgramGroup g(String name) => c.groups.firstWhere((x) => x.fileName == name);
    Set<String> why(String name) => g(name).reasons.map((r) => r.title).toSet();

    expect(why('powershell.exe'), contains('Started by a document app'));
    expect(g('powershell.exe').startedBy, ['WINWORD.EXE', 'explorer.exe']);
    expect(g('powershell.exe').level, RiskLevel.dangerous);

    expect(why('AnyDesk.exe'), {'Remote-control app is running'});
    expect(c.statusOf(g('AnyDesk.exe')), ProgramStatus.risky);

    expect(why('svch0st.exe'), contains('Starts by itself with Windows'));
    expect(g('svch0st.exe').autostarts.single.name, 'WindowsUpdateHelper');

    expect(why('invoice_2026.pdf.exe'), contains('Talks to a reported address'));

    // Signed apps that start with Windows stay trusted and hidden.
    expect(g('Discord.exe').autostarts, isNotEmpty);
    expect(c.statusOf(g('Discord.exe')), ProgramStatus.trusted);

    // The AI is told about the behaviour too.
    final facts = jsonEncode(describeGroupForAi(g('powershell.exe')));
    expect(facts, contains('WINWORD.EXE'));
    c.dispose();
  });
}
