// Decides how suspicious a connection looks, using simple, explainable clues.
// Every clue adds points; 20+ points = suspicious, 50+ points = dangerous.
// It also lists the good signs, so the app can say why something looks safe.

import 'dart:math' as math;

import '../models.dart';
import 'ip_utils.dart';

class RiskInput {
  const RiskInput({
    required this.connection,
    required this.direction,
    this.process,
    this.file,
    this.geo,
    this.flaggedCountries = const {},
    this.isAdmin = true,
    this.selfPid,
    this.now,
  });

  final NetConnection connection;
  final Direction direction;
  final ProcessInfo? process;
  final FileInfo? file;
  final GeoInfo? geo;

  /// Upper-case 2-letter country codes the user wants to be warned about.
  final Set<String> flaggedCountries;
  final bool isAdmin;

  /// Process id of Connection Finder itself (it talks to the IP lookup and
  /// AI services, which is expected).
  final int? selfPid;
  final DateTime? now;
}

/// Real Windows programs that malware likes to copy the name of.
const Set<String> windowsSystemNames = {
  'svchost.exe',
  'lsass.exe',
  'csrss.exe',
  'winlogon.exe',
  'services.exe',
  'smss.exe',
  'wininit.exe',
  'explorer.exe',
  'spoolsv.exe',
  'taskhostw.exe',
  'dllhost.exe',
  'rundll32.exe',
  'conhost.exe',
  'dwm.exe',
  'ctfmon.exe',
  'sihost.exe',
  'runtimebroker.exe',
  'lsm.exe',
  'taskmgr.exe',
  'wuauclt.exe',
  'audiodg.exe',
  'fontdrvhost.exe',
  'userinit.exe',
  'regsvr32.exe',
  'cmd.exe',
};

/// Built-in Windows tools that attackers often misuse ("living off the
/// land"), with how many points it's worth when they touch the internet.
const Map<String, int> abusedWindowsTools = {
  'powershell.exe': 30,
  'powershell_ise.exe': 30,
  'pwsh.exe': 15,
  'cmd.exe': 30,
  'wscript.exe': 35,
  'cscript.exe': 35,
  'mshta.exe': 40,
  'rundll32.exe': 30,
  'regsvr32.exe': 35,
  'certutil.exe': 40,
  'bitsadmin.exe': 30,
  'msbuild.exe': 35,
  'installutil.exe': 35,
  'regasm.exe': 30,
  'regsvcs.exe': 30,
  'wmic.exe': 30,
  'cmstp.exe': 35,
  'hh.exe': 30,
  'forfiles.exe': 30,
  'odbcconf.exe': 30,
  'msiexec.exe': 10,
};

/// Ports often used by hacking tools, botnets, Tor or crypto miners.
/// The text completes the sentence "Port N is ...".
const Map<int, (String, int)> suspiciousPorts = {
  4444: ('used by the Metasploit hacking tool', 25),
  4445: ('used by hacking tools', 20),
  1337: ('a well-known "hacker" port', 25),
  31337: ('the "elite hacker" port of old trojans', 30),
  12345: ('used by the NetBus trojan', 25),
  54321: ('used by old trojans', 20),
  6666: ('IRC chat, used to control hacked PCs', 25),
  6667: ('IRC chat, used to control hacked PCs', 25),
  6668: ('IRC chat, used to control hacked PCs', 25),
  6669: ('IRC chat, used to control hacked PCs', 25),
  6697: ('IRC chat, used to control hacked PCs', 20),
  1080: ('a proxy that passes traffic along', 15),
  3128: ('a proxy that passes traffic along', 10),
  9001: ('used by the Tor network to hide traffic', 30),
  9030: ('used by the Tor network to hide traffic', 30),
  9050: ('used by the Tor network to hide traffic', 30),
  9051: ('used by the Tor network to hide traffic', 30),
  9150: ('used by the Tor network to hide traffic', 30),
  3333: ('used by crypto-mining pools', 25),
  5555: ('used by crypto-mining pools', 20),
  7777: ('used by crypto-mining pools', 20),
  14444: ('used by crypto-mining pools', 25),
  14433: ('used by crypto-mining pools', 25),
  45700: ('used by crypto-mining pools', 25),
  23: ('Telnet, an old unencrypted remote login', 20),
};

/// "Doors" that let someone control or log in to this PC.
const Map<int, String> remoteAccessPorts = {
  3389: 'Remote Desktop',
  5900: 'VNC remote control',
  5901: 'VNC remote control',
  5938: 'TeamViewer',
  4899: 'Radmin remote control',
  22: 'SSH remote login',
  23: 'Telnet remote login',
  5985: 'PowerShell remoting',
  5986: 'PowerShell remoting',
};

final RegExp _systemFolder =
    RegExp(r'^[a-z]:\\windows(\\system32|\\syswow64)?$');
final RegExp _hiddenWindowsFolder = RegExp(
    r'^[a-z]:\\windows\\(fonts|tasks|debug|help|media|cursors|addins|inf|tracing|registration|system32\\tasks|system32\\spool\\drivers\\color)(\\|$)');
final RegExp _personalFolder =
    RegExp(r'\\(desktop|documents|pictures|music|videos)\\');
final RegExp _tempFolder = RegExp(r'\\(temp|tmp)\\');
final RegExp _oddRoot =
    RegExp(r'^[a-z]:\\?$|^[a-z]:\\programdata$|^[a-z]:\\users\\[^\\]+$');
final RegExp _programFiles = RegExp(r'^[a-z]:\\program files( \(x86\))?\\');
final RegExp _fakeDocument = RegExp(
    r'\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp[34]|mov|avi|zip|rar|7z)\.(exe|scr|com|bat|cmd|pif|vbs|js)$');
final RegExp _oddProgramType = RegExp(r'\.(scr|pif|com)$');

/// Patterns in a start-up command that mean "hidden / downloading / encoded".
final List<(RegExp, String)> _commandPatterns = [
  (RegExp(r'frombase64string'), 'decodes hidden data'),
  (RegExp(r'downloadstring|downloadfile|downloaddata'), 'downloads code'),
  (RegExp(r'invoke-expression|(^|[\s;|(])iex[\s(]'), 'runs code it got from somewhere'),
  (RegExp(r'javascript:|vbscript:'), 'runs hidden script code'),
];
final List<(RegExp, String)> _scriptHostPatterns = [
  (RegExp(r'\s[-/]e(nc|ncodedcommand|c)?\s+[a-z0-9+/=]{16,}'), 'runs a scrambled (encoded) command'),
  (RegExp(r'\s[-/]w(in(dow)?(style)?)?\s+h(idden)?\b'), 'hides its window'),
  (RegExp(r'[-/](exec(utionpolicy)?|ep)\s+bypass'), 'switches off script safety'),
  (RegExp(r'net\.webclient|invoke-webrequest|(^|\s)iwr\s|start-bitstransfer|urlcache|/transfer\s'), 'downloads from the internet'),
];

class RiskEngine {
  const RiskEngine();

  RiskAssessment assess(RiskInput input) {
    final conn = input.connection;
    if (conn.pid == 0 || conn.pid == 4) {
      return const RiskAssessment(score: 0, goodSigns: ['Part of Windows itself']);
    }
    if (input.selfPid != null && conn.pid == input.selfPid) {
      return const RiskAssessment(
        score: 0,
        goodSigns: ['This is Connection Finder itself'],
        notes: ['Connection Finder uses the internet to look up IPs and to ask your AI.'],
      );
    }

    final reasons = <RiskReason>[];
    final good = <String>[];
    final notes = <String>[];
    void add(ReasonKind kind, String title, String detail, int points) =>
        reasons.add(RiskReason(
            kind: kind, title: title, detail: detail, points: points));

    final path = input.process?.path;
    final rawName = path != null && path.isNotEmpty
        ? fileNameOf(path)
        : (input.process?.name ?? '');
    final name = rawName.toLowerCase();
    final base = name.endsWith('.exe') ? name.substring(0, name.length - 4) : name;
    final folder = (folderOf(path) ?? '').toLowerCase();
    final folderSlash = '$folder\\';
    final file = input.file;
    final signed = file?.isSigned ?? false;
    final cmd = ' ${(input.process?.commandLine ?? '').toLowerCase()} ';
    final remote = conn.remoteAddress;
    final remoteIsPublic = remote.isNotEmpty && isPublicIp(remote);
    final inWindowsFolder = _systemFolder.hasMatch(folder) ||
        folderSlash.contains(r'\windows\winsxs\') ||
        folderSlash.contains(r'\windows\systemapps\');
    final now = input.now ?? DateTime.now();

    if (path == null || path.isEmpty) {
      notes.add(input.isAdmin
          ? "Windows wouldn't share this program's folder."
          : 'Windows hides this folder. Use "Restart as admin" to see it.');
    }

    // 1. Sneaky folders --------------------------------------------------
    if (path != null && path.isNotEmpty) {
      if (folderSlash.contains(r'\$recycle.bin\')) {
        add(ReasonKind.folder, 'Hiding in the Recycle Bin',
            'Real programs never run from the Recycle Bin.', 60);
      } else if (_tempFolder.hasMatch(folderSlash)) {
        add(ReasonKind.folder, 'Runs from a Temp folder',
            'Temp is for throwaway files. Real apps rarely run from there.', 40);
      } else if (folderSlash.contains(r'\users\public\')) {
        add(ReasonKind.folder, 'Runs from the Public folder',
            'A shared folder that malware likes to hide in.', 30);
      } else if (folderSlash.contains(r'\downloads\')) {
        add(ReasonKind.folder, 'Runs from Downloads',
            'It was never installed. It runs straight from Downloads.', 25);
      } else if (_hiddenWindowsFolder.hasMatch(folder)) {
        add(ReasonKind.folder, 'Hiding inside a Windows folder',
            'This Windows folder normally has no programs in it.', 35);
      } else if (_personalFolder.hasMatch(folderSlash)) {
        add(ReasonKind.folder, 'Runs from a personal folder',
            'Apps normally live in Program Files, not Desktop or Documents.', 15);
      } else if (_oddRoot.hasMatch(folder)) {
        add(ReasonKind.folder, 'Odd location',
            'Real apps rarely sit loose at the top of a drive.', 25);
      } else if (folderSlash.contains(r'\appdata\roaming\')) {
        add(ReasonKind.folder, 'Runs from AppData\\Roaming',
            'Some real apps live here, but malware likes it too.', 10);
      } else if (inWindowsFolder) {
        good.add('In the Windows system folder');
      } else if (_programFiles.hasMatch(folderSlash)) {
        good.add('Installed in Program Files');
      }
    }

    // 2. Digital signature ---------------------------------------------
    if (file != null && file.exists) {
      switch (file.signature) {
        case SignatureStatus.valid:
          final maker = file.signer ?? file.company;
          good.insert(0, maker == null ? 'Digitally signed' : 'Made by $maker (signed)');
        case SignatureStatus.notSigned:
          add(ReasonKind.signature, 'No digital signature',
              'No company vouches for who made it.', 25);
        case SignatureStatus.hashMismatch:
          add(ReasonKind.signature, 'Broken signature',
              'The file was changed after it was signed.', 60);
        case SignatureStatus.notTrusted:
          add(ReasonKind.signature, 'Untrusted signature',
              "It's signed by someone Windows doesn't trust.", 30);
        case SignatureStatus.unknownError:
          add(ReasonKind.signature, 'Signature problem',
              "Windows couldn't confirm who made it.", 20);
        case SignatureStatus.notSupported:
        case SignatureStatus.unknown:
          break;
      }
    }

    // 3. Program file gone / brand new -----------------------------------
    if (file != null &&
        !file.exists &&
        path != null &&
        !inWindowsFolder &&
        !folderSlash.contains(r'\windowsapps\')) {
      add(ReasonKind.file, 'Program file is gone',
          'Its file was deleted while it runs. Malware does this to hide.', 30);
    }
    final created = file?.created;
    if (created != null && !signed && file!.exists) {
      final age = now.difference(created);
      if (!age.isNegative && age < const Duration(days: 3)) {
        final when = age.inHours < 1
            ? 'less than an hour'
            : age.inHours < 48
                ? '${age.inHours} hours'
                : '${age.inDays} days';
        add(ReasonKind.file, 'Brand-new program',
            "It appeared on your PC $when ago and isn't signed.", 10);
      }
    }

    // 4. Fake / look-alike Windows names --------------------------------
    if (name.isNotEmpty) {
      if (windowsSystemNames.contains(name) &&
          path != null &&
          path.isNotEmpty &&
          !inWindowsFolder) {
        add(ReasonKind.disguise, 'Pretends to be a Windows file',
            'The real "$rawName" lives in C:\\Windows\\System32, not here.',
            signed ? 35 : 70);
      } else {
        final twin = lookAlikeWindowsName(base);
        if (twin != null) {
          add(ReasonKind.disguise, 'Name looks like a Windows file',
              '"$rawName" looks like "$twin". A trick to blend in.',
              signed ? 10 : 45);
        }
      }
    }

    // 5. Built-in tools that hackers misuse ------------------------------
    final toolPoints = abusedWindowsTools[name];
    if (toolPoints != null) {
      if (remoteIsPublic) {
        add(ReasonKind.tool, 'Windows tool using the internet',
            'Hackers often misuse "$rawName" to download bad things.',
            toolPoints);
      } else if (input.direction == Direction.listening &&
          !isLoopback(conn.localAddress)) {
        add(ReasonKind.tool, 'Windows tool waiting for connections',
            '"$rawName" waiting for others to connect is unusual.',
            toolPoints);
      }
    }

    // 6. Sneaky start-up command -----------------------------------------
    final hits = <String>[
      for (final (pattern, label) in _commandPatterns)
        if (pattern.hasMatch(cmd)) label,
      if (abusedWindowsTools.containsKey(name))
        for (final (pattern, label) in _scriptHostPatterns)
          if (pattern.hasMatch(cmd)) label,
    ];
    if (hits.isNotEmpty) {
      add(ReasonKind.command, 'Sneaky start-up command',
          'It was started with a command that ${_joinNice(hits)}.',
          hits.length >= 3 ? 40 : 30);
    }

    // 7. Tricky file names -----------------------------------------------
    if (_fakeDocument.hasMatch(name)) {
      add(ReasonKind.file, 'Fake document name',
          '"$rawName" pretends to be a document, but it is a program.', 50);
    } else if (_oddProgramType.hasMatch(name)) {
      add(ReasonKind.file, 'Unusual program type',
          '.scr, .pif and .com files rarely need the internet.', 30);
    }
    if (!signed && looksRandomName(base)) {
      add(ReasonKind.file, 'Random-looking name',
          'Malware often uses jumbled names like this.', 15);
    }

    // 8. Ports and direction ---------------------------------------------
    switch (input.direction) {
      case Direction.outgoing:
      case Direction.incoming:
        final incoming = input.direction == Direction.incoming;
        if (remoteIsPublic) {
          final door = incoming ? remoteAccessPorts[conn.localPort] : null;
          if (door != null) {
            add(ReasonKind.network, 'Remote access from the internet',
                "Someone is connected to your $door. If that isn't you, stop it!",
                40);
          } else if (incoming && !signed) {
            add(ReasonKind.network, 'Someone outside connected in',
                'A computer on the internet connected to this program.', 15);
          }
          final port = suspiciousPorts[incoming ? conn.localPort : conn.remotePort];
          if (port != null) {
            final n = incoming ? conn.localPort : conn.remotePort;
            add(ReasonKind.port, 'Suspicious port $n', 'Port $n is ${port.$1}.', port.$2);
          }
          if (!incoming && const {135, 139, 445}.contains(conn.remotePort)) {
            add(ReasonKind.network, 'File sharing over the internet',
                'Windows file sharing should never go out to the internet.', 25);
          }
          final webPort = incoming ? conn.localPort : conn.remotePort;
          if (webPort == 443) {
            good.add('Secure connection (port 443)');
          } else if (webPort == 80) {
            good.add('Normal web traffic (port 80)');
          } else if (webPort == 53) {
            good.add('Website name lookup (DNS)');
          }
        } else if (remote.isNotEmpty) {
          good.add('Talks to your home network');
        }
      case Direction.listening:
        if (isLoopback(conn.localAddress)) {
          good.add('Only this PC can connect');
        } else {
          final port = suspiciousPorts[conn.localPort];
          if (port != null) {
            add(ReasonKind.port, 'Waiting on port ${conn.localPort}',
                'Port ${conn.localPort} is ${port.$1}.', port.$2);
          }
          final door = remoteAccessPorts[conn.localPort];
          if (door != null) {
            notes.add('$door is switched on (port ${conn.localPort} is open).');
          }
          if (conn.isTcp &&
              !signed &&
              !inWindowsFolder &&
              isUnspecified(conn.localAddress)) {
            add(ReasonKind.network, 'Open door to everyone',
                'Anyone on your network can connect to it.', 15);
          }
        }
      case Direction.local:
        good.add('Stays inside your PC');
      case Direction.other:
        break;
    }

    // 9. Who is on the other end ------------------------------------------
    final geo = input.geo;
    if (geo != null) {
      if (geo.proxy) {
        add(ReasonKind.network, 'Hidden behind a VPN or Tor',
            'The other side hides who it really is.', 20);
      }
      final code = geo.countryCode?.toUpperCase();
      if (code != null && input.flaggedCountries.contains(code)) {
        add(ReasonKind.country, 'Flagged country: ${geo.country ?? code}',
            'You asked to be warned about ${geo.country ?? code}.', 25);
      }
      if (geo.hosting && geo.owner != null) {
        notes.add('The other computer is in a data center (${geo.owner}).');
      }
    }

    if (reasons.isEmpty && good.isEmpty) good.add('No warning signs found');
    reasons.sort((a, b) => b.points.compareTo(a.points));
    final score = math.min(100, reasons.fold<int>(0, (s, r) => s + r.points));
    return RiskAssessment(
        score: score, reasons: reasons, goodSigns: good, notes: notes);
  }
}

String _joinNice(List<String> parts) {
  if (parts.length == 1) return parts.first;
  return '${parts.sublist(0, parts.length - 1).join(', ')} and ${parts.last}';
}

const Map<String, String> _digitLookAlikes = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '\$': 's',
};

/// If [base] (a file name without `.exe`) looks like a Windows file name but
/// isn't one, returns the real name it imitates.
String? lookAlikeWindowsName(String base) {
  final b = base.toLowerCase();
  if (b.length < 5 ||
      windowsSystemNames.contains('$b.exe') ||
      _legitNearNames.contains(b)) {
    return null;
  }
  final normalized = b.split('').map((c) => _digitLookAlikes[c] ?? c).join();
  for (final real in windowsSystemNames) {
    final r = real.substring(0, real.length - 4);
    if (r.length < 5 || r == 'services') continue;
    if (normalized == r || osaDistance(b, r) == 1) return real;
  }
  return null;
}

/// Real programs whose names happen to be one letter away from a Windows
/// file name.
const Set<String> _legitNearNames = {'taskhost', 'service', 'explore'};

/// Optimal-string-alignment distance (typos incl. swapped letters).
int osaDistance(String a, String b) {
  final n = a.length, m = b.length;
  if ((n - m).abs() > 1) return 2; // we only care about distance <= 1
  final d = List.generate(n + 1, (_) => List<int>.filled(m + 1, 0));
  for (var i = 0; i <= n; i++) {
    d[i][0] = i;
  }
  for (var j = 0; j <= m; j++) {
    d[0][j] = j;
  }
  for (var i = 1; i <= n; i++) {
    for (var j = 1; j <= m; j++) {
      final cost = a[i - 1] == b[j - 1] ? 0 : 1;
      var v = math.min(
          math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + cost);
      if (i > 1 &&
          j > 1 &&
          a[i - 1] == b[j - 2] &&
          a[i - 2] == b[j - 1]) {
        v = math.min(v, d[i - 2][j - 2] + 1);
      }
      d[i][j] = v;
    }
  }
  return d[n][m];
}

final RegExp _hexName = RegExp(r'^[a-f0-9]{12,}$');
final RegExp _guidName = RegExp(r'^\{?[0-9a-f]{8}-[0-9a-f]{4}-');
final RegExp _alnum = RegExp(r'^[a-z0-9]+$');
final RegExp _consonantRun = RegExp(r'[bcdfghjklmnpqrstvwxz]{6,}');

/// Guesses whether a file name is a random jumble like `xk2qz8vbt0`.
bool looksRandomName(String base) {
  final b = base.toLowerCase();
  if (b.length < 8) return false;
  if (_hexName.hasMatch(b) || _guidName.hasMatch(b)) return true;
  if (!_alnum.hasMatch(b)) return false;
  if (_consonantRun.hasMatch(b)) return true;
  final letters = b.replaceAll(RegExp(r'[0-9]'), '');
  final digits = b.length - letters.length;
  if (b.length >= 10 && digits >= 2 && letters.length >= 3) {
    final vowels = letters.split('').where('aeiouy'.contains).length;
    return vowels / letters.length < 0.2;
  }
  return false;
}
