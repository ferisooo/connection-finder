// Decides how suspicious a connection looks, using simple, explainable clues.
// Every clue adds points; 20+ points = suspicious, 50+ points = dangerous.

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

/// Ports that are commonly used by hacking tools, botnets, Tor or miners.
const Map<int, (String, int)> suspiciousPorts = {
  4444: ('a port used by the Metasploit hacking tool', 25),
  4445: ('a port used by hacking tools', 20),
  1337: ('a well-known "hacker" port', 25),
  31337: ('the "elite hacker" port used by old trojans', 30),
  12345: ('a port used by the NetBus trojan', 25),
  54321: ('a port used by old trojans', 20),
  6666: ('IRC chat, often used to control hacked PCs', 25),
  6667: ('IRC chat, often used to control hacked PCs', 25),
  6668: ('IRC chat, often used to control hacked PCs', 25),
  6669: ('IRC chat, often used to control hacked PCs', 25),
  6697: ('IRC chat, often used to control hacked PCs', 20),
  1080: ('a SOCKS proxy port that relays traffic', 15),
  3128: ('a proxy port that relays traffic', 10),
  9001: ('a Tor network port (hides who you talk to)', 30),
  9030: ('a Tor network port (hides who you talk to)', 30),
  9050: ('a Tor network port (hides who you talk to)', 30),
  9051: ('a Tor network port (hides who you talk to)', 30),
  9150: ('a Tor network port (hides who you talk to)', 30),
  3333: ('a port used by crypto-mining pools', 25),
  5555: ('a port used by crypto-mining pools and remote debugging', 20),
  7777: ('a port used by crypto-mining pools', 20),
  14444: ('a port used by crypto-mining pools', 25),
  14433: ('a port used by crypto-mining pools', 25),
  45700: ('a port used by crypto-mining pools', 25),
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
      return const RiskAssessment(
        score: 0,
        notes: ['This is Windows itself (the system core). It has no program file.'],
      );
    }

    if (input.selfPid != null && conn.pid == input.selfPid) {
      return const RiskAssessment(
        score: 0,
        notes: ['This is Connection Finder itself (looking up IPs or asking your AI).'],
      );
    }

    final reasons = <RiskReason>[];
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
          : 'Folder hidden by Windows. Use "Restart as admin" to see it.');
    }

    // 1. Sneaky folders --------------------------------------------------
    if (path != null && path.isNotEmpty) {
      if (folderSlash.contains(r'\$recycle.bin\')) {
        add(ReasonKind.folder, 'Hiding in the Recycle Bin',
            "Programs never run from the Recycle Bin. It's a classic malware hiding spot.", 60);
      } else if (_tempFolder.hasMatch(folderSlash)) {
        add(ReasonKind.folder, 'Runs from a Temp folder',
            'Temp folders are for throwaway files. Real apps rarely run from there, but malware often does.', 40);
      } else if (folderSlash.contains(r'\users\public\')) {
        add(ReasonKind.folder, 'Runs from the Public folder',
            'The shared Public folder is a favorite hiding place for malware.', 30);
      } else if (folderSlash.contains(r'\downloads\')) {
        add(ReasonKind.folder, 'Runs from Downloads',
            'This program runs straight from your Downloads folder instead of being installed.', 25);
      } else if (_hiddenWindowsFolder.hasMatch(folder)) {
        add(ReasonKind.folder, 'Hiding inside a Windows folder',
            'This Windows folder normally holds no programs. Malware hides here to look official.', 35);
      } else if (_personalFolder.hasMatch(folderSlash)) {
        add(ReasonKind.folder, 'Runs from a personal folder',
            'Programs usually live in Program Files, not in Desktop, Documents or Pictures.', 15);
      } else if (_oddRoot.hasMatch(folder)) {
        add(ReasonKind.folder, 'Odd location',
            'Sitting loose at the top of a drive or user folder is unusual for real apps.', 25);
      } else if (folderSlash.contains(r'\appdata\roaming\')) {
        add(ReasonKind.folder, 'Runs from AppData\\Roaming',
            "Some real apps live here, but it's also a popular malware hideout.", 10);
      }
    }

    // 2. Digital signature ---------------------------------------------
    if (file != null && file.exists) {
      switch (file.signature) {
        case SignatureStatus.notSigned:
          add(ReasonKind.signature, 'No digital signature',
              "Real companies usually sign their programs so you know who made them. This one isn't signed by anyone.", 25);
        case SignatureStatus.hashMismatch:
          add(ReasonKind.signature, 'Broken signature',
              'The file was changed after it was signed. It may have been tampered with.', 60);
        case SignatureStatus.notTrusted:
          add(ReasonKind.signature, 'Untrusted signature',
              "It's signed, but by someone Windows doesn't trust.", 30);
        case SignatureStatus.unknownError:
          add(ReasonKind.signature, 'Signature problem',
              "Windows couldn't confirm who made this program (self-made or expired certificate).", 20);
        case SignatureStatus.valid:
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
          'The program is running but its file was deleted or moved. Malware does this to hide.', 30);
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
            "This file appeared on your PC $when ago and isn't signed.", 10);
      }
    }

    // 4. Fake / look-alike Windows names --------------------------------
    if (name.isNotEmpty) {
      if (windowsSystemNames.contains(name) &&
          path != null &&
          path.isNotEmpty &&
          !inWindowsFolder) {
        add(ReasonKind.disguise, 'Pretends to be a Windows file',
            '"$rawName" is a Windows system file name, but the real one lives in C:\\Windows\\System32. This copy is somewhere else.',
            signed ? 35 : 70);
      } else {
        final twin = lookAlikeWindowsName(base);
        if (twin != null) {
          add(ReasonKind.disguise, 'Name looks like a Windows file',
              '"$rawName" looks a lot like "$twin", a real Windows file. That is a common trick to blend in.',
              signed ? 10 : 45);
        }
      }
    }

    // 5. Built-in tools that hackers misuse ------------------------------
    final toolPoints = abusedWindowsTools[name];
    if (toolPoints != null) {
      if (remoteIsPublic) {
        add(ReasonKind.tool, 'Windows tool talking to the internet',
            '"$rawName" is a built-in Windows tool that hackers often misuse to download or run bad things.',
            toolPoints);
      } else if (input.direction == Direction.listening &&
          !isLoopback(conn.localAddress)) {
        add(ReasonKind.tool, 'Windows tool waiting for connections',
            '"$rawName" is waiting for other computers to connect to it, which is unusual.',
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
          'The command that started it ${_joinNice(hits)}.',
          hits.length >= 3 ? 40 : 30);
    }

    // 7. Tricky file names -----------------------------------------------
    if (_fakeDocument.hasMatch(name)) {
      add(ReasonKind.file, 'Fake document name',
          '"$rawName" pretends to be a document or picture, but it is really a program.', 50);
    } else if (_oddProgramType.hasMatch(name)) {
      add(ReasonKind.file, 'Unusual program type',
          'Screensaver (.scr), .pif and .com files rarely need the internet. Malware uses them to look harmless.', 30);
    }
    if (!signed && looksRandomName(base)) {
      add(ReasonKind.file, 'Random-looking name',
          '"$rawName" looks like a random jumble of letters. Malware often uses names like this.', 15);
    }

    // 8. Ports and direction ---------------------------------------------
    switch (input.direction) {
      case Direction.outgoing:
        if (remoteIsPublic) {
          final port = suspiciousPorts[conn.remotePort];
          if (port != null) {
            add(ReasonKind.port, 'Suspicious port ${conn.remotePort}',
                'It talks on port ${conn.remotePort}: ${port.$1}.', port.$2);
          }
          if (const {135, 139, 445}.contains(conn.remotePort)) {
            add(ReasonKind.network, 'File sharing over the internet',
                'Windows file sharing (port ${conn.remotePort}) should never go out to the internet.', 25);
          }
        }
      case Direction.incoming:
        if (remoteIsPublic) {
          final door = remoteAccessPorts[conn.localPort];
          if (door != null) {
            add(ReasonKind.network, 'Someone is remote-accessing your PC',
                "A computer on the internet is connected to your $door door (port ${conn.localPort}). If you didn't set this up, disconnect!",
                40);
          } else if (!signed) {
            add(ReasonKind.network, 'Someone outside connected in',
                'A computer on the internet connected in to this program.', 15);
          }
          final port = suspiciousPorts[conn.localPort];
          if (port != null) {
            add(ReasonKind.port, 'Suspicious port ${conn.localPort}',
                'Outsiders reach it on port ${conn.localPort}: ${port.$1}.', port.$2);
          }
        }
      case Direction.listening:
        if (!isLoopback(conn.localAddress)) {
          final port = suspiciousPorts[conn.localPort];
          if (port != null) {
            add(ReasonKind.port, 'Waiting on port ${conn.localPort}',
                'It keeps port ${conn.localPort} open: ${port.$1}.', port.$2);
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
                "It's waiting for anyone on your network to connect to it.", 15);
          }
        }
      case Direction.local:
      case Direction.other:
        break;
    }

    // 9. Who is on the other end ------------------------------------------
    final geo = input.geo;
    if (geo != null) {
      if (geo.proxy) {
        add(ReasonKind.network, 'VPN / proxy / Tor address',
            'The other computer belongs to a VPN, proxy or Tor service, which hides who is really behind it.', 20);
      }
      final code = geo.countryCode?.toUpperCase();
      if (code != null && input.flaggedCountries.contains(code)) {
        add(ReasonKind.country, 'Flagged country: ${geo.country ?? code}',
            'You asked to be warned about connections to ${geo.country ?? code}.', 25);
      }
      if (geo.hosting && geo.owner != null) {
        notes.add('The other computer is in a data center (${geo.owner}).');
      }
    }

    reasons.sort((a, b) => b.points.compareTo(a.points));
    final score = math.min(100, reasons.fold<int>(0, (s, r) => s + r.points));
    return RiskAssessment(score: score, reasons: reasons, notes: notes);
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
