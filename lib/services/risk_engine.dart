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
    this.ancestors = const [],
    this.autostarts = const [],
    this.autostartIsNew = false,
    this.repeat,
    this.firstSeenRecently = false,
    this.badAddress = false,
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

  /// The programs that started this one: parent first, then grandparent...
  final List<ProcessInfo> ancestors;

  /// Ways this program starts by itself with Windows.
  final List<AutostartEntry> autostarts;

  /// One of those entries was added recently.
  final bool autostartIsNew;

  /// It keeps contacting this address on a timer.
  final RepeatInfo? repeat;

  /// Connection Finder saw this program on the network for the first time
  /// in the last day.
  final bool firstSeenRecently;

  /// The other side is on a public list of addresses reported for attacks.
  final bool badAddress;
}

/// Apps that open documents. They should not start command tools.
const Map<String, String> documentApps = {
  'winword.exe': 'Word',
  'excel.exe': 'Excel',
  'powerpnt.exe': 'PowerPoint',
  'outlook.exe': 'Outlook',
  'onenote.exe': 'OneNote',
  'msaccess.exe': 'Access',
  'mspub.exe': 'Publisher',
  'visio.exe': 'Visio',
  'wordpad.exe': 'WordPad',
  'acrord32.exe': 'Adobe Reader',
  'acrobat.exe': 'Adobe Acrobat',
  'foxitpdfreader.exe': 'Foxit PDF Reader',
  'foxitreader.exe': 'Foxit Reader',
  'sumatrapdf.exe': 'Sumatra PDF',
  'soffice.bin': 'LibreOffice',
  'soffice.exe': 'LibreOffice',
  'thunderbird.exe': 'Thunderbird',
};

/// Apps that let someone else see and control this PC.
const Map<String, String> remoteControlApps = {
  'anydesk.exe': 'AnyDesk',
  'teamviewer.exe': 'TeamViewer',
  'teamviewer_service.exe': 'TeamViewer',
  'tv_w32.exe': 'TeamViewer',
  'tv_x64.exe': 'TeamViewer',
  'rustdesk.exe': 'RustDesk',
  'screenconnect.clientservice.exe': 'ScreenConnect',
  'screenconnect.windowsclient.exe': 'ScreenConnect',
  'logmein.exe': 'LogMeIn',
  'lmiguardiansvc.exe': 'LogMeIn',
  'srserver.exe': 'Splashtop',
  'srservice.exe': 'Splashtop',
  'strwinclt.exe': 'Splashtop',
  'remoting_host.exe': 'Chrome Remote Desktop',
  'tvnserver.exe': 'TightVNC',
  'winvnc.exe': 'UltraVNC',
  'winvnc4.exe': 'RealVNC',
  'vncserver.exe': 'RealVNC',
  'rserver3.exe': 'Radmin',
  'aa_v3.exe': 'Ammyy Admin',
  'supremo.exe': 'Supremo',
  'supremoservice.exe': 'Supremo',
  'dwagent.exe': 'DWService',
  'dwagsvc.exe': 'DWService',
  'client32.exe': 'NetSupport Manager',
  'ateraagent.exe': 'Atera',
  'meshagent.exe': 'MeshCentral',
  'zaservice.exe': 'Zoho Assist',
  'getscreen.exe': 'Getscreen',
  'hoptodesk.exe': 'HopToDesk',
  'rutserv.exe': 'Remote Utilities',
  'rfusclient.exe': 'Remote Utilities',
  'quickassist.exe': 'Quick Assist',
  'msra.exe': 'Windows Remote Assistance',
  'parsecd.exe': 'Parsec',
};

/// Words in an IP owner's name that mean "remote-control service".
const Map<String, String> remoteControlOwners = {
  'teamviewer': 'TeamViewer',
  'anydesk': 'AnyDesk',
  'logmein': 'LogMeIn',
  'splashtop': 'Splashtop',
  'rustdesk': 'RustDesk',
  'screenconnect': 'ScreenConnect',
  'connectwise': 'ScreenConnect',
  'realvnc': 'RealVNC',
  'ngrok': 'ngrok',
};

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
    // Checked, and nobody vouches for it.
    final knownUnsigned = file != null && !signed;
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
    if (input.firstSeenRecently &&
        knownUnsigned &&
        !reasons.any((r) => r.title == 'Brand-new program')) {
      add(ReasonKind.file, 'New on your network',
          "Connection Finder hadn't seen this program go online before today.", 10);
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

    // 6b. Who started it ----------------------------------------------------
    if (!documentApps.containsKey(name)) {
      final chain = input.ancestors.take(4).toList();
      final docAt =
          chain.indexWhere((a) => documentApps.containsKey(a.fileName.toLowerCase()));
      if (docAt >= 0) {
        final doc = documentApps[chain[docAt].fileName.toLowerCase()]!;
        final selfIsTool = abusedWindowsTools.containsKey(name);
        String? toolBetween;
        for (final a in chain.take(docAt)) {
          if (abusedWindowsTools.containsKey(a.fileName.toLowerCase())) {
            toolBetween = a.fileName;
            break;
          }
        }
        if (selfIsTool) {
          add(ReasonKind.behavior, 'Started by a document app',
              '$doc started "$rawName", which then used the network. Documents should never do that. It often means a booby-trapped file.',
              45);
        } else if (toolBetween != null) {
          add(ReasonKind.behavior, 'Started by a document app',
              '$doc started "$toolBetween", which started this program. Documents should never do that. It often means a booby-trapped file.',
              45);
        } else if (knownUnsigned) {
          add(ReasonKind.behavior, 'Started by $doc',
              "$doc started this unsigned program. Documents normally don't start programs.",
              30);
        }
      }
    }

    // 6c. Starts by itself with Windows --------------------------------------
    if (input.autostarts.isNotEmpty) {
      final e = input.autostarts.first;
      final how = 'a ${e.where} entry called "${e.shortName}"';
      if (abusedWindowsTools.containsKey(name) && e.kind != 'service') {
        add(ReasonKind.startup, 'Windows tool set to start by itself',
            'Every time Windows starts, $how runs "$rawName". Normal apps rarely do that.',
            25);
      } else if (knownUnsigned && !inWindowsFolder) {
        if (input.autostartIsNew) {
          add(ReasonKind.startup, 'Just set itself to start with Windows',
              'It was recently added to start every time you turn on your PC ($how). Malware does this to come back after a restart.',
              25);
        } else {
          add(ReasonKind.startup, 'Starts by itself with Windows',
              "It runs every time you turn on your PC ($how) and isn't signed.",
              10);
        }
      }
    }

    // 6d. Remote control -----------------------------------------------------
    final remoteApp = remoteControlApps[name];
    final onNetwork = input.direction == Direction.outgoing ||
        input.direction == Direction.incoming ||
        (input.direction == Direction.listening &&
            !isLoopback(conn.localAddress));
    if (remoteApp != null && onNetwork) {
      add(ReasonKind.remote, 'Remote-control app is running',
          '$remoteApp lets another person see and control this PC. Fine if you set it up yourself. If a stranger asked you to install it, stop it now.',
          20);
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
          // Keeps calling the same address on a timer.
          final repeat = input.repeat;
          if (!incoming && repeat != null) {
            if (knownUnsigned) {
              add(ReasonKind.network, 'Calls the same address like clockwork',
                  'It contacted $remote ${repeat.count} times, about every ${repeat.seconds} seconds. Malware "phones home" on a timer like this, though some updaters do too.',
                  15);
            } else {
              notes.add('It contacts $remote about every ${repeat.seconds} seconds. Many normal apps do this.');
            }
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
          final door = incoming ? remoteAccessPorts[conn.localPort] : null;
          if (door != null) {
            add(ReasonKind.remote, 'Remote access from your network',
                "A device on your network ($remote) is connected to your $door. If that isn't you, stop it.",
                25);
          } else {
            good.add('Talks to your home network');
          }
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
          if (door != null && conn.isTcp && remoteApp == null) {
            add(ReasonKind.remote, '$door is switched on',
                'Other computers can log in to this PC through it. If you never use it, turn it off in Windows Settings.',
                20);
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
        // Big cloud networks (Amazon CloudFront, Azure, Cloudflare...) are
        // often marked as "proxy" because they pass traffic along for
        // websites. That's normal for signed apps, so it only counts for
        // unsigned programs talking to an unknown proxy.
        if (signed || isBigCloudOwner(geo.owner)) {
          notes.add('The other side is a cloud or proxy network (${geo.owner ?? 'unknown owner'}). '
              'That is normal for well-known apps.');
        } else {
          add(ReasonKind.network, 'Hidden behind a VPN or Tor',
              'The other side hides who it really is.', 20);
        }
      }
      final code = geo.countryCode?.toUpperCase();
      if (code != null && input.flaggedCountries.contains(code)) {
        add(ReasonKind.country, 'Flagged country: ${geo.country ?? code}',
            'You asked to be warned about ${geo.country ?? code}.', 25);
      }
      if (geo.hosting && geo.owner != null) {
        notes.add('The other computer is in a data center (${geo.owner}).');
      }
      // An ordinary program talking to a remote-control company.
      final owner = geo.owner?.toLowerCase() ?? '';
      if (remoteApp == null && owner.isNotEmpty) {
        for (final e in remoteControlOwners.entries) {
          if (owner.contains(e.key)) {
            add(ReasonKind.remote, 'Talks to a remote-control service',
                'The other side belongs to ${e.value}, a service for controlling PCs from far away. Unusual for this program.',
                20);
            break;
          }
        }
      }
    }

    // 10. Addresses with a bad reputation ------------------------------------
    if (input.badAddress && remote.isNotEmpty) {
      if (input.direction == Direction.incoming) {
        add(ReasonKind.network, 'Reported address connected in',
            '$remote is on a public list of addresses reported for attacks, and it connected to this program.',
            30);
      } else if (!signed) {
        add(ReasonKind.network, 'Talks to a reported address',
            '$remote is on a public list of addresses reported for attacks.', 40);
      } else {
        notes.add('$remote is on a public list of addresses reported for attacks. The program itself is signed.');
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

const List<String> _bigCloudNames = [
  'amazon',
  'aws',
  'cloudfront',
  'microsoft',
  'azure',
  'google',
  'cloudflare',
  'akamai',
  'fastly',
  'apple',
  'facebook',
  'meta platforms',
];

/// Is this IP owner one of the big, well-known cloud / CDN companies?
bool isBigCloudOwner(String? owner) {
  final o = owner?.toLowerCase();
  if (o == null || o.isEmpty) return false;
  return _bigCloudNames.any(o.contains);
}
