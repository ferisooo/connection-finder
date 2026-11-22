// Things the app can ask Windows to do: show a file in Explorer, stop a
// program, restart itself as administrator, open a web page.

import 'dart:io';

class ActionResult {
  const ActionResult(this.ok, this.message);
  final bool ok;
  final String message;
}

/// What Windows Defender said about one file.
enum DefenderOutcome { clean, threat, unavailable }

class DefenderResult {
  const DefenderResult(this.outcome, this.message);
  final DefenderOutcome outcome;
  final String message;
}

class SystemActions {
  const SystemActions();

  bool get supported => Platform.isWindows;

  static const _notWindows =
      ActionResult(false, 'This only works when the app runs on Windows.');

  /// Opens File Explorer with the program file selected.
  Future<ActionResult> revealInExplorer(String path) async {
    if (!supported) return _notWindows;
    if (!File(path).existsSync()) {
      final folder = Directory(File(path).parent.path);
      if (!folder.existsSync()) {
        return const ActionResult(false, "That folder doesn't exist anymore.");
      }
      await Process.start('explorer.exe', [folder.path]);
      return const ActionResult(true, 'Opened the folder.');
    }
    await Process.start('explorer.exe', ['/select,', path]);
    return const ActionResult(true, 'Opened the folder in File Explorer.');
  }

  /// Force-closes a program.
  Future<ActionResult> killProcess(int pid) async {
    if (!supported) return _notWindows;
    if (pid <= 4) {
      return const ActionResult(false, "Windows itself can't be stopped.");
    }
    final result =
        await Process.run('taskkill.exe', ['/PID', '$pid', '/F']);
    if (result.exitCode == 0) {
      return const ActionResult(true, 'Program stopped.');
    }
    final text = '${result.stdout}\n${result.stderr}'.toLowerCase();
    if (text.contains('access') && text.contains('denied')) {
      return const ActionResult(false,
          'Windows said no. Use "Restart as admin" and try again.');
    }
    if (text.contains('not found')) {
      return const ActionResult(true, 'That program already closed.');
    }
    return ActionResult(false, 'Could not stop it: ${result.stderr}'.trim());
  }

  /// Starts a new copy of this app with administrator rights. Returns true
  /// if the user said yes to the Windows prompt.
  Future<bool> relaunchAsAdmin() async {
    if (!supported) return false;
    final exe = Platform.resolvedExecutable.replaceAll("'", "''");
    final result = await Process.run('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "Start-Process -FilePath '$exe' -Verb RunAs",
    ]);
    return result.exitCode == 0;
  }

  /// File name of the harmless fake virus that ships next to the app.
  static const fakeVirusName = 'ConnectionFinder-FakeVirus.exe';

  /// Copies the harmless fake virus into the Temp folder and starts it, so
  /// people can see Connection Finder catch something suspicious.
  Future<ActionResult> startFakeVirus() async {
    if (!supported) return _notWindows;
    final appDir = File(Platform.resolvedExecutable).parent.path;
    final source = File('$appDir\\$fakeVirusName');
    if (!source.existsSync()) {
      return const ActionResult(false,
          "The fake virus isn't installed. Please install the newest version.");
    }
    final temp = Platform.environment['TEMP'] ?? Directory.systemTemp.path;
    final target = File('$temp\\$fakeVirusName');
    try {
      if (target.existsSync()) target.deleteSync();
      source.copySync(target.path);
    } catch (_) {
      // Still running from last time: that's fine, it is already visible.
      if (target.existsSync()) {
        return const ActionResult(true,
            'The fake virus is already running. Look for it in the list!');
      }
      return const ActionResult(false, "Couldn't copy the fake virus to the Temp folder.");
    }
    await Process.start(target.path, const [], mode: ProcessStartMode.detached);
    return const ActionResult(true,
        'Fake virus started! It should show up as "Danger!" in a few seconds. '
        'It stops by itself after 3 minutes.');
  }

  /// Finds Windows Defender's command-line scanner.
  String? _findDefender() {
    final data = Platform.environment['ProgramData'] ?? r'C:\ProgramData';
    final platform = Directory('$data\\Microsoft\\Windows Defender\\Platform');
    try {
      if (platform.existsSync()) {
        final versions = platform.listSync().whereType<Directory>().toList()
          ..sort((a, b) => b.path.compareTo(a.path));
        for (final v in versions) {
          final exe = File('${v.path}\\MpCmdRun.exe');
          if (exe.existsSync()) return exe.path;
        }
      }
    } catch (_) {}
    final pf = Platform.environment['ProgramFiles'] ?? r'C:\Program Files';
    final exe = File('$pf\\Windows Defender\\MpCmdRun.exe');
    return exe.existsSync() ? exe.path : null;
  }

  /// Asks Windows Defender to check one file for viruses. Connection Finder
  /// itself never scans or removes anything: that is the antivirus's job.
  Future<DefenderResult> scanWithDefender(String path) async {
    if (!supported) {
      return const DefenderResult(DefenderOutcome.unavailable,
          'This only works when the app runs on Windows.');
    }
    if (!File(path).existsSync()) {
      return const DefenderResult(
          DefenderOutcome.unavailable, "The file isn't there anymore.");
    }
    final exe = _findDefender();
    if (exe == null) {
      return const DefenderResult(DefenderOutcome.unavailable,
          "Couldn't find Windows Defender. Scan the file with your own antivirus instead.");
    }
    try {
      final r = await Process.run(
              exe, ['-Scan', '-ScanType', '3', '-File', path])
          .timeout(const Duration(minutes: 3));
      return readDefenderOutput(r.exitCode, '${r.stdout}\n${r.stderr}');
    } catch (_) {
      return const DefenderResult(DefenderOutcome.unavailable,
          "Windows Defender didn't answer. Right-click the file and choose \"Scan with Microsoft Defender\" instead.");
    }
  }

  /// Opens a web page in the default browser.
  Future<void> openUrl(String url) async {
    if (!supported || !url.startsWith('https://')) return;
    await Process.start('rundll32.exe', ['url.dll,FileProtocolHandler', url]);
  }
}

/// Turns the scanner's exit code and text into a plain answer.
DefenderResult readDefenderOutput(int exitCode, String output) {
  final text = output.toLowerCase();
  if (exitCode == 0) {
    return const DefenderResult(DefenderOutcome.clean,
        'Windows Defender found no known virus in this file. '
        "That's good, but a brand-new threat can still slip past, so keep the warnings in mind.");
  }
  final failed =
      text.contains('failed with hr') || text.contains('cmdtool: failed');
  if (exitCode == 2 && !failed) {
    return const DefenderResult(DefenderOutcome.threat,
        'Windows Defender found a threat in this file! Open Windows Security to see what it did about it.');
  }
  return const DefenderResult(DefenderOutcome.unavailable,
      "Windows Defender couldn't scan the file (another antivirus may be in charge). "
      'Right-click the file and scan it with your antivirus instead.');
}
