// Things the app can ask Windows to do: show a file in Explorer, stop a
// program, restart itself as administrator, open a web page.

import 'dart:io';

class ActionResult {
  const ActionResult(this.ok, this.message);
  final bool ok;
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
        'It stops by itself after 2 minutes.');
  }

  /// Opens a web page in the default browser.
  Future<void> openUrl(String url) async {
    if (!supported || !url.startsWith('https://')) return;
    await Process.start('rundll32.exe', ['url.dll,FileProtocolHandler', url]);
  }
}
