import 'package:connection_finder/services/ai_service.dart';
import 'package:connection_finder/services/demo_data.dart';
import 'package:connection_finder/services/settings.dart';
import 'package:connection_finder/state/app_controller.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  test('trusted programs stay hidden; risky and unchecked ones are shown', () async {
    SharedPreferences.setMockInitialValues({'scan.auto': false});
    final settings = AppSettings(keyStore: MemoryKeyStore());
    await settings.load();
    final c = AppController(
      settings: settings,
      scanner: DemoScanner(delay: Duration.zero),
      geo: demoGeoLookup(),
      ai: AiService(),
    );
    await c.refresh();
    await Future<void>.delayed(const Duration(milliseconds: 50)); // file checks

    final shown = c.visibleGroups.map((g) => g.fileName).toSet();
    expect(shown, containsAll(['svch0st.exe', 'invoice_2026.pdf.exe', 'lsass.exe']));
    expect(shown, isNot(contains('chrome.exe')));
    expect(shown, isNot(contains('svchost.exe')));
    expect(shown, isNot(contains('System')));

    final lsass = c.groups.firstWhere((g) => g.fileName == 'lsass.exe');
    expect(c.statusOf(lsass), ProgramStatus.unchecked);
    final chrome = c.groups.firstWhere((g) => g.fileName == 'chrome.exe');
    expect(c.statusOf(chrome), ProgramStatus.trusted);

    expect(c.stats.uncheckedPrograms, 1);
    expect(c.stats.trustedNames, isNotEmpty);
    c.dispose();
  });
}
