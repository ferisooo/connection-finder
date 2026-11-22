// Renders the app with demo data into PNG screenshots (for previews).
// Run with:  CF_SCREENSHOTS=1 flutter test --update-goldens test/screenshot_test.dart

import 'dart:io';

import 'package:connection_finder/main.dart';
import 'package:connection_finder/models.dart';
import 'package:connection_finder/services/ai_service.dart';
import 'package:connection_finder/services/demo_data.dart';
import 'package:connection_finder/services/settings.dart';
import 'package:connection_finder/state/app_controller.dart';
import 'package:connection_finder/theme.dart';
import 'package:connection_finder/ui/details_dialog.dart';
import 'package:connection_finder/ui/settings_screen.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

class FakeAi extends AiService {
  @override
  Future<Map<String, AiVerdict>> analyze(AiConfig config, List<AiItem> items) async {
    final file = ((items.first.facts['program'] as Map)['file'] as String).toLowerCase();
    final dangerous = file.contains('svch0st');
    return {
      items.first.id: AiVerdict(
        rating: dangerous ? AiRating.dangerous : AiRating.suspicious,
        confidence: dangerous ? 94 : 70,
        summary: dangerous
            ? 'Looks like malware pretending to be a Windows file.'
            : 'Probably a real script, but worth a quick check.',
        advice: dangerous
            ? 'Stop the program, then run a full scan with Windows Security.'
            : 'If you did not write this script, open the folder and have a look.',
        provider: 'Claude',
        model: config.model,
        time: DateTime(2026, 11, 22),
      ),
    };
  }
}

Future<void> _loadFont(String family, List<String> files) async {
  final loader = FontLoader(family);
  var any = false;
  for (final f in files) {
    final file = File(f);
    if (file.existsSync()) {
      loader.addFont(Future.value(ByteData.sublistView(file.readAsBytesSync())));
      any = true;
    }
  }
  if (any) await loader.load();
}

String _flutterRoot() {
  final env = Platform.environment['FLUTTER_ROOT'];
  if (env != null) return env;
  // .../flutter/bin/cache/artifacts/engine/<platform>/flutter_tester
  var dir = File(Platform.resolvedExecutable).parent;
  for (var i = 0; i < 6; i++) {
    if (File('${dir.path}/bin/flutter').existsSync()) return dir.path;
    dir = dir.parent;
  }
  return '/opt/flutter-sdk/flutter';
}

void main() {
  final enabled = Platform.environment.containsKey('CF_SCREENSHOTS');

  setUpAll(() async {
    if (!enabled) return;
    final fonts = '${_flutterRoot()}/bin/cache/artifacts/material_fonts';
    await _loadFont('Roboto', [
      for (final w in ['Regular', 'Medium', 'Bold', 'Black', 'Light'])
        '$fonts/Roboto-$w.ttf',
    ]);
    await _loadFont('MaterialIcons', ['$fonts/MaterialIcons-Regular.otf']);
    await _loadFont('Consolas', [
      '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
      '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
    ]);
  });

  Future<AppController> makeController() async {
    SharedPreferences.setMockInitialValues({
      'scan.auto': false,
      'ai.provider': 'anthropic',
    });
    final keys = MemoryKeyStore();
    await keys.write('apikey.anthropic', 'sk-ant-demo');
    final settings = AppSettings(keyStore: keys);
    await settings.load();
    return AppController(
      settings: settings,
      scanner: DemoScanner(delay: Duration.zero),
      geo: demoGeoLookup(),
      ai: FakeAi(),
    );
  }

  Future<void> settle(WidgetTester tester) async {
    final context = tester.element(find.byType(Scaffold).first);
    await tester.runAsync(
        () => precacheImage(const AssetImage('assets/icon.png'), context));
    await tester.pump();
    for (var i = 0; i < 8; i++) {
      await tester.pump(const Duration(milliseconds: 60));
    }
  }

  void setWindow(WidgetTester tester, {double height = 1180}) {
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = Size(1360 * 2, height * 2);
    addTearDown(tester.view.reset);
  }

  testWidgets('home screen', (tester) async {
    setWindow(tester);
    final controller = await makeController();
    await tester.pumpWidget(ConnectionFinderApp(controller: controller));
    for (var i = 0; i < 6; i++) {
      await tester.pump(const Duration(milliseconds: 50));
    }
    final rows = controller.visibleRows;
    await tester.runAsync(() async {
      await controller.askAi(rows.firstWhere((r) => r.fileName == 'svch0st.exe'));
      await controller.askAi(rows.firstWhere((r) => r.fileName == 'powershell.exe'));
    });
    await settle(tester);
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('screenshots/home.png'));
    await tester.pumpWidget(const SizedBox());
  }, skip: !enabled);

  testWidgets('details dialog', (tester) async {
    setWindow(tester, height: 1000);
    final controller = await makeController();
    await tester.pumpWidget(ConnectionFinderApp(controller: controller));
    for (var i = 0; i < 6; i++) {
      await tester.pump(const Duration(milliseconds: 50));
    }
    final row = controller.visibleRows.firstWhere((r) => r.fileName == 'svch0st.exe');
    await tester.runAsync(() => controller.askAi(row));
    final context = tester.element(find.byType(Scaffold).first);
    showDialog<void>(
      context: context,
      builder: (_) => DetailsDialog(
        controller: controller,
        initialRow: row,
        onAskAi: (_) {},
        onOpenFolder: (_) {},
        onCopyPath: (_) {},
        onStop: (_) {},
      ),
    );
    await settle(tester);
    expect(find.byType(DetailsDialog), findsOneWidget);
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('screenshots/details.png'));
    await tester.pumpWidget(const SizedBox());
  }, skip: !enabled);

  testWidgets('settings screen', (tester) async {
    setWindow(tester, height: 1300);
    final controller = await makeController();
    await tester.pumpWidget(MaterialApp(
      theme: buildTheme(),
      debugShowCheckedModeBanner: false,
      home: SettingsScreen(settings: controller.settings, ai: controller.ai),
    ));
    await settle(tester);
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('screenshots/settings.png'));
    await tester.pumpWidget(const SizedBox());
    controller.dispose();
  }, skip: !enabled);
}
