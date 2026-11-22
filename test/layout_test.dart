// Makes sure the screens fit at the smallest window size (960 x 640) without
// anything overflowing. Uses real fonts so text widths are realistic.

import 'dart:io';

import 'package:connection_finder/main.dart';
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

String? _flutterRoot() {
  final env = Platform.environment['FLUTTER_ROOT'];
  if (env != null && Directory(env).existsSync()) return env;
  var dir = File(Platform.resolvedExecutable).parent;
  for (var i = 0; i < 7; i++) {
    if (Directory('${dir.path}${Platform.pathSeparator}bin').existsSync() &&
        Directory('${dir.path}${Platform.pathSeparator}packages${Platform.pathSeparator}flutter').existsSync()) {
      return dir.path;
    }
    dir = dir.parent;
  }
  return null;
}

Future<bool> _loadFont(String family, List<String> files) async {
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
  return any;
}

void main() {
  var fontsReady = false;

  setUpAll(() async {
    final root = _flutterRoot();
    if (root == null) return;
    final sep = Platform.pathSeparator;
    final fonts = '$root${sep}bin${sep}cache${sep}artifacts${sep}material_fonts';
    fontsReady = await _loadFont('Roboto', [
      for (final w in ['Regular', 'Medium', 'Bold', 'Black'])
        '$fonts${sep}Roboto-$w.ttf',
    ]);
    await _loadFont('MaterialIcons', ['$fonts${sep}MaterialIcons-Regular.otf']);
    await _loadFont('Consolas', [
      r'C:\Windows\Fonts\consola.ttf',
      '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
    ]);
  });

  Future<AppController> makeController() async {
    SharedPreferences.setMockInitialValues({'scan.auto': false});
    final settings = AppSettings(keyStore: MemoryKeyStore());
    await settings.load();
    return AppController(
      settings: settings,
      scanner: DemoScanner(delay: Duration.zero),
      geo: demoGeoLookup(),
      ai: AiService(),
    );
  }

  void smallWindow(WidgetTester tester) {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(960, 640);
    addTearDown(tester.view.reset);
  }

  testWidgets('home and details fit in the smallest window', (tester) async {
    if (!fontsReady) {
      markTestSkipped('fonts not found');
      return;
    }
    smallWindow(tester);
    final controller = await makeController();
    await tester.pumpWidget(ConnectionFinderApp(controller: controller));
    for (var i = 0; i < 6; i++) {
      await tester.pump(const Duration(milliseconds: 50));
    }
    expect(controller.visibleRows, isNotEmpty);
    expect(tester.takeException(), isNull);

    // Scroll through every card so each one gets laid out.
    final list = find.byType(Scrollable).last;
    for (var i = 0; i < 12; i++) {
      await tester.drag(list, const Offset(0, -300));
      await tester.pump();
      expect(tester.takeException(), isNull);
    }

    final row = controller.visibleRows.first;
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
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400));
    expect(find.byType(DetailsDialog), findsOneWidget);
    expect(tester.takeException(), isNull);

    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('settings fit in the smallest window', (tester) async {
    if (!fontsReady) {
      markTestSkipped('fonts not found');
      return;
    }
    smallWindow(tester);
    final controller = await makeController();
    for (final provider in [AiProvider.openai, AiProvider.custom]) {
      controller.settings.provider = provider;
      await tester.pumpWidget(MaterialApp(
        theme: buildTheme(),
        home: SettingsScreen(settings: controller.settings, ai: controller.ai),
      ));
      await tester.pump(const Duration(milliseconds: 100));
      expect(tester.takeException(), isNull);
    }
    await tester.pumpWidget(const SizedBox());
    controller.dispose();
  });
}
