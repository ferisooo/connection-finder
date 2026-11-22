// Makes sure the screens fit at the smallest window size (960 x 640) without
// anything overflowing, and that every piece of text is at least 15px.
// Uses real fonts so text widths are realistic.

import 'dart:io';

import 'package:connection_finder/main.dart';
import 'package:connection_finder/services/ai_service.dart';
import 'package:connection_finder/services/demo_data.dart';
import 'package:connection_finder/services/settings.dart';
import 'package:connection_finder/state/app_controller.dart';
import 'package:connection_finder/theme.dart';
import 'package:connection_finder/ui/details_dialog.dart';
import 'package:connection_finder/ui/home_screen.dart';
import 'package:connection_finder/ui/settings_screen.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

String? _flutterRoot() {
  final env = Platform.environment['FLUTTER_ROOT'];
  if (env != null && Directory(env).existsSync()) return env;
  var dir = File(Platform.resolvedExecutable).parent;
  final sep = Platform.pathSeparator;
  for (var i = 0; i < 7; i++) {
    if (Directory('${dir.path}${sep}bin').existsSync() &&
        Directory('${dir.path}${sep}packages${sep}flutter').existsSync()) {
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

/// Every visible piece of text smaller than 15px (icons don't count).
List<String> textsUnder15(WidgetTester tester) {
  final out = <String>[];
  for (final p in tester.allRenderObjects.whereType<RenderParagraph>()) {
    void visit(InlineSpan span, TextStyle? inherited) {
      final style = inherited?.merge(span.style) ?? span.style;
      if (span is TextSpan) {
        final family = style?.fontFamily ?? '';
        final size = style?.fontSize;
        final text = span.text;
        if (text != null &&
            text.trim().isNotEmpty &&
            !family.contains('MaterialIcons') &&
            size != null &&
            size < 15) {
          out.add('"${text.trim()}" is ${size}px');
        }
        for (final child in span.children ?? const <InlineSpan>[]) {
          visit(child, style);
        }
      }
    }

    visit(p.text, null);
  }
  return out.toSet().toList();
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

  Future<void> settle(WidgetTester tester) async {
    await tester.pump();
    for (var i = 0; i < 6; i++) {
      await tester.pump(const Duration(milliseconds: 60));
    }
  }

  testWidgets('the 15px checker really catches small text', (tester) async {
    await tester.pumpWidget(MaterialApp(
      theme: buildTheme(),
      home: const Column(children: [
        Text('big enough'),
        Text('tiny', style: TextStyle(fontSize: 12)),
      ]),
    ));
    expect(textsUnder15(tester), ['"tiny" is 12.0px']);
  });

  testWidgets('home, details and help fit and use 15px+ text', (tester) async {
    if (!fontsReady) {
      markTestSkipped('fonts not found');
      return;
    }
    smallWindow(tester);
    final controller = await makeController();
    await tester.pumpWidget(ConnectionFinderApp(controller: controller));
    await settle(tester);
    expect(controller.visibleGroups, isNotEmpty);
    expect(tester.takeException(), isNull);
    expect(textsUnder15(tester), isEmpty);

    // Scroll through every card so each one gets laid out.
    final list = find.byType(Scrollable).last;
    for (var i = 0; i < 12; i++) {
      await tester.drag(list, const Offset(0, -300));
      await tester.pump();
      expect(tester.takeException(), isNull);
      expect(textsUnder15(tester), isEmpty);
    }

    // Details of every program, with the technical part opened.
    final context = tester.element(find.byType(Scaffold).first);
    for (final group in controller.visibleGroups) {
      showDialog<void>(
        context: context,
        builder: (_) => DetailsDialog(
          controller: controller,
          initialGroup: group,
          onAskAi: (_) {},
          onOpenFolder: (_) {},
          onCopy: (_) {},
          onStop: (_) {},
        ),
      );
      await settle(tester);
      expect(find.byType(DetailsDialog), findsOneWidget);
      await tester.scrollUntilVisible(find.text('Technical details'), 200,
          scrollable: find.descendant(
              of: find.byType(DetailsDialog), matching: find.byType(Scrollable)).first);
      await tester.tap(find.text('Technical details'));
      await settle(tester);
      expect(tester.takeException(), isNull, reason: group.fileName);
      expect(textsUnder15(tester), isEmpty, reason: group.fileName);
      Navigator.of(tester.element(find.byType(DetailsDialog))).pop();
      await settle(tester);
    }

    // Help.
    showDialog<void>(context: context, builder: (_) => const HelpDialog());
    await settle(tester);
    expect(tester.takeException(), isNull);
    expect(textsUnder15(tester), isEmpty);

    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('settings fit and use 15px+ text', (tester) async {
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
      await settle(tester);
      final list = find.byType(Scrollable).first;
      for (var i = 0; i < 8; i++) {
        expect(tester.takeException(), isNull);
        expect(textsUnder15(tester), isEmpty);
        await tester.drag(list, const Offset(0, -300));
        await tester.pump();
      }
    }
    await tester.pumpWidget(const SizedBox());
    controller.dispose();
  });
}
