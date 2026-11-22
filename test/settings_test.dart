import 'package:connection_finder/services/ai_service.dart';
import 'package:connection_finder/services/settings.dart';
import 'package:connection_finder/theme.dart';
import 'package:connection_finder/ui/settings_screen.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  late AppSettings settings;
  var clipboard = '';

  Future<void> open(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1360, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    SharedPreferences.setMockInitialValues({'ai.provider': 'deepseek'});
    settings = AppSettings(keyStore: MemoryKeyStore());
    await settings.load();
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.getData') return {'text': clipboard};
      if (call.method == 'Clipboard.hasStrings') return {'value': clipboard.isNotEmpty};
      return null;
    });
    await tester.pumpWidget(MaterialApp(
        theme: buildTheme(),
        home: SettingsScreen(settings: settings, ai: AiService())));
    await tester.pump();
  }

  testWidgets('"Paste key" pastes, cleans and saves the key in one click', (tester) async {
    await open(tester);
    clipboard = '  "sk-abcdef1234567890"\r\n';
    await tester.tap(find.text('Paste key'));
    await tester.pump(const Duration(milliseconds: 100));
    expect(settings.keyFor(AiProvider.deepseek), 'sk-abcdef1234567890');
    expect(settings.aiReady, isTrue);
    expect(find.text('Saved: sk-ab…7890'), findsOneWidget);
    await tester.pump(const Duration(seconds: 5)); // let the toast finish
  });

  testWidgets('Ctrl+V works and the key saves by itself', (tester) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.windows;
    await open(tester);
    clipboard = 'sk-typed0000000000';
    await tester.tap(find.byType(TextField).first);
    await tester.pump();
    await tester.sendKeyDownEvent(LogicalKeyboardKey.controlLeft);
    await tester.sendKeyEvent(LogicalKeyboardKey.keyV);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.controlLeft);
    await tester.pump(const Duration(milliseconds: 600)); // auto-save delay
    expect(settings.keyFor(AiProvider.deepseek), 'sk-typed0000000000');
    debugDefaultTargetPlatformOverride = null;
  });

  test('cleanApiKey and maskApiKey', () {
    expect(cleanApiKey(' Bearer sk-1 23\n'), 'sk-123');
    expect(maskApiKey('sk-abcdef1234567890'), 'sk-ab…7890');
  });
}
