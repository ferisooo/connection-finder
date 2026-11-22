// Connection Finder: shows which IPs are connected to this PC, which program
// (folder + file) is behind each one, and warns about suspicious ones.

import 'dart:io';

import 'package:material_ui/material_ui.dart';

import 'services/ai_service.dart';
import 'services/demo_data.dart';
import 'services/geo_service.dart';
import 'services/scanner.dart';
import 'services/settings.dart';
import 'state/app_controller.dart';
import 'theme.dart';
import 'ui/home_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final settings = AppSettings();
  await settings.load();

  final onWindows = Platform.isWindows;
  final controller = AppController(
    settings: settings,
    scanner: onWindows ? WindowsScanner() : DemoScanner(),
    geo: onWindows ? IpApiGeoLookup() : demoGeoLookup(),
    ai: AiService(),
  );

  runApp(ConnectionFinderApp(controller: controller));
}

class ConnectionFinderApp extends StatefulWidget {
  const ConnectionFinderApp({super.key, required this.controller});

  final AppController controller;

  @override
  State<ConnectionFinderApp> createState() => _ConnectionFinderAppState();
}

class _ConnectionFinderAppState extends State<ConnectionFinderApp> {
  @override
  void initState() {
    super.initState();
    widget.controller.start();
  }

  @override
  void dispose() {
    widget.controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Connection Finder',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(),
      home: HomeScreen(controller: widget.controller),
    );
  }
}
