/// The app's version, filled in by the GitHub build
/// (`--dart-define=APP_VERSION=...`). Shows "dev" for local builds.
const String appVersion =
    String.fromEnvironment('APP_VERSION', defaultValue: 'dev');
