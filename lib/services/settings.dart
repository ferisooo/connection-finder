// Remembers the user's choices. API keys go into the Windows Credential
// Manager (via flutter_secure_storage), everything else into a small
// preferences file.

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'ai_service.dart';

abstract class KeyStore {
  Future<String?> read(String key);
  Future<void> write(String key, String? value);
}

class SecureKeyStore implements KeyStore {
  const SecureKeyStore();

  static const FlutterSecureStorage _storage = FlutterSecureStorage();

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String? value) async {
    if (value == null || value.isEmpty) {
      await _storage.delete(key: key);
    } else {
      await _storage.write(key: key, value: value);
    }
  }
}

/// Keeps keys in memory only (used by tests and as a fallback).
class MemoryKeyStore implements KeyStore {
  final Map<String, String> _values = {};

  @override
  Future<String?> read(String key) async => _values[key];

  @override
  Future<void> write(String key, String? value) async {
    if (value == null || value.isEmpty) {
      _values.remove(key);
    } else {
      _values[key] = value;
    }
  }
}

class AppSettings extends ChangeNotifier {
  AppSettings({KeyStore? keyStore})
      : _keyStore = keyStore ?? const SecureKeyStore();

  final KeyStore _keyStore;
  SharedPreferences? _prefs;

  static const List<int> refreshChoices = [3, 5, 10, 30];

  bool _loaded = false;
  String? _storageWarning;
  AiProvider _provider = AiProvider.openai;
  final Map<AiProvider, String> _models = {};
  final Map<AiProvider, String> _apiKeys = {};
  String _customUrl = 'http://localhost:11434/v1/chat/completions';
  bool _autoRefresh = true;
  int _refreshSeconds = 5;
  bool _geoLookup = true;
  bool _showLocal = false;
  Set<String> _flaggedCountries = {};

  bool get loaded => _loaded;

  /// Set when API keys can't be stored safely on this PC.
  String? get storageWarning => _storageWarning;
  AiProvider get provider => _provider;
  String get customUrl => _customUrl;
  bool get autoRefresh => _autoRefresh;
  int get refreshSeconds => _refreshSeconds;
  bool get geoLookup => _geoLookup;

  /// Show connections that stay inside this PC and closing connections.
  bool get showLocal => _showLocal;
  Set<String> get flaggedCountries => Set.unmodifiable(_flaggedCountries);

  String modelFor(AiProvider p) {
    final m = _models[p]?.trim();
    return (m == null || m.isEmpty) ? p.defaultModel : m;
  }

  String keyFor(AiProvider p) => _apiKeys[p] ?? '';
  bool hasKey(AiProvider p) => keyFor(p).isNotEmpty;

  AiConfig get aiConfig => AiConfig(
        provider: _provider,
        apiKey: keyFor(_provider),
        model: modelFor(_provider),
        customUrl: _customUrl,
      );

  /// True when the AI helper has everything it needs.
  bool get aiReady {
    if (_provider.needsKey && !hasKey(_provider)) return false;
    if (modelFor(_provider).isEmpty) return false;
    if (_provider == AiProvider.custom && _customUrl.trim().isEmpty) {
      return false;
    }
    return true;
  }

  Future<void> load() async {
    try {
      _prefs = await SharedPreferences.getInstance();
    } catch (_) {
      _prefs = null;
    }
    final p = _prefs;
    if (p != null) {
      _provider = AiProvider.fromName(p.getString('ai.provider'));
      for (final pr in AiProvider.values) {
        final m = p.getString('ai.model.${pr.name}');
        if (m != null && m.trim().isNotEmpty) _models[pr] = m;
      }
      _customUrl = p.getString('ai.customUrl') ?? _customUrl;
      _autoRefresh = p.getBool('scan.auto') ?? true;
      final secs = p.getInt('scan.seconds') ?? 5;
      _refreshSeconds = refreshChoices.contains(secs) ? secs : 5;
      _geoLookup = p.getBool('geo.enabled') ?? true;
      _showLocal = p.getBool('view.showLocal') ?? false;
      _flaggedCountries = (p.getStringList('geo.flagged') ?? const []).toSet();
    }
    for (final pr in AiProvider.values) {
      try {
        final k = await _keyStore.read('apikey.${pr.name}');
        if (k != null && k.isNotEmpty) _apiKeys[pr] = k;
      } catch (_) {
        _storageWarning =
            "Couldn't open the safe key storage, so API keys won't be remembered after closing the app.";
      }
    }
    _loaded = true;
    notifyListeners();
  }

  set provider(AiProvider value) {
    if (value == _provider) return;
    _provider = value;
    _prefs?.setString('ai.provider', value.name);
    notifyListeners();
  }

  void setModel(AiProvider p, String model) {
    _models[p] = model.trim();
    _prefs?.setString('ai.model.${p.name}', model.trim());
    notifyListeners();
  }

  Future<void> setApiKey(AiProvider p, String key) async {
    final clean = key.trim();
    if (clean.isEmpty) {
      _apiKeys.remove(p);
    } else {
      _apiKeys[p] = clean;
    }
    notifyListeners();
    try {
      await _keyStore.write('apikey.${p.name}', clean);
    } catch (_) {
      _storageWarning =
          "Couldn't save the key safely, so it will be forgotten when the app closes.";
      notifyListeners();
    }
  }

  set customUrl(String value) {
    _customUrl = value.trim();
    _prefs?.setString('ai.customUrl', _customUrl);
    notifyListeners();
  }

  set autoRefresh(bool value) {
    _autoRefresh = value;
    _prefs?.setBool('scan.auto', value);
    notifyListeners();
  }

  set refreshSeconds(int value) {
    _refreshSeconds = value;
    _prefs?.setInt('scan.seconds', value);
    notifyListeners();
  }

  set geoLookup(bool value) {
    _geoLookup = value;
    _prefs?.setBool('geo.enabled', value);
    notifyListeners();
  }

  set showLocal(bool value) {
    _showLocal = value;
    _prefs?.setBool('view.showLocal', value);
    notifyListeners();
  }

  /// Accepts text like "RU, CN kp" and keeps valid 2-letter codes.
  void setFlaggedCountriesText(String text) {
    _flaggedCountries = parseCountryCodes(text);
    _prefs?.setStringList('geo.flagged', _flaggedCountries.toList()..sort());
    notifyListeners();
  }
}

Set<String> parseCountryCodes(String text) => text
    .split(RegExp(r'[^A-Za-z]+'))
    .where((t) => t.length == 2)
    .map((t) => t.toUpperCase())
    .toSet();
