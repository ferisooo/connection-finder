// Sends connection details to the user's own AI provider (with their API key)
// and gets back a simple safe / suspicious / dangerous opinion.

import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models.dart';
import 'ip_utils.dart';

enum AiApiStyle { openai, anthropic, gemini }

enum AiProvider {
  openai(
    label: 'OpenAI (ChatGPT)',
    shortName: 'ChatGPT',
    defaultModel: 'gpt-5-mini',
    endpoint: 'https://api.openai.com/v1/chat/completions',
    style: AiApiStyle.openai,
    keyHint: 'sk-...',
    keyPage: 'https://platform.openai.com/api-keys',
  ),
  anthropic(
    label: 'Anthropic (Claude)',
    shortName: 'Claude',
    defaultModel: 'claude-opus-5-5',
    endpoint: 'https://api.anthropic.com/v1/messages',
    style: AiApiStyle.anthropic,
    keyHint: 'sk-ant-...',
    keyPage: 'https://console.anthropic.com/settings/keys',
  ),
  gemini(
    label: 'Google Gemini',
    shortName: 'Gemini',
    defaultModel: 'gemini-flash-latest',
    endpoint: 'https://generativelanguage.googleapis.com/v1beta',
    style: AiApiStyle.gemini,
    keyHint: 'AIza...',
    keyPage: 'https://aistudio.google.com/apikey',
  ),
  deepseek(
    label: 'DeepSeek',
    shortName: 'DeepSeek',
    defaultModel: 'deepseek-chat',
    endpoint: 'https://api.deepseek.com/chat/completions',
    style: AiApiStyle.openai,
    keyHint: 'sk-...',
    keyPage: 'https://platform.deepseek.com/api_keys',
  ),
  xai(
    label: 'xAI (Grok)',
    shortName: 'Grok',
    defaultModel: 'grok-4.7',
    endpoint: 'https://api.x.ai/v1/chat/completions',
    style: AiApiStyle.openai,
    keyHint: 'xai-...',
    keyPage: 'https://console.x.ai',
  ),
  mistral(
    label: 'Mistral',
    shortName: 'Mistral',
    defaultModel: 'mistral-small-latest',
    endpoint: 'https://api.mistral.ai/v1/chat/completions',
    style: AiApiStyle.openai,
    keyHint: 'your Mistral key',
    keyPage: 'https://console.mistral.ai/api-keys',
  ),
  openrouter(
    label: 'OpenRouter (many AIs, one key)',
    shortName: 'OpenRouter',
    defaultModel: 'openrouter/auto',
    endpoint: 'https://openrouter.ai/api/v1/chat/completions',
    style: AiApiStyle.openai,
    keyHint: 'sk-or-...',
    keyPage: 'https://openrouter.ai/keys',
  ),
  custom(
    label: 'Custom / local AI (OpenAI-compatible)',
    shortName: 'Custom AI',
    defaultModel: '',
    endpoint: '',
    style: AiApiStyle.openai,
    keyHint: 'optional for local AIs',
    keyPage: '',
  );

  const AiProvider({
    required this.label,
    required this.shortName,
    required this.defaultModel,
    required this.endpoint,
    required this.style,
    required this.keyHint,
    required this.keyPage,
  });

  final String label;
  final String shortName;
  final String defaultModel;
  final String endpoint;
  final AiApiStyle style;
  final String keyHint;
  final String keyPage;

  bool get needsKey => this != AiProvider.custom;

  static AiProvider fromName(String? name) => AiProvider.values
      .firstWhere((p) => p.name == name, orElse: () => AiProvider.openai);
}

class AiConfig {
  const AiConfig({
    required this.provider,
    required this.apiKey,
    required this.model,
    this.customUrl = '',
  });

  final AiProvider provider;
  final String apiKey;
  final String model;
  final String customUrl;

  String get chatUrl =>
      provider == AiProvider.custom ? customUrl.trim() : provider.endpoint;
}

class AiException implements Exception {
  AiException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// One connection to ask about. [facts] is plain JSON-able data.
class AiItem {
  const AiItem(this.id, this.facts);
  final String id;
  final Map<String, Object?> facts;
}

/// Claude models that accept `output_config.effort`.
final RegExp _claudeEffortModels =
    RegExp(r'^claude-(opus-(4-[678]|5)|sonnet-(4-6|5)|haiku-5|fable|mythos)');

/// Claude models that support server-side refusal fallbacks.
final RegExp _claudeFallbackModels =
    RegExp(r'^claude-(fable-5-[12]|mythos-5-[12]|opus-5|sonnet-5-5)');

class AiService {
  AiService({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;

  static const String systemPrompt = '''
You are the security helper inside "Connection Finder", a Windows app that shows which programs on the PC use the network.
For each program you get its file name and folder, its digital signature, its start-up command, its network connections (remote IP with owner and country, ports, direction), and the warning clues and good signs the app already found.
Judge each program as "safe", "suspicious" or "dangerous".
- Well-known, properly signed software running from its normal folder is usually safe, even if it talks to many servers.
- Programs in Temp, Downloads or hidden folders, unsigned files, fake Windows names, hidden or encoded commands, hacker or remote-control ports, and Tor/proxy IPs raise suspicion.
- Be calm and accurate. Only say "dangerous" when there are real signs.
Write for a beginner: short, friendly, no jargon.
Reply with ONLY this JSON, no markdown and no other text:
{"results":[{"id":"<the id you were given>","verdict":"safe|suspicious|dangerous","confidence":<0-100>,"summary":"<at most 15 words>","advice":"<1-2 short sentences on what to do>"}]}''';

  /// Asks the AI about [items] and returns a verdict per item id.
  Future<Map<String, AiVerdict>> analyze(
      AiConfig config, List<AiItem> items) async {
    final payload = [
      for (final item in items) {'id': item.id, ...item.facts},
    ];
    final user = 'Check these ${items.length} program(s) on my Windows PC:\n'
        '${const JsonEncoder.withIndent(' ').convert(payload)}';
    final text = await complete(config,
        system: systemPrompt, user: user, wantJson: true);
    return parseVerdicts(
      text,
      [for (final i in items) i.id],
      provider: config.provider.shortName,
      model: config.model,
    );
  }

  /// Sends a tiny message to check that the key and model work.
  Future<String> testConnection(AiConfig config) async {
    final reply = await complete(
      config,
      system: 'You are a connection test. Reply with exactly the word OK.',
      user: 'Are you there?',
      maxTokens: 4000,
    );
    final clean = reply.trim();
    return clean.length > 80 ? '${clean.substring(0, 80)}...' : clean;
  }

  /// Raw text answer from the provider.
  Future<String> complete(
    AiConfig config, {
    required String system,
    required String user,
    int maxTokens = 16000,
    bool wantJson = false,
  }) async {
    _check(config);
    switch (config.provider.style) {
      case AiApiStyle.anthropic:
        return _anthropic(config, system, user, maxTokens);
      case AiApiStyle.gemini:
        return _gemini(config, system, user, wantJson);
      case AiApiStyle.openai:
        return _openAiCompatible(config, system, user);
    }
  }

  void _check(AiConfig config) {
    if (config.provider.needsKey && config.apiKey.trim().isEmpty) {
      throw AiException(
          'Add your ${config.provider.shortName} API key in Settings first.');
    }
    if (config.model.trim().isEmpty) {
      throw AiException('Choose an AI model in Settings first.');
    }
    if (config.chatUrl.isEmpty || Uri.tryParse(config.chatUrl) == null) {
      throw AiException('Enter the address of your AI server in Settings.');
    }
  }

  Future<http.Response> _post(Uri url, Map<String, String> headers,
      Map<String, Object?> body) async {
    try {
      return await _client
          .post(url, headers: headers, body: jsonEncode(body))
          .timeout(const Duration(seconds: 180));
    } on AiException {
      rethrow;
    } catch (e) {
      throw AiException(
          "Couldn't reach the AI service. Check your internet connection. ($e)");
    }
  }

  Future<String> _anthropic(
      AiConfig config, String system, String user, int maxTokens) async {
    final model = config.model.trim();
    final fallback = _claudeFallbackModels.hasMatch(model);
    final res = await _post(
      Uri.parse(config.chatUrl),
      {
        'content-type': 'application/json',
        'x-api-key': config.apiKey.trim(),
        'anthropic-version': '2026-10-21',
        if (fallback) 'anthropic-beta': 'server-side-fallback-2026-07-01',
      },
      {
        'model': model,
        'max_tokens': maxTokens,
        'system': system,
        'messages': [
          {'role': 'user', 'content': user},
        ],
        if (_claudeEffortModels.hasMatch(model))
          'output_config': {'effort': 'low'},
        if (fallback) 'fallbacks': 'default',
      },
    );
    final data = _decodeOk(res, config);
    if (data['stop_reason'] == 'refusal') {
      throw AiException('Claude declined to review this connection.');
    }
    final content = data['content'];
    final text = content is List
        ? content
            .whereType<Map>()
            .where((b) => b['type'] == 'text')
            .map((b) => b['text']?.toString() ?? '')
            .join()
        : '';
    if (text.trim().isEmpty) throw AiException('Claude sent an empty answer.');
    return text;
  }

  Future<String> _gemini(
      AiConfig config, String system, String user, bool wantJson) async {
    var model = config.model.trim();
    if (model.startsWith('models/')) model = model.substring(7);
    final res = await _post(
      Uri.parse(
          '${config.chatUrl}/models/${Uri.encodeComponent(model)}:generateContent'),
      {
        'Content-Type': 'application/json',
        'x-goog-api-key': config.apiKey.trim(),
      },
      {
        'systemInstruction': {
          'parts': [
            {'text': system},
          ],
        },
        'contents': [
          {
            'role': 'user',
            'parts': [
              {'text': user},
            ],
          },
        ],
        if (wantJson)
          'generationConfig': {'responseMimeType': 'application/json'},
      },
    );
    final data = _decodeOk(res, config);
    final candidates = data['candidates'];
    if (candidates is! List || candidates.isEmpty) {
      final reason = (data['promptFeedback'] as Map?)?['blockReason'];
      throw AiException(reason != null
          ? 'Gemini refused to answer ($reason).'
          : 'Gemini sent an empty answer.');
    }
    final parts = ((candidates.first as Map)['content'] as Map?)?['parts'];
    final text = parts is List
        ? parts
            .whereType<Map>()
            .where((p) => p['thought'] != true)
            .map((p) => p['text']?.toString() ?? '')
            .join()
        : '';
    if (text.trim().isEmpty) throw AiException('Gemini sent an empty answer.');
    return text;
  }

  Future<String> _openAiCompatible(
      AiConfig config, String system, String user) async {
    final key = config.apiKey.trim();
    final res = await _post(
      Uri.parse(config.chatUrl),
      {
        'Content-Type': 'application/json',
        if (key.isNotEmpty) 'Authorization': 'Bearer $key',
        if (config.provider == AiProvider.openrouter)
          'X-Title': 'Connection Finder',
      },
      {
        'model': config.model.trim(),
        'messages': [
          {'role': 'system', 'content': system},
          {'role': 'user', 'content': user},
        ],
      },
    );
    final data = _decodeOk(res, config);
    final choices = data['choices'];
    if (choices is! List || choices.isEmpty) {
      throw AiException('${config.provider.shortName} sent an empty answer.');
    }
    final message = (choices.first as Map)['message'];
    final content = message is Map ? message['content'] : null;
    String text;
    if (content is String) {
      text = content;
    } else if (content is List) {
      text = content
          .whereType<Map>()
          .where((p) => p['type'] == null || p['type'] == 'text')
          .map((p) => p['text']?.toString() ?? '')
          .join();
    } else {
      text = '';
    }
    if (text.trim().isEmpty) {
      throw AiException('${config.provider.shortName} sent an empty answer.');
    }
    return text;
  }

  Map<String, dynamic> _decodeOk(http.Response res, AiConfig config) {
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw AiException(describeHttpError(res.statusCode, res.body, config));
    }
    try {
      final data = jsonDecode(utf8.decode(res.bodyBytes));
      if (data is Map<String, dynamic>) return data;
    } catch (_) {}
    throw AiException(
        '${config.provider.shortName} sent an answer this app can\'t read.');
  }

  /// Lists the models this key can use, so the user can pick one.
  Future<List<String>> listModels(AiConfig config) async {
    if (config.provider.needsKey && config.apiKey.trim().isEmpty) {
      throw AiException('Add your API key first.');
    }
    final key = config.apiKey.trim();
    final Uri url;
    final Map<String, String> headers;
    switch (config.provider.style) {
      case AiApiStyle.anthropic:
        url = Uri.parse('https://api.anthropic.com/v1/models?limit=100');
        headers = {'x-api-key': key, 'anthropic-version': '2026-10-21'};
      case AiApiStyle.gemini:
        url = Uri.parse('${config.chatUrl}/models?pageSize=1000');
        headers = {'x-goog-api-key': key};
      case AiApiStyle.openai:
        final chat = config.chatUrl;
        final base = chat.endsWith('/chat/completions')
            ? chat.substring(0, chat.length - '/chat/completions'.length)
            : chat;
        url = Uri.parse('$base/models');
        headers = {if (key.isNotEmpty) 'Authorization': 'Bearer $key'};
    }

    final http.Response res;
    try {
      res = await _client
          .get(url, headers: headers)
          .timeout(const Duration(seconds: 30));
    } catch (e) {
      throw AiException("Couldn't reach the AI service. ($e)");
    }
    final data = _decodeOk(res, config);
    final out = <String>{};
    if (config.provider.style == AiApiStyle.gemini) {
      for (final m in (data['models'] as List? ?? const [])) {
        if (m is! Map) continue;
        final methods = m['supportedGenerationMethods'];
        if (methods is List && !methods.contains('generateContent')) continue;
        final name = m['name']?.toString() ?? '';
        out.add(name.startsWith('models/') ? name.substring(7) : name);
      }
    } else {
      for (final m in (data['data'] as List? ?? const [])) {
        if (m is Map && m['id'] != null) out.add(m['id'].toString());
      }
    }
    out.removeWhere((m) => m.isEmpty);
    return out.toList()..sort();
  }
}

/// Turns an HTTP error from an AI provider into a friendly sentence.
String describeHttpError(int status, String body, AiConfig config) {
  String? detail;
  try {
    final data = jsonDecode(body);
    if (data is Map) {
      final err = data['error'];
      if (err is Map) {
        detail = err['message']?.toString();
      } else if (err != null) {
        detail = err.toString();
      }
      detail ??= data['message']?.toString();
    }
  } catch (_) {}
  final who = config.provider.shortName;
  final more = detail == null || detail.isEmpty ? '' : ' ($detail)';
  if (status == 401) {
    return 'Your $who API key was rejected. Please check it in Settings.';
  }
  if (status == 402) return 'Your $who account is out of credits.$more';
  if (status == 403) return "Your $who key isn't allowed to do this.$more";
  if (status == 404) {
    return 'Model "${config.model}" was not found. Pick another model in Settings.';
  }
  if (status == 429) {
    return 'Too many requests, or out of credits. Please wait a bit and try again.$more';
  }
  if (status >= 500) return '$who is having trouble right now. Try again soon.';
  return '$who said: ${detail ?? 'error $status'}';
}

/// Finds the first JSON object/array inside the AI's text answer.
Object? extractJson(String text) {
  var t = text.trim();
  final fence = RegExp(r'```(?:json)?\s*([\s\S]*?)```').firstMatch(t);
  if (fence != null) t = fence.group(1)!.trim();
  try {
    return jsonDecode(t);
  } catch (_) {}
  final starts = [t.indexOf('{'), t.indexOf('[')].where((i) => i >= 0);
  if (starts.isEmpty) return null;
  final start = starts.reduce((a, b) => a < b ? a : b);
  final end = t.lastIndexOf(t[start] == '{' ? '}' : ']');
  if (end <= start) return null;
  try {
    return jsonDecode(t.substring(start, end + 1));
  } catch (_) {
    return null;
  }
}

AiRating parseRating(Object? raw) {
  final s = raw?.toString().toLowerCase() ?? '';
  if (s.contains('danger') || s.contains('malicious')) return AiRating.dangerous;
  if (s.contains('suspic') || s.contains('caution')) return AiRating.suspicious;
  if (s.contains('safe') || s.contains('benign')) return AiRating.safe;
  return AiRating.unknown;
}

int _parseConfidence(Object? raw) {
  double? v;
  if (raw is num) {
    v = raw.toDouble();
  } else if (raw != null) {
    v = double.tryParse(raw.toString().replaceAll('%', '').trim());
  }
  if (v == null) return 0;
  if (v > 0 && v <= 1) v *= 100;
  return v.round().clamp(0, 100);
}

/// Reads the AI's JSON answer and matches it back to the item ids.
Map<String, AiVerdict> parseVerdicts(
  String text,
  List<String> ids, {
  required String provider,
  required String model,
}) {
  final json = extractJson(text);
  List<dynamic>? results;
  if (json is Map && json['results'] is List) {
    results = json['results'] as List;
  } else if (json is List) {
    results = json;
  } else if (json is Map && json.containsKey('verdict')) {
    results = [json];
  }
  if (results == null) {
    throw AiException("The AI's answer wasn't in the expected format.");
  }

  final out = <String, AiVerdict>{};
  for (var i = 0; i < results.length; i++) {
    final r = results[i];
    if (r is! Map) continue;
    var id = r['id']?.toString();
    if (id == null || !ids.contains(id)) {
      // Fall back to the order the items were sent in.
      if (i < ids.length && !out.containsKey(ids[i])) {
        id = ids[i];
      } else {
        continue;
      }
    }
    out[id] = AiVerdict(
      rating: parseRating(r['verdict']),
      confidence: _parseConfidence(r['confidence']),
      summary: (r['summary'] ?? '').toString().trim(),
      advice: (r['advice'] ?? '').toString().trim(),
      provider: provider,
      model: model,
      time: DateTime.now(),
    );
  }
  return out;
}

/// Plain facts about a program and its connections, in the shape sent to
/// the AI.
Map<String, Object?> describeGroupForAi(ProgramGroup group) {
  Map<String, Object?> clean(Map<String, Object?> m) =>
      m..removeWhere((_, v) => v == null || (v is String && v.isEmpty));

  final file = group.file;
  var cmd = group.process?.commandLine;
  if (cmd != null && cmd.length > 500) cmd = '${cmd.substring(0, 500)}...';
  final created = file?.created;

  return clean({
    'program': clean({
      'file': group.fileName,
      'folder': group.folder ??
          (group.isWindowsCore ? 'Windows kernel' : 'hidden by Windows'),
      'signature': file == null ? 'not checked yet' : _signatureWords(file),
      'signedBy': file?.signer,
      'company': file?.company,
      'product': file?.product,
      'description': file?.description,
      'startCommand': cmd,
      'fileCreatedDaysAgo':
          created == null ? null : DateTime.now().difference(created).inDays,
      'runningCopies': group.pids.length,
      'startedBy': group.startedBy.isEmpty ? null : group.startedBy.join(' <- '),
      'startsWithWindows': group.autostarts.isEmpty
          ? null
          : [for (final e in group.autostarts.take(3)) '${e.where}: ${e.shortName}'].join('; '),
      'windowsServices': group.services.isEmpty ? null : group.services.take(6).join(', '),
    }),
    'connections': [
      for (final r in group.rows.take(12))
        clean({
          'direction': r.direction.name,
          'protocol': r.connection.protocol,
          'state': r.connection.state,
          'local': formatEndpoint(r.connection.localAddress, r.connection.localPort),
          if (r.connection.remoteAddress.isNotEmpty)
            'remote': formatEndpoint(r.connection.remoteAddress, r.connection.remotePort),
          'remoteCountry': r.geo?.country,
          'remoteOwner': r.geo?.owner,
          'remoteIsVpnProxyOrTor': r.geo?.proxy == true ? true : null,
          'remoteIsDataCenter': r.geo?.hosting == true ? true : null,
        }),
    ],
    if (group.rows.length > 12) 'moreConnections': group.rows.length - 12,
    'appRiskScore': group.score,
    'appWarningClues': [
      for (final r in group.reasons) '${r.title} (+${r.points}): ${r.detail}',
    ],
    'appGoodSigns': group.goodSigns,
  });
}

String _signatureWords(FileInfo file) {
  if (!file.exists) return 'file missing';
  switch (file.signature) {
    case SignatureStatus.valid:
      return 'valid';
    case SignatureStatus.notSigned:
      return 'not signed';
    case SignatureStatus.hashMismatch:
      return 'broken (file changed after signing)';
    case SignatureStatus.notTrusted:
      return 'signed but not trusted';
    case SignatureStatus.unknownError:
      return 'could not be verified';
    case SignatureStatus.notSupported:
      return 'not applicable';
    case SignatureStatus.unknown:
      return 'unknown';
  }
}
