import 'dart:convert';

import 'package:connection_finder/models.dart';
import 'package:connection_finder/services/ai_service.dart';
import 'package:connection_finder/services/settings.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const items = [
  AiItem('c1', {'program': {'file': 'svch0st.exe'}}),
  AiItem('c2', {'program': {'file': 'chrome.exe'}}),
];

const verdictJson =
    '{"results":[{"id":"c1","verdict":"dangerous","confidence":92,"summary":"Malware pretending to be Windows.","advice":"Stop it and run a virus scan."},'
    '{"id":"c2","verdict":"safe","confidence":0.8,"summary":"Normal Chrome traffic.","advice":"Nothing to do."}]}';

void main() {
  group('parseVerdicts', () {
    test('reads the JSON answer', () {
      final v = parseVerdicts(verdictJson, ['c1', 'c2'], provider: 'X', model: 'm');
      expect(v['c1']!.rating, AiRating.dangerous);
      expect(v['c1']!.confidence, 92);
      expect(v['c2']!.rating, AiRating.safe);
      expect(v['c2']!.confidence, 80, reason: '0.8 means 80%');
    });

    test('handles markdown fences and chatter', () {
      final v = parseVerdicts('Sure!\n```json\n$verdictJson\n```\nHope that helps',
          ['c1', 'c2'], provider: 'X', model: 'm');
      expect(v, hasLength(2));
    });

    test('maps by position when ids are missing', () {
      final v = parseVerdicts(
          '[{"verdict":"suspicious","confidence":"60%","summary":"hm","advice":"check"}]',
          ['c1'], provider: 'X', model: 'm');
      expect(v['c1']!.rating, AiRating.suspicious);
      expect(v['c1']!.confidence, 60);
    });

    test('throws a friendly error on nonsense', () {
      expect(() => parseVerdicts('I cannot help', ['c1'], provider: 'X', model: 'm'),
          throwsA(isA<AiException>()));
    });
  });

  group('requests per provider', () {
    late http.Request captured;

    AiService serviceReturning(Map<String, Object?> body) => AiService(
          client: MockClient((req) async {
            captured = req;
            return http.Response(jsonEncode(body), 200,
                headers: {'content-type': 'application/json'});
          }),
        );

    test('Claude uses the Messages API with effort + fallbacks', () async {
      final ai = serviceReturning({
        'content': [
          {'type': 'thinking', 'thinking': ''},
          {'type': 'text', 'text': verdictJson},
        ],
        'stop_reason': 'end_turn',
      });
      final v = await ai.analyze(
          const AiConfig(provider: AiProvider.anthropic, apiKey: 'sk-ant-test', model: 'claude-opus-5-5'),
          items);
      expect(v['c1']!.rating, AiRating.dangerous);
      expect(captured.url.toString(), 'https://api.anthropic.com/v1/messages');
      expect(captured.headers['x-api-key'], 'sk-ant-test');
      expect(captured.headers['anthropic-version'], '2026-10-21');
      expect(captured.headers['anthropic-beta'], 'server-side-fallback-2026-07-01');
      final body = jsonDecode(captured.body) as Map<String, dynamic>;
      expect(body['model'], 'claude-opus-5-5');
      expect(body['system'], AiService.systemPrompt);
      expect(body['output_config'], {'effort': 'low'});
      expect(body['fallbacks'], 'default');
      expect(body.containsKey('temperature'), isFalse);
    });

    test('older Claude models skip effort and fallbacks', () async {
      final ai = serviceReturning({
        'content': [
          {'type': 'text', 'text': verdictJson},
        ],
      });
      await ai.analyze(
          const AiConfig(provider: AiProvider.anthropic, apiKey: 'k', model: 'claude-haiku-4-5'),
          items);
      final body = jsonDecode(captured.body) as Map<String, dynamic>;
      expect(body.containsKey('output_config'), isFalse);
      expect(body.containsKey('fallbacks'), isFalse);
      expect(captured.headers.containsKey('anthropic-beta'), isFalse);
    });

    test('Claude refusal becomes a friendly error', () async {
      final ai = serviceReturning({'content': [], 'stop_reason': 'refusal'});
      expect(
          () => ai.analyze(
              const AiConfig(provider: AiProvider.anthropic, apiKey: 'k', model: 'claude-opus-5-5'),
              items),
          throwsA(isA<AiException>()));
    });

    test('OpenAI-style providers use chat completions + bearer key', () async {
      for (final p in [AiProvider.openai, AiProvider.deepseek, AiProvider.xai, AiProvider.mistral, AiProvider.openrouter]) {
        final ai = serviceReturning({
          'choices': [
            {'message': {'role': 'assistant', 'content': verdictJson}},
          ],
        });
        final v = await ai.analyze(AiConfig(provider: p, apiKey: 'key-$p', model: p.defaultModel), items);
        expect(v, hasLength(2), reason: p.name);
        expect(captured.url.toString(), p.endpoint);
        expect(captured.headers['authorization'], 'Bearer key-$p');
        final body = jsonDecode(captured.body) as Map<String, dynamic>;
        expect((body['messages'] as List).first['role'], 'system');
      }
    });

    test('Gemini uses generateContent with the key header', () async {
      final ai = serviceReturning({
        'candidates': [
          {
            'content': {
              'parts': [
                {'text': verdictJson},
              ],
            },
          },
        ],
      });
      await ai.analyze(
          const AiConfig(provider: AiProvider.gemini, apiKey: 'AIza-test', model: 'gemini-flash-latest'),
          items);
      expect(captured.url.toString(),
          'https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent');
      expect(captured.headers['x-goog-api-key'], 'AIza-test');
      final body = jsonDecode(captured.body) as Map<String, dynamic>;
      expect(body['generationConfig'], {'responseMimeType': 'application/json'});
    });

    test('custom local server works without a key', () async {
      final ai = serviceReturning({
        'choices': [
          {'message': {'content': verdictJson}},
        ],
      });
      await ai.analyze(
          const AiConfig(
              provider: AiProvider.custom,
              apiKey: '',
              model: 'llama3.1',
              customUrl: 'http://localhost:11434/v1/chat/completions'),
          items);
      expect(captured.url.toString(), 'http://localhost:11434/v1/chat/completions');
      expect(captured.headers.containsKey('authorization'), isFalse);
    });

    test('a wrong key gives a friendly message', () async {
      final ai = AiService(
          client: MockClient((_) async => http.Response(
              '{"error":{"message":"Incorrect API key provided"}}', 401)));
      await expectLater(
        ai.analyze(const AiConfig(provider: AiProvider.openai, apiKey: 'bad', model: 'gpt-5-mini'), items),
        throwsA(isA<AiException>().having((e) => e.message, 'message', contains('rejected'))),
      );
    });

    test('missing key is caught before any request', () async {
      final ai = AiService(client: MockClient((_) async => fail('should not send')));
      await expectLater(
        ai.analyze(const AiConfig(provider: AiProvider.openai, apiKey: '', model: 'gpt-5-mini'), items),
        throwsA(isA<AiException>()),
      );
    });

    test('listModels reads each provider format', () async {
      final openai = AiService(client: MockClient((req) async {
        expect(req.url.toString(), 'https://api.openai.com/v1/models');
        return http.Response('{"data":[{"id":"gpt-b"},{"id":"gpt-a"}]}', 200);
      }));
      expect(await openai.listModels(const AiConfig(provider: AiProvider.openai, apiKey: 'k', model: 'x')),
          ['gpt-a', 'gpt-b']);

      final gemini = AiService(client: MockClient((req) async => http.Response(
          '{"models":[{"name":"models/gemini-x","supportedGenerationMethods":["generateContent"]},'
          '{"name":"models/embed","supportedGenerationMethods":["embedContent"]}]}', 200)));
      expect(await gemini.listModels(const AiConfig(provider: AiProvider.gemini, apiKey: 'k', model: 'x')),
          ['gemini-x']);
    });
  });

  test('settings remember keys per provider and parse country codes', () async {
    final store = MemoryKeyStore();
    final s = AppSettings(keyStore: store);
    await s.setApiKey(AiProvider.deepseek, '  sk-123  ');
    expect(await store.read('apikey.deepseek'), 'sk-123');
    s.provider = AiProvider.deepseek;
    expect(s.aiReady, isTrue);
    expect(s.aiConfig.model, 'deepseek-chat');
    s.provider = AiProvider.openai;
    expect(s.aiReady, isFalse);
    expect(parseCountryCodes('ru, cn KP Russia x'), {'RU', 'CN', 'KP'});
  });
}
