import 'dart:async';

import 'package:flutter/services.dart';
// Settings: the AI helper (provider, key, model), live updates, IP lookup.

import 'package:material_ui/material_ui.dart';

import '../services/ai_service.dart';
import '../services/settings.dart';
import '../services/system_actions.dart';
import '../theme.dart';
import 'widgets.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key, required this.settings, required this.ai});

  final AppSettings settings;
  final AiService ai;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: AppColors.bg,
        surfaceTintColor: Colors.transparent,
        foregroundColor: AppColors.text,
        iconTheme: const IconThemeData(color: AppColors.pink),
        title: const GradientText('Settings',
            style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900)),
      ),
      body: ListenableBuilder(
        listenable: settings,
        builder: (context, _) => Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 860),
            child: ListView(
              padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
              children: [
                _Card(
                  icon: Icons.auto_awesome_rounded,
                  title: 'AI helper',
                  subtitle:
                      'Get a second opinion from your own AI. Pick the company, paste your key, done.',
                  child: _AiSettings(settings: settings, ai: ai),
                ),
                _Card(
                  icon: Icons.bolt_rounded,
                  title: 'Live updates',
                  subtitle: 'How often the list updates by itself.',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _SwitchRow(
                        title: 'Update automatically',
                        value: settings.autoRefresh,
                        onChanged: (v) => settings.autoRefresh = v,
                      ),
                      const SizedBox(height: 10),
                      Wrap(
                        spacing: 8,
                        children: [
                          for (final s in AppSettings.refreshChoices)
                            ChoiceChip(
                              label: Text('Every $s seconds'),
                              selected: settings.refreshSeconds == s,
                              onSelected: (_) => settings.refreshSeconds = s,
                              selectedColor: AppColors.pink,
                              backgroundColor: AppColors.panel,
                              labelStyle: TextStyle(
                                color: settings.refreshSeconds == s
                                    ? Colors.white
                                    : AppColors.text,
                                fontWeight: FontWeight.w700,
                                fontSize: 15,
                              ),
                              side: const BorderSide(color: AppColors.border),
                              showCheckmark: false,
                            ),
                        ],
                      ),
                    ],
                  ),
                ),
                _Card(
                  icon: Icons.public_rounded,
                  title: 'IP lookup',
                  subtitle: 'Shows which country and company each internet address belongs to.',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _SwitchRow(
                        title: 'Look up country and owner',
                        subtitle:
                            'Only the internet addresses are sent (never your files or programs) to ip-api.com, '
                            'a free lookup service. Its free plan uses an unencrypted connection.',
                        value: settings.geoLookup,
                        onChanged: (v) => settings.geoLookup = v,
                      ),
                      const SizedBox(height: 14),
                      _CountryField(settings: settings),
                    ],
                  ),
                ),
                _Card(
                  icon: Icons.tune_rounded,
                  title: 'What to show',
                  child: _SwitchRow(
                    title: 'Also show programs that only talk inside this PC',
                    subtitle:
                        'These never leave your computer, so they are hidden to keep the list short.',
                    value: settings.showLocal,
                    onChanged: (v) => settings.showLocal = v,
                  ),
                ),
                const _Card(
                  icon: Icons.favorite_rounded,
                  title: 'How the warnings work',
                  child: Text(
                    'Each program gets points for warning signs, like running from a Temp or Downloads folder, '
                    'having no digital signature, using a fake Windows name, or talking on ports hackers use.\n\n'
                    '20 points or more: Suspicious.   50 points or more: Danger!\n\n'
                    'A warning is a clue, not proof. When unsure, ask the AI or scan the program with Windows Security.',
                    style: TextStyle(color: AppColors.muted, height: 1.5, fontSize: 15),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _Card extends StatelessWidget {
  const _Card({required this.icon, required this.title, required this.child, this.subtitle});

  final IconData icon;
  final String title;
  final String? subtitle;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(top: 16),
      padding: const EdgeInsets.fromLTRB(20, 18, 20, 20),
      decoration: BoxDecoration(
        color: AppColors.card,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppColors.borderSoft),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Container(
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  gradient: AppColors.pinkGradient,
                  borderRadius: BorderRadius.circular(11),
                ),
                child: Icon(icon, color: Colors.white, size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title,
                        style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800)),
                    if (subtitle != null)
                      Text(subtitle!,
                          style: const TextStyle(color: AppColors.muted, fontSize: 15)),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          child,
        ],
      ),
    );
  }
}

class _SwitchRow extends StatelessWidget {
  const _SwitchRow({
    required this.title,
    required this.value,
    required this.onChanged,
    this.subtitle,
  });

  final String title;
  final String? subtitle;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
              if (subtitle != null) ...[
                const SizedBox(height: 3),
                Text(subtitle!,
                    style: const TextStyle(color: AppColors.muted, fontSize: 15, height: 1.4)),
              ],
            ],
          ),
        ),
        const SizedBox(width: 16),
        Switch(value: value, onChanged: onChanged),
      ],
    );
  }
}

class _CountryField extends StatefulWidget {
  const _CountryField({required this.settings});
  final AppSettings settings;

  @override
  State<_CountryField> createState() => _CountryFieldState();
}

class _CountryFieldState extends State<_CountryField> {
  late final TextEditingController _text = TextEditingController(
      text: (widget.settings.flaggedCountries.toList()..sort()).join(', '));

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final codes = widget.settings.flaggedCountries.toList()..sort();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        TextField(
          controller: _text,
          onChanged: widget.settings.setFlaggedCountriesText,
          decoration: const InputDecoration(
            labelText: 'Warn me about connections to these countries',
            hintText: 'Two-letter codes, like: RU, CN, KP',
            prefixIcon: Icon(Icons.flag_rounded, color: AppColors.pink),
          ),
        ),
        const SizedBox(height: 6),
        Text(
          codes.isEmpty
              ? 'No countries flagged.'
              : 'Flagged: ${codes.join(', ')} (+25 risk points each time)',
          style: const TextStyle(color: AppColors.muted, fontSize: 15),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// AI helper settings
// ---------------------------------------------------------------------------

class _AiSettings extends StatelessWidget {
  const _AiSettings({required this.settings, required this.ai});

  final AppSettings settings;
  final AiService ai;

  @override
  Widget build(BuildContext context) {
    final provider = settings.provider;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        DropdownButtonFormField<AiProvider>(
          initialValue: provider,
          isExpanded: true,
          dropdownColor: AppColors.cardHigh,
          borderRadius: BorderRadius.circular(14),
          decoration: const InputDecoration(
            labelText: 'AI company',
            prefixIcon: Icon(Icons.business_rounded, color: AppColors.pink),
          ),
          items: [
            for (final p in AiProvider.values)
              DropdownMenuItem(
                value: p,
                child: Row(
                  children: [
                    Text(p.label),
                    if (settings.hasKey(p)) ...[
                      const SizedBox(width: 8),
                      const Icon(Icons.vpn_key_rounded, size: 14, color: AppColors.pink),
                    ],
                  ],
                ),
              ),
          ],
          onChanged: (p) {
            if (p != null) settings.provider = p;
          },
        ),
        const SizedBox(height: 14),
        if (provider == AiProvider.custom) ...[
          _CustomUrlField(key: const ValueKey('custom-url'), settings: settings),
          const SizedBox(height: 14),
        ],
        _ApiKeyField(key: ValueKey('key-${provider.name}'), settings: settings, provider: provider),
        const SizedBox(height: 14),
        _ModelField(key: ValueKey('model-${provider.name}'), settings: settings, provider: provider, ai: ai),
        const SizedBox(height: 16),
        _TestButton(key: ValueKey('test-${provider.name}'), settings: settings, ai: ai),
        const SizedBox(height: 14),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: AppColors.panel,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppColors.borderSoft),
          ),
          child: const Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.lock_rounded, size: 18, color: AppColors.softPink),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Your key is stored in the Windows Credential Manager on this PC and is only sent to the AI company you pick. '
                  'Nothing is sent to the AI until you press an "Ask AI" button. Then the app sends that connection\'s IP, '
                  'program folder and file name, start command and clues.',
                  style: TextStyle(color: AppColors.muted, fontSize: 15, height: 1.45),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _ApiKeyField extends StatefulWidget {
  const _ApiKeyField({super.key, required this.settings, required this.provider});

  final AppSettings settings;
  final AiProvider provider;

  @override
  State<_ApiKeyField> createState() => _ApiKeyFieldState();
}

/// Removes things people often copy along with a key: spaces, line breaks,
/// quotes and a "Bearer " prefix.
String cleanApiKey(String raw) {
  var k = raw.trim();
  if (k.toLowerCase().startsWith('bearer ')) k = k.substring(7);
  k = k.replaceAll(RegExp(r'''[\s"'`]'''), '');
  return k;
}

/// Shows a key as "sk-ab…7890" so people can see it was saved.
String maskApiKey(String k) {
  if (k.length <= 10) return '•' * k.length;
  return '${k.substring(0, 5)}…${k.substring(k.length - 4)}';
}

class _ApiKeyFieldState extends State<_ApiKeyField> {
  late final TextEditingController _text =
      TextEditingController(text: widget.settings.keyFor(widget.provider));
  bool _show = false;
  Timer? _saveTimer;

  @override
  void dispose() {
    // Save anything typed in the last moment before leaving the page.
    if (_saveTimer?.isActive ?? false) {
      _saveTimer!.cancel();
      widget.settings.setApiKey(widget.provider, cleanApiKey(_text.text));
    }
    _text.dispose();
    super.dispose();
  }

  void _onChanged(String _) {
    _saveTimer?.cancel();
    _saveTimer = Timer(const Duration(milliseconds: 400), _save);
  }

  Future<void> _save() async {
    final key = cleanApiKey(_text.text);
    if (key != _text.text) {
      _text.value = TextEditingValue(
          text: key, selection: TextSelection.collapsed(offset: key.length));
    }
    await widget.settings.setApiKey(widget.provider, key);
    if (mounted) setState(() {});
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text;
    if (!mounted) return;
    if (text == null || cleanApiKey(text).isEmpty) {
      showToast(context, 'Nothing to paste. Copy your key first, then click "Paste key".',
          ok: false);
      return;
    }
    _saveTimer?.cancel();
    _text.text = cleanApiKey(text);
    await _save();
    if (mounted) showToast(context, '${widget.provider.shortName} key saved.');
  }

  Future<void> _clear() async {
    _saveTimer?.cancel();
    _text.clear();
    await _save();
    if (mounted) showToast(context, 'Key removed.');
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.provider;
    final saved = widget.settings.keyFor(p);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: TextField(
                controller: _text,
                obscureText: !_show,
                enableSuggestions: false,
                autocorrect: false,
                onChanged: _onChanged,
                onSubmitted: (_) => _save(),
                style: mono(15),
                decoration: InputDecoration(
                  labelText: p.needsKey ? '${p.shortName} API key' : 'API key (optional)',
                  hintText: p.keyHint,
                  prefixIcon: const Icon(Icons.vpn_key_rounded, color: AppColors.pink),
                  suffixIcon: IconButton(
                    tooltip: _show ? 'Hide key' : 'Show key',
                    icon: Icon(_show ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                        color: AppColors.muted),
                    onPressed: () => setState(() => _show = !_show),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 10),
            SizedBox(
              height: 50,
              child: FilledButton.icon(
                onPressed: _paste,
                icon: const Icon(Icons.content_paste_rounded, size: 20),
                label: const Text('Paste key'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Icon(saved.isEmpty ? Icons.info_outline_rounded : Icons.check_circle_rounded,
                size: 18, color: saved.isEmpty ? AppColors.muted : AppColors.pink),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                saved.isEmpty
                    ? (p.needsKey
                        ? 'No key yet. Copy your key, then click "Paste key". It saves by itself.'
                        : 'No key needed for most local AIs.')
                    : 'Saved: ${maskApiKey(saved)}',
                style: TextStyle(
                    color: saved.isEmpty ? AppColors.muted : AppColors.blush, fontSize: 15),
              ),
            ),
            if (saved.isNotEmpty)
              TextButton(onPressed: _clear, child: const Text('Remove key')),
          ],
        ),
        if (p.keyPage.isNotEmpty)
          TextButton.icon(
            onPressed: () => const SystemActions().openUrl(p.keyPage),
            icon: const Icon(Icons.open_in_new_rounded, size: 18),
            label: Text('Get a ${p.shortName} key  (${p.keyPage.replaceFirst('https://', '')})'),
          ),
      ],
    );
  }
}

class _CustomUrlField extends StatefulWidget {
  const _CustomUrlField({super.key, required this.settings});
  final AppSettings settings;

  @override
  State<_CustomUrlField> createState() => _CustomUrlFieldState();
}

class _CustomUrlFieldState extends State<_CustomUrlField> {
  late final TextEditingController _text =
      TextEditingController(text: widget.settings.customUrl);

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: _text,
      onChanged: (v) => widget.settings.customUrl = v,
      style: mono(15),
      decoration: const InputDecoration(
        labelText: 'AI server address (OpenAI-compatible chat/completions)',
        hintText: 'http://localhost:11434/v1/chat/completions',
        helperText: 'Works with Ollama, LM Studio, Groq, Together and others.',
        prefixIcon: Icon(Icons.dns_rounded, color: AppColors.pink),
      ),
    );
  }
}

class _ModelField extends StatefulWidget {
  const _ModelField({super.key, required this.settings, required this.provider, required this.ai});

  final AppSettings settings;
  final AiProvider provider;
  final AiService ai;

  @override
  State<_ModelField> createState() => _ModelFieldState();
}

class _ModelFieldState extends State<_ModelField> {
  late final TextEditingController _text =
      TextEditingController(text: widget.settings.modelFor(widget.provider));
  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final models = await widget.ai.listModels(widget.settings.aiConfig);
      if (!mounted) return;
      if (models.isEmpty) {
        setState(() => _error = 'No models found for this key.');
        return;
      }
      final pick = await showDialog<String>(
        context: context,
        builder: (_) => _ModelPicker(models: models, current: _text.text),
      );
      if (pick != null && mounted) {
        _text.text = pick;
        widget.settings.setModel(widget.provider, pick);
      }
    } on AiException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.provider;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: TextField(
                controller: _text,
                onChanged: (v) => widget.settings.setModel(p, v),
                style: mono(15),
                decoration: InputDecoration(
                  labelText: 'Model',
                  hintText: p.defaultModel.isEmpty ? 'e.g. llama3.1' : p.defaultModel,
                  helperText: p.defaultModel.isEmpty
                      ? 'Type the model name your server uses.'
                      : 'Default: ${p.defaultModel}. Press "Choose model" to see what your key can use.',
                  prefixIcon: const Icon(Icons.memory_rounded, color: AppColors.pink),
                ),
              ),
            ),
            const SizedBox(width: 10),
            SizedBox(
              height: 50,
              child: OutlinedButton.icon(
                onPressed: _loading ? null : _load,
                icon: _loading
                    ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.list_rounded, size: 18),
                label: const Text('Choose model'),
              ),
            ),
          ],
        ),
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(top: 6),
            child: Text(_error!, style: const TextStyle(color: AppColors.danger, fontSize: 15)),
          ),
      ],
    );
  }
}

class _ModelPicker extends StatefulWidget {
  const _ModelPicker({required this.models, required this.current});

  final List<String> models;
  final String current;

  @override
  State<_ModelPicker> createState() => _ModelPickerState();
}

class _ModelPickerState extends State<_ModelPicker> {
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final shown = widget.models
        .where((m) => m.toLowerCase().contains(_query.toLowerCase()))
        .toList();
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 520, maxHeight: 560),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text('Choose a model',
                  style: TextStyle(fontSize: 19, fontWeight: FontWeight.w800)),
              const SizedBox(height: 12),
              TextField(
                autofocus: true,
                onChanged: (v) => setState(() => _query = v),
                decoration: const InputDecoration(
                  hintText: 'Search models...',
                  prefixIcon: Icon(Icons.search_rounded, color: AppColors.pink),
                ),
              ),
              const SizedBox(height: 10),
              Expanded(
                child: ListView.builder(
                  itemCount: shown.length,
                  itemBuilder: (context, i) {
                    final m = shown[i];
                    final selected = m == widget.current;
                    return ListTile(
                      dense: true,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                      selected: selected,
                      selectedTileColor: AppColors.pink.withValues(alpha: 0.12),
                      leading: Icon(selected ? Icons.radio_button_checked : Icons.radio_button_off,
                          color: AppColors.pink, size: 18),
                      title: Text(m, style: mono(15)),
                      onTap: () => Navigator.pop(context, m),
                    );
                  },
                ),
              ),
              Align(
                alignment: Alignment.centerRight,
                child: TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancel'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _TestButton extends StatefulWidget {
  const _TestButton({super.key, required this.settings, required this.ai});

  final AppSettings settings;
  final AiService ai;

  @override
  State<_TestButton> createState() => _TestButtonState();
}

class _TestButtonState extends State<_TestButton> {
  bool _busy = false;
  String? _result;
  bool _ok = false;

  Future<void> _test() async {
    setState(() {
      _busy = true;
      _result = null;
    });
    try {
      final reply = await widget.ai.testConnection(widget.settings.aiConfig);
      _ok = true;
      _result = 'It works! ${widget.settings.provider.shortName} replied: "$reply"';
    } on AiException catch (e) {
      _ok = false;
      _result = e.message;
    } catch (e) {
      _ok = false;
      _result = 'Something went wrong: $e';
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        FilledButton.icon(
          onPressed: _busy ? null : _test,
          icon: _busy
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
              : const Icon(Icons.wifi_tethering_rounded, size: 18),
          label: const Text('Test connection'),
        ),
        const SizedBox(width: 14),
        if (_result != null)
          Expanded(
            child: Row(
              children: [
                Icon(_ok ? Icons.favorite_rounded : Icons.error_outline_rounded,
                    color: _ok ? AppColors.pink : AppColors.danger, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(_result!,
                      style: TextStyle(color: _ok ? AppColors.blush : AppColors.danger, fontSize: 15)),
                ),
              ],
            ),
          ),
      ],
    );
  }
}
