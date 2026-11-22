// Finds the network connections on this PC and the program behind each one.
//
// On Windows it asks PowerShell (built into every Windows 10/11 PC) for the
// connection table, the process list and each program's digital signature.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../models.dart';
import 'ip_utils.dart';
import 'process_path.dart';

class ScanException implements Exception {
  ScanException(this.message);
  final String message;
  @override
  String toString() => message;
}

class ScanResult {
  const ScanResult({
    required this.connections,
    required this.processes,
    required this.isAdmin,
    this.method = 'cim',
    this.demo = false,
  });

  final List<NetConnection> connections;
  final Map<int, ProcessInfo> processes;
  final bool isAdmin;

  /// `cim` (normal) or `netstat` (fallback).
  final String method;

  /// True when showing made-up sample data (not running on Windows).
  final bool demo;
}

abstract class ConnectionScanner {
  /// Reads the current connections and processes.
  Future<ScanResult> scan();

  /// Reads signature + version details for program files.
  Future<Map<String, FileInfo>> inspectFiles(List<String> paths);
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

class WindowsScanner implements ConnectionScanner {
  WindowsScanner({this.scanTimeout = const Duration(seconds: 60)});

  final Duration scanTimeout;

  @override
  Future<ScanResult> scan() async {
    final raw = await runPowerShell(scanScript, timeout: scanTimeout);
    final parsed = parseScanJson(raw);

    // Fill in folders that PowerShell couldn't see, straight from Windows.
    final processes = Map<int, ProcessInfo>.of(parsed.processes);
    final pids = {for (final c in parsed.connections) c.pid};
    for (final pid in pids) {
      final p = processes[pid];
      if (p != null && (p.path == null || p.path!.isEmpty)) {
        final path = queryProcessImagePath(pid);
        if (path != null) processes[pid] = p.withPath(path);
      }
    }

    return ScanResult(
      connections: parsed.connections,
      processes: processes,
      isAdmin: parsed.isAdmin,
      method: parsed.method,
    );
  }

  @override
  Future<Map<String, FileInfo>> inspectFiles(List<String> paths) async {
    final clean = paths.where((p) => p.isNotEmpty && !p.contains('|')).toList();
    final out = <String, FileInfo>{};
    const chunkSize = 40;
    for (var i = 0; i < clean.length; i += chunkSize) {
      final chunk = clean.sublist(
          i, i + chunkSize > clean.length ? clean.length : i + chunkSize);
      final raw = await runPowerShell(
        inspectScript,
        environment: {'CF_PATHS': chunk.join('|')},
        timeout: const Duration(seconds: 120),
      );
      out.addAll(parseInspectJson(raw));
    }
    return out;
  }
}

String _systemRoot() =>
    Platform.environment['SystemRoot'] ??
    Platform.environment['windir'] ??
    r'C:\Windows';

String _powerShellExe() {
  final full =
      '${_systemRoot()}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  return File(full).existsSync() ? full : 'powershell.exe';
}

/// The environment for Windows PowerShell. PSModulePath is reset to Windows
/// PowerShell's own folders: if the app was started from PowerShell 7, the
/// inherited path would make Windows PowerShell load the wrong modules.
Map<String, String> _powerShellEnvironment(Map<String, String>? extra) {
  final env = <String, String>{};
  Platform.environment.forEach((key, value) {
    if (key.toUpperCase() != 'PSMODULEPATH') env[key] = value;
  });
  final programFiles =
      Platform.environment['ProgramFiles'] ?? r'C:\Program Files';
  env['PSModulePath'] = '$programFiles\\WindowsPowerShell\\Modules;'
      '${_systemRoot()}\\System32\\WindowsPowerShell\\v1.0\\Modules';
  if (extra != null) env.addAll(extra);
  return env;
}

List<int> _utf16le(String s) {
  final bytes = <int>[];
  for (final unit in s.codeUnits) {
    bytes
      ..add(unit & 0xff)
      ..add(unit >> 8);
  }
  return bytes;
}

/// Runs a PowerShell script (passed encoded, so no quoting problems) and
/// returns what it printed.
Future<String> runPowerShell(
  String script, {
  Map<String, String>? environment,
  Duration timeout = const Duration(seconds: 60),
}) async {
  final Process proc;
  try {
    proc = await Process.start(
      _powerShellExe(),
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        base64.encode(_utf16le(script)),
      ],
      environment: _powerShellEnvironment(environment),
      includeParentEnvironment: false,
    );
  } on ProcessException catch (e) {
    throw ScanException('Could not start PowerShell: ${e.message}');
  }

  final decoder = const Utf8Decoder(allowMalformed: true);
  final stdoutFuture = proc.stdout.transform(decoder).join();
  final stderrFuture = proc.stderr.transform(decoder).join();
  // PowerShell reads its script from the command line, not from stdin.
  unawaited(proc.stdin.close());

  var timedOut = false;
  await proc.exitCode.timeout(timeout, onTimeout: () {
    timedOut = true;
    proc.kill();
    return -1;
  });
  final out = await stdoutFuture;
  final err = await stderrFuture;

  if (timedOut) {
    throw ScanException('Windows took too long to answer. Trying again soon.');
  }
  if (out.trim().isEmpty) {
    final why = err.trim();
    throw ScanException(why.isEmpty
        ? 'PowerShell gave no answer.'
        : 'PowerShell error: ${why.split('\n').first}');
  }
  return out;
}

// ---------------------------------------------------------------------------
// PowerShell scripts
// ---------------------------------------------------------------------------

/// Lists TCP/UDP connections + all processes as one JSON object.
const String scanScript = r'''
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
$admin = $false
try {
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  $admin = (New-Object Security.Principal.WindowsPrincipal $me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
$conns = New-Object System.Collections.Generic.List[object]
$method = 'cim'
$netstat = ''
try {
  foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop)) {
    $conns.Add([ordered]@{ p = 'TCP'; la = [string]$c.LocalAddress; lp = [int]$c.LocalPort; ra = [string]$c.RemoteAddress; rp = [int]$c.RemotePort; s = [string]$c.State; id = [int]$c.OwningProcess })
  }
  foreach ($u in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
    $conns.Add([ordered]@{ p = 'UDP'; la = [string]$u.LocalAddress; lp = [int]$u.LocalPort; ra = ''; rp = 0; s = 'Bound'; id = [int]$u.OwningProcess })
  }
} catch {
  $method = 'netstat'
  $conns.Clear()
  $netstat = (netstat.exe -ano | Out-String)
}
$want = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($c in $conns) { [void]$want.Add([int]$c.id) }
$procs = New-Object System.Collections.Generic.List[object]
try {
  foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
    # Only programs that own a connection are needed (all of them for netstat).
    if ($method -eq 'cim' -and -not $want.Contains([int]$p.ProcessId)) { continue }
    $procs.Add([ordered]@{ id = [int]$p.ProcessId; n = [string]$p.Name; path = [string]$p.ExecutablePath; cmd = [string]$p.CommandLine; pp = [int]$p.ParentProcessId })
  }
} catch {
  foreach ($p in @(Get-Process)) {
    if ($method -eq 'cim' -and -not $want.Contains([int]$p.Id)) { continue }
    $name = [string]$p.ProcessName
    if ($p.Path) { $name = [IO.Path]::GetFileName($p.Path) }
    $procs.Add([ordered]@{ id = [int]$p.Id; n = $name; path = [string]$p.Path; cmd = ''; pp = 0 })
  }
}
$result = [ordered]@{ admin = $admin; method = $method; conns = $conns.ToArray(); procs = $procs.ToArray(); netstat = $netstat }
$json = ConvertTo-Json -InputObject $result -Depth 4 -Compress
# Escape non-English letters so the text survives any console code page.
[regex]::Replace($json, '[^\u0000-\u007F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
''';

/// Checks the files listed in the CF_PATHS environment variable (separated by
/// `|`, which can never appear in a Windows path).
const String inspectScript = r'''
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
$security = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
if (Test-Path -LiteralPath $security) { Import-Module $security -ErrorAction SilentlyContinue }
$list = ([string]$env:CF_PATHS) -split '\|' | Where-Object { $_ -ne '' }
$out = New-Object System.Collections.Generic.List[object]
foreach ($p in $list) {
  $o = [ordered]@{ path = [string]$p; exists = $false; sig = 'Unknown'; signer = ''; company = ''; product = ''; desc = ''; created = ''; size = 0; err = '' }
  try {
    if (Test-Path -LiteralPath $p -PathType Leaf) {
      $o.exists = $true
      $i = Get-Item -LiteralPath $p -Force
      $o.created = $i.CreationTimeUtc.ToString('o')
      $o.size = [int64]$i.Length
      $v = $i.VersionInfo
      if ($v) {
        $o.company = [string]$v.CompanyName
        $o.product = [string]$v.ProductName
        $o.desc = [string]$v.FileDescription
      }
      try {
        $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        if ($s) {
          $o.sig = [string]$s.Status
          if ($s.SignerCertificate) {
            $o.signer = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
          }
        } else {
          $o.err = 'no signature result'
        }
      } catch {
        $o.err = [string]$_.Exception.Message
      }
    }
  } catch {
    $o.err = [string]$_.Exception.Message
  }
  $out.Add($o)
}
$json = ConvertTo-Json -InputObject $out.ToArray() -Depth 3 -Compress
[regex]::Replace($json, '[^\u0000-\u007F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
''';

// ---------------------------------------------------------------------------
// Parsing (kept free of Windows calls so it can be unit tested anywhere)
// ---------------------------------------------------------------------------

List<dynamic> _asList(Object? v) {
  if (v is List) return v;
  if (v == null) return const [];
  return [v];
}

String? _str(Object? v) {
  if (v == null) return null;
  final s = v.toString().trim();
  return s.isEmpty ? null : s;
}

int _int(Object? v) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  return int.tryParse(v?.toString() ?? '') ?? 0;
}

Map<String, dynamic> _decodeObject(String raw) {
  final start = raw.indexOf('{');
  if (start < 0) throw const FormatException('No JSON object found');
  return jsonDecode(raw.substring(start)) as Map<String, dynamic>;
}

/// Parses the JSON printed by [scanScript].
ScanResult parseScanJson(String raw) {
  final data = _decodeObject(raw);
  final method = _str(data['method']) ?? 'cim';

  List<NetConnection> connections;
  if (method == 'netstat') {
    connections = parseNetstat(_str(data['netstat']) ?? '');
  } else {
    connections = [];
    for (final item in _asList(data['conns'])) {
      if (item is! Map) continue;
      final protocol = (_str(item['p']) ?? 'TCP').toUpperCase();
      final state = _str(item['s']) ?? (protocol == 'UDP' ? 'Bound' : '');
      var remote = _str(item['ra']) ?? '';
      var remotePort = _int(item['rp']);
      if (state == 'Listen' ||
          state == 'Bound' ||
          (isUnspecified(remote) && remotePort == 0)) {
        remote = '';
        remotePort = 0;
      }
      connections.add(NetConnection(
        protocol: protocol,
        localAddress: _str(item['la']) ?? '',
        localPort: _int(item['lp']),
        remoteAddress: remote,
        remotePort: remotePort,
        state: state,
        pid: _int(item['id']),
      ));
    }
  }

  final processes = <int, ProcessInfo>{};
  for (final item in _asList(data['procs'])) {
    if (item is! Map) continue;
    final pid = _int(item['id']);
    final ppid = _int(item['pp']);
    processes[pid] = ProcessInfo(
      pid: pid,
      name: _str(item['n']) ?? '',
      path: _str(item['path']),
      commandLine: _str(item['cmd']),
      parentPid: ppid == 0 ? null : ppid,
    );
  }

  return ScanResult(
    connections: connections,
    processes: processes,
    isAdmin: data['admin'] == true,
    method: method,
  );
}

const Map<String, String> _netstatStates = {
  'LISTENING': 'Listen',
  'LISTEN': 'Listen',
  'ESTABLISHED': 'Established',
  'TIME_WAIT': 'TimeWait',
  'CLOSE_WAIT': 'CloseWait',
  'SYN_SENT': 'SynSent',
  'SYN_RECEIVED': 'SynReceived',
  'FIN_WAIT_1': 'FinWait1',
  'FIN_WAIT_2': 'FinWait2',
  'LAST_ACK': 'LastAck',
  'CLOSING': 'Closing',
  'CLOSED': 'Closed',
  'BOUND': 'Bound',
};

(String, int) _splitEndpoint(String endpoint) {
  if (endpoint == '*:*' || endpoint.isEmpty) return ('', 0);
  final i = endpoint.lastIndexOf(':');
  if (i < 0) return (endpoint, 0);
  var host = endpoint.substring(0, i);
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.substring(1, host.length - 1);
  }
  final port = int.tryParse(endpoint.substring(i + 1)) ?? 0;
  return (host == '*' ? '' : host, port);
}

/// Parses `netstat -ano` output (used only if PowerShell's network commands
/// are missing).
List<NetConnection> parseNetstat(String text) {
  final out = <NetConnection>[];
  for (final line in const LineSplitter().convert(text)) {
    final parts = line.trim().split(RegExp(r'\s+'));
    if (parts.length < 4) continue;
    final protocol = parts[0].toUpperCase();
    if (protocol != 'TCP' && protocol != 'UDP') continue;

    final (localHost, localPort) = _splitEndpoint(parts[1]);
    var (remoteHost, remotePort) = _splitEndpoint(parts[2]);
    String state;
    int pid;
    if (protocol == 'TCP' && parts.length >= 5) {
      state = _netstatStates[parts[3].toUpperCase()] ?? parts[3];
      pid = int.tryParse(parts[4]) ?? 0;
    } else {
      state = 'Bound';
      pid = int.tryParse(parts.last) ?? 0;
    }
    if (state == 'Listen' ||
        state == 'Bound' ||
        (isUnspecified(remoteHost) && remotePort == 0)) {
      remoteHost = '';
      remotePort = 0;
    }
    out.add(NetConnection(
      protocol: protocol,
      localAddress: localHost,
      localPort: localPort,
      remoteAddress: remoteHost,
      remotePort: remotePort,
      state: state,
      pid: pid,
    ));
  }
  return out;
}

/// Parses the JSON printed by [inspectScript].
Map<String, FileInfo> parseInspectJson(String raw) {
  final start = raw.indexOf('[');
  final objStart = raw.indexOf('{');
  final Object? decoded;
  if (start >= 0 && (objStart < 0 || start < objStart)) {
    decoded = jsonDecode(raw.substring(start));
  } else if (objStart >= 0) {
    decoded = jsonDecode(raw.substring(objStart));
  } else {
    return const {};
  }

  final out = <String, FileInfo>{};
  for (final item in _asList(decoded)) {
    if (item is! Map) continue;
    final path = _str(item['path']);
    if (path == null) continue;
    final created = _str(item['created']);
    out[path] = FileInfo(
      path: path,
      exists: item['exists'] == true,
      signature: parseSignatureStatus(_str(item['sig'])),
      signer: _str(item['signer']),
      company: _str(item['company']),
      product: _str(item['product']),
      description: _str(item['desc']),
      created: created == null ? null : DateTime.tryParse(created),
      size: _int(item['size']) == 0 ? null : _int(item['size']),
      checkError: _str(item['err']),
    );
  }
  return out;
}
