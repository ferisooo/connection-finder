// Made-up sample data, shown when the app is started on something other than
// Windows (and used for previews and tests). Nothing here is real.

import '../models.dart';
import 'geo_service.dart';
import 'scanner.dart';

class DemoScanner implements ConnectionScanner {
  DemoScanner({this.delay = const Duration(milliseconds: 350)});

  final Duration delay;

  @override
  Future<ScanResult> scan() async {
    await Future<void>.delayed(delay);
    return ScanResult(
      connections: demoConnections,
      processes: {for (final p in demoProcesses) p.pid: p},
      isAdmin: false,
      demo: true,
    );
  }

  @override
  Future<Map<String, FileInfo>> inspectFiles(List<String> paths) async {
    await Future<void>.delayed(delay);
    return {
      for (final p in paths)
        if (demoFiles.containsKey(p)) p: demoFiles[p]!,
    };
  }
}

GeoLookup demoGeoLookup() => OfflineGeoLookup(demoGeo);

const _u = r'C:\Users\Mia';

final List<ProcessInfo> demoProcesses = [
  const ProcessInfo(pid: 4, name: 'System'),
  const ProcessInfo(
    pid: 1180,
    name: 'svchost.exe',
    path: r'C:\Windows\System32\svchost.exe',
    commandLine: r'C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache',
  ),
  const ProcessInfo(
    pid: 9120,
    name: 'chrome.exe',
    path: r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    commandLine: r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
  ),
  const ProcessInfo(
    pid: 7340,
    name: 'Discord.exe',
    path: '$_u\\AppData\\Local\\Discord\\app-1.0.9187\\Discord.exe',
  ),
  const ProcessInfo(
    pid: 5512,
    name: 'Spotify.exe',
    path: '$_u\\AppData\\Roaming\\Spotify\\Spotify.exe',
  ),
  const ProcessInfo(
    pid: 6620,
    name: 'steam.exe',
    path: r'C:\Program Files (x86)\Steam\steam.exe',
  ),
  const ProcessInfo(
    pid: 1520,
    name: 'Code.exe',
    path: '$_u\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe',
  ),
  const ProcessInfo(
    pid: 8848,
    name: 'svch0st.exe',
    path: '$_u\\AppData\\Local\\Temp\\svch0st.exe',
    commandLine: '"$_u\\AppData\\Local\\Temp\\svch0st.exe" --silent',
  ),
  const ProcessInfo(
    pid: 10432,
    name: 'invoice_2026.pdf.exe',
    path: '$_u\\Downloads\\invoice_2026.pdf.exe',
  ),
  const ProcessInfo(
    pid: 3964,
    name: 'powershell.exe',
    path: r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    commandLine: r'powershell.exe -File C:\Users\Mia\Scripts\backup.ps1',
  ),
  const ProcessInfo(
    pid: 7788,
    name: 'game_server.exe',
    path: r'C:\Games\BlockWorld\game_server.exe',
  ),
  const ProcessInfo(
    pid: 6100,
    name: 'Zoom.exe',
    path: '$_u\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe',
  ),
];

NetConnection _tcp(int pid, String la, int lp, String ra, int rp,
        [String state = 'Established']) =>
    NetConnection(
      protocol: 'TCP',
      localAddress: la,
      localPort: lp,
      remoteAddress: ra,
      remotePort: rp,
      state: state,
      pid: pid,
    );

NetConnection _listen(int pid, String la, int lp, {String protocol = 'TCP'}) =>
    NetConnection(
      protocol: protocol,
      localAddress: la,
      localPort: lp,
      remoteAddress: '',
      remotePort: 0,
      state: protocol == 'TCP' ? 'Listen' : 'Bound',
      pid: pid,
    );

const _me = '192.168.1.42';

final List<NetConnection> demoConnections = [
  _tcp(8848, _me, 51544, '185.220.101.47', 9001),
  _tcp(10432, _me, 51602, '45.142.212.61', 4444),
  _tcp(3964, _me, 51710, '140.82.112.3', 443),
  _listen(7788, '0.0.0.0', 25565),
  _tcp(7788, _me, 25565, '86.12.33.4', 50411),
  _tcp(9120, _me, 51320, '142.250.80.46', 443),
  _tcp(9120, _me, 51322, '142.250.72.110', 443),
  _tcp(7340, _me, 51401, '162.159.130.234', 443),
  _tcp(5512, _me, 51450, '35.186.224.25', 443),
  _tcp(6620, _me, 51480, '155.133.252.38', 27019),
  _tcp(1520, _me, 51500, '13.107.42.16', 443),
  _tcp(6100, _me, 51530, '170.114.52.2', 443),
  _tcp(1180, _me, 51200, '20.190.160.20', 443),
  _listen(4, '0.0.0.0', 445),
  _listen(1180, '0.0.0.0', 5353, protocol: 'UDP'),
  _tcp(9120, '127.0.0.1', 51800, '127.0.0.1', 51801),
];

final DateTime _now = DateTime.now();

final Map<String, FileInfo> demoFiles = {
  r'C:\Windows\System32\svchost.exe': FileInfo(
    path: r'C:\Windows\System32\svchost.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Microsoft Windows Publisher',
    company: 'Microsoft Corporation',
    product: 'Microsoft® Windows® Operating System',
    description: 'Host Process for Windows Services',
    created: DateTime(2025, 3, 2),
  ),
  r'C:\Program Files\Google\Chrome\Application\chrome.exe': FileInfo(
    path: r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Google LLC',
    company: 'Google LLC',
    product: 'Google Chrome',
    description: 'Google Chrome',
    created: DateTime(2026, 11, 2),
  ),
  '$_u\\AppData\\Local\\Discord\\app-1.0.9187\\Discord.exe': FileInfo(
    path: '$_u\\AppData\\Local\\Discord\\app-1.0.9187\\Discord.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Discord Inc.',
    company: 'Discord Inc.',
    product: 'Discord',
    created: DateTime(2026, 10, 28),
  ),
  '$_u\\AppData\\Roaming\\Spotify\\Spotify.exe': FileInfo(
    path: '$_u\\AppData\\Roaming\\Spotify\\Spotify.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Spotify AB',
    company: 'Spotify Ltd',
    product: 'Spotify',
    created: DateTime(2026, 9, 14),
  ),
  r'C:\Program Files (x86)\Steam\steam.exe': FileInfo(
    path: r'C:\Program Files (x86)\Steam\steam.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Valve Corp.',
    company: 'Valve Corporation',
    product: 'Steam',
    created: DateTime(2026, 8, 1),
  ),
  '$_u\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe': FileInfo(
    path: '$_u\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Microsoft Corporation',
    company: 'Microsoft Corporation',
    product: 'Visual Studio Code',
    created: DateTime(2026, 11, 10),
  ),
  '$_u\\AppData\\Local\\Temp\\svch0st.exe': FileInfo(
    path: '$_u\\AppData\\Local\\Temp\\svch0st.exe',
    exists: true,
    signature: SignatureStatus.notSigned,
    created: _now.subtract(const Duration(hours: 5)),
    size: 482304,
  ),
  '$_u\\Downloads\\invoice_2026.pdf.exe': FileInfo(
    path: '$_u\\Downloads\\invoice_2026.pdf.exe',
    exists: true,
    signature: SignatureStatus.notSigned,
    description: 'PDF Document',
    created: _now.subtract(const Duration(days: 1, hours: 2)),
    size: 1203712,
  ),
  r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe': FileInfo(
    path: r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Microsoft Windows',
    company: 'Microsoft Corporation',
    product: 'Microsoft® Windows® Operating System',
    description: 'Windows PowerShell',
    created: DateTime(2025, 3, 2),
  ),
  r'C:\Games\BlockWorld\game_server.exe': FileInfo(
    path: r'C:\Games\BlockWorld\game_server.exe',
    exists: true,
    signature: SignatureStatus.notSigned,
    product: 'BlockWorld Server',
    created: DateTime(2026, 9, 30),
  ),
  '$_u\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe': FileInfo(
    path: '$_u\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe',
    exists: true,
    signature: SignatureStatus.valid,
    signer: 'Zoom Video Communications, Inc.',
    company: 'Zoom Video Communications, Inc.',
    product: 'Zoom Workplace',
    created: DateTime(2026, 10, 3),
  ),
};

const Map<String, GeoInfo> demoGeo = {
  '185.220.101.47': GeoInfo(
      ip: '185.220.101.47',
      country: 'Germany',
      countryCode: 'DE',
      city: 'Berlin',
      org: 'Tor exit relay',
      isp: 'Artikel10 e.V.',
      proxy: true,
      hosting: true),
  '45.142.212.61': GeoInfo(
      ip: '45.142.212.61',
      country: 'Netherlands',
      countryCode: 'NL',
      city: 'Amsterdam',
      org: 'Unknown hosting LLC',
      hosting: true),
  '140.82.112.3': GeoInfo(
      ip: '140.82.112.3',
      country: 'United States',
      countryCode: 'US',
      city: 'Seattle',
      org: 'GitHub, Inc.'),
  '86.12.33.4': GeoInfo(
      ip: '86.12.33.4',
      country: 'United Kingdom',
      countryCode: 'GB',
      city: 'London',
      isp: 'Virgin Media'),
  '142.250.80.46': GeoInfo(
      ip: '142.250.80.46',
      country: 'United States',
      countryCode: 'US',
      city: 'New York',
      org: 'Google LLC'),
  '142.250.72.110': GeoInfo(
      ip: '142.250.72.110',
      country: 'United States',
      countryCode: 'US',
      city: 'Los Angeles',
      org: 'Google LLC'),
  '162.159.130.234': GeoInfo(
      ip: '162.159.130.234',
      country: 'United States',
      countryCode: 'US',
      city: 'San Francisco',
      org: 'Cloudflare, Inc.',
      hosting: true),
  '35.186.224.25': GeoInfo(
      ip: '35.186.224.25',
      country: 'United States',
      countryCode: 'US',
      city: 'Kansas City',
      org: 'Google Cloud (Spotify)',
      hosting: true),
  '155.133.252.38': GeoInfo(
      ip: '155.133.252.38',
      country: 'Sweden',
      countryCode: 'SE',
      city: 'Stockholm',
      org: 'Valve Corporation'),
  '13.107.42.16': GeoInfo(
      ip: '13.107.42.16',
      country: 'United States',
      countryCode: 'US',
      city: 'Redmond',
      org: 'Microsoft Corporation'),
  '170.114.52.2': GeoInfo(
      ip: '170.114.52.2',
      country: 'United States',
      countryCode: 'US',
      city: 'San Jose',
      org: 'Zoom Video Communications'),
  '20.190.160.20': GeoInfo(
      ip: '20.190.160.20',
      country: 'United States',
      countryCode: 'US',
      city: 'Boydton',
      org: 'Microsoft Azure'),
};
