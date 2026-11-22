// Asks Windows directly (through its kernel32.dll) for the full path of a
// running program. This works for many programs whose folder is hidden from
// PowerShell when the app is not running as administrator.

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

typedef _OpenProcessNative = IntPtr Function(
    Uint32 desiredAccess, Int32 inheritHandle, Uint32 processId);
typedef _OpenProcessDart = int Function(
    int desiredAccess, int inheritHandle, int processId);

typedef _QueryImageNameNative = Int32 Function(
    IntPtr process, Uint32 flags, Pointer<Utf16> exeName, Pointer<Uint32> size);
typedef _QueryImageNameDart = int Function(
    int process, int flags, Pointer<Utf16> exeName, Pointer<Uint32> size);

typedef _CloseHandleNative = Int32 Function(IntPtr handle);
typedef _CloseHandleDart = int Function(int handle);

const int _processQueryLimitedInformation = 0x1000;
const int _maxPathChars = 32768;

class _Kernel32 {
  _Kernel32(DynamicLibrary lib)
      : openProcess = lib.lookupFunction<_OpenProcessNative, _OpenProcessDart>(
            'OpenProcess'),
        queryImageName =
            lib.lookupFunction<_QueryImageNameNative, _QueryImageNameDart>(
                'QueryFullProcessImageNameW'),
        closeHandle = lib.lookupFunction<_CloseHandleNative, _CloseHandleDart>(
            'CloseHandle');

  final _OpenProcessDart openProcess;
  final _QueryImageNameDart queryImageName;
  final _CloseHandleDart closeHandle;

  static _Kernel32? tryLoad() {
    if (!Platform.isWindows) return null;
    try {
      return _Kernel32(DynamicLibrary.open('kernel32.dll'));
    } catch (_) {
      return null;
    }
  }
}

final _Kernel32? _kernel32 = _Kernel32.tryLoad();

/// Full path of the program running as [pid], or null if Windows won't say.
String? queryProcessImagePath(int pid) {
  final api = _kernel32;
  if (api == null || pid <= 4) return null;

  final handle = api.openProcess(_processQueryLimitedInformation, 0, pid);
  if (handle == 0) return null;

  final buffer = calloc<Uint16>(_maxPathChars).cast<Utf16>();
  final size = calloc<Uint32>()..value = _maxPathChars;
  try {
    if (api.queryImageName(handle, 0, buffer, size) == 0) return null;
    final path = buffer.toDartString(length: size.value);
    return path.isEmpty ? null : path;
  } finally {
    calloc.free(buffer);
    calloc.free(size);
    api.closeHandle(handle);
  }
}
