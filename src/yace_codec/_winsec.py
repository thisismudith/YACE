"""Windows security helpers (ctypes, no extra dependencies).

- :func:`protect` / :func:`unprotect`: DPAPI (``CryptProtectData``), which
  encrypts data with a key tied to the current Windows user account.
- :func:`restrict_to_owner`: give a file a protected DACL that allows only
  the current user and SYSTEM.

On other systems the functions raise :class:`~yace_codec.errors.KeyStoreError`
(or do nothing, for :func:`restrict_to_owner`).
"""

from __future__ import annotations

import sys

from .errors import KeyStoreError

__all__ = ["protect", "restrict_to_owner", "unprotect"]

_ENTROPY = b"yace-codec secret key"

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _CryptProtectData = _crypt32.CryptProtectData
    _CryptProtectData.argtypes = (
        ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.POINTER(_Blob), wintypes.LPVOID,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(_Blob),
    )
    _CryptProtectData.restype = wintypes.BOOL
    _CryptUnprotectData = _crypt32.CryptUnprotectData
    _CryptUnprotectData.argtypes = (
        ctypes.POINTER(_Blob), wintypes.LPVOID, ctypes.POINTER(_Blob), wintypes.LPVOID,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(_Blob),
    )
    _CryptUnprotectData.restype = wintypes.BOOL
    _LocalFree = _kernel32.LocalFree
    _LocalFree.argtypes = (wintypes.HLOCAL,)
    _LocalFree.restype = wintypes.HLOCAL
    _GetCurrentProcess = _kernel32.GetCurrentProcess
    _GetCurrentProcess.restype = wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = (wintypes.HANDLE,)
    _OpenProcessToken = _advapi32.OpenProcessToken
    _OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    _OpenProcessToken.restype = wintypes.BOOL
    _GetTokenInformation = _advapi32.GetTokenInformation
    _GetTokenInformation.argtypes = (
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    )
    _GetTokenInformation.restype = wintypes.BOOL
    _ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
    _ConvertSidToStringSidW.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR))
    _ConvertSidToStringSidW.restype = wintypes.BOOL
    _ConvertSddl = _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    _ConvertSddl.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG),
    )
    _ConvertSddl.restype = wintypes.BOOL
    _SetFileSecurityW = _advapi32.SetFileSecurityW
    _SetFileSecurityW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID)
    _SetFileSecurityW.restype = wintypes.BOOL

    _CRYPTPROTECT_UI_FORBIDDEN = 0x1
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _SDDL_REVISION_1 = 1
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

    def _blob(data: bytes) -> "tuple[_Blob, ctypes.Array[ctypes.c_char]]":
        buffer = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer

    def _take(blob: _Blob) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            _LocalFree(ctypes.cast(blob.pbData, wintypes.HLOCAL))

    def protect(data: bytes) -> bytes:
        """Encrypt ``data`` for the current Windows user with DPAPI."""
        source, _keep = _blob(data)
        entropy, _keep_entropy = _blob(_ENTROPY)
        out = _Blob()
        if not _CryptProtectData(
            ctypes.byref(source), "yace-codec key", ctypes.byref(entropy), None, None,
            _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out),
        ):
            raise KeyStoreError(f"DPAPI could not protect a key: {ctypes.WinError(ctypes.get_last_error())}")
        return _take(out)

    def unprotect(data: bytes) -> bytes:
        """Decrypt DPAPI data protected by :func:`protect` for this user."""
        source, _keep = _blob(data)
        entropy, _keep_entropy = _blob(_ENTROPY)
        out = _Blob()
        if not _CryptUnprotectData(
            ctypes.byref(source), None, ctypes.byref(entropy), None, None,
            _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out),
        ):
            raise KeyStoreError(
                "DPAPI could not unprotect a key; it was protected by another Windows "
                f"user or computer ({ctypes.WinError(ctypes.get_last_error())})"
            )
        return _take(out)

    def _current_user_sid() -> str:
        token = wintypes.HANDLE()
        if not _OpenProcessToken(_GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = wintypes.DWORD()
            _GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not _GetTokenInformation(token, _TOKEN_USER, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = ctypes.cast(buffer, ctypes.POINTER(_SidAndAttributes)).contents.Sid
            text = wintypes.LPWSTR()
            if not _ConvertSidToStringSidW(sid, ctypes.byref(text)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return str(text.value)
            finally:
                _LocalFree(ctypes.cast(text, wintypes.HLOCAL))
        finally:
            _CloseHandle(token)

    def restrict_to_owner(path: str) -> None:
        """Allow only the current user and SYSTEM to access ``path``; nothing is inherited."""
        sddl = f"D:P(A;;FA;;;{_current_user_sid()})(A;;FA;;;SY)"
        descriptor = wintypes.LPVOID()
        if not _ConvertSddl(sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not _SetFileSecurityW(
                path, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION, descriptor
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))

else:

    def protect(data: bytes) -> bytes:
        raise KeyStoreError("DPAPI key stores are only available on Windows")

    def unprotect(data: bytes) -> bytes:
        raise KeyStoreError("DPAPI key stores are only available on Windows")

    def restrict_to_owner(path: str) -> None:
        """New key store files are already created with mode 0600 on POSIX."""
