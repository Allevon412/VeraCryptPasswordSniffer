#pragma once
int FromBase64Crypto(const BYTE* pSrc, int nLenSrc, char* pDst, int nLenDst);
void convert_str(unsigned char* src_str, int src_len, char* dest_str, char * dest_2);
HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName);