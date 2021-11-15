#pragma once
#include <Windows.h>

// pointer to original WideCharToMultiByte
int (WINAPI* pWideCharToMultiByte)(
	UINT                               CodePage,
	DWORD                              dwFlags,
	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
	int                                cchWideChar,
	LPSTR                              lpMultiByteStr,
	int                                cbMultiByte,
	LPCCH                              lpDefaultChar,
	LPBOOL                             lpUsedDefaultChar) = WideCharToMultiByte;

BOOL IAT_Hookem(char* dll, char* origFunc, PROC hookingFunc);
BOOL Hookem(void);
BOOL UnHookem(void);