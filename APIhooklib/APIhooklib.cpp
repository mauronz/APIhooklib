#include <Windows.h>
#include <stdio.h>
#include "hook_engine.h"
#include "APIhooklib.h"
#include <map>

typedef struct _api_hook {
	LPVOID original;
	LPVOID stub;
	DWORD length;
} api_hook;

std::map<DWORD, api_hook> hooks;

FARPROC SetHookByName(LPSTR lpDllName, LPSTR lpFuncName, DWORD dwNumArgs, CallConv callConv, FARPROC lpBeforeHook, FARPROC lpAfterHook, BOOL bDoCall, BOOL bOverrideRet) {
	LPVOID addr = (LPVOID)GetProcAddress(LoadLibraryA(lpDllName), lpFuncName);
	return SetHookByAddr(addr, dwNumArgs, callConv, lpBeforeHook, lpAfterHook, bDoCall, bOverrideRet);
}

FARPROC SetHookByAddr(LPVOID lpaddr, DWORD dwNumArgs, CallConv callConv, FARPROC lpBeforeHook, FARPROC lpAfterHook, BOOL bDoCall, BOOL bOverrideRet) {
	LPVOID original;
	DWORD length, size, offset, tmp;
	DWORD addr = (DWORD)lpaddr;

	BYTE head[] = "\x55\x89\xE5";  // push ebp; mov ebp, esp
	BYTE push_param[] = "\x8B\x45X\x50";  // mov eax, [ebp+X]; push eax
	BYTE call_func[] = "\xE8XXXX"; // call XXXX
	BYTE fix_stack[] = "\x83\xECX"; // sub esp, X
	BYTE end[] = "\x89\xEC\x5D"; // mov esp,ebp; pop ebp;
	BYTE ret_stdcall[] = "\xC2XX"; // ret XX
	BYTE ret_cdecl[] = "\xC3"; // ret

	api_hook *hook = &hooks[addr];
	if (hook->original != NULL) {
		printf("Hook already set at 0x%08x, aborting...\n", addr);
		return NULL;
	}
	
	original = VirtualAlloc(NULL, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	size = 3 + 6;
	if (lpBeforeHook)
		size += 4 * dwNumArgs + 5;
	if (bDoCall)
		size += 4 * dwNumArgs + 5;
	if (lpAfterHook)
		size += 4 * dwNumArgs + 5 + 1;
	if (!bOverrideRet)
		size += 2;
	offset = 0;
	tmp = dwNumArgs * 4;
	memcpy(ret_stdcall + 1, &tmp, 2);

	LPBYTE stub = (LPBYTE)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// fill stub with NOPs
	memset(stub, 0x90, size);


	memcpy(stub, head, 3);
	offset += 3;

	if (lpBeforeHook) {
		// Push params for before-hook
		for (int i = dwNumArgs - 1; i >= 0; i--) {
			push_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_param, 4);
			offset += 4;
		}

		// Call before-hook
		DWORD tmp = (DWORD)lpBeforeHook - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, 5);
		offset += 5;
	}
	
	if (bDoCall) {
		// Push params for function
		for (int i = dwNumArgs - 1; i >= 0; i--) {
			push_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_param, 4);
			offset += 4;
		}

		// Call fuction
		tmp = (DWORD)original - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, 5);
		offset += 5;

		if (callConv == CV_CDECL) {
			tmp = dwNumArgs * 4;
			memcpy(fix_stack + 2, &tmp, 1);
			memcpy(stub + offset, fix_stack, 3);
			offset += 3;
		}
	}
	
	if (lpAfterHook) {
		// Push return value to save it for later (push eax)
		if (!bOverrideRet) {
			stub[offset] = 0x50;
			offset++;
		}

		// Push return value to pass it as parameter of after-hook
		stub[offset] = 0x50;
		offset++;

		// Push params for after-hook
		for (int i = dwNumArgs - 1; i >= 0; i--) {
			push_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_param, 4);
			offset += 4;
		}

		// Call after-hook
		tmp = (DWORD)lpAfterHook - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, 5);
		offset += 5;

		// Pop return value from stack (pop eax)
		if (!bOverrideRet) {
			stub[offset] = 0x58;
			offset++;
		}
	}

	memcpy(stub + offset, end, 3);
	offset += 3;
	if (callConv == CV_STDCALL) {
		memcpy(stub + offset, ret_stdcall, 3);
		offset += 3;
	}
	else {
		memcpy(stub + offset, ret_cdecl, 1);
		offset += 1;
	}

	HookFunction((LPVOID)addr, stub, original, &length);

	hook->original = original;
	hook->stub = stub;
	hook->length = length;

	return (FARPROC)original;
}

BOOL RemoveHook(LPSTR lpDllName, LPSTR lpFuncName) {
	DWORD addr = (DWORD)GetProcAddress(LoadLibraryA(lpDllName), lpFuncName);
	api_hook *hook = &hooks[addr];
	if (hook->original == NULL) {
		return FALSE;
	}
	UnhookFunction(lpDllName, lpFuncName, hook->original, hook->length);
	VirtualFree(hook->original, 0, MEM_RELEASE);
	VirtualFree(hook->stub, 0, MEM_RELEASE);
	memset(hook, 0, sizeof(api_hook));
}