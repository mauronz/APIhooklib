#include <Windows.h>
#include <stdio.h>
#include "hook_engine.h"
#include "APIhooklib.h"
#include <map>

#define ASM_SIZE(asm) (sizeof(asm) - 1)

typedef struct _api_hook {
	LPVOID original;
	LPVOID stub;
	DWORD length;
} api_hook;

std::map<DWORD, api_hook> hooks;


FARPROC SetHookByName(LPSTR lpDllName, LPSTR lpFuncName, DWORD dwNumArgs, CallConv callConv, FARPROC lpBeforeHook, FARPROC lpAfterHook, BOOL bDoCall, BOOL bOverrideRet, BOOL bOverrideParams) {
	return SetHookByNameWithId(NO_ID, lpDllName, lpFuncName, dwNumArgs, callConv, lpBeforeHook, lpAfterHook, bDoCall, bOverrideRet, bOverrideParams);
}

FARPROC SetHookByNameWithId(int id, LPSTR lpDllName, LPSTR lpFuncName, DWORD dwNumArgs, CallConv callConv, FARPROC lpBeforeHook, FARPROC lpAfterHook, BOOL bDoCall, BOOL bOverrideRet, BOOL bOverrideParams) {
	HMODULE hLib = LoadLibraryA(lpDllName);
	if (!hLib)
		return NULL;
	LPVOID addr = (LPVOID)GetProcAddress(hLib, lpFuncName);
	if (!addr)
		return NULL;
	return SetHookByAddrWithId(id, addr, dwNumArgs, callConv, lpBeforeHook, lpAfterHook, bDoCall, bOverrideRet, bOverrideParams);
}

FARPROC SetHookByAddr(LPVOID lpaddr, DWORD dwNumArgs, CallConv callConv, FARPROC lpBeforeHook, FARPROC lpAfterHook, BOOL bDoCall, BOOL bOverrideRet, BOOL bOverrideParams) {
	return SetHookByAddrWithId(NO_ID, lpaddr, dwNumArgs, callConv, lpBeforeHook, lpAfterHook, bDoCall, bOverrideRet, bOverrideParams);
}

FARPROC SetHookByAddrWithId(int id, LPVOID lpaddr, DWORD dwNumArgs, CallConv callConv, FARPROC lpBeforeHook, FARPROC lpAfterHook, BOOL bDoCall, BOOL bOverrideRet, BOOL bOverrideParams) {
	LPVOID original;
	DWORD length, size, offset, tmp;
	DWORD addr = (DWORD)lpaddr;

	BYTE head[] = "\x55\x89\xE5";  // push ebp; mov ebp, esp
	BYTE push_param[] = "\x8B\x45X\x50";  // mov eax, [ebp+X]; push eax
	BYTE push_param_ptr[] = "\x8D\x45X\x50";  // lea eax, [ebp+X]; push eax
	BYTE push1_imm[] = "\x6aX\x90\x90\x90"; // push X; nop; nop
	BYTE push4_imm[] = "\x68XXXX"; // push X
	BYTE call_func[] = "\xE8XXXX"; // call XXXX
	BYTE fix_stack[] = "\x83\xC4X"; // add esp, X
	BYTE end[] = "\x89\xEC\x5D"; // mov esp,ebp; pop ebp;
	BYTE ret_stdcall[] = "\xC2XX"; // ret XX
	BYTE ret_cdecl[] = "\xC3"; // ret

	api_hook *hook = &hooks[addr];
	if (hook->original != NULL) {
		printf("Hook already set at 0x%08x, aborting...\n", addr);
		return NULL;
	}
	
	original = VirtualAlloc(NULL, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	size = ASM_SIZE(head);
	if (lpBeforeHook) {
		size += ASM_SIZE(push_param) * dwNumArgs + ASM_SIZE(call_func) + ASM_SIZE(fix_stack);
		if (id != NO_ID)
			size += ASM_SIZE(push4_imm);
	}

	if (bDoCall)
		size += ASM_SIZE(push_param) * dwNumArgs + ASM_SIZE(call_func) + ASM_SIZE(fix_stack);

	if (lpAfterHook) {
		size += ASM_SIZE(push_param) * dwNumArgs + ASM_SIZE(call_func) + ASM_SIZE(fix_stack) + 1; // +1 = push eax
		if (id != NO_ID)
			size += ASM_SIZE(push4_imm);
	}

	if (!bOverrideRet)
		size += 2; // push eax / pop eax to save the return value

	size += ASM_SIZE(end) + ASM_SIZE(ret_stdcall);

	offset = 0;
	tmp = dwNumArgs * 4;
	memcpy(ret_stdcall + 1, &tmp, 2);

	tmp = dwNumArgs * 4;
	fix_stack[2] = (BYTE)tmp;

	BYTE hook_fix_stack[4];
	memcpy(hook_fix_stack, fix_stack, ASM_SIZE(fix_stack));
	if (id != NO_ID)
		hook_fix_stack[2] += 4;


	LPBYTE stub = (LPBYTE)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// fill stub with NOPs
	memset(stub, 0x90, size);

	PBYTE push_imm = NULL;
	if (id != NO_ID) {
		if (id < 128) {
			push_imm = push1_imm;
			push_imm[1] = id;
		}
		else {
			push_imm = push4_imm;
			*(int*)(push_imm + 1) = id;
		}

	}

	memcpy(stub, head, 3);
	offset += 3;

	if (lpBeforeHook) {
		// Push params for before-hook
		BYTE* push_bh_param = bOverrideParams ? push_param_ptr : push_param;
		for (int i = dwNumArgs - 1; i >= 0; i--) {
			push_bh_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_bh_param, ASM_SIZE(push_param));
			offset += ASM_SIZE(push_param);
		}

		if (id != NO_ID) {
			memcpy(stub + offset, push_imm, ASM_SIZE(push4_imm));
			offset += ASM_SIZE(push4_imm);
		}

		// Call before-hook
		DWORD tmp = (DWORD)lpBeforeHook - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, ASM_SIZE(call_func));
		offset += ASM_SIZE(call_func);
		memcpy(stub + offset, hook_fix_stack, ASM_SIZE(hook_fix_stack));
		offset += ASM_SIZE(hook_fix_stack);
	}
	
	if (bDoCall) {
		// Push params for function
		for (int i = dwNumArgs - 1; i >= 0; i--) {
			push_param[2] = (BYTE)(i * 4 + 8);
			memcpy(stub + offset, push_param, ASM_SIZE(push_param));
			offset += ASM_SIZE(push_param);
		}

		// Call fuction
		tmp = (DWORD)original - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, ASM_SIZE(call_func));
		offset += ASM_SIZE(call_func);

		if (callConv == CV_CDECL) {
			memcpy(stub + offset, fix_stack, ASM_SIZE(fix_stack));
			offset += ASM_SIZE(fix_stack);
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
			memcpy(stub + offset, push_param, ASM_SIZE(push_param));
			offset += ASM_SIZE(push_param);
		}

		if (id != NO_ID) {
			memcpy(stub + offset, push_imm, ASM_SIZE(push4_imm));
			offset += ASM_SIZE(push4_imm);
		}

		// Call after-hook
		tmp = (DWORD)lpAfterHook - ((DWORD)stub + offset) - 5;
		memcpy(call_func + 1, &tmp, 4);
		memcpy(stub + offset, call_func, ASM_SIZE(call_func));
		offset += ASM_SIZE(call_func);
		// after-hook has one more param (the real return value)
		hook_fix_stack[2] += 4;
		memcpy(stub + offset, hook_fix_stack, ASM_SIZE(hook_fix_stack));
		offset += ASM_SIZE(hook_fix_stack);

		// Pop return value from stack (pop eax)
		if (!bOverrideRet) {
			stub[offset] = 0x58;
			offset++;
		}
	}

	memcpy(stub + offset, end, ASM_SIZE(end));
	offset += ASM_SIZE(end);
	if (callConv == CV_STDCALL) {
		memcpy(stub + offset, ret_stdcall, ASM_SIZE(ret_stdcall));
		offset += ASM_SIZE(ret_stdcall);
	}
	else {
		memcpy(stub + offset, ret_cdecl, ASM_SIZE(ret_cdecl));
		offset += ASM_SIZE(ret_cdecl);
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