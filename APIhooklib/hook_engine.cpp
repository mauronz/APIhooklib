#include <windows.h>
#include <stdio.h>
#include <intrin.h>

#include "hook_engine.h"
#include "Disassembler\hde32.h"

//use _InterlockedCompareExchange64 instead of inline ASM (depends on compiler)
#define NO_INLINE_ASM

LPVOID OriginalMemArea;

//We need to copy 5 bytes, but we can only do 2, 4, 8 atomically
//Pad buffer to 8 bytes then use lock cmpxchg8b instruction
void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size)
{
	BYTE SourceBuffer[8];

	if(size > 8)
		return;

	//Pad the source buffer with bytes from destination
	memcpy(SourceBuffer, destination, 8);
	memcpy(SourceBuffer, source, size);

#ifndef NO_INLINE_ASM
	__asm 
	{
		lea esi, SourceBuffer;
		mov edi, destination;

		mov eax, [edi];
		mov edx, [edi+4];
		mov ebx, [esi];
		mov ecx, [esi+4];

		lock cmpxchg8b[edi];
	}
#else
	_InterlockedCompareExchange64((LONGLONG *)destination, *(LONGLONG *)SourceBuffer, *(LONGLONG *)destination);
#endif
}

BOOL HookFunction(LPVOID addr, LPVOID proxy, LPVOID original, PDWORD length)
{
	DWORD TrampolineLength = 0, OriginalProtection;
	hde32s disam;
	BYTE Jump[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
	LPVOID FunctionAddress = addr;

	//disassemble length of each instruction, until we have 5 or more bytes worth
	while(TrampolineLength < 5)
	{
		LPVOID InstPointer = (LPVOID)((DWORD)FunctionAddress + TrampolineLength);
		TrampolineLength += hde32_disasm(InstPointer, &disam);
	}

	//Build the trampoline buffer
	memcpy(original, FunctionAddress, TrampolineLength);
	*(DWORD *)(Jump+1) = ((DWORD)FunctionAddress + TrampolineLength) - ((DWORD)original + TrampolineLength + 5);
	memcpy((LPVOID)((DWORD)original+TrampolineLength), Jump, 5);

	//Make sure the function is writable
	if(!VirtualProtect(FunctionAddress, TrampolineLength, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;

	//Build and atomically write the hook
	*(DWORD *)(Jump+1) = (DWORD)proxy - (DWORD)FunctionAddress - 5;
	SafeMemcpyPadded(FunctionAddress, Jump, 5);

	//Restore the original page protection
	VirtualProtect(FunctionAddress, TrampolineLength, OriginalProtection, &OriginalProtection);

	//Clear CPU instruction cache
	FlushInstructionCache(GetCurrentProcess(), FunctionAddress, TrampolineLength);

	*length = TrampolineLength;
	return TRUE;
}

BOOL UnhookFunction(CHAR *dll, CHAR *name, LPVOID original, DWORD length)
{
	LPVOID FunctionAddress;
	DWORD OriginalProtection;

	FunctionAddress = GetProcAddress(GetModuleHandleA(dll), name);
	if(!FunctionAddress)
		return FALSE;

	if(!VirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;

	SafeMemcpyPadded(FunctionAddress, original, length);

	VirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection);

	FlushInstructionCache(GetCurrentProcess(), FunctionAddress, length);

	return TRUE;
}

