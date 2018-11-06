#ifndef HOOK_ENGINE
#define HOOK_ENGINE

#include <Windows.h>

BOOL HookFunction(LPVOID addr, LPVOID proxy, LPVOID original, PDWORD length);
BOOL UnhookFunction(CHAR *dll, CHAR *name, LPVOID original, DWORD length);

#endif