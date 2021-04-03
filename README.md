# APIhooklib

APIhooklib is a static library that contains a set of functions to perform function hooking in the current process. The basic idea is to use this library inside a DLL which will be loaded/injected in the target process.

There are two ways to set hooks:
- **by address**: directly specify the address in memory of the function to be hooked. This allows to hook any function from any module of the process. Note that you will to take into account the relocation. A simple solution is to compute the address as module_base + function_offset, where function_offset is hardcoded and module_base is retrieve at runtime.
- **by name**: specify the name of the module and the name of the function to be hooked. This is the easiest way if you are only interested in hooking Windows API functions.

In both cases it is possible to set two hooks, one before and one after the execution of the target function.

The prototypes of the two functions for setting the hooks are:

```c
FARPROC SetHookByName(
	LPSTR lpDllName, 
	LPSTR lpFuncName, 
	DWORD dwNumArgs,
	CallConv callConv,
	FARPROC lpBeforeHook, 
	FARPROC lpAfterHook,
	BOOL bDoCall,
	BOOL bOverrideRet
);

FARPROC SetHookByAddr(
	LPVOID addr,
	DWORD dwNumArgs,
	CallConv callConv,
	FARPROC lpBeforeHook,
	FARPROC lpAfterHook,
	BOOL bDoCall,
	BOOL bOverrideRet
);
```

- **dwNumArgs**: number of arguments of the hooked function
- **callConv**: calling convention of the hooked function (either CV_STDCALL or CV_CDECL)
- **lpBeforeHook**: address of the hook executed before the hooked function (can be NULL if not needed)
- **lpAfterHook**: address of the hook executed after the hooked function (can be NULL if not needed)
- **bDoCall**: if bDoCall is FALSE the hooked function is bypassed, otherwise it is executed
- **bOverrideRet**: if bOverrideRet is TRUE the return value of the last executed hook will be returned to the callee, otherwise the return value of the hooked function will be returned

**return value**: both functions return the address of a trampoline to the original target function. If one of the hooks needs to use another hooked function, it must call this trampoline (with the same prototype of the hooked function). In this way we avoid "false positives" and dangerous recursions.

## Hook routines
Both hook routines must use the cdecl calling convention.
The prototype of the before-hook is identical to that of the hooked function.
The prototype of the before-hook is identical to that of the hooked function, with an additional parameter for the return value.
For example:

Target:
```c
FARPROC GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName
);
```
Before-hook:
```c
FARPROC bh_GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName
);
```
After-hook:
```c
FARPROC bh_GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName,
  FARPROC pRetValue
);
```
