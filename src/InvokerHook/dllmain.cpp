// Copyright (c) 2019 Ivan Šincek

#include <windows.h>

void MsgBox() {
	MessageBoxA(0, "Hello from InvokerHook DLL!\n", "Invoker", MB_OK);
}

// NOTE: Do not change the name of this method. This method is required.
// NOTE: Feel free to change the content of this method - make your own hook procedure.
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION) {
		PCWPSTRUCT data = (PCWPSTRUCT)lParam;
		// NOTE: Invoke a message box on window close.
		if (data->message == WM_CLOSE) {
			MsgBox();
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// NOTE: Do not change the name of this method. This method is required.
// NOTE: Change the return value (i.e. hook type) as necessary.
extern "C" __declspec(dllexport) int GetHookType() {
	return WH_CALLWNDPROC;
	// return WH_CALLWNDPROCRET;
	// return WH_CBT;
	// return WH_DEBUG;
	// return WH_FOREGROUNDIDLE;
	// return WH_GETMESSAGE;
	// return WH_JOURNALPLAYBACK;
	// return WH_JOURNALRECORD;
	// return WH_KEYBOARD;
	// return WH_KEYBOARD_LL;
	// return WH_MOUSE;
	// return WH_MOUSE_LL;
	// return WH_MSGFILTER;
	// return WH_SHELL;
	// return WH_SYSMSGFILTER;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
		// NOTE: You can also try and play with this.
		case DLL_PROCESS_ATTACH: { break; } // NOTE: This case will run on DLL load - e.g. upon DLL injection.
		case DLL_PROCESS_DETACH: { break; }
		case DLL_THREAD_ATTACH:  { break; }
		case DLL_THREAD_DETACH:  { break; } // NOTE: This case will run on DLL unload.
	}
	return TRUE;
}

