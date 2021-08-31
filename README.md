# websocket_hook_ws
不支持hookwss\n
依赖：https://github.com/microsoft/Detours\n
DetourRestoreAfterWith();
DetourTransactionBegin();
DetourUpdateThread(GetCurrentThread());
LPVOID g_pOldHTMLayoutProcND = DetourFindFunction("htmlayout.dll", "HTMLayoutProcND");
DetourAttach(&g_pOldHTMLayoutProcND, MyHTMLayoutProcND);
if (DetourTransactionCommit() == NO_ERROR)
OutputDebugString(_T("MyHTMLayoutProcND detoured successfully"));
