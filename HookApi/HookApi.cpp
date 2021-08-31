#include <iostream>
#include <windows.h>
#include <tchar.h>
#include "detours.h"

#pragma comment(lib,"detours.lib")


static int(WINAPI* OLD_MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) = MessageBoxW;

int WINAPI NEW_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	//修改输入参数，调用原函数
	int ret = OLD_MessageBoxW(hWnd, L"Hook", L"Hook", uType);
	return ret;
}

void Hook()
{
	DetourRestoreAfterWith();//恢复原来状态
	DetourTransactionBegin();//拦截开始
	DetourUpdateThread(GetCurrentThread());//刷新当前线程
	DetourAttach((void **)&OLD_MessageBoxW, NEW_MessageBoxW);
	DetourTransactionCommit();//拦截生效
}
void UnHook()
{

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((void **)&OLD_MessageBoxW, NEW_MessageBoxW);//撤销拦截函数
	DetourTransactionCommit();
}

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	if (!DetourCreateProcessWithDllEx(_T("D:\\PddPrint\\PDDPrintClient.exe"),
		NULL, NULL, NULL, TRUE,
		CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED,
		NULL, _T("D:\\PddPrint\\"), &si, &pi,
		"HookApiDLL.dll", NULL))
		printf("Failed");
	else
		printf("Success");

	/*if (!DetourCreateProcessWithDllEx(_T("D:\\Websocket.exe"),
			NULL, NULL, NULL, TRUE,
			CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED,
			NULL, _T("D:\\"), &si, &pi,
			"D:\\PddPrint\\HookApiDLL.dll", NULL))
			printf("Failed");
		else
			printf("Success");*/

	ResumeThread(pi.hThread);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return EXIT_SUCCESS;
}
