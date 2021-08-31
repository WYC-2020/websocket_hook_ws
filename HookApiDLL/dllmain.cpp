#include "pch.h"
#include <windows.h>
#include <WinSock2.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>
#include <map>
#include <mutex>
#include "detours.h"
#include "ws_endpoint.h"

#pragma comment(lib,"detours.lib")
#pragma comment(lib,"ws2_32.lib")

int (WINAPI *pSend)(SOCKET , const char* , int ,int ) = send;
int (WINAPI *pRecv)(SOCKET , char* , int , int ) = recv;
int(WSAAPI *pWSARecv)(SOCKET,LPWSABUF , DWORD ,LPDWORD ,LPDWORD ,LPWSAOVERLAPPED ,LPWSAOVERLAPPED_COMPLETION_ROUTINE ) = WSARecv;
int(WSAAPI*pWSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = WSASend;
BOOL (WSAAPI*pWSAGetOverlappedResult)(SOCKET,LPWSAOVERLAPPED ,LPDWORD ,BOOL ,LPDWORD )= WSAGetOverlappedResult;
BOOL (WINAPI*pGetQueuedCompletionStatus)(HANDLE ,LPDWORD ,PULONG_PTR , LPOVERLAPPED*,DWORD)=GetQueuedCompletionStatus;

typedef struct ST_CONTEXT_INFO
{
	char*pBuffer{ nullptr };
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine{ nullptr };
}ST_CONTEXT_INFO;

std::map<LPWSAOVERLAPPED, ST_CONTEXT_INFO> g_map;
std::mutex g_mutex;

void OutputDebugStringFomart(LPCTSTR lpszFormat, ...)
{
	va_list arglist;
	va_start(arglist, lpszFormat);
	TCHAR outputstr[4095] = {0};
	_vstprintf(outputstr, lpszFormat, arglist);
	OutputDebugString(outputstr);
}

void CALLBACK MyCompletionRoutine(IN DWORD dwError,IN DWORD cbTransferred,IN LPWSAOVERLAPPED lpOverlapped,IN DWORD dwFlags)
{
	std::unique_lock<std::mutex>lock(g_mutex);
	auto it = g_map.find(lpOverlapped);
	if (it != g_map.end())
	{
		OutputDebugStringFomart("%s:length:%d-data:%s", "MyCompletionRoutine", cbTransferred, it->second.pBuffer);
		g_map.erase(it);
		lock.unlock();
		it->second.lpCompletionRoutine(dwError, cbTransferred, lpOverlapped, dwFlags);
	}
}

BOOL WSAAPI MyWSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lpOverlapped, LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags)
{
	std::unique_lock<std::mutex>lock(g_mutex);
	auto it = g_map.find(lpOverlapped);
	if (it != g_map.end())
	{
		OutputDebugStringFomart("%s:length:%d-data:%s", "WSAGetOverlappedResult", lpcbTransfer, it->second.pBuffer);
		g_map.erase(it);
		lock.unlock();
	}
	return pWSAGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags);
}

void write_cb(char * buf, int64_t size, void* wd)
{
	TCHAR outputstr[4095] = { 0 };
	sprintf(outputstr, "length:%I64d-data:%s", size, buf);

	OutputDebugStringFomart(outputstr);
}

WebSocketEndpoint endpoint(write_cb);

BOOL WINAPI MyGetQueuedCompletionStatus(HANDLE CompletionPort, LPDWORD lpNumberOfBytesTransferred, PULONG_PTR lpCompletionKey, LPOVERLAPPED* lpOverlapped, DWORD dwMilliseconds)
{
	BOOL completed= pGetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds);
	if (completed)
	{
		std::unique_lock<std::mutex>lock(g_mutex);
		auto it = g_map.find(*lpOverlapped);
		if (it != g_map.end())
		{
			endpoint.from_wire(it->second.pBuffer, *lpNumberOfBytesTransferred);
			g_map.erase(it);
			lock.unlock();
		}
	}
	return completed;
}

int WINAPI MyWSARecv(_In_ SOCKET s, _In_reads_(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers, _In_ DWORD dwBufferCount, _Out_opt_ LPDWORD lpNumberOfBytesRecvd, _Inout_ LPDWORD lpFlags, _Inout_opt_ LPWSAOVERLAPPED lpOverlapped, _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (!lpOverlapped)
	{
		OutputDebugStringFomart("%s:length:%d-data:%s", "WSARecv", lpBuffers->len, lpBuffers->buf);
	}

	if ((lpOverlapped != nullptr) && (lpCompletionRoutine != nullptr))
	{
		std::unique_lock<std::mutex>lock(g_mutex);
		ST_CONTEXT_INFO stContext;
		stContext.pBuffer = lpBuffers->buf;
		stContext.lpCompletionRoutine = lpCompletionRoutine;
		lpCompletionRoutine = MyCompletionRoutine;

		g_map[lpOverlapped] = stContext;
	}

	if ((lpOverlapped != NULL) &&(lpCompletionRoutine==NULL)&&(lpOverlapped->hEvent != NULL))
	{
		//WSAGetOverlappedResult
		std::unique_lock<std::mutex>lock(g_mutex);
		ST_CONTEXT_INFO stContext;
		stContext.pBuffer = lpBuffers->buf;
		g_map[lpOverlapped] = stContext;
	}

	if ((lpOverlapped != NULL) && (lpOverlapped->hEvent == NULL) && (lpCompletionRoutine == NULL))
	{
		//GetQueuedCompletionStatus
		std::unique_lock<std::mutex>lock(g_mutex);
		ST_CONTEXT_INFO stContext;
		stContext.pBuffer = lpBuffers->buf;
		g_map[lpOverlapped] = stContext;
	}

	return pWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

int WINAPI MyWSASend(_In_ SOCKET s, _In_reads_(dwBufferCount) LPWSABUF lpBuffers, _In_ DWORD dwBufferCount, _Out_opt_ LPDWORD lpNumberOfBytesSent, _In_ DWORD dwFlags, _Inout_opt_ LPWSAOVERLAPPED lpOverlapped, _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (!lpOverlapped)
	{
		OutputDebugStringFomart("%s:length:%d-data:%s", "WSASend", lpBuffers->len, lpBuffers->buf);
	}

	if ((lpOverlapped != NULL) && (lpCompletionRoutine != nullptr))
	{
		std::unique_lock<std::mutex>lock(g_mutex);
		ST_CONTEXT_INFO stContext;
		stContext.pBuffer = lpBuffers->buf;
		stContext.lpCompletionRoutine = lpCompletionRoutine;
		lpCompletionRoutine = MyCompletionRoutine;

		g_map[lpOverlapped] = stContext;
	}

	if ((lpOverlapped != NULL) && (lpCompletionRoutine == NULL) && (lpOverlapped->hEvent != NULL))
	{
		std::unique_lock<std::mutex>lock(g_mutex);
		//WSAGetOverlappedResult
		ST_CONTEXT_INFO stContext;
		stContext.pBuffer = lpBuffers->buf;
		g_map[lpOverlapped] = stContext;
	}

	if ((lpOverlapped != NULL) && (lpOverlapped->hEvent == NULL) && (lpCompletionRoutine == NULL))
	{
		//std::unique_lock<std::mutex>lock(g_mutex);
		////GetQueuedCompletionStatus
		//ST_CONTEXT_INFO stContext;
		//stContext.pBuffer = lpBuffers->buf;
		//g_map[lpOverlapped] = stContext;
	}

	return pWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

extern "C" __declspec(dllexport) void test(void) {
	return;
}

int WINAPI MySend(SOCKET s, const char* buf, int len, int flags)
{
	endpoint.from_wire(buf, len);
	return pSend(s, buf, len, flags);
}

int WINAPI MyRecv(SOCKET s, char* buf, int len, int flags)
{
	/*std::string strDebug = "recv:";
	strDebug += buf;

	OutputDebugStringA(strDebug.c_str());*/

	endpoint.from_wire(buf, len);

	return pRecv(s, buf, len, flags);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DetourRestoreAfterWith();
		/*DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pSend, MySend);
		if (DetourTransactionCommit() == NO_ERROR)
			OutputDebugString(_T("send() detoured successfully"));

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pRecv, MyRecv);
		if (DetourTransactionCommit() == NO_ERROR)
			OutputDebugString(_T("recv() detoured successfully"));*/

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pWSARecv, MyWSARecv);
		if (DetourTransactionCommit() == NO_ERROR)
			OutputDebugString(_T("WSARecv() detoured successfully"));

		/*DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pWSASend, MyWSASend);
		if (DetourTransactionCommit() == NO_ERROR)
			OutputDebugString(_T("WSASend() detoured successfully"));
*/
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pWSAGetOverlappedResult, MyWSAGetOverlappedResult);
		if (DetourTransactionCommit() == NO_ERROR)
			OutputDebugString(_T("WSAGetOverlappedResult() detoured successfully"));

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pGetQueuedCompletionStatus, MyGetQueuedCompletionStatus);
		if (DetourTransactionCommit() == NO_ERROR)
			OutputDebugString(_T("WSAGetOverlappedResult() detoured successfully"));
	}
	break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		/*DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pSend, MySend);
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pRecv, MyRecv);
		DetourTransactionCommit();*/

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pWSARecv, MyWSARecv);
		DetourTransactionCommit();

		/*DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pWSASend, MyWSASend);
		DetourTransactionCommit();*/

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pWSAGetOverlappedResult, MyWSAGetOverlappedResult);
		DetourTransactionCommit();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pGetQueuedCompletionStatus, MyGetQueuedCompletionStatus);
		DetourTransactionCommit();
	}
	break;
	}
	return TRUE;
}

