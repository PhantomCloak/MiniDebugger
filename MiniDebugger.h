#include <Windows.h>
#include <iostream>
#include <string>
#include <map>
#include <atlstr.h>
#include <queue>
#include <psapi.h>

using namespace std;

struct RESTORE_INFO
{
	DWORD oldProtection;
	CHAR opCode;
};
struct BP_INFO
{
	map<DWORD, RESTORE_INFO*> bpRestoreTable;
};
struct MDG_HANDLE
{
public:
	STARTUPINFOA processStartupInfo;
	PROCESS_INFORMATION processInfo;
	LPVOID StartAddress;
	BP_INFO BP_INFOS;
	DWORD bpHitCounter;
	BOOL singleStepAfter;

	map<LPVOID, CString> LoadedDlls;
	MDG_HANDLE()
	{
		ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&processStartupInfo, sizeof(STARTUPINFOA));
		StartAddress = 0;
		bpHitCounter = 0;
		singleStepAfter = 0;
	}
};
struct CREATE_DBG_PROCESS_INFO
{
	CHAR Path[BUFSIZ];
	BOOL BreakOnEntry = FALSE;
};

class MiniDebugger
{
public:
	typedef void(__cdecl* CreateProcessDebugEvent)(CREATE_PROCESS_DEBUG_INFO info, CString fileName, DEBUG_EVENT eventInfo, MDG_HANDLE* hDbgProcess);
	typedef void(__cdecl* CreateThreadEvent)(CREATE_THREAD_DEBUG_INFO info, DWORD threadId, MDG_HANDLE* mHandle);
	typedef void(__cdecl* ExitThreadEvent)(DWORD threadId, DWORD threadExitCode, MDG_HANDLE* mHandle);
	typedef void(__cdecl* ExitProcessEvent)(DWORD errorCode, MDG_HANDLE* mHandle);
	typedef void(__cdecl* DllLoadEvent)(CString dllName, LPVOID baseAddr, MDG_HANDLE* mHandle);
	typedef void(__cdecl* DllUnloadEvent)(LPVOID baseAddr, MDG_HANDLE* mHandle);
	typedef void(__cdecl* DebugMsgEvent)(CString msg, MDG_HANDLE* mHandle);
	typedef void(__cdecl* FirstExceptionEvent)(EXCEPTION_DEBUG_INFO exceptionInfo, MDG_HANDLE* mHandle);
	typedef void(__cdecl* ExceptionEvent)(EXCEPTION_DEBUG_INFO exceptionInfo, MDG_HANDLE* mHandle);
	typedef void(__cdecl* BreakpointEvent)(EXCEPTION_DEBUG_INFO exceptionInfo, MDG_HANDLE* mHandle);
	typedef void(__cdecl* EntryPointEvent)(MDG_HANDLE* mHandle);
	typedef bool(__cdecl* SingleStepEvent)(PVOID Address, MDG_HANDLE* mHandle);

	MiniDebugger()
	{
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Event_Handler, this, NULL, NULL);
	}

	CreateProcessDebugEvent createProcessCallback;
	CreateThreadEvent createThreadCallback;
	ExitThreadEvent exitThreadCallback;
	ExitProcessEvent exitProcessCallback;
	DllLoadEvent dllLoadCallback;
	DllUnloadEvent dllUnloadCallback;
	DebugMsgEvent debugMsgCallback;
	ExceptionEvent exceptionCallback;
	BreakpointEvent breakpointCallback;
	FirstExceptionEvent firstChanceExceptionCallback;
	EntryPointEvent entryPointEvent;
	SingleStepEvent singleStepCallback;

	MDG_HANDLE* CreateDebugProcess(LPCSTR path, BOOL bpOnEntry)
	{
		MDG_HANDLE* dbgHandle = new MDG_HANDLE();

		if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &(dbgHandle)->processStartupInfo, &(dbgHandle)->processInfo))
		{
			return NULL;
		}

		dbgHandle->StartAddress = GetEntryPoint(dbgHandle);

		DWORD processId = dbgHandle->processInfo.dwProcessId;
		processHandleMap.insert(make_pair(processId, dbgHandle));

		if (bpOnEntry)
		{
			PutBreakPoint(dbgHandle, dbgHandle->StartAddress);
		}


		Working = true;
		Event_Handler(this);

		return dbgHandle;
	}
	MDG_HANDLE* CreateDebugProcessNonBlocking(LPCSTR path, BOOL bpOnEntry)
	{
		CREATE_DBG_PROCESS_INFO* dbgInfo = new CREATE_DBG_PROCESS_INFO();
		strcpy_s(dbgInfo->Path, path);
		dbgInfo->BreakOnEntry = bpOnEntry;
		pendingDebugTargets.push(dbgInfo);

		return NULL;
	}
private:
	map <DWORD, MDG_HANDLE*> processHandleMap;
	queue<CREATE_DBG_PROCESS_INFO*> pendingDebugTargets;
	BOOL Working = FALSE;
	CString GetFileNameFromHandle(HANDLE hFile)
	{
		BOOL bSuccess = FALSE;
		TCHAR pszFilename[MAX_PATH + 1];
		HANDLE hFileMap;

		CString strFilename;

		// Get the file size.
		DWORD dwFileSizeHi = 0;
		DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

		if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
		{
			return CString();
		}

		// Create a file mapping object.
		hFileMap = CreateFileMapping(hFile,
			NULL,
			PAGE_READONLY,
			0,
			1,
			NULL);

		if (hFileMap)
		{
			// Create a file mapping to get the file name.
			void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

			if (pMem)
			{
				if (GetMappedFileName(GetCurrentProcess(),
					pMem,
					pszFilename,
					MAX_PATH))
				{
					// Translate path with device name to drive letters.
					TCHAR szTemp[BUFSIZ];
					szTemp[0] = '\0';

					if (GetLogicalDriveStrings(BUFSIZ - 1, szTemp))
					{
						TCHAR szName[MAX_PATH];
						TCHAR szDrive[3] = TEXT(" :");
						BOOL bFound = FALSE;
						TCHAR* p = szTemp;

						do
						{
							// Copy the drive letter to the template string
							*szDrive = *p;

							// Look up each device name
							if (QueryDosDevice(szDrive, szName, MAX_PATH))
							{
								size_t uNameLen = _tcslen(szName);

								if (uNameLen < MAX_PATH)
								{
									bFound = _tcsnicmp(pszFilename, szName,
										uNameLen) == 0;

									if (bFound)
									{
										strFilename.Format(L"%s%s", szDrive, pszFilename + uNameLen);
									}
								}
							}

							// Go to the next NULL character.
							while (*p++);
						} while (!bFound && *p); // end of string
					}
				}
				bSuccess = TRUE;
				UnmapViewOfFile(pMem);
			}

			CloseHandle(hFileMap);
		}

		return(strFilename);
	}
	PVOID GetEntryPoint(MDG_HANDLE* mHandle)
	{
		CONTEXT context;
		memset(&context, 0, sizeof(CONTEXT));
		context.ContextFlags = CONTEXT_INTEGER;
		GetThreadContext(mHandle->processInfo.hThread, &context);


		DWORD PEB_addr = context.Ebx;
		DWORD targetImageBase = 0; //for 32 bit

		if (!ReadProcessMemory(mHandle->processInfo.hProcess, LPVOID(PEB_addr + 8), &targetImageBase, sizeof(DWORD), NULL)) {
			printf("[ERROR] Cannot read from PEB - incompatibile target!\n");
		}

		LPVOID remMemBuff = (LPVOID)_malloca(sizeof(IMAGE_DOS_HEADER));

		if (!ReadProcessMemory(mHandle->processInfo.hProcess, (LPVOID)targetImageBase, remMemBuff, sizeof(IMAGE_DOS_HEADER), NULL))
		{
			printf("err");
		}

		DWORD e_lfanew = ((PIMAGE_DOS_HEADER)remMemBuff)->e_lfanew;

		remMemBuff = (LPVOID)_malloca(sizeof(IMAGE_NT_HEADERS));

		if (!ReadProcessMemory(mHandle->processInfo.hProcess, (LPCVOID)((DWORD_PTR)targetImageBase + e_lfanew), remMemBuff, sizeof(IMAGE_NT_HEADERS), NULL))
		{
			printf("err");
		}
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)remMemBuff;
		PVOID entryPoint = (PVOID)ntHeader->OptionalHeader.AddressOfEntryPoint;
		return (PVOID)(targetImageBase + (DWORD)entryPoint);
	}

	void PutBreakPoint(MDG_HANDLE* mHandle, PVOID addr)
	{
		CHAR orgOpCode = 0;
		DWORD orgProtection = 0;

		if (!VirtualProtectEx(mHandle->processInfo.hProcess, addr, sizeof(CHAR), PAGE_EXECUTE_READWRITE, &orgProtection))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured during the VirtualProtectEx in %d error code %d", (DWORD)&addr, &errCode);
		}

		if (!ReadProcessMemory(mHandle->processInfo.hProcess, addr, &orgOpCode, sizeof(CHAR), NULL))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured during the reading first instruction of %d error code %d", (DWORD)&addr, &errCode);
		}

		RESTORE_INFO* info = new RESTORE_INFO();

		info->oldProtection = orgProtection;
		info->opCode = orgOpCode;

		mHandle->BP_INFOS.bpRestoreTable.insert(make_pair((DWORD)addr, info));

		CHAR  bpOpCode = 0xCC;

		if (!WriteProcessMemory(mHandle->processInfo.hProcess, mHandle->StartAddress, (LPCVOID)&bpOpCode, sizeof(CHAR), NULL))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured during the writing first instruction of %d error code %d", (DWORD)&addr, &errCode);
		}
	}
	void RecoverBreakPoint(MDG_HANDLE* mHandle, PVOID addr)
	{
		RESTORE_INFO* info = mHandle->BP_INFOS.bpRestoreTable[(DWORD)addr];

		CHAR orgOpCode = info->opCode;
		DWORD orgProtect = info->oldProtection;
		DWORD oldProtect = 0;

		CONTEXT threadContext;
		threadContext.ContextFlags = CONTEXT_ALL;

		if (!GetThreadContext(mHandle->processInfo.hThread, &threadContext))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured during the getting context of %d in debugee error code %d", (DWORD)&mHandle->processInfo.hThread & errCode);
		}

		threadContext.Eip--;
		threadContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception

		if (!SetThreadContext(mHandle->processInfo.hThread, &threadContext))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured during the setting context of %d in debugee error code %d", (DWORD)&mHandle->processInfo.hThread & errCode);
		}

		if (!WriteProcessMemory(mHandle->processInfo.hProcess, addr, (LPCVOID)&orgOpCode, sizeof(CHAR), NULL))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured during the writing original op code to %d in debugee error code %d", (DWORD)&addr & errCode);
		}

		if (!VirtualProtectEx(mHandle->processInfo.hProcess, addr, sizeof(CHAR), orgProtect, &oldProtect))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured during the VirtualProtectEx in %d error code %d", (DWORD)&addr, &errCode);
		}


		FlushInstructionCache(mHandle->processInfo.hProcess, addr, sizeof(CHAR));

		delete[] info;
		mHandle->BP_INFOS.bpRestoreTable.erase((DWORD)addr);
	}
	void SetTrapFlag(MDG_HANDLE* mHandle)
	{
		CONTEXT threadContext;
		threadContext.ContextFlags = CONTEXT_ALL;

		if (!GetThreadContext(mHandle->processInfo.hThread, &threadContext))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured in the GetThreadContext during singe step error code %d", &errCode);
		}

		threadContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception

		if (!SetThreadContext(mHandle->processInfo.hThread, &threadContext))
		{
			DWORD errCode = GetLastError();
			printf("An Error occured in the SetThreadContext during singe step error code %d", &errCode);
		}
	}


	static DWORD __stdcall Event_Handler(MiniDebugger* instance)
	{
		DEBUG_EVENT debug_event = { 0 };
		DWORD dwContinueStatus = DBG_CONTINUE;
		while (true)
		{

			if (instance->pendingDebugTargets.size() > 0)
			{
				//todo thread safe
				CREATE_DBG_PROCESS_INFO* pendingProcess = instance->pendingDebugTargets.front();
				instance->pendingDebugTargets.pop();
				
				instance->CreateDebugProcess(pendingProcess->Path, pendingProcess->BreakOnEntry);

				delete[] pendingProcess;
			}

			if (instance->Working == 0)
			{
				Sleep(16);
				continue;
			}

			if (!WaitForDebugEvent(&debug_event, INFINITE))
				continue;

			MDG_HANDLE* mHandle = instance->processHandleMap[debug_event.dwProcessId];

			switch (debug_event.dwDebugEventCode)
			{
			case CREATE_PROCESS_DEBUG_EVENT:
				if (instance->createProcessCallback != NULL)
					instance->createProcessCallback(debug_event.u.CreateProcessInfo, instance->GetFileNameFromHandle(debug_event.u.CreateProcessInfo.hFile), debug_event, mHandle);
				break;
			case CREATE_THREAD_DEBUG_EVENT:
				if (instance->createThreadCallback != NULL)
					instance->createThreadCallback(debug_event.u.CreateThread, debug_event.dwThreadId, mHandle);
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				if (instance->exitThreadCallback != NULL)
					instance->exitThreadCallback(debug_event.dwThreadId, debug_event.u.ExitThread.dwExitCode, mHandle);
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
			{
				MDG_HANDLE* disposedHandleInfo = instance->processHandleMap[debug_event.dwProcessId];
				delete disposedHandleInfo;

				instance->processHandleMap.erase(debug_event.dwProcessId);
				if (instance->exitProcessCallback != NULL)
					instance->exitProcessCallback(debug_event.u.ExitProcess.dwExitCode, NULL);

				DWORD instanceCount = instance->processHandleMap.size();
				if (instanceCount <= 0)
				{
					instance->Working = false;
				}

				break;
			}
			case LOAD_DLL_DEBUG_EVENT:
			{
				CString dllName = instance->GetFileNameFromHandle(debug_event.u.LoadDll.hFile);
				mHandle->LoadedDlls.insert(std::make_pair(debug_event.u.LoadDll.lpBaseOfDll, dllName));

				if (instance->dllLoadCallback != NULL)
					instance->dllLoadCallback(dllName, debug_event.u.LoadDll.lpBaseOfDll, mHandle);
				break;
			}
			case UNLOAD_DLL_DEBUG_EVENT:
				if (instance->dllUnloadCallback != NULL)
					instance->dllUnloadCallback(debug_event.u.UnloadDll.lpBaseOfDll, NULL);
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
			{
				if (instance->debugMsgCallback != NULL)
				{
					OUTPUT_DEBUG_STRING_INFO& DebugString = debug_event.u.DebugString;
					CString strEventMessage;

					WCHAR* msg = new WCHAR[DebugString.nDebugStringLength];
					ZeroMemory(msg, DebugString.nDebugStringLength);

					ReadProcessMemory(mHandle->processInfo.hProcess, DebugString.lpDebugStringData, msg, DebugString.nDebugStringLength, NULL);

					if (DebugString.fUnicode)
						strEventMessage = msg;
					else
						strEventMessage = (LPSTR)msg;

					instance->debugMsgCallback(strEventMessage, NULL);

					delete[]msg;
				}
				break;
			}
			case EXCEPTION_DEBUG_EVENT:
			{
				EXCEPTION_DEBUG_INFO& exception = debug_event.u.Exception;
				switch (exception.ExceptionRecord.ExceptionCode)
				{
				case STATUS_BREAKPOINT:
				{
					if (mHandle->bpHitCounter == 0)
					{
						instance->PutBreakPoint(mHandle, mHandle->StartAddress);
					}
					DWORD exceptionAddr = (DWORD)exception.ExceptionRecord.ExceptionAddress;


					//debugger defined breakpoint
					if (mHandle->BP_INFOS.bpRestoreTable.find(exceptionAddr) != mHandle->BP_INFOS.bpRestoreTable.end())
					{
						instance->RecoverBreakPoint(mHandle, exception.ExceptionRecord.ExceptionAddress);
					}

					if (exceptionAddr == (DWORD)mHandle->StartAddress)
						if (instance->entryPointEvent != NULL)
							instance->entryPointEvent(mHandle);
						else
							if (instance->breakpointCallback != NULL)
								instance->breakpointCallback(exception, mHandle);

					if (mHandle->singleStepAfter)
						instance->SetTrapFlag(mHandle);

					mHandle->bpHitCounter++;
				}
				break;
				case EXCEPTION_SINGLE_STEP:
					if (instance->singleStepCallback != NULL)
					{
						BOOL status = instance->singleStepCallback(exception.ExceptionRecord.ExceptionAddress, mHandle);
						if (status)
						{
							instance->SetTrapFlag(mHandle);
						}
					}
					break;
				default:
					if (exception.dwFirstChance == 1)
					{
						if (instance->firstChanceExceptionCallback != NULL)
							instance->firstChanceExceptionCallback(exception, mHandle);
					}
					else
					{
						if (instance->exceptionCallback != NULL)
							instance->exceptionCallback(exception, mHandle);
					}
					dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}

				break;
			}

			}

			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus);

			// Reset
			dwContinueStatus = DBG_CONTINUE;
		}
	}

};
