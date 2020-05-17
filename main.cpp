#include "MiniDebugger.h"

bool OnSingleStep(PVOID Address, MDG_HANDLE* mHandle)
{
    wcout << "Stepping onto " << Address << endl;
    return FALSE; //if function returns true next instruction will be catch again otherwise program continues as usual
}
void OnEntryPoint(MDG_HANDLE* mHandle)
{
    //Trap next instruction
    mHandle->singleStepAfter = TRUE;
}
void OnBreakpoint(EXCEPTION_DEBUG_INFO exceptionInfo, MDG_HANDLE* mHandle)
{
    wcout << "Breakpoint at " << exceptionInfo.ExceptionRecord.ExceptionAddress << endl;
}
void OnDllLoad(CString dllName, LPVOID baseAddr, MDG_HANDLE* mHandle)
{
    wcout << "Loaded Dll: " << dllName.GetString() << " BaseAddr: " << baseAddr << endl;
}
void OnDebugMsg(CString msg, MDG_HANDLE* mHandle)
{
    wcout << "Dbg Msg: " << msg.GetString() << endl;
}
void OnCreateThread(CREATE_THREAD_DEBUG_INFO info, DWORD threadId, MDG_HANDLE* mHandle)
{
    wcout << "Thread started at : " << info.lpStartAddress << endl;
}
void OnException(EXCEPTION_DEBUG_INFO exceptionInfo, MDG_HANDLE* mHandle)
{
    wcout << "Exception occured at : " << exceptionInfo.ExceptionRecord.ExceptionCode << "Code: " << exceptionInfo.ExceptionRecord.ExceptionCode << " Is First Chance: " << exceptionInfo.dwFirstChance << endl;
}
void OnProcessExit(DWORD errorCode, MDG_HANDLE* mHandle)
{
    wcout << "Debugge exited with code " << errorCode << endl;
}
void OnThreadExit(DWORD threadId, DWORD threadExitCode, MDG_HANDLE* mHandle)
{
    wcout << "Thread " << threadId << " exited with code " << threadExitCode << endl;
}
int main()
{
    MiniDebugger * debugger = new MiniDebugger();
    debugger->dllLoadCallback = OnDllLoad;
    debugger->breakpointCallback = OnBreakpoint;
    debugger->debugMsgCallback = OnDebugMsg;
    debugger->createThreadCallback = OnCreateThread;
    debugger->exceptionCallback = OnException;
    debugger->entryPointEvent = OnEntryPoint;
    debugger->singleStepCallback = OnSingleStep;
    debugger->exitProcessCallback = OnProcessExit;
    debugger->exitThreadCallback = OnThreadExit;

    debugger->CreateDebugProcess("C:\\Users\\phantom\\Desktop\\tsetup.2.0.1.exe", TRUE);
}
