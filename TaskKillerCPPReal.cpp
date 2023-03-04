
#include <Windows.h>
#include <string>
#include <ntstatus.h>
#include <codecvt>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
//NTAPIDECLARE
typedef NTSTATUS(WINAPI* LPFN_NTQUERYVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    int MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

using namespace std;
//Thisonlywork ForExactly one Process Found
DWORD GetProcessIdFromName(const std::wstring& processName)
{
    DWORD processId = -1;
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshotHandle != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshotHandle, &processEntry)) {
            do {
                if (_wcsicmp(processName.c_str(), processEntry.szExeFile) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshotHandle, &processEntry));
        }
        CloseHandle(snapshotHandle);             
    } 
    if (processId == -1) return -1;
    cout << "PID = " << processId<<endl;
    return processId; //return -1 for ProcessNameNotFoundException
}

int CloseProcesIfExceedPrivateMemoryUsage(DWORD ProcessId, int RamExceed) {

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE,ProcessId);

    if (hProcess == nullptr)
    {
        std::cout << "Failed to open process" << std::endl;        
        return -1;
    }

    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&pmc), sizeof(pmc)))
    {   
        std::cout << "Private Working Set Size: " << (pmc.WorkingSetSize / 1000)  << "KB" << std::endl;
        //Start check And Kill Procedure
        if (pmc.WorkingSetSize > RamExceed * 1000 * 1000) {
            if (!TerminateProcess(hProcess, 0)) {
                cerr << "Failed to terminate process. Error code: " << GetLastError() << endl;
                CloseHandle(hProcess);
                return -1;
            }
            cout << "Process terminated successfully." << endl;
        }
        else {
            cout << "Process is not using more than "<<RamExceed<<"MB of RAM." << endl;
        }
        
    }
    else
    {
        std::cout << "Failed to get process memory info" << std::endl;
        return -1;
    }
    //END OF KILL PROCEDURE
    // Close the handle to the target process USE NT API <<<- Should Be A Close Handle If No Check Using NTLibrary
    // Get the private RAM usage
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        CloseHandle(hProcess);
        return 1;
    }

    LPFN_NTQUERYVIRTUALMEMORY lpfnNtQueryVirtualMemory = (LPFN_NTQUERYVIRTUALMEMORY)GetProcAddress(hNtDll, "NtQueryVirtualMemory");
    if (!lpfnNtQueryVirtualMemory) {
        printf("Failed to get address of NtQueryVirtualMemory\n");
        CloseHandle(hProcess);
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T dwLength = 0;
    SIZE_T dwPrivateBytes = 0;

    for (PBYTE pAddress = NULL; ; pAddress += mbi.RegionSize) {
        if (lpfnNtQueryVirtualMemory(hProcess, pAddress, 0, &mbi, sizeof(mbi), &dwLength) != STATUS_SUCCESS) {
            break;
        }
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            dwPrivateBytes += mbi.RegionSize;
        }
    }

    cout<<"Private RAM usage NT API (Closest to Windows Task Manager):" << dwPrivateBytes/1024<<"KB"<< endl;

    CloseHandle(hProcess);
    FreeLibrary(hNtDll);
    return 1;

}


int main()
{
    string procname ;
    cin >> procname ;
    int exceed = 1000; //MB
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wprocname = converter.from_bytes(procname);//convert to Wstring
    DWORD PID = GetProcessIdFromName(wprocname);
    if (PID == -1) {
        cout << "Error PID Not Found" << endl;
        return -1;
    }
    else {
        cout << "Checking RAM Usage of :" + procname << endl;
        if (CloseProcesIfExceedPrivateMemoryUsage(PID, exceed) == -1) {
            cout << "ERROR" << endl;
        }
        else {
            cout << "Checking Succced" << endl;
        }
    }
    return 1;

}

