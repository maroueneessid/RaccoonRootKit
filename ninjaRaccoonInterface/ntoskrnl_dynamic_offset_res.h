#pragma once
#include <windows.h>


typedef struct symbol_ctx_t {
    LPWSTR pdb_name_w;
    DWORD64 pdb_base_addr;
    HANDLE sym_handle;
} symbol_ctx;

typedef struct PE_codeview_debug_info_t {
    DWORD signature;
    GUID guid;
    DWORD age;
    CHAR pdbName[1];
} PE_codeview_debug_info;

typedef struct PE_relocation_t {
    DWORD RVA;
    WORD Type : 4;
} PE_relocation;

typedef VOID(*kernel_read_memory_func) (DWORD64 Address, PVOID Buffer, SIZE_T Size);

typedef struct PE_pointers {
    BOOL isMemoryMapped;

    BOOL isInAnotherAddressSpace;
    HANDLE hProcess;

    BOOL isInKernelLand;
    kernel_read_memory_func kernel_read;

    PVOID baseAddress;
    //headers ptrs
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS* ntHeader;
    IMAGE_OPTIONAL_HEADER* optHeader;
    IMAGE_DATA_DIRECTORY* dataDir;
    IMAGE_SECTION_HEADER* sectionHeaders;
    //export info
    IMAGE_EXPORT_DIRECTORY* exportDirectory;
    LPDWORD exportedNames;
    DWORD exportedNamesLength;
    LPDWORD exportedFunctions;
    LPWORD exportedOrdinals;
    //relocations info
    DWORD nbRelocations;
    PE_relocation* relocations;
    //debug info
    IMAGE_DEBUG_DIRECTORY* debugDirectory;
    PE_codeview_debug_info* codeviewDebugInfo;
} PE;









enum NtoskrnlOffsetType {
    CREATE_PROCESS_ROUTINE = 0,
    CREATE_THREAD_ROUTINE,
    LOAD_IMAGE_ROUTINE,
    PROTECTION_LEVEL,
    ETW_THREAT_INT_PROV_REG_HANDLE,
    ETW_REG_ENTRY_GUIDENTRY,
    ETW_GUID_ENTRY_PROVIDERENABLEINFO,
    PSPROCESSTYPE,
    PSTHREADTYPE,
    OBJECT_TYPE_CALLBACKLIST,
    SECICALLBACKS,
    _SUPPORTED_NTOSKRNL_OFFSETS_END
};

union NtoskrnlOffsets {
    // structure version of ntoskrnl.exe's offsets
    struct {
        // ntoskrnl's PspCreateProcessNotifyRoutine
        DWORD64 pspCreateProcessNotifyRoutine;
        // ntoskrnl's PspCreateThreadNotifyRoutine
        DWORD64 pspCreateThreadNotifyRoutine;
        // ntoskrnl's PspLoadImageNotifyRoutine
        DWORD64 pspLoadImageNotifyRoutine;
        // ntoskrnl EPROCESS's Protection field offset
        DWORD64 eprocess_protection;
        // ntoskrnl ETW Threat Intelligence's EtwThreatIntProvRegHandle
        DWORD64 etwThreatIntProvRegHandle;
        // ntoskrnl _ETW_REG_ENTRY's GuidEntry
        DWORD64 etwRegEntry_GuidEntry;
        // ntoskrnl _ETW_GUID_ENTRY's ProviderEnableInfo
        DWORD64 etwGuidEntry_ProviderEnableInfo;
        // ntoskrnl PsProcessType symbol offset
        DWORD64 psProcessType;
        // ntoskrnl PsThreadType symbol offset
        DWORD64 psThreadType;
        // ntoskrnl _OBJECT_TYPE's CallbackList symbol offset
        DWORD64 object_type_callbacklist;
        // ntoskrnl SeCiCallbacks array
        DWORD64 seCiCallbacks;
    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[_SUPPORTED_NTOSKRNL_OFFSETS_END];
};




// Contains all of resolved kernel struct offssets
union NtoskrnlOffsets g_ntoskrnlOffsets;

typedef DWORD ulittle32_t;

typedef struct SuperBlock_t {
    char FileMagic[0x20];
    ulittle32_t BlockSize;
    ulittle32_t FreeBlockMapBlock;
    ulittle32_t NumBlocks;
    ulittle32_t NumDirectoryBytes;
    ulittle32_t Unknown;
    ulittle32_t BlockMapAddr;
}SuperBlock;

typedef struct PdbInfoStreamHeader_t {
    DWORD Version;
    DWORD Signature;
    DWORD Age;
    GUID UniqueId;
} PdbInfoStreamHeader;




#define printf_or_not(...) printf(__VA_ARGS__)
#define wprintf_or_not(...) wprintf(__VA_ARGS__)






void LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb);