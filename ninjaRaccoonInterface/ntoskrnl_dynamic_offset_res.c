#include "ntoskrnl_dynamic_offset_res.h"
#include <Shlwapi.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <assert.h>
#include <winhttp.h>


#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Shlwapi.lib")


TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };


union NtoskrnlOffsets g_ntoskrnlOffsets = { 0 };

VOID PE_read(PE* pe, LPCVOID address, SIZE_T size, PVOID buffer) {
    if (pe->isInAnotherAddressSpace) {
        ReadProcessMemory(pe->hProcess, address, buffer, size, NULL);
    }
    else if (pe->isInKernelLand) {
        pe->kernel_read((DWORD64)address, buffer, size);
    }
    else {
        memcpy(buffer, address, size);
    }
}

#define PE_ReadMemoryType(TYPE) \
TYPE PE_ ## TYPE ## (PE* pe, LPCVOID address) {\
    TYPE res;\
    PE_read(pe, address, sizeof(TYPE), &res);\
    return res;\
}
PE_ReadMemoryType(BYTE);
PE_ReadMemoryType(WORD);
PE_ReadMemoryType(DWORD);
PE_ReadMemoryType(DWORD64);

IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
    IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
    for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
        DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
        DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
        if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
            return &sectionHeaders[sectionIndex];
        }
    }
    return NULL;
}

PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
    PVOID peBase = pe->dosHeader;
    if (pe->isMemoryMapped) {
        return (PBYTE)peBase + rva;
    }

    IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
    if (NULL == rvaSectionHeader) {
        return NULL;
    }
    else {
        return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
    }
}

DWORD PE_Addr_to_RVA(PE* pe, PVOID addr) {
    for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD sectionVA = pe->sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = pe->sectionHeaders[i].Misc.VirtualSize;
        PVOID sectionAddr = PE_RVA_to_Addr(pe, sectionVA);
        if (sectionAddr <= addr && addr < (PVOID)((intptr_t)sectionAddr + (intptr_t)sectionSize)) {
            intptr_t relativeOffset = ((intptr_t)addr - (intptr_t)sectionAddr);
            assert(relativeOffset <= MAXDWORD);
            return sectionVA + (DWORD)relativeOffset;
        }
    }
    return 0;
}

PE* _PE_create_common(PVOID imageBase, BOOL isMemoryMapped, BOOL isInAnotherAddressSpace, HANDLE hProcess, BOOL isInKernelLand, kernel_read_memory_func ReadPrimitive) {
    PE* pe = calloc(1, sizeof(PE));
    if (NULL == pe) {
        exit(1);
    }
    pe->isMemoryMapped = isMemoryMapped;
    pe->hProcess = hProcess;
    pe->isInAnotherAddressSpace = isInAnotherAddressSpace;
    pe->isInKernelLand = isInKernelLand;
    pe->kernel_read = ReadPrimitive;
    pe->baseAddress = imageBase;
    pe->dosHeader = imageBase;
    DWORD ntHeaderPtrAddress = PE_DWORD(pe, &((IMAGE_DOS_HEADER*)imageBase)->e_lfanew);
    pe->ntHeader = (IMAGE_NT_HEADERS*)((intptr_t)pe->baseAddress + ntHeaderPtrAddress);
    pe->optHeader = (IMAGE_OPTIONAL_HEADER*)(&pe->ntHeader->OptionalHeader);
    pe->dataDir = pe->optHeader->DataDirectory;
    WORD sizeOfOptionnalHeader = PE_WORD(pe, &pe->ntHeader->FileHeader.SizeOfOptionalHeader);
    pe->sectionHeaders = (IMAGE_SECTION_HEADER*)((intptr_t)pe->optHeader + sizeOfOptionnalHeader);
    DWORD exportRVA = PE_DWORD(pe, &pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (exportRVA == 0) {
        pe->exportDirectory = NULL;
        pe->exportedNames = NULL;
        pe->exportedFunctions = NULL;
        pe->exportedOrdinals = NULL;
    }
    else {
        pe->exportDirectory = PE_RVA_to_Addr(pe, exportRVA);

        DWORD AddressOfNames = PE_DWORD(pe, &pe->exportDirectory->AddressOfNames);
        pe->exportedNames = PE_RVA_to_Addr(pe, AddressOfNames);

        DWORD AddressOfFunctions = PE_DWORD(pe, &pe->exportDirectory->AddressOfFunctions);
        pe->exportedFunctions = PE_RVA_to_Addr(pe, AddressOfFunctions);

        DWORD AddressOfNameOrdinals = PE_DWORD(pe, &pe->exportDirectory->AddressOfNameOrdinals);
        pe->exportedOrdinals = PE_RVA_to_Addr(pe, AddressOfNameOrdinals);

        pe->exportedNamesLength = PE_DWORD(pe, &pe->exportDirectory->NumberOfNames);
    }
    pe->relocations = NULL;
    DWORD debugRVA = PE_DWORD(pe, &pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    if (debugRVA == 0) {
        pe->debugDirectory = NULL;
    }
    else {
        pe->debugDirectory = PE_RVA_to_Addr(pe, debugRVA);
        DWORD debugDirectoryType = PE_DWORD(pe, &pe->debugDirectory->Type);
        if (debugDirectoryType != IMAGE_DEBUG_TYPE_CODEVIEW) {
            pe->debugDirectory = NULL;
        }
        else {
            DWORD debugDirectoryAddressOfRawData = PE_DWORD(pe, &pe->debugDirectory->AddressOfRawData);
            pe->codeviewDebugInfo = PE_RVA_to_Addr(pe, debugDirectoryAddressOfRawData);
            DWORD codeviewDebugInfoSignature = PE_DWORD(pe, &pe->codeviewDebugInfo->signature);
            if (codeviewDebugInfoSignature != *((DWORD*)"RSDS")) {
                pe->debugDirectory = NULL;
                pe->codeviewDebugInfo = NULL;
            }
        }
    }
    return pe;
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
    return _PE_create_common(imageBase, isMemoryMapped, FALSE, INVALID_HANDLE_VALUE, FALSE, NULL);
}

PBYTE ReadFullFileW(LPCWSTR fileName) {
    HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    PBYTE fileContent = malloc(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(fileContent);
        fileContent = NULL;
    }
    CloseHandle(hFile);
    return fileContent;
}

BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
    HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
    CloseHandle(hFile);
    return res;
}

LPTSTR GetNtoskrnlPath() {
    if (_tcslen(g_ntoskrnlPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        GetSystemDirectory(g_ntoskrnlPath, _countof(g_ntoskrnlPath));

        // Compute ntoskrnl.exe path.
        PathAppendW(g_ntoskrnlPath, TEXT("\\ntoskrnl.exe"));
    }
    return g_ntoskrnlPath;
}


DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
    SYMBOL_INFO_PACKAGE si = { 0 };
    si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    si.si.MaxNameLen = sizeof(si.name);
    BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si);
    if (res) {
        return si.si.Address - ctx->pdb_base_addr;
    }
    else {
        return 0;
    }
}



BOOL FileExistsW(LPCWSTR szPath)
{
    DWORD dwAttrib = GetFileAttributesW(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


PVOID extractGuidFromPdb(LPWSTR filepath) {
    GUID* guid = NULL;
    HANDLE hMapping = NULL;
    PBYTE filemap = NULL;
    DWORD* StreamDirectory = NULL;
    DWORD** StreamBlocks = NULL;
    DWORD NumStreams = 0;

    HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        goto clean;
    }
    filemap = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (filemap == NULL) {
        goto clean;
    }
    SuperBlock* superblock = (SuperBlock*)filemap;
    DWORD blockSize = superblock->BlockSize;
    DWORD* StreamDirectoryBlockMap = (DWORD*)(filemap + (ULONG_PTR)superblock->BlockMapAddr * blockSize);
    StreamDirectory = calloc(superblock->NumDirectoryBytes, 1);
    if (StreamDirectory == NULL) {
        goto clean;
    }
    DWORD StreamDirectoryBlockIndex = 0;
    DWORD StreamDirectoryRemainingSize = superblock->NumDirectoryBytes;
    while (StreamDirectoryRemainingSize) {
        DWORD SizeToCopy = min(StreamDirectoryRemainingSize, blockSize);
        memcpy(
            ((PBYTE)StreamDirectory) + (ULONG_PTR)StreamDirectoryBlockIndex * blockSize,
            ((PBYTE)filemap) + (ULONG_PTR)blockSize * StreamDirectoryBlockMap[StreamDirectoryBlockIndex],
            SizeToCopy);
        StreamDirectoryBlockIndex++;
        StreamDirectoryRemainingSize -= SizeToCopy;
    }
    NumStreams = StreamDirectory[0];
    if (NumStreams < 2) {
        NumStreams = 0;
        goto clean;
    }
    StreamBlocks = calloc(NumStreams, sizeof(DWORD*));
    if (StreamBlocks == NULL) {
        goto clean;
    }
    DWORD* StreamBlocksFlat = &StreamDirectory[1 + NumStreams];
    DWORD i = 0;
    if ((1 + NumStreams) >= superblock->NumDirectoryBytes / 4) {
        goto clean;
    }
    for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
        DWORD StreamSize = StreamDirectory[1 + stream_i];
        DWORD StreamBlockCount = 0;
        while (StreamBlockCount * blockSize < StreamSize) {
            PVOID tmp = realloc(StreamBlocks[stream_i], ((SIZE_T)StreamBlockCount + 1) * sizeof(DWORD));
            if (tmp == NULL) {
                goto clean;
            }
            StreamBlocks[stream_i] = tmp;
            StreamBlocks[stream_i][StreamBlockCount] = StreamBlocksFlat[i];
            i++;
            StreamBlockCount++;
        }
    }
    DWORD PdbInfoStreamSize = StreamDirectory[1 + 1];
    if (PdbInfoStreamSize == 0) {
        goto clean;
    }
    PdbInfoStreamHeader* PdbInfoStream = (PdbInfoStreamHeader*)(filemap + (ULONG_PTR)StreamBlocks[1][0] * blockSize);
    guid = calloc(1, sizeof(GUID));
    if (guid == NULL) {
        goto clean;
    }
    memcpy(guid, &PdbInfoStream->UniqueId, sizeof(GUID));
clean:
    if (StreamBlocks) {
        for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
            if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
                free(StreamBlocks[stream_i]);
            }
        }
        free(StreamBlocks);
    }
    if (StreamDirectory) {
        free(StreamDirectory);
    }
    if (filemap) {
        UnmapViewOfFile(filemap);
    }
    if (hMapping != NULL) {
        CloseHandle(hMapping);
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    return guid;
}


VOID PE_destroy(PE* pe)
{
    if (pe->relocations) {
        free(pe->relocations);
        pe->relocations = NULL;
    }
    free(pe);
}


BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size) {
    wprintf_or_not(L"Downloading https://%s%s...\n", domain, uri);
    // Get proxy configuration
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
    WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
    BOOL proxySet = !(proxyConfig.fAutoDetect || proxyConfig.lpszAutoConfigUrl != NULL);
    DWORD proxyAccessType = proxySet ? ((proxyConfig.lpszProxy == NULL) ?
        WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY) : WINHTTP_ACCESS_TYPE_NO_PROXY;
    LPCWSTR proxyName = proxySet ? proxyConfig.lpszProxy : WINHTTP_NO_PROXY_NAME;
    LPCWSTR proxyBypass = proxySet ? proxyConfig.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS;

    // Initialize HTTP session and request
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.0", proxyAccessType, proxyName, proxyBypass, 0);
    if (hSession == NULL) {
        printf_or_not("WinHttpOpen failed with error : 0x%x\n", GetLastError());
        return FALSE;
    }
    HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        printf_or_not("WinHttpConnect failed with error : 0x%x\n", GetLastError());
        return FALSE;
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uri, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        return FALSE;
    }

    // Configure proxy manually
    if (!proxySet)
    {
        WINHTTP_AUTOPROXY_OPTIONS  autoProxyOptions;
        autoProxyOptions.dwFlags = proxyConfig.lpszAutoConfigUrl != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : WINHTTP_AUTOPROXY_AUTO_DETECT;
        autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        autoProxyOptions.fAutoLogonIfChallenged = TRUE;

        if (proxyConfig.lpszAutoConfigUrl != NULL)
            autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;

        WCHAR szUrl[MAX_PATH] = { 0 };
        swprintf_s(szUrl, _countof(szUrl), L"https://%ws%ws", domain, uri);

        WINHTTP_PROXY_INFO proxyInfo;
        WinHttpGetProxyForUrl(
            hSession,
            szUrl,
            &autoProxyOptions,
            &proxyInfo);

        WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
        DWORD logonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &logonPolicy, sizeof(logonPolicy));
    }

    // Perform request
    BOOL bRequestSent;
    do {
        bRequestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    } while (!bRequestSent && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
    if (!bRequestSent) {
        return FALSE;
    }
    BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResponseReceived) {
        return FALSE;
    }

    // Read response
    DWORD dwAvailableSize = 0;
    DWORD dwDownloadedSize = 0;
    SIZE_T allocatedSize = 4096;
    if (!WinHttpQueryDataAvailable(hRequest, &dwAvailableSize))
    {
        return FALSE;
    }
    *output = (PBYTE)malloc(allocatedSize);
    *output_size = 0;
    while (dwAvailableSize)
    {
        while (*output_size + dwAvailableSize > allocatedSize) {
            allocatedSize *= 2;
            PBYTE new_output = (PBYTE)realloc(*output, allocatedSize);
            if (new_output == NULL)
            {
                return FALSE;
            }
            *output = new_output;
        }
        if (!WinHttpReadData(hRequest, *output + *output_size, dwAvailableSize, &dwDownloadedSize))
        {
            return FALSE;
        }
        *output_size += dwDownloadedSize;

        WinHttpQueryDataAvailable(hRequest, &dwAvailableSize);
    }
    PBYTE new_output = (PBYTE)realloc(*output, *output_size);
    if (new_output == NULL)
    {
        return FALSE;
    }
    *output = new_output;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;
}



BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
    WCHAR full_pdb_uri[MAX_PATH] = { 0 };
    swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
    return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
    WCHAR pdb_name_w[MAX_PATH] = { 0 };
    GUID guid = image_pe->codeviewDebugInfo->guid;
    DWORD age = image_pe->codeviewDebugInfo->age;
    MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
    return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

symbol_ctx* LoadSymbolsFromPE(PE* pe) {
    symbol_ctx* ctx = calloc(1, sizeof(symbol_ctx));
    if (ctx == NULL) {
        return NULL;
    }
    if (strchr(pe->codeviewDebugInfo->pdbName, '\\')) {
        // path is strange, PDB file won't be found on Microsoft Symbol Server, better give up...
        return NULL;
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
    ctx->pdb_name_w = calloc(size_needed, sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
    BOOL needPdbDownload = FALSE;
    if (!FileExistsW(ctx->pdb_name_w)) {
        needPdbDownload = TRUE;
    }
    else {
        // PDB file exists, but is it the right version ?
        GUID* guid = extractGuidFromPdb(ctx->pdb_name_w);
        if (!guid || memcmp(guid, &pe->codeviewDebugInfo->guid, sizeof(GUID))) {
            needPdbDownload = TRUE;
        }
        free(guid);
    }
    if (needPdbDownload) {
        PBYTE file;
        SIZE_T file_size;
        BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
        if (!res) {
            free(ctx);
            return NULL;
        }
        WriteFullFileW(ctx->pdb_name_w, file, file_size);
        free(file);
    }
    DWORD64 asked_pdb_base_addr = 0x1337000;
    DWORD pdb_image_size = MAXDWORD;
    HANDLE cp = GetCurrentProcess();
    if (!SymInitialize(cp, NULL, FALSE)) {
        free(ctx);
        return NULL;
    }
    ctx->sym_handle = cp;

    DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
    while (pdb_base_addr == 0) {
        DWORD err = GetLastError();
        if (err == ERROR_SUCCESS)
            break;
        if (err == ERROR_FILE_NOT_FOUND) {
            //printf_or_not("PDB file not found\n");
            SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
            SymCleanup(cp);
            free(ctx);
            return NULL;
        }
        //printf_or_not("SymLoadModuleExW, error 0x%x\n", GetLastError());
        asked_pdb_base_addr += 0x1000000;
        pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
    }
    ctx->pdb_base_addr = pdb_base_addr;
    return ctx;
}



symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
    PVOID image_content = ReadFullFileW(image_file_path);
    PE* pe = PE_create(image_content, FALSE);
    symbol_ctx* ctx = LoadSymbolsFromPE(pe);
    PE_destroy(pe);
    free(image_content);
    return ctx;
}




DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
    SYMBOL_INFO_PACKAGE si = { 0 };
    si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    si.si.MaxNameLen = sizeof(si.name);
    BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
    if (!res) {
        return 0;
    }

    TI_FINDCHILDREN_PARAMS* childrenParam = calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
    if (childrenParam == NULL) {
        return 0;
    }

    res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
    if (!res) {
        return 0;
    }
    TI_FINDCHILDREN_PARAMS* ptr = realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
    if (ptr == NULL) {
        free(childrenParam);
        return 0;
    }
    childrenParam = ptr;
    res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
    DWORD offset = 0;
    for (ULONG i = 0; i < childrenParam->Count; i++) {
        ULONG childID = childrenParam->ChildId[i];
        WCHAR* name = NULL;
        SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
        if (wcscmp(field_name, name)) {
            continue;
        }
        SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
        break;
    }
    free(childrenParam);
    return offset;
}

void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
    SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr);
    SymCleanup(ctx->sym_handle);
    if (delete_pdb) {
        DeleteFileW(ctx->pdb_name_w);
    }
    free(ctx->pdb_name_w);
    ctx->pdb_name_w = NULL;
    free(ctx);
}



void LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb) {
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(GetNtoskrnlPath());
    if (sym_ctx == NULL) {
        return;
    }
    g_ntoskrnlOffsets.st.pspCreateProcessNotifyRoutine = GetSymbolOffset(sym_ctx, "PspCreateProcessNotifyRoutine");
    g_ntoskrnlOffsets.st.pspCreateThreadNotifyRoutine = GetSymbolOffset(sym_ctx, "PspCreateThreadNotifyRoutine");
    g_ntoskrnlOffsets.st.pspLoadImageNotifyRoutine = GetSymbolOffset(sym_ctx, "PspLoadImageNotifyRoutine");
    g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle = GetSymbolOffset(sym_ctx, "EtwThreatIntProvRegHandle");
    g_ntoskrnlOffsets.st.eprocess_protection = GetFieldOffset(sym_ctx, "_EPROCESS", L"Protection");
    g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry = GetFieldOffset(sym_ctx, "_ETW_REG_ENTRY", L"GuidEntry");
    g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo = GetFieldOffset(sym_ctx, "_ETW_GUID_ENTRY", L"ProviderEnableInfo");
    g_ntoskrnlOffsets.st.psProcessType = GetSymbolOffset(sym_ctx, "PsProcessType");
    g_ntoskrnlOffsets.st.psThreadType = GetSymbolOffset(sym_ctx, "PsThreadType");
    g_ntoskrnlOffsets.st.object_type_callbacklist = GetFieldOffset(sym_ctx, "_OBJECT_TYPE", L"CallbackList");
    g_ntoskrnlOffsets.st.seCiCallbacks = GetSymbolOffset(sym_ctx, "SeCiCallbacks");
    UnloadSymbols(sym_ctx, delete_pdb);
}





