#pragma once
#include <ntifs.h>
#include <ntddk.h>

#define DEBUG_PRINT(format , ...) DbgPrintEx(0, 0, format , __VA_ARGS__)

#define IOCTL_REPLACE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_KILL_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x922, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_UNPROTECT_LSA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x923, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)



#define DEVICE L"\\Device\\internalsRaccoon"
#define LINK L"\\DosDevices\\internalsRaccoon"



NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(LINK);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	KdPrint(("[-] driver Unload called\n"));
}



typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;
		struct
		{
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;




typedef struct {

	DWORD32 target;
	DWORD32 stealFrom;
	DWORD64 offset;

} TASK_INFO, * PTASK_INFO;


