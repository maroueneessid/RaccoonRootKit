#pragma once
#include <ntifs.h>
#include <ntddk.h>

#define DEBUG_PRINT(format , ...) DbgPrintEx(0, 0, format , __VA_ARGS__)

#define IOCTL_REPLACE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_KILL_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x922, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)



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






typedef struct {

	DWORD32 target;
	DWORD32 stealFrom;

} REPLACE_TOKEN_INFO, * PREPLACE_TOKEN_INFO;