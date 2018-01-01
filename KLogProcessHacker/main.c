/*
 * KProcessHacker
 *
 * Copyright (C) 2010-2018 wj32/tigros/Battelle
 *
 * This file is part of Process Hacker.
 *
 * Process Hacker is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Process Hacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <kph.h>
#include <wdf.h>
#include <dyndata.h>
#include "read_interface_priv.h"

typedef NTSTATUS(*INIT_FUNC)(__in DEVICE_OBJECT *device);
typedef NTSTATUS(*DEINIT_FUNC)(void);

struct DRIVER_COMPONENT {
	char        *Name;
	INIT_FUNC    Initialize;
	DEINIT_FUNC  Deinitialize;
};

typedef struct DRIVER_COMPONENT DRIVER_COMPONENT;

static const DRIVER_COMPONENT gComponents[] = {
	{ "queue manager",   InitializeQueueManager,   DeinitializeQueueManager },
{ "process monitor", InitializeProcessMonitor, DeinitializeProcessMonitor },
//{ "network monitor", InitializeNetworkMonitor, DeinitializeNetworkMonitor },
{ "read interface",  InitializeReadInterface,  DeinitializeReadInterface }
};

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnloadold;
EVT_WDF_DRIVER_UNLOAD DriverUnload;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH KphDispatchCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH KphDispatchClose;

// LLRB tree to hold process information
typedef LLRB_HEAD(ProcessTree, PROCESS_NODE) PROCESS_TREE_HEAD;
static PROCESS_TREE_HEAD gProcessTreeHead = LLRB_INITIALIZER(&gProcessTreeHead);

#pragma warning(push)
#pragma warning(disable:4706) // LLRB uses assignments in conditional expressions
LLRB_GENERATE(ProcessTree, PROCESS_NODE, TreeEntry, CompareProcessNodes);
#pragma warning(pop)

LLRB_CLEAR_GENERATE(ProcessTree, PROCESS_NODE, TreeEntry, DeleteProcessNode);

static UINT32            gLastLoadedPid = 0;   // ID of last process whose image was loaded
static UINT32            gInitializationFlags = 0;   // Components that were initialized successfully
static KSPIN_LOCK        gProcessTreeLock;           // Locks process trees
static LOOKASIDE_LIST_EX gLookasideList;             // Lookaside list for allocating LLRB nodes
static const UINT32		 gPoolTag = 'ohpK'; // Tag to use when allocating pool data
static const UINT32      gPoolTagLookaside = 'lHPK'; // Tag to use when allocating lookaside buffers

ULONG KphpReadIntegerParameter(
    _In_opt_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ ULONG DefaultValue
    );

NTSTATUS KphpReadDriverParameters(
    _In_ PUNICODE_STRING RegistryPath
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, KphpReadIntegerParameter)
#pragma alloc_text(PAGE, KphpReadDriverParameters)
#pragma alloc_text(PAGE, KpiGetFeatures)
#endif

PDRIVER_OBJECT KphDriverObject;
PDEVICE_OBJECT KphDeviceObject;
ULONG KphFeatures;
KPH_PARAMETERS KphParameters;

typedef struct WDFDEVICE_INIT { int x; } WDFDEVICE_INIT;

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:
DriverEntry initializes the driver and is the first routine called by the
system after the driver is loaded. DriverEntry specifies the other entry
points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

DriverObject - represents the instance of the function driver that is loaded
into memory. DriverEntry must initialize members of DriverObject before it
returns to the caller. DriverObject is allocated by the system before the
driver is loaded, and it is released by the system after the system unloads
the function driver from memory.

RegistryPath - represents the driver specific path in the Registry.
The function driver can use the path to store driver related data between
reboots. The path does not store hardware instance specific data.

Return Value:

STATUS_SUCCESS if successful,
STATUS_UNSUCCESSFUL otherwise.

--*/
{
	NTSTATUS           status;
	WDF_DRIVER_CONFIG  wdfConfig;
	WDFDEVICE          wdfDevice;
	WDFDRIVER          wdfDriver;
	WDFDEVICE_INIT    *wdfInit = NULL;
	DEVICE_OBJECT     *wdmDevice = NULL;
	static const GUID  deviceGuid = { 0x5728b2c2, 0x859, 0x4b9f,
	{ 0xa0, 0xdc, 0xb4, 0x12, 0xc4, 0x47, 0xe8, 0x11 } };

	DECLARE_CONST_UNICODE_STRING(deviceName, KPH_DEVICE_NAME);
	DECLARE_CONST_UNICODE_STRING(deviceLinkName, L"\\DosDevices\\KProcessHacker3");

	// Create WDF driver object
	WDF_DRIVER_CONFIG_INIT(&wdfConfig, WDF_NO_EVENT_CALLBACK);
	wdfConfig.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	wdfConfig.DriverPoolTag = gPoolTag;
	wdfConfig.EvtDriverUnload = DriverUnload;
	status = WdfDriverCreate(DriverObject, RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES, &wdfConfig, &wdfDriver);

	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot create WDF driver: %08X", status);
		goto Cleanup;
	}

	// Create WDF device object
	wdfInit = WdfControlDeviceInitAllocate(wdfDriver, &SDDL_DEVOBJ_KERNEL_ONLY);
	if (!wdfInit) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DBGPRINT(D_ERR, "Cannot allocate WDF device initialization structure: %08X",
			status);
		goto Cleanup;
	}
	WdfDeviceInitSetDeviceClass(wdfInit, &deviceGuid);
	WdfDeviceInitSetDeviceType(wdfInit, FILE_DEVICE_UNKNOWN);
	WdfDeviceInitSetCharacteristics(wdfInit, FILE_DEVICE_SECURE_OPEN, FALSE);
	status = WdfDeviceInitAssignName(wdfInit, &deviceName);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot assign name to WDF device: %08X", status);
		goto Cleanup;
	}
	status = WdfDeviceInitAssignSDDLString(wdfInit, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot assign security descriptor to WDF device: %08X", status);
		goto Cleanup;
	}
	status = WdfDeviceCreate(&wdfInit, WDF_NO_OBJECT_ATTRIBUTES, &wdfDevice);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot create WDF device: %08X", status);
		goto Cleanup;
	}

	status = WdfDeviceCreateSymbolicLink(wdfDevice, &deviceLinkName);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot create WDF symbolic link: %08X", status);
		goto Cleanup;
	}

	// Get the WDM device object
	WdfControlFinishInitializing(wdfDevice);
	wdmDevice = WdfDeviceWdmGetDeviceObject(wdfDevice);

	// Initialize components
	status = InitializeComponents(wdmDevice);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot initialize components: %08X", status);
		goto Cleanup;
	}

	// Finish initializing read interface
	DriverObject->MajorFunction[IRP_MJ_CREATE] = KphDispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = KphDispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KphDispatchDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;

Cleanup:
	if (NT_SUCCESS(status)) {
		DBGPRINT(D_INFO, "Finished initializing driver");
	}
	else {
		// The framework doesn't call DriverUnload if DriverEntry returns an error
		// http://msdn.microsoft.com/en-us/library/ff541694.aspx
		DeinitializeComponents();
		DBGPRINT(D_ERR, "Failed to initialize driver");
	}
	return status;
}

__checkReturn __drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS InitializeComponents(__in DEVICE_OBJECT *device)
{
	for (int i = 0; i < ARRAY_SIZEOF(gComponents); i++) {
		DBGPRINT(D_INFO, "Initializing %s", gComponents[i].Name);
		const NTSTATUS status = gComponents[i].Initialize(device);
		if (!NT_SUCCESS(status)) {
			DBGPRINT(D_ERR, "Cannot initialize %s", gComponents[i].Name);
			return status;
		}
		DBGPRINT(D_INFO, "Finished initializing %s", gComponents[i].Name);
	}
	return STATUS_SUCCESS;
}

void DeinitializeComponents(void)
{
	// Deinitialize components in reverse order they were initialized in
	for (int i = ARRAY_SIZEOF(gComponents) - 1; i >= 0; i--) {
		DBGPRINT(D_INFO, "Deinitializing %s", gComponents[i].Name);
		const NTSTATUS status = gComponents[i].Deinitialize();
		if (!NT_SUCCESS(status)) {
			DBGPRINT(D_WARN, "Cannot deinitialize %s", gComponents[i].Name);
		}
		else {
			DBGPRINT(D_INFO, "Finished deinitializing %s", gComponents[i].Name);
		}
	}
}

//----------------------------------------------------------------------------
__checkReturn
NTSTATUS DeinitializeProcessMonitor(void)
{
	NTSTATUS           status;
	KLOCK_QUEUE_HANDLE lockHandle;

	if (gInitializationFlags & InitializedProcessNotifyRoutine) {
		status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
		if (!NT_SUCCESS(status)) {
			DBGPRINT(D_ERR, "Cannot remove callback from process notify list");
		}
	}

	if (gInitializationFlags & InitializedLoadImageNotifyRoutine) {
		status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		if (!NT_SUCCESS(status)) {
			DBGPRINT(D_ERR, "Cannot remove callback from image notify list");
		}
	}

	DBGPRINT(D_LOCK, "Acquiring process tree lock at %d", __LINE__);
	KeAcquireInStackQueuedSpinLock(&gProcessTreeLock, &lockHandle);
	LLRB_CLEAR(ProcessTree, &gProcessTreeHead);
	KeReleaseInStackQueuedSpinLock(&lockHandle);
	DBGPRINT(D_LOCK, "Released process tree lock at %d", __LINE__);

	if (gInitializationFlags & InitializedLookasideList) {
		ExDeleteLookasideListEx(&gLookasideList);
	}

	return STATUS_SUCCESS;
}

void DriverUnload(__in WDFDRIVER driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	DBGPRINT(D_INFO, "Unloading driver");
	DeinitializeComponents();
	DBGPRINT(D_INFO, "Finished unloading driver");
}

NTSTATUS KphDispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION stackLocation;
    PFILE_OBJECT fileObject;
    PIO_SECURITY_CONTEXT securityContext;
    PKPH_CLIENT client;

    stackLocation = IoGetCurrentIrpStackLocation(Irp);
    fileObject = stackLocation->FileObject;
    securityContext = stackLocation->Parameters.Create.SecurityContext;

    dprintf("Client (PID %Iu) is connecting\n", PsGetCurrentProcessId());

    if (KphParameters.SecurityLevel == KphSecurityPrivilegeCheck ||
        KphParameters.SecurityLevel == KphSecuritySignatureAndPrivilegeCheck)
    {
        UCHAR requiredPrivilegesBuffer[FIELD_OFFSET(PRIVILEGE_SET, Privilege) + sizeof(LUID_AND_ATTRIBUTES)];
        PPRIVILEGE_SET requiredPrivileges;

        // Check for SeDebugPrivilege.

        requiredPrivileges = (PPRIVILEGE_SET)requiredPrivilegesBuffer;
        requiredPrivileges->PrivilegeCount = 1;
        requiredPrivileges->Control = PRIVILEGE_SET_ALL_NECESSARY;
        requiredPrivileges->Privilege[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        requiredPrivileges->Privilege[0].Luid.HighPart = 0;
        requiredPrivileges->Privilege[0].Attributes = 0;

        if (!SePrivilegeCheck(
            requiredPrivileges,
            &securityContext->AccessState->SubjectSecurityContext,
            Irp->RequestorMode
            ))
        {
            status = STATUS_PRIVILEGE_NOT_HELD;
            dprintf("Client (PID %Iu) was rejected\n", PsGetCurrentProcessId());
        }
    }

    if (NT_SUCCESS(status))
    {
        client = ExAllocatePoolWithTag(PagedPool, sizeof(KPH_CLIENT), 'ZhpK');

        if (client)
        {
            memset(client, 0, sizeof(KPH_CLIENT));

            ExInitializeFastMutex(&client->StateMutex);
            ExInitializeFastMutex(&client->KeyBackoffMutex);

            fileObject->FsContext = client;
        }
        else
        {
            dprintf("Unable to allocate memory for client (PID %Iu)\n", PsGetCurrentProcessId());
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

	if (NT_SUCCESS(status))
		return DispatchCreate(DeviceObject, Irp);
    
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS KphDispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION stackLocation;
    PFILE_OBJECT fileObject;
    PKPH_CLIENT client;

    stackLocation = IoGetCurrentIrpStackLocation(Irp);
    fileObject = stackLocation->FileObject;
    client = fileObject->FsContext;

    if (client)
    {
        ExFreePoolWithTag(client, 'ZhpK');
    }
	
	return DispatchClose(DeviceObject, Irp);
}

/**
 * Reads an integer (REG_DWORD) parameter from the registry.
 *
 * \param KeyHandle A handle to the Parameters key. If NULL, the function
 * fails immediately and returns \a DefaultValue.
 * \param ValueName The name of the parameter.
 * \param DefaultValue The value that is returned if the function fails
 * to retrieve the parameter from the registry.
 *
 * \return The parameter value, or \a DefaultValue if the function failed.
 */
ULONG KphpReadIntegerParameter(
    _In_opt_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ ULONG DefaultValue
    )
{
    NTSTATUS status;
    UCHAR buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION info;
    ULONG resultLength;

    PAGED_CODE();

    if (!KeyHandle)
        return DefaultValue;

    info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    status = ZwQueryValueKey(
        KeyHandle,
        ValueName,
        KeyValuePartialInformation,
        info,
        sizeof(buffer),
        &resultLength
        );

    if (info->Type != REG_DWORD)
        status = STATUS_OBJECT_TYPE_MISMATCH;

    if (!NT_SUCCESS(status))
    {
        dprintf("Unable to query parameter %.*S: 0x%x\n", ValueName->Length / sizeof(WCHAR), ValueName->Buffer, status);
        return DefaultValue;
    }

    return *(PULONG)info->Data;
}

/**
 * Reads the driver parameters.
 *
 * \param RegistryPath The registry path of the driver.
 */
NTSTATUS KphpReadDriverParameters(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    HANDLE parametersKeyHandle;
    UNICODE_STRING parametersString;
    UNICODE_STRING parametersKeyName;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING valueName;

    PAGED_CODE();

    // Open the Parameters key.

    RtlInitUnicodeString(&parametersString, L"\\Parameters");

    parametersKeyName.Length = RegistryPath->Length + parametersString.Length;
    parametersKeyName.MaximumLength = parametersKeyName.Length;
    parametersKeyName.Buffer = ExAllocatePoolWithTag(PagedPool, parametersKeyName.MaximumLength, 'ThpK');

    if (!parametersKeyName.Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(parametersKeyName.Buffer, RegistryPath->Buffer, RegistryPath->Length);
    memcpy(&parametersKeyName.Buffer[RegistryPath->Length / sizeof(WCHAR)], parametersString.Buffer, parametersString.Length);

    InitializeObjectAttributes(
        &objectAttributes,
        &parametersKeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );
    status = ZwOpenKey(
        &parametersKeyHandle,
        KEY_READ,
        &objectAttributes
        );
    ExFreePoolWithTag(parametersKeyName.Buffer, 'ThpK');

    if (!NT_SUCCESS(status))
    {
        dprintf("Unable to open Parameters key: 0x%x\n", status);
        status = STATUS_SUCCESS;
        parametersKeyHandle = NULL;
        // Continue so we can set up defaults.
    }

    // Read in the parameters.

    RtlInitUnicodeString(&valueName, L"SecurityLevel");
    KphParameters.SecurityLevel = KphpReadIntegerParameter(parametersKeyHandle, &valueName, KphSecurityPrivilegeCheck);

    KphReadDynamicDataParameters(parametersKeyHandle);

    if (parametersKeyHandle)
        ZwClose(parametersKeyHandle);

    return status;
}

NTSTATUS KpiGetFeatures(
    _Out_ PULONG Features,
    _In_ KPROCESSOR_MODE AccessMode
    )
{
    PAGED_CODE();

    if (AccessMode != KernelMode)
    {
        __try
        {
            ProbeForWrite(Features, sizeof(ULONG), sizeof(ULONG));
            *Features = KphFeatures;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }
    else
    {
        *Features = KphFeatures;
    }

    return STATUS_SUCCESS;
}

__checkReturn
NTSTATUS CreateProcessCallback(__in HANDLE pid, __in HANDLE parentPid)
{
	// We need to wait until the process is loaded into memory to retrieve the
	// path and commandline info.  So here, we collect what we can't collect
	// there (e.g., ppid), and store it for later.
	return StoreProcessInfo(pid, parentPid, false);
}

//----------------------------------------------------------------------------
__drv_requiresIRQL(PASSIVE_LEVEL)
void ProcessNotifyCallback(
	__in HANDLE  parentPid,
	__in HANDLE  pid,
	__in BOOLEAN create)
{
	if (create) {
		(void)CreateProcessCallback(pid, parentPid);
	}
	else {
		CleanupProcessCallback(pid);
	} 
}

//----------------------------------------------------------------------------
__drv_requiresIRQL(PASSIVE_LEVEL)
void LoadImageNotifyRoutine(
	__in PUNICODE_STRING fullImageName,
	__in HANDLE          pid,
	__in PIMAGE_INFO     imageInfo)
{
	PROCESS_BASIC_INFORMATION procBasicInfo;
	PROCESS_NODE             *processNode;
	PROCESS_NODE              searchNode;
	UINT32                    parentPid;
	UNICODE_STRING            path = { 0 };
	UNICODE_STRING            args = { 0 };
	UNICODE_STRING            sid = { 0 };
	KLOCK_QUEUE_HANDLE        lockHandle;

	UNREFERENCED_PARAMETER(fullImageName);
	UNREFERENCED_PARAMETER(imageInfo);

	// Check if image is a driver
	if (pid == 0) {
		// TODO: Handle this.  We get the FullImageName, we just need some
		// place to store device driver info.  The trick is detecting when a
		// driver is unloaded.
		return;
	}

	// Check if this is the last process loaded
	// After a process loads, it often loads several DLLs, each of which trigger
	// this callback.  By caching the ID of the last process loaded, we can
	// avoid having to lock and search the process tree.
	if (pid == gLastLoadedPid) {
		return;
	}
	gLastLoadedPid = pid;

	// Get previously stored information for the process
	// We can safely access the stored information after releasing the spin lock,
	// since the process cannot go away while we're still in the load image
	// notify routine
	searchNode.Pid = pid;
	DBGPRINT(D_LOCK, "Acquiring process tree lock at %d", __LINE__);
	KeAcquireInStackQueuedSpinLock(&gProcessTreeLock, &lockHandle);
	processNode = LLRB_FIND(ProcessTree, &gProcessTreeHead, &searchNode);
	KeReleaseInStackQueuedSpinLock(&lockHandle);
	DBGPRINT(D_LOCK, "Released process tree lock at %d", __LINE__);
	if (processNode) {
		if (processNode->ImageLoaded) {
			return; // The image is a DLL, which we currently ignore
		}
		else {
			parentPid = processNode->ParentPid;
		}
	}
	else {
		DBGPRINT(D_WARN, "Received image load notification for untracked process %u",
			pid);
		return;
	}
	processNode->ImageLoaded = true;

	// Get process path and arguments and process owner's SID
	GetProcessPathArgs(pid, &procBasicInfo,
		&path, &args);
	GetProcessSid(pid, &procBasicInfo, &sid);

	DBGPRINT(D_INFO, "Process %u starting: parent %u, path %ws", pid, parentPid,
		path.Buffer);

	QmEnqueueProcessBlock(true, (UINT32)pid, parentPid, &path, &args, &sid, NULL);

	if (sid.Buffer) {
		RtlFreeUnicodeString(&sid); 
	} 
}

//----------------------------------------------------------------------------
__checkReturn
NTSTATUS InitializeProcessMonitor(DEVICE_OBJECT *device)
{
	NTSTATUS       status;
	UNICODE_STRING routineName;

	UNREFERENCED_PARAMETER(device);

	KeInitializeSpinLock(&gProcessTreeLock);

	// Initialize lookaside list
	status = ExInitializeLookasideListEx(&gLookasideList, NULL, NULL,
		NonPagedPool, 0, sizeof(PROCESS_NODE), gPoolTagLookaside, 0);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot create lookaside list");
		return status;
	}
	gInitializationFlags |= InitializedLookasideList;

	// Register callback function for when a process gets created.
	status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot register process create callback: %08X", status);
		return status;
	}
	gInitializationFlags |= InitializedProcessNotifyRoutine;

	// Register callback function for when an image is loaded for execution
	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot register image load callback: %08X", status);
		return status;
	}
	gInitializationFlags |= InitializedLoadImageNotifyRoutine;

	return status;
}

//----------------------------------------------------------------------------
int CompareProcessNodes(PROCESS_NODE *first, PROCESS_NODE *second)
{
	return (first->Pid - second->Pid);
}

//----------------------------------------------------------------------------
void DeleteProcessNode(PROCESS_NODE *processNode)
{
	if (processNode) {
		ExFreeToLookasideListEx(&gLookasideList, processNode);
	}
}

//----------------------------------------------------------------------------
__checkReturn
NTSTATUS StoreProcessInfo(
	__in const UINT32 pid,
	__in const UINT32 parentPid,
	__in const _Bool  imageLoaded)
{
	PROCESS_NODE       *processNode;
	PROCESS_NODE       *insertNode;
	KLOCK_QUEUE_HANDLE  lockHandle;

	processNode = ExAllocateFromLookasideListEx(&gLookasideList);
	if (processNode == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	processNode->Pid = pid;
	processNode->ParentPid = parentPid;
	processNode->ImageLoaded = imageLoaded;
	DBGPRINT(D_LOCK, "Acquiring process tree lock at %d", __LINE__);
	KeAcquireInStackQueuedSpinLock(&gProcessTreeLock, &lockHandle);
	insertNode = LLRB_INSERT(ProcessTree, &gProcessTreeHead, processNode);
	KeReleaseInStackQueuedSpinLock(&lockHandle);
	DBGPRINT(D_LOCK, "Released process tree lock at %d", __LINE__);
	if (insertNode) {
		DBGPRINT(D_WARN, "Already storing information for process %u", pid);
		ExFreeToLookasideListEx(&gLookasideList, processNode);
	}
	return STATUS_SUCCESS;
}


//----------------------------------------------------------------------------
void CleanupProcessCallback(__in HANDLE pid)
{
	PROCESS_NODE       *processNode;
	PROCESS_NODE        searchNode;
	KLOCK_QUEUE_HANDLE  lockHandle;

	// Clear the ID of last process loaded, if that process is going away
	InterlockedCompareExchange(&gLastLoadedPid, 0, pid);

	// Remove process information from process tree
	searchNode.Pid = pid;
	DBGPRINT(D_LOCK, "Acquiring process tree lock at %d", __LINE__);
	KeAcquireInStackQueuedSpinLock(&gProcessTreeLock, &lockHandle);
	processNode = LLRB_REMOVE(ProcessTree, &gProcessTreeHead, &searchNode);
	KeReleaseInStackQueuedSpinLock(&lockHandle);
	DBGPRINT(D_LOCK, "Released process tree lock at %d", __LINE__);
	if (processNode) {
		DBGPRINT(D_INFO, "Process %u ended: parent %u",
			(UINT32)pid, processNode->ParentPid);
		QmEnqueueProcessBlock(false, pid, processNode->ParentPid, NULL, NULL, NULL, NULL);
		ExFreeToLookasideListEx(&gLookasideList, processNode);
	}
	else {
		DBGPRINT(D_WARN, "Received cleanup notification for untracked process %u",
			pid);
	}
}

//----------------------------------------------------------------------------
// To get the command line, we need to use various undocumented features.
// Here's the basic idea:
//
// By the time this callback is executed, the given process' info is loaded
// into memory, including the PEB structure and the RTL_USER_PROCESS_PARAMETERS
// structure.
//
// We use ZwQueryInformationProcess() to get the location of the process' PEB,
// and from there we can extract the RTL_USER_PROCESS_PARAMETERS structure.
// This structure is used to extract the command line.
NTSTATUS GetProcessPathArgs(
	__in const UINT32               pid,
	__in PROCESS_BASIC_INFORMATION *procBasicInfo,
	__in UNICODE_STRING            *path,
	__in UNICODE_STRING            *args)
{
	NTSTATUS                     status;
	RTL_USER_PROCESS_PARAMETERS *params;

#ifndef DBG
	// The process ID argument is only used in debugging messages
	UNREFERENCED_PARAMETER(pid);
#endif

	if (!procBasicInfo || !path || !args) {
		return STATUS_INVALID_PARAMETER;
	}

	// Get the basic process information for the attached process.  Since we're
	// attached to the process, we can use the "current process" value of -1.
	status = ZwQueryInformationProcess(ZwCurrentProcess(),
		ProcessBasicInformation, procBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot get information for process %u: %08X", pid,
			status);
		return status;
	}

	// Extract path and command line information
	if (!procBasicInfo->PebBaseAddress) {
		return STATUS_INVALID_ADDRESS;
	}
	params = procBasicInfo->PebBaseAddress->ProcessParameters;
	path->Buffer = GetUnicodeStringBuffer(&params->ImagePathName, params);
	path->Length = params->ImagePathName.Length;
	args->Buffer = GetUnicodeStringBuffer(&params->CommandLine, params);
	args->Length = params->CommandLine.Length;
	return status;
}

//----------------------------------------------------------------------------
// The RTL_USER_PROCESS_PARAMETERS struct contains two UNICODE_STRING structs
// which contain the image name and commandline arguments.  These, however,
// are not your typical UNICODE_STRING structs.
//
// On x86 machines, for _most_ processes, PUNICODE_STRING->Buffer is not a
// normal pointer to a buffer containing a unicode string, but instead is an
// _offset_ from the location of RTL_USER_PROCESS_PARAMETERS.  However, this
// does not hold for all processes.  In particular, the svchost.exe process'
// PUNICODE_STRING->Buffer variable is in fact a pointer to the location,
// _not_ an offset!
//
// On x64 machines, this is always a normal pointer.
//
// So, in the x86 case, to get the actual unicode string, we check whether
// UNICODE_STRING.Buffer is greater than the memory location of
// RTL_USER_PROCESS_PARAMETERS, and if so we calculate
// 0x20000 + RTL_USER_PROCESS_PARAMETERS->UNICODE_STRING.Buffer.
// Otherwise, we assume UNICODE_STRING.Buffer is a valid pointer, and use it
// directly.
wchar_t *GetUnicodeStringBuffer(
	__in PUNICODE_STRING              string,
	__in RTL_USER_PROCESS_PARAMETERS *processParams)
{
#ifdef _X86_
	return (reinterpret_cast<UINT32>(string->Buffer) >
		reinterpret_cast<UINT32>(processParams)) ? string->Buffer :
		reinterpret_cast<PWCH>(reinterpret_cast<UINT32>(string->Buffer) +
			reinterpret_cast<UINT32>(processParams));
#else
	UNREFERENCED_PARAMETER(processParams);
	return string->Buffer;
#endif
}

//----------------------------------------------------------------------------
// Getting the user name itself requires SecLookupAccountSid(), which relies
// on a user-mode helper, and therefore cannot be used early in the boot
// process.  Instead, we just get the SID itself.  If we need the user name,
// a user-mode tool can use the SID to get the user name.
NTSTATUS GetProcessSid(
	__in const UINT32               pid,
	__in PROCESS_BASIC_INFORMATION *procBasicInfo,
	__in UNICODE_STRING            *sid)
{
	NTSTATUS    status;
	HANDLE      processToken = NULL;
	TOKEN_USER *processUser = NULL;
	ULONG       processUserBytes = 0;

#ifndef DBG
	// Since we're attached to the process, we just use the special "current
	// process" value (-1).  The process ID argument is only used in debugging
	// messages.
	UNREFERENCED_PARAMETER(pid);
#endif

	if (!procBasicInfo || !sid) {
		return STATUS_INVALID_PARAMETER;
	}

	// Open process token
	status = ZwOpenProcessTokenEx(ZwCurrentProcess(), GENERIC_READ,
		OBJ_KERNEL_HANDLE, &processToken);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot open token for process %u: %08X",
			pid, status);
		goto Cleanup;
	}

	// Get size of buffer to hold the user information, which contains the SID
	status = ZwQueryInformationToken(processToken, TokenUser,
		NULL, 0, &processUserBytes);
	if (status != STATUS_BUFFER_TOO_SMALL) {
		DBGPRINT(D_ERR, "Cannot get token information size for process %u: %08X",
			pid, status);
		goto Cleanup;
	}

	// Allocate the buffer to hold the user information
	processUser = ExAllocatePoolWithTag(NonPagedPool, processUserBytes, gPoolTag);
	if (processUser == NULL) {
		DBGPRINT(D_ERR, "Cannot allocate %u token information bytes for process %u",
			processUserBytes, pid);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	// Get user information for the process token
	status = ZwQueryInformationToken(processToken, TokenUser,
		processUser, processUserBytes, &processUserBytes);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot get token information for process %u: %08X",
			pid, status);
		goto Cleanup;
	}

	// Convert the SID to a string, but don't free it until after enqueing the
	// PCAP-NG process block
	status = RtlConvertSidToUnicodeString(sid, processUser->User.Sid, TRUE);
	if (!NT_SUCCESS(status)) {
		DBGPRINT(D_ERR, "Cannot convert SID to string for process %u: %08X",
			pid, status);
		goto Cleanup;
	}

Cleanup:
	if (processToken) {
		ZwClose(processToken);
	}
	if (processUser) {
		ExFreePool(processUser);
	}
	return status;
}
