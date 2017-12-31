#ifndef KPH_H
#define KPH_H

#include <ntifs.h>
#define PHNT_MODE PHNT_MODE_KERNEL
typedef _Bool bool;
#define false 0
#define true 1
#include <phnt.h>
#include <ntfill.h>
#include <bcrypt.h>
#include <kphapi.h>
#include "llrb_clear.h"
#include "ring_buffer.h"
#include "ioctls.h"
#include "debug_print.h"
#include "system_id.h"
#include "queue_manager.h"

// Memory

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))
#define PTR_SUB_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) - (ULONG_PTR)(Offset)))

// Zero extension and sign extension macros

#define C_2sTo4(x) ((unsigned int)(signed short)(x))

// Debugging

#ifdef DBG
#define dprintf(Format, ...) DbgPrint("KProcessHacker: " Format, __VA_ARGS__)
#else
#define dprintf
#endif

typedef struct _KPH_CLIENT
{
    struct
    {
        ULONG VerificationPerformed : 1;
        ULONG VerificationSucceeded : 1;
        ULONG KeysGenerated : 1;
        ULONG SpareBits : 29;
    };
    FAST_MUTEX StateMutex;
    NTSTATUS VerificationStatus;
    PVOID VerifiedProcess; // EPROCESS (for equality checking only - do not access contents)
    HANDLE VerifiedProcessId;
    PVOID VerifiedRangeBase;
    SIZE_T VerifiedRangeSize;
    // Level 1 and 2 secret keys
    FAST_MUTEX KeyBackoffMutex;
    KPH_KEY L1Key;
    KPH_KEY L2Key;
} KPH_CLIENT, *PKPH_CLIENT;

typedef struct _KPH_PARAMETERS
{
    KPH_SECURITY_LEVEL SecurityLevel;
} KPH_PARAMETERS, *PKPH_PARAMETERS;

// main

extern ULONG KphFeatures;
extern KPH_PARAMETERS KphParameters;

NTSTATUS KpiGetFeatures(
    _Out_ PULONG Features,
    _In_ KPROCESSOR_MODE AccessMode
    );

// devctrl

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH KphDispatchDeviceControl;

NTSTATUS KphDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

// dynimp

VOID KphDynamicImport(
    VOID
    );

PVOID KphGetSystemRoutineAddress(
    _In_ PWSTR SystemRoutineName
    );

// object

PHANDLE_TABLE KphReferenceProcessHandleTable(
    _In_ PEPROCESS Process
    );

VOID KphDereferenceProcessHandleTable(
    _In_ PEPROCESS Process
    );

VOID KphUnlockHandleTableEntry(
    _In_ PHANDLE_TABLE HandleTable,
    _In_ PHANDLE_TABLE_ENTRY HandleTableEntry
    );

NTSTATUS KpiEnumerateProcessHandles(
    _In_ HANDLE ProcessHandle,
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_opt_ ULONG BufferLength,
    _Out_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KphQueryNameObject(
    _In_ PVOID Object,
    _Out_writes_bytes_(BufferLength) POBJECT_NAME_INFORMATION Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG ReturnLength
    );

NTSTATUS KphQueryNameFileObject(
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_bytes_(BufferLength) POBJECT_NAME_INFORMATION Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG ReturnLength
    );

NTSTATUS KpiQueryInformationObject(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE Handle,
    _In_ KPH_OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiSetInformationObject(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE Handle,
    _In_ KPH_OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KphOpenNamedObject(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode
    );

// process

NTSTATUS KpiOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCLIENT_ID ClientId,
    _In_opt_ KPH_KEY Key,
    _In_ PKPH_CLIENT Client,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiOpenProcessToken(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle,
    _In_opt_ KPH_KEY Key,
    _In_ PKPH_CLIENT Client,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiOpenProcessJob(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE JobHandle,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiTerminateProcess(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus,
    _In_opt_ KPH_KEY Key,
    _In_ PKPH_CLIENT Client,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ KPH_PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ KPH_PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

// qrydrv

NTSTATUS KpiOpenDriver(
    _Out_ PHANDLE DriverHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiQueryInformationDriver(
    _In_ HANDLE DriverHandle,
    _In_ DRIVER_INFORMATION_CLASS DriverInformationClass,
    _Out_writes_bytes_(DriverInformationLength) PVOID DriverInformation,
    _In_ ULONG DriverInformationLength,
    _Out_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

// thread

NTSTATUS KpiOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCLIENT_ID ClientId,
    _In_opt_ KPH_KEY Key,
    _In_ PKPH_CLIENT Client,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiOpenThreadProcess(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle,
    _In_ KPROCESSOR_MODE AccessMode
    );

ULONG KphCaptureStackBackTrace(
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _In_opt_ ULONG Flags,
    _Out_writes_(FramesToCapture) PVOID *BackTrace,
    _Out_opt_ PULONG BackTraceHash
    );

NTSTATUS KphCaptureStackBackTraceThread(
    _In_ PETHREAD Thread,
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_(FramesToCapture) PVOID *BackTrace,
    _Out_opt_ PULONG CapturedFrames,
    _Out_opt_ PULONG BackTraceHash,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiCaptureStackBackTraceThread(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_(FramesToCapture) PVOID *BackTrace,
    _Out_opt_ PULONG CapturedFrames,
    _Out_opt_ PULONG BackTraceHash,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ KPH_THREAD_INFORMATION_CLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

NTSTATUS KpiSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ KPH_THREAD_INFORMATION_CLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _In_ KPROCESSOR_MODE AccessMode
    );

// util

VOID KphFreeCapturedUnicodeString(
    _In_ PUNICODE_STRING CapturedUnicodeString
    );

NTSTATUS KphCaptureUnicodeString(
    _In_ PUNICODE_STRING UnicodeString,
    _Out_ PUNICODE_STRING CapturedUnicodeString
    );

NTSTATUS KphEnumerateSystemModules(
    _Out_ PRTL_PROCESS_MODULES *Modules
    );

NTSTATUS KphValidateAddressForSystemModules(
    _In_ PVOID Address,
    _In_ SIZE_T Length
    );

NTSTATUS KphGetProcessMappedFileName(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PUNICODE_STRING *FileName
    );

// verify

NTSTATUS KphHashFile(
    _In_ PUNICODE_STRING FileName,
    _Out_ PVOID *Hash,
    _Out_ PULONG HashSize
    );

NTSTATUS KphVerifyFile(
    _In_ PUNICODE_STRING FileName,
    _In_reads_bytes_(SignatureSize) PUCHAR Signature,
    _In_ ULONG SignatureSize
    );

VOID KphVerifyClient(
    _Inout_ PKPH_CLIENT Client,
    _In_ PVOID CodeAddress,
    _In_reads_bytes_(SignatureSize) PUCHAR Signature,
    _In_ ULONG SignatureSize
    );

NTSTATUS KpiVerifyClient(
    _In_ PVOID CodeAddress,
    _In_reads_bytes_(SignatureSize) PUCHAR Signature,
    _In_ ULONG SignatureSize,
    _In_ PKPH_CLIENT Client
    );

VOID KphGenerateKeysClient(
    _Inout_ PKPH_CLIENT Client
    );

NTSTATUS KphRetrieveKeyViaApc(
    _Inout_ PKPH_CLIENT Client,
    _In_ KPH_KEY_LEVEL KeyLevel,
    _Inout_ PIRP Irp
    );

NTSTATUS KphValidateKey(
    _In_ KPH_KEY_LEVEL RequiredKeyLevel,
    _In_opt_ KPH_KEY Key,
    _In_ PKPH_CLIENT Client,
    _In_ KPROCESSOR_MODE AccessMode
    );

// vm

NTSTATUS KphCopyVirtualMemory(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _In_ PVOID ToAddress,
    _In_ SIZE_T BufferLength,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PSIZE_T ReturnLength
    );

NTSTATUS KpiReadVirtualMemoryUnsafe(
    _In_opt_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead,
    _In_opt_ KPH_KEY Key,
    _In_ PKPH_CLIENT Client,
    _In_ KPROCESSOR_MODE AccessMode
    );

// An LLRB tree node that holds process information
//typedef bool _Bool;
#if defined(__cplusplus)
typedef bool _Bool;
#endif

struct PROCESS_NODE {
	LLRB_ENTRY(PROCESS_NODE) TreeEntry;    // LLRB tree entry
	UINT32                   Pid;          // Process ID
	UINT32                   ParentPid;    // Parent process ID
	_Bool                    ImageLoaded;  // True if process image loaded in memory
};

typedef struct PROCESS_NODE PROCESS_NODE;

// Flags to track components that were successfully initialized
enum INIT_FLAGS {
	InitializedLookasideList = 0x0001,
	InitializedProcessNotifyRoutine = 0x0002,
	InitializedLoadImageNotifyRoutine = 0x0004,
};

__checkReturn __drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS InitializeComponents(__in DEVICE_OBJECT *device);

void DeinitializeComponents(__in void);

__checkReturn
NTSTATUS InitializeProcessMonitor(__in DEVICE_OBJECT *device);

__checkReturn
NTSTATUS DeinitializeProcessMonitor(void);

int CompareProcessNodes(PROCESS_NODE *first, PROCESS_NODE *second);

void DeleteProcessNode(PROCESS_NODE *processNode);

__checkReturn
NTSTATUS CreateProcessCallback(__in HANDLE pid, __in HANDLE parentPid);

__checkReturn
NTSTATUS StoreProcessInfo(
	__in const UINT32 pid,
	__in const UINT32 parentPid,
	__in const _Bool  imageLoaded);

void CleanupProcessCallback(__in HANDLE pid);

NTSTATUS GetProcessPathArgs(
	__in const UINT32               pid,
	__in PROCESS_BASIC_INFORMATION *procBasicInfo,
	__in UNICODE_STRING            *path,
	__in UNICODE_STRING            *args);

// Structures needed to get command line info from a process
// Simplified versions of those found in winternl.h
typedef struct _RTL_USER_PROCESS_PARAMETERS {
	unsigned char   Reserved1[16];
	void           *Reserved2[10];
	UNICODE_STRING  ImagePathName;
	UNICODE_STRING  CommandLine;
} RTL_USER_PROCESS_PARAMETERS;

// Simplified system process information structure
struct SYSTEM_PROCESS_INFORMATION {
	UINT32         NextEntryOffset;
	UINT32         NumberOfThreads;
	LARGE_INTEGER  Reserved[3];
	LARGE_INTEGER  CreateTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY      BasePriority;
	HANDLE         ProcessId;
	HANDLE         InheritedFromProcessId;
	// ...
};

wchar_t *GetUnicodeStringBuffer(
	__in PUNICODE_STRING              string,
	__in RTL_USER_PROCESS_PARAMETERS *processParams);

NTSTATUS GetProcessSid(
	__in const UINT32               pid,
	__in PROCESS_BASIC_INFORMATION *procBasicInfo,
	__in UNICODE_STRING            *sid);

__drv_requiresIRQL(PASSIVE_LEVEL)
void ProcessNotifyCallback(
	__in HANDLE  parentPid,
	__in HANDLE  pid,
	__in BOOLEAN create);

__drv_requiresIRQL(PASSIVE_LEVEL)
void LoadImageNotifyRoutine(
	__in PUNICODE_STRING fullImageName,
	__in HANDLE          pid,
	__in PIMAGE_INFO     imageInfo);

#endif
