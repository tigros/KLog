/*
 * Process Hacker KLog -
 *
 * Copyright (C) 2018 tigros
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

#include "exttools.h"
#include <toolstatusintf.h>
#include <stdlib.h>
#include <psapi.h>
#include "linkedlist.h"
#include "BTree.h"

BOOLEAN KLogTreeNewCreated = FALSE;
HWND KLogTreeNewHandle;

static HANDLE gDriver = INVALID_HANDLE_VALUE;
static ULONG PhCsKLogAutoScroll = 0;
static PPH_MAIN_TAB_PAGE KLogPage;
static ULONG KLogTreeNewSortColumn;
static PH_SORT_ORDER KLogTreeNewSortOrder;

static PPH_HASHTABLE KLogNodeHashtable; // hashtable of all nodes
static PPH_LIST KLogNodeList; // list of all nodes

static PH_CALLBACK_REGISTRATION KLogItemAddedRegistration;
static PH_CALLBACK_REGISTRATION KLogItemModifiedRegistration;
static PH_CALLBACK_REGISTRATION KLogItemRemovedRegistration;
static PH_CALLBACK_REGISTRATION KLogItemsUpdatedRegistration;

static PH_TN_FILTER_SUPPORT FilterSupport;
static PTOOLSTATUS_INTERFACE ToolStatusInterface;
static PH_CALLBACK_REGISTRATION SearchChangedRegistration;
static PWE_KLOG_NODE gPrevBottomNode = NULL;

static BTnode *gBTroot = NULL;
static LLnode *gBacklogLL = NULL;

HANDLE myOpenDriver()
{
	HANDLE drv = INVALID_HANDLE_VALUE;
	LPCSTR driverFile = "\\\\.\\KProcessHacker3";

	drv = CreateFileA(driverFile, GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, 0, 0);

	return drv;
}

VOID initDriver()
{
	DWORD bytesReturned;
	UINT32 snapLenSet;
	UINT32 snapLen = 0;
	DWORD bytesRead;

	gDriver = myOpenDriver();

	if (gDriver == INVALID_HANDLE_VALUE)
	{
		PhShowMessage(KLogTreeNewHandle, MB_ICONERROR | MB_OK, L"KLog: Is the modified kprocesshacker.sys driver started?");
		return;
	}

	if (!DeviceIoControl(gDriver, IOCTL_KPH_SET_SNAP_LENGTH, &snapLen,
		sizeof(UINT32), NULL, 0, &bytesReturned, NULL)) {
		PhShowMessage(KLogTreeNewHandle, MB_ICONERROR | MB_OK, L"KLog: Cannot send IOCTL to set snap length");
	}

	if (!DeviceIoControl(gDriver, IOCTL_KPH_GET_SNAP_LENGTH, NULL, 0,
		&snapLenSet, sizeof(UINT32), &bytesReturned, NULL)) {
		PhShowMessage(KLogTreeNewHandle, MB_ICONERROR | MB_OK, L"KLog: Cannot send IOCTL to get snap length");
	}

	// Discard first chunk.
	char buffer[bufferSize];
	if (!ReadFile(gDriver, buffer, bufferSize, &bytesRead, NULL)) {
		PhShowMessage(KLogTreeNewHandle, MB_ICONERROR | MB_OK, L"KLog: Cannot read bytes from driver");
	}
}

VOID EtInitializeKlogTab(
    VOID
    )
{
	PH_MAIN_TAB_PAGE page;
    PPH_PLUGIN toolStatusPlugin;

    if (toolStatusPlugin = PhFindPlugin(TOOLSTATUS_PLUGIN_NAME))
    {
        ToolStatusInterface = PhGetPluginInformation(toolStatusPlugin)->Interface;

        if (ToolStatusInterface->Version < TOOLSTATUS_INTERFACE_VERSION)
            ToolStatusInterface = NULL;
    }

	memset(&page, 0, sizeof(PH_MAIN_TAB_PAGE));
	PhInitializeStringRef(&page.Name, L"KLog");
	page.Callback = EtpKLogPageCallback;
	KLogPage = ProcessHacker_CreateTabPage(PhMainWndHandle, &page);

    if (ToolStatusInterface)
    {
        PTOOLSTATUS_TAB_INFO tabInfo;

		tabInfo = ToolStatusInterface->RegisterTabInfo(KLogPage->Index);
		tabInfo->BannerText = L"Search KLog";
		tabInfo->ActivateContent = EtpToolStatusActivateContent;
		tabInfo->GetTreeNewHandle = EtpToolStatusGetTreeNewHandle;
    }

	initDriver();
}

HWND NTAPI EtpToolStatusGetTreeNewHandle(
	VOID
)
{
	return KLogTreeNewHandle;
}

void ProcessKLog()
{
	PPH_TREENEW_CONTEXT context;

	context = (PPH_TREENEW_CONTEXT)GetWindowLongPtr(KLogTreeNewHandle, 0);
	WepAddKLogs(context);
}

void CreateHwnd()
{
	HWND hwnd;
	HWND tmp = PhMainWndHandle;
	ULONG thinRows;

	thinRows = PhGetIntegerSetting(L"ThinRows") ? TN_STYLE_THIN_ROWS : 0;
	hwnd = CreateWindow(
		PH_TREENEW_CLASSNAME,
		NULL,
		WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | WS_BORDER | TN_STYLE_ICONS | TN_STYLE_DOUBLE_BUFFERED | thinRows,
		0,
		0,
		3,
		3,
		PhMainWndHandle,
		NULL,
		NULL,
		NULL
	);

	if (!hwnd)
		return NULL;

	KLogNodeList = PhCreateList(100);

	EtInitializeKLogTreeList(hwnd);

	KLogTreeNewCreated = TRUE;

	return hwnd;
}

BOOLEAN NTAPI EtpKLogPageCallback(
	_In_ struct _PH_MAIN_TAB_PAGE *Page,
	_In_ PH_MAIN_TAB_PAGE_MESSAGE Message,
	_In_opt_ PVOID Parameter1,
	_In_opt_ PVOID Parameter2
)
{
	switch (Message)
	{
	case MainTabPageCreateWindow:
	{
		CreateHwnd();
		*(HWND *)Parameter1 = KLogTreeNewHandle;
	}
	return TRUE;
	case MainTabPageLoadSettings:
	{
		// Nothing
	}
	return TRUE;
	case MainTabPageSaveSettings:
	{
		// Nothing
	}
	return TRUE;
    case MainTabPageSelected:
	if (KLogTreeNewCreated)
	{
        ProcessKLog();
	}
	return TRUE;

	case MainTabPageExportContent:
	{
		PPH_MAIN_TAB_PAGE_EXPORT_CONTENT exportContent = Parameter1;

		EtWriteKLogList(exportContent->FileStream, exportContent->Mode);
	}
	return TRUE;
	case MainTabPageFontChanged:
	{
		HFONT font = (HFONT)Parameter1;

		if (KLogTreeNewHandle)
			SendMessage(KLogTreeNewHandle, WM_SETFONT, (WPARAM)Parameter1, TRUE);
	}
	break;
	}

	return FALSE;
}

VOID NTAPI EtpKlogTabSelectionChangedCallback(
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3,
    _In_ PVOID Context
    )
{
    if ((BOOLEAN)Parameter1)
    {
        if (KLogTreeNewHandle)
            SetFocus(KLogTreeNewHandle);
    }
}

VOID EtWriteKLogList(
	_Inout_ PPH_FILE_STREAM FileStream,
	_In_ ULONG Mode
	)
{
	PPH_LIST lines;
	ULONG i;

	lines = PhGetGenericTreeNewLines(KLogTreeNewHandle, Mode);

	for (i = 0; i < lines->Count; i++)
	{
		PPH_STRING line;

		line = lines->Items[i];
		PhWriteStringAsUtf8FileStream(FileStream, &line->sr);
		PhDereferenceObject(line);
		PhWriteStringAsUtf8FileStream2(FileStream, L"\r\n");
	}

	PhDereferenceObject(lines);
}

VOID NTAPI EtpKlogTabSaveContentCallback(
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3,
    _In_ PVOID Context
    )
{
	PPH_FILE_STREAM fileStream = Parameter1;
	ULONG mode = PtrToUlong(Parameter2);

	EtWriteKLogList(fileStream, mode);
}

VOID NTAPI EtpKlogTabFontChangedCallback(
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3,
    _In_ PVOID Context
    )
{
    if (KLogTreeNewHandle)
        SendMessage(KLogTreeNewHandle, WM_SETFONT, (WPARAM)Parameter1, TRUE);
}


VOID EtSelectAndEnsureVisibleKLogNode(
	_In_ PWE_KLOG_NODE KLogNode
)
{
	if (KLogNode == NULL || !KLogNode->Node.Visible || KLogNode == gPrevBottomNode)
		return;

	gPrevBottomNode = KLogNode;
	EtDeselectAllKLogNodes();
	TreeNew_SetFocusNode(KLogTreeNewHandle, &KLogNode->Node);
	TreeNew_SetMarkNode(KLogTreeNewHandle, &KLogNode->Node);
	TreeNew_SelectRange(KLogTreeNewHandle, KLogNode->Node.Index, KLogNode->Node.Index);
	TreeNew_EnsureVisible(KLogTreeNewHandle, &KLogNode->Node);
}

void Autoscroll()
{
	if (!PhCsKLogAutoScroll || 
		KLogTreeNewSortColumn > 1 || 
		KLogTreeNewSortOrder != AscendingSortOrder)
		return;

	ULONG index = TreeNew_GetFlatNodeCount(KLogTreeNewHandle) - 1;

	if (index > 0)
		EtSelectAndEnsureVisibleKLogNode((PWE_KLOG_NODE)TreeNew_GetFlatNode(KLogTreeNewHandle, index));
}

PWE_KLOG_NODE WeAddKLogNode(
	_Inout_ PPH_TREENEW_CONTEXT Context
	)
{
	PWE_KLOG_NODE klogNode;

	klogNode = PhAllocate(sizeof(WE_KLOG_NODE));
	memset(klogNode, 0, sizeof(WE_KLOG_NODE));
	PhInitializeTreeNewNode(&klogNode->Node);

	memset(klogNode->TextCache, 0, sizeof(PH_STRINGREF) * WEWNTLC_MAXIMUM);
	klogNode->Node.TextCache = klogNode->TextCache;
	klogNode->Node.TextCacheSize = WEWNTLC_MAXIMUM;

	PhAddItemList(KLogNodeList, klogNode);

	TreeNew_NodesStructured(Context->Handle);

	return klogNode;
}

void add2BT(PWE_KLOG_NODE childNode)
{

	BTnode *node;

	node = BTsearch(gBTroot, childNode->aklog.PID);

	if (!node)
	{
		BTinsert(&gBTroot, BTnew(childNode));
	}
	else
	{
		node->klognode = childNode;
	}

}

VOID WepAddChildKLogNode(
	_In_ PPH_TREENEW_CONTEXT Context,
	ULONGLONG timestamp,
	DWORD PID,
	DWORD ParentPID,
	wchar_t *Wexecutable,
	wchar_t *Wcmdline
)
{
	PWE_KLOG_NODE childNode;
	LARGE_INTEGER tstamp;
	BTnode *btnode;

	childNode = WeAddKLogNode(Context);
	RtlSecondsSince1970ToTime(timestamp / 1000000, &tstamp);
	PhPrintUInt64(childNode->aklog.timestampstring, timestamp);
	childNode->aklog.timestamp = timestamp;
	childNode->aklog.time.QuadPart = tstamp.QuadPart;

	childNode->aklog.PID = PID;
	childNode->aklog.ParentPID = ParentPID;
	PhPrintUInt32(childNode->aklog.PIDstring, PID);
	PhPrintUInt32(childNode->aklog.ParentPIDstring, ParentPID);

	if (Wexecutable == NULL)
	{
		childNode->aklog.startexit = 1;
		btnode = BTsearch(gBTroot, childNode->aklog.PID);

		if (btnode)
		{
			childNode->aklog.executable = PhReferenceObject(btnode->klognode->aklog.executable);
			childNode->aklog.cmdline = PhReferenceObject(btnode->klognode->aklog.cmdline);
		}
		else
		{
			childNode->aklog.executable = PhCreateString(L"Exited");
			childNode->aklog.cmdline = PhCreateString(L" ");
		}
	}
	else
	{
		childNode->aklog.startexit = 0;
		childNode->aklog.executable = PhCreateString(Wexecutable);
		childNode->aklog.cmdline = PhCreateString(Wcmdline);
		add2BT(childNode);
	}

	childNode->Node.Expanded = FALSE;
	PhAddItemList(Context->FlatList, childNode);

	if (FilterSupport.NodeList)
		childNode->Node.Visible = PhApplyTreeNewFiltersToNode(&FilterSupport, &childNode->Node);
}

VOID WepAddChildKLogNodes(
	_In_ PPH_TREENEW_CONTEXT Context,
	char *buff,
	DWORD bytesread
	)
{
	UINT len;
	WORD *bufw = (WORD *)buff;
	DWORD *bufd = (DWORD *)buff;
	wchar_t *Wcmdline;
	wchar_t *Wexecutable;
	ULONGLONG timestamp;
	DWORD timestamp_high;
	DWORD timestamp_low;
	DWORD PID = 0;
	DWORD ParentPID = 0;
	WORD *execpos = NULL;
	DWORD i;
	int requiredSize;

	if (bufd[0] != 257)
		return;

	TreeNew_SetRedraw(KLogTreeNewHandle, FALSE);

	for (i = 0; i < bytesread / 2; i++)
	{
		if (((i % 2) == 0) && (bufd[i / 2] == 257))
		{
			timestamp_high = bufd[i / 2 + 3];
			timestamp_low = bufd[i / 2 + 4];

			timestamp = ((ULONGLONG)timestamp_high << 32) | timestamp_low;

			PID = bufd[i / 2 + 2];
			ParentPID = bufd[i / 2 + 6];

			if (bufd[i / 2 + 1] == 44 && bufd[i / 2 + 8] == 0xffffffff)
			{
				WepAddChildKLogNode(Context, timestamp, PID, ParentPID, NULL, NULL);
				i += 21;
			}
			else
				execpos = &bufw[i + 15];
		}
		else if (bufw[i] == 11 && (bufw[i - 1] == 0 || bufw[i - 1] > 12))
		{
			len = bufw[++i];

			requiredSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, &bufw[++i],
				len, NULL, 0);
			Wcmdline = (wchar_t *)malloc((requiredSize + 1) * sizeof(wchar_t));
			requiredSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, &bufw[i],
				len, Wcmdline, requiredSize);
			Wcmdline[requiredSize] = L'\0';

			requiredSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, &execpos[1],
				*execpos, NULL, 0);
			Wexecutable = (wchar_t *)malloc((requiredSize + 1) * sizeof(wchar_t));
			requiredSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, &execpos[1],
				*execpos, Wexecutable, requiredSize);
			Wexecutable[requiredSize] = L'\0';

			WepAddChildKLogNode(Context, timestamp, PID, ParentPID, Wexecutable, Wcmdline);

			i += len / 2;

			free(Wexecutable);
			free(Wcmdline);
		}
	}

	TreeNew_NodesStructured(KLogTreeNewHandle);
	TreeNew_SetRedraw(KLogTreeNewHandle, TRUE);
}

LLnode *getLL(DWORD *totbytesRead)
{
	DWORD bytesRead = bufferSize;
	LLnode *head = LLcreate();
	LLnode *node = head;
	char tmpbuff[bufferSize];

	*totbytesRead = 0;

	while (bytesRead == bufferSize)
	{
		if (!ReadFile(gDriver, tmpbuff, bufferSize, &bytesRead, NULL)) {
			PhShowMessage(KLogTreeNewHandle, MB_ICONERROR | MB_OK, L"KLog: Cannot read bytes from driver");
			*totbytesRead = 0;
			break;
		}

		*totbytesRead += bytesRead;
		node->size = bytesRead;

		if (bytesRead > 0)
		{
			node->buffer = (char *)malloc(bytesRead);
			if (!node->buffer)
			{
				*totbytesRead = 0;
				break;
			}

			memcpy(node->buffer, tmpbuff, bytesRead);
		}

		if (bytesRead == bufferSize)
		{
			node = LLappend(head);
		}
	}

	if (*totbytesRead == 0)
	{
		LLfree(head);
		head = NULL;
	}

	return head;
}

VOID ProcessLL(_In_ PPH_TREENEW_CONTEXT Context, LLnode *LL)
{
	DWORD totbytesRead = 0;
	LLnode *node = LL;
	DWORD pos = 0;
	char *buff;

	while (node)
	{
		totbytesRead += node->size;
		node = node->next;
	}

	if (!totbytesRead)
		return;

	buff = (char *)malloc(totbytesRead);

	if (!buff)
		return;

	ZeroMemory(buff, totbytesRead);

	node = LL;

	while (node)
	{
		if (node->buffer)
			memcpy(&buff[pos], node->buffer, node->size);
		pos += node->size;
		node = node->next;
	}

	WepAddChildKLogNodes(Context, buff, totbytesRead);

	free(buff);

	Autoscroll();
}

VOID WepAddKLogs(
	_In_ PPH_TREENEW_CONTEXT Context
	)
{
	DWORD totbytesRead = 0;

	if (!Context || gDriver == INVALID_HANDLE_VALUE)
		return;
	
	LLnode *head = getLL(&totbytesRead);

	if (totbytesRead > 0)
	{
		ProcessLL(Context, head);
		LLfree(head);
	}
}

void UpdateBacklog()
{
	if (gDriver == INVALID_HANDLE_VALUE)
		return;

	DWORD totbytesRead = 0;

	LLnode *head = getLL(&totbytesRead);

	if (totbytesRead > 0)
	{
		if (gBacklogLL == NULL)
			gBacklogLL = head;
		else
			LLappendLL(gBacklogLL, head);
	}
}

VOID ProcessBacklog(_In_ PPH_TREENEW_CONTEXT Context)
{
	if (gBacklogLL == NULL)
		return;

	ProcessLL(Context, gBacklogLL);

	LLfree(gBacklogLL);
	gBacklogLL = NULL;
}

VOID EtInitializeKLogTreeList(
    _In_ HWND hwnd
    )
{
	KLogTreeNewHandle = hwnd;
	PhSetControlTheme(KLogTreeNewHandle, L"explorer");
	SendMessage(TreeNew_GetTooltips(KLogTreeNewHandle), TTM_SETDELAYTIME, TTDT_AUTOPOP, 0x7fff);

	TreeNew_SetCallback(hwnd, EtpKLogTreeNewCallback, NULL);

	TreeNew_SetRedraw(hwnd, FALSE);

	// Default columns
	PhAddTreeNewColumn(hwnd, ETKLTNC_TIMESTAMP, TRUE, L"Timestamp", 120, PH_ALIGN_LEFT, 0, DT_LEFT);
	PhAddTreeNewColumn(hwnd, ETKLTNC_TIME, TRUE, L"Time", 150, PH_ALIGN_LEFT, 1, 0);
	PhAddTreeNewColumn(hwnd, ETKLTNC_PID, TRUE, L"PID", 100, PH_ALIGN_RIGHT, 2, DT_RIGHT);
	PhAddTreeNewColumn(hwnd, ETKLTNC_STARTEXIT, TRUE, L"Start/Exit", 80, PH_ALIGN_LEFT, 3, DT_LEFT);
	PhAddTreeNewColumn(hwnd, ETKLTNC_EXECUTABLE, TRUE, L"Executable", 200, PH_ALIGN_LEFT, 4, DT_END_ELLIPSIS);
    PhAddTreeNewColumn(hwnd, ETKLTNC_CMDLINE, TRUE, L"Command Line", 700, PH_ALIGN_LEFT, 5, DT_END_ELLIPSIS);
	PhAddTreeNewColumn(hwnd, ETKLTNC_PARENTPID, TRUE, L"Parent PID", 100, PH_ALIGN_RIGHT, 6, DT_RIGHT);

	TreeNew_SetRedraw(hwnd, TRUE);

	PhInitializeTreeNewFilterSupport(&FilterSupport, hwnd, KLogNodeList);

	if (ToolStatusInterface)
	{
		PhRegisterCallback(ToolStatusInterface->SearchChangedEvent, EtpSearchChangedHandler, NULL, &SearchChangedRegistration);
		PhAddTreeNewFilter(&FilterSupport, EtpSearchKLogListFilterCallback, NULL);
	}

	PPH_TREENEW_CONTEXT context;

	context = (PPH_TREENEW_CONTEXT)GetWindowLongPtr(hwnd, 0);

	ProcessBacklog(context);

	WepAddKLogs(context);

	wchar_t *msg;
	if (gDriver == INVALID_HANDLE_VALUE)
		WepAddChildKLogNode(context, time(NULL) * 1000000LL, 0, 0,
			msg = L"*** The modified kprocesshacker.sys driver is not started! ***",  msg);

	EtLoadSettingsKLogTreeList();
}

VOID EtLoadSettingsKLogTreeList(
    VOID
    )
{
    PH_INTEGER_PAIR sortSettings;

	PhCmLoadSettings(KLogTreeNewHandle, &PhaGetStringSetting(SETTING_NAME_KLOG_TREE_LIST_COLUMNS)->sr);

    sortSettings = PhGetIntegerPairSetting(SETTING_NAME_KLOG_TREE_LIST_SORT);
    TreeNew_SetSort(KLogTreeNewHandle, (ULONG)sortSettings.X, (PH_SORT_ORDER)sortSettings.Y);

	PhCsKLogAutoScroll = PhGetIntegerSetting(SETTING_NAME_KLOG_AUTOSCROLL);
}

VOID EtSaveSettingsKLogTreeList(
    VOID
    )
{
    PPH_STRING settings;
    PH_INTEGER_PAIR sortSettings;
    ULONG sortColumn;
    PH_SORT_ORDER sortOrder;

    if (!KLogTreeNewCreated)
        return;

	settings = PH_AUTO(PhCmSaveSettings(KLogTreeNewHandle));
	PhSetStringSetting2(SETTING_NAME_KLOG_TREE_LIST_COLUMNS, &settings->sr);

    TreeNew_GetSort(KLogTreeNewHandle, &sortColumn, &sortOrder);
    sortSettings.X = sortColumn;
    sortSettings.Y = sortOrder;
	PhSetIntegerPairSetting(SETTING_NAME_KLOG_TREE_LIST_SORT, sortSettings);

	PhSetIntegerSetting(SETTING_NAME_KLOG_AUTOSCROLL, PhCsKLogAutoScroll);
}

void CleanupDriver()
{
	if (gDriver != INVALID_HANDLE_VALUE)
		CloseHandle(gDriver);

	if (gBacklogLL != NULL) 
		LLfree(gBacklogLL);
	
	BTfree(gBTroot);
	gBTroot = NULL;
}

VOID EtRemoveKLogNode(
    _In_ PWE_KLOG_NODE KLogNode
    )
{
    ULONG index;

    if ((index = PhFindItemList(KLogNodeList, KLogNode)) != -1)
        PhRemoveItemList(KLogNodeList, index);

	if (KLogNode->TimeText) PhDereferenceObject(KLogNode->TimeText);
	if (KLogNode->aklog.executable) PhDereferenceObject(KLogNode->aklog.executable);
	if (KLogNode->aklog.cmdline) PhDereferenceObject(KLogNode->aklog.cmdline);

	PhFree(KLogNode);
}

#define SORT_FUNCTION(Column) EtpKLogTreeNewCompare##Column

#define BEGIN_SORT_FUNCTION(Column) static int __cdecl EtpKLogTreeNewCompare##Column( \
    _In_ const void *_elem1, \
    _In_ const void *_elem2 \
    ) \
{ \
    PWE_KLOG_NODE node1 = *(PWE_KLOG_NODE *)_elem1; \
    PWE_KLOG_NODE node2 = *(PWE_KLOG_NODE *)_elem2; \
    pklog klogItem1 = &node1->aklog; \
    pklog klogItem2 = &node2->aklog; \
    int sortResult = 0; 

#define END_SORT_FUNCTION \
    if (sortResult == 0) \
	{ \
        sortResult = uint64cmp(klogItem1->timestamp, klogItem2->timestamp); \
		if (sortResult == 0) \
		{ \
			if (klogItem1->cmdline && klogItem2->cmdline) \
				sortResult = PhCompareString(klogItem1->cmdline, klogItem2->cmdline, TRUE); \
		} \
	} \
    return PhModifySort(sortResult, KLogTreeNewSortOrder); \
}

BEGIN_SORT_FUNCTION(Timestamp)
{
	sortResult = uint64cmp(klogItem1->timestamp, klogItem2->timestamp);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(Time)
{
	sortResult = uint64cmp(klogItem1->timestamp, klogItem2->timestamp);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(PID)
{
	sortResult = uintcmp(klogItem1->PID, klogItem2->PID);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(ParentPID)
{
	sortResult = uintcmp(klogItem1->ParentPID, klogItem2->ParentPID);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(StartExit)
{
	sortResult = -uintcmp(klogItem1->startexit, klogItem2->startexit);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(Executable)
{
	if (klogItem1->executable && klogItem2->executable)
		sortResult = PhCompareString(klogItem1->executable, klogItem2->executable, TRUE);
}
END_SORT_FUNCTION

BEGIN_SORT_FUNCTION(CommandLine)
{
    if (klogItem1->cmdline && klogItem2->cmdline)
        sortResult = PhCompareString(klogItem1->cmdline, klogItem2->cmdline, TRUE);
}
END_SORT_FUNCTION

BOOLEAN NTAPI EtpKLogTreeNewCallback(
    _In_ HWND hwnd,
    _In_ PH_TREENEW_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2,
    _In_opt_ PVOID Context
    )
{
	PWE_KLOG_NODE node;
    SYSTEMTIME systemTime;

    switch (Message)
    {
    case TreeNewGetChildren:
        {
            PPH_TREENEW_GET_CHILDREN getChildren = Parameter1;

            if (!getChildren->Node)
            {
                static PVOID sortFunctions[] =
                {
					SORT_FUNCTION(Timestamp),
					SORT_FUNCTION(Time),
					SORT_FUNCTION(PID),
					SORT_FUNCTION(StartExit),
					SORT_FUNCTION(Executable),
                    SORT_FUNCTION(CommandLine),
					SORT_FUNCTION(ParentPID)
                };
                int (__cdecl *sortFunction)(const void *, const void *);

                if (KLogTreeNewSortColumn < ETKLTNC_MAXIMUM)
                    sortFunction = sortFunctions[KLogTreeNewSortColumn];
                else
                    sortFunction = NULL;

                if (sortFunction)
                {
                    qsort(KLogNodeList->Items, KLogNodeList->Count, sizeof(PVOID), sortFunction);
                }

                getChildren->Children = (PPH_TREENEW_NODE *)KLogNodeList->Items;
                getChildren->NumberOfChildren = KLogNodeList->Count;
            }
        }
        return TRUE;
    case TreeNewIsLeaf:
        {
            PPH_TREENEW_IS_LEAF isLeaf = Parameter1;

            isLeaf->IsLeaf = TRUE;
        }
        return TRUE;
    case TreeNewGetCellText:
        {
            PPH_TREENEW_GET_CELL_TEXT getCellText = Parameter1;
			pklog klogItem;

			node = (PWE_KLOG_NODE)getCellText->Node;

			klogItem = &node->aklog;

            switch (getCellText->Id)
            {
			case ETKLTNC_PID:
			{
				PhInitializeStringRef(&getCellText->Text, klogItem->PIDstring);
			}
			break;
			case ETKLTNC_STARTEXIT:
			{
				PhInitializeStringRef(&getCellText->Text, klogItem->startexit ? L"Exit" : L"Start");
			}
			break;
			case ETKLTNC_PARENTPID:
			{
				PhInitializeStringRef(&getCellText->Text, klogItem->ParentPIDstring);
			}
			break;
			case ETKLTNC_TIMESTAMP:
			{
				PhInitializeStringRef(&getCellText->Text, klogItem->timestampstring);
			}
			break;
			case ETKLTNC_TIME:
			{
				PhLargeIntegerToLocalSystemTime(&systemTime, &klogItem->time);
				PhMoveReference(&node->TimeText, PhFormatDateTime(&systemTime));
				if (node->TimeText)
					getCellText->Text = node->TimeText->sr;
			}
			break;
			case ETKLTNC_EXECUTABLE:
			{
				if (!klogItem->executable)
					return FALSE;
				getCellText->Text = klogItem->executable->sr;
			}
			break;
            case ETKLTNC_CMDLINE:
            {
                if (!klogItem->cmdline)
                    return FALSE;
                getCellText->Text = klogItem->cmdline->sr;
            }
            break;

            default:
                return FALSE;
            }

            getCellText->Flags = TN_CACHE;
        }
        return TRUE;
    case TreeNewGetNodeIcon:
        return TRUE;
    case TreeNewGetCellTooltip:
        return TRUE;
    case TreeNewSortChanged:
        {
            TreeNew_GetSort(hwnd, &KLogTreeNewSortColumn, &KLogTreeNewSortOrder);
            // Force a rebuild to sort the items.
            TreeNew_NodesStructured(hwnd);
        }
        return TRUE;
    case TreeNewKeyDown:
        {
            PPH_TREENEW_KEY_EVENT keyEvent = Parameter1;

            switch (keyEvent->VirtualKey)
            {
            case 'C':
                if (GetKeyState(VK_CONTROL) < 0)
                    EtHandleKLogCommand(ID_KLOG_COPY);
                break;
            case 'A':
                if (GetKeyState(VK_CONTROL) < 0)
                    TreeNew_SelectRange(KLogTreeNewHandle, 0, -1);
                break;
            case VK_RETURN:
                EtHandleKLogCommand(ID_KLOG_OPENFILELOCATION);
                break;
            }
        }
        return TRUE;
    case TreeNewHeaderRightClick:
        {
            PH_TN_COLUMN_MENU_DATA data;

            data.TreeNewHandle = hwnd;
            data.MouseEvent = Parameter1;
            data.DefaultSortColumn = 0;
            data.DefaultSortOrder = AscendingSortOrder;
            PhInitializeTreeNewColumnMenu(&data);

            data.Selection = PhShowEMenu(data.Menu, hwnd, PH_EMENU_SHOW_LEFTRIGHT,
                PH_ALIGN_LEFT | PH_ALIGN_TOP, data.MouseEvent->ScreenLocation.x, data.MouseEvent->ScreenLocation.y);
            PhHandleTreeNewColumnMenu(&data);
            PhDeleteTreeNewColumnMenu(&data);
        }
        return TRUE;
    case TreeNewLeftDoubleClick:
        {
            EtHandleKLogCommand(ID_KLOG_OPENFILELOCATION);
        }
        return TRUE;
    case TreeNewContextMenu:
        {
            PPH_TREENEW_MOUSE_EVENT mouseEvent = Parameter1;

            EtShowKLogContextMenu(mouseEvent->Location);
        }
        return TRUE;
    case TreeNewDestroying:
        return TRUE;
    }

    return FALSE;
}

pklog EtGetSelectedKLogItem(
    VOID
    )
{
    pklog klogItem = NULL;
    ULONG i;

    for (i = 0; i < KLogNodeList->Count; i++)
    {
        PWE_KLOG_NODE node = KLogNodeList->Items[i];

        if (node->Node.Selected)
        {
            klogItem = &node->aklog;
            break;
        }
    }

    return klogItem;
}

VOID EtGetSelectedKLogItems(
    _Out_ pklog **KLogItems,
    _Out_ PULONG NumberOfKLogItems
    )
{
    PPH_LIST list;
    ULONG i;

    list = PhCreateList(2);

    for (i = 0; i < KLogNodeList->Count; i++)
    {
        PWE_KLOG_NODE node = KLogNodeList->Items[i];

        if (node->Node.Selected)
        {
            PhAddItemList(list, &node->aklog);
        }
    }

    *KLogItems = PhAllocateCopy(list->Items, sizeof(PVOID) * list->Count);
    *NumberOfKLogItems = list->Count;

    PhDereferenceObject(list);
}

VOID EtDeselectAllKLogNodes(
    VOID
    )
{
    TreeNew_DeselectRange(KLogTreeNewHandle, 0, -1);
}

VOID EtCopyKLogList(
    VOID
    )
{
    PPH_STRING text;

    text = PhGetTreeNewText(KLogTreeNewHandle, 0);
    PhSetClipboardString(KLogTreeNewHandle, &text->sr);
    PhDereferenceObject(text);
}

void clearallrows()
{
	ULONG i;

	TreeNew_SetRedraw(KLogTreeNewHandle, FALSE);

	BTfree(gBTroot);
	gBTroot = NULL;

	while (KLogNodeList->Count > 0)
	{
		for (i = 0; i < KLogNodeList->Count; i++)
		{
			PWE_KLOG_NODE node = KLogNodeList->Items[i];
			EtRemoveKLogNode(node);
		}
	}

	TreeNew_NodesStructured(KLogTreeNewHandle);
	TreeNew_SetRedraw(KLogTreeNewHandle, TRUE);
}

VOID EtHandleKLogCommand(
    _In_ ULONG Id
    )
{
	pklog klogItem;

    switch (Id)
    {
    case ID_KLOG_GOTOPROCESS:
	case ID_KLOG_GOTOPARENTPROCESS:
        {
            klogItem = EtGetSelectedKLogItem();
            PPH_PROCESS_NODE processNode;

			if (klogItem)
            {
				DWORD PID = (Id == ID_KLOG_GOTOPROCESS ? klogItem->PID : klogItem->ParentPID);
				if (processNode = PhFindProcessNode(PID))
                {
                    ProcessHacker_SelectTabPage(PhMainWndHandle, 0);
                    PhSelectAndEnsureVisibleProcessNode(processNode);
                }
            }
        }
        break;

	case ID_KLOG_OPENFILELOCATION:
        {
			klogItem = EtGetSelectedKLogItem();

			if (klogItem && 
				klogItem->PID != 0 &&
				klogItem->executable && wcscmp(klogItem->executable->Buffer, L"Exited") != 0)
            {
				PhShellExploreFile(PhMainWndHandle, klogItem->executable->Buffer);
            }
        }
        break;
	case ID_KLOG_CLEARALL:
		{
			clearallrows();
		}
		break;
    case ID_KLOG_COPY:
        {
            EtCopyKLogList();
        }
        break;
    case ID_KLOG_PROPERTIES:
        {
            klogItem = EtGetSelectedKLogItem();

			if (klogItem && klogItem->executable && wcscmp(klogItem->executable->Buffer, L"Exited") != 0)
            {
                PhShellProperties(PhMainWndHandle, klogItem->executable->Buffer);
            }
        }
        break;
	case ID_KLOG_AUTOSCROLL:
		{
			PhCsKLogAutoScroll ^= 1;
		}
		break;
    }
}

VOID EtpInitializeKLogMenu(
    _In_ PPH_EMENU Menu,
    _In_ pklog *KLogItems,
    _In_ ULONG NumberOfKLogItems
    )
{
	if (PhCsKLogAutoScroll)
		PhSetFlagsEMenuItem(Menu, ID_KLOG_AUTOSCROLL, PH_EMENU_CHECKED, PH_EMENU_CHECKED);

    if (NumberOfKLogItems == 0)
    {
        PhSetFlagsAllEMenuItems(Menu, PH_EMENU_DISABLED, PH_EMENU_DISABLED);
    }
	else if (NumberOfKLogItems > 1)
    {
        PhSetFlagsAllEMenuItems(Menu, PH_EMENU_DISABLED, PH_EMENU_DISABLED);
		PhEnableEMenuItem(Menu, ID_KLOG_CLEARALL, TRUE);
        PhEnableEMenuItem(Menu, ID_KLOG_COPY, TRUE);
    }
	else
	{
		if (KLogItems[0]->PID == 0)
		{
			PhSetFlagsAllEMenuItems(Menu, PH_EMENU_DISABLED, PH_EMENU_DISABLED);
			PhEnableEMenuItem(Menu, ID_KLOG_CLEARALL, TRUE);
			PhEnableEMenuItem(Menu, ID_KLOG_COPY, TRUE);
			PhEnableEMenuItem(Menu, ID_KLOG_AUTOSCROLL, TRUE);
			return;
		}
		else if (wcscmp(KLogItems[0]->executable->Buffer, L"Exited") == 0)
		{
			PhEnableEMenuItem(Menu, ID_KLOG_OPENFILELOCATION, FALSE);
			PhEnableEMenuItem(Menu, ID_KLOG_PROPERTIES, FALSE);
		}

		if (!PhFindProcessNode(KLogItems[0]->PID))
			PhEnableEMenuItem(Menu, ID_KLOG_GOTOPROCESS, FALSE);

		if (!PhFindProcessNode(KLogItems[0]->ParentPID))
			PhEnableEMenuItem(Menu, ID_KLOG_GOTOPARENTPROCESS, FALSE);
	}
}

VOID EtShowKLogContextMenu(
    _In_ POINT Location
    )
{
    pklog *klogItems;
    ULONG numberOfKLogItems;

    EtGetSelectedKLogItems(&klogItems, &numberOfKLogItems);

    if (numberOfKLogItems != 0)
    {
        PPH_EMENU menu;
        PPH_EMENU_ITEM item;

        menu = PhCreateEMenu();
        PhLoadResourceEMenuItem(menu, PluginInstance->DllBase, MAKEINTRESOURCE(IDR_KLOG), 0);
        PhSetFlagsEMenuItem(menu, ID_KLOG_OPENFILELOCATION, PH_EMENU_DEFAULT, PH_EMENU_DEFAULT);

        EtpInitializeKLogMenu(menu, klogItems, numberOfKLogItems);

        item = PhShowEMenu(
            menu,
            PhMainWndHandle,
            PH_EMENU_SHOW_LEFTRIGHT,
            PH_ALIGN_LEFT | PH_ALIGN_TOP,
            Location.x,
            Location.y
            );

        if (item)
        {
            EtHandleKLogCommand(item->Id);
        }

        PhDestroyEMenu(menu);
    }

    PhFree(klogItems);
}

VOID NTAPI EtpSearchChangedHandler(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
    )
{
    PhApplyTreeNewFilters(&FilterSupport);
}

BOOLEAN NTAPI EtpSearchKLogListFilterCallback(
    _In_ PPH_TREENEW_NODE Node,
    _In_opt_ PVOID Context
    )
{
    PWE_KLOG_NODE klogNode = (PWE_KLOG_NODE)Node;
    PTOOLSTATUS_WORD_MATCH wordMatch = ToolStatusInterface->WordMatch;
	struct klogstruc *klogItem = NULL;
	PH_STRINGREF sr;

    klogItem = &klogNode->aklog;

    if (PhIsNullOrEmptyString(ToolStatusInterface->GetSearchboxText()))
        return TRUE;

    if (!klogItem || !klogItem->cmdline)
        return FALSE;

	PhInitializeStringRef(&sr, klogItem->cmdline->Buffer);

	if (wordMatch(&sr))
        return TRUE;

	PhInitializeStringRef(&sr, klogItem->executable->Buffer);

	if (wordMatch(&sr))
		return TRUE;

	PhInitializeStringRef(&sr, klogItem->PIDstring);

	if (wordMatch(&sr))
		return TRUE;

	PhInitializeStringRef(&sr, klogItem->ParentPIDstring);

	if (wordMatch(&sr))
		return TRUE;

	PhInitializeStringRef(&sr, klogItem->startexit ? L"Exit" : L"Start");

	if (wordMatch(&sr))
		return TRUE;

    return FALSE;
}

VOID NTAPI EtpToolStatusActivateContent(
    _In_ BOOLEAN Select
    )
{
    SetFocus(KLogTreeNewHandle);

    if (Select)
    {
        if (TreeNew_GetFlatNodeCount(KLogTreeNewHandle) > 0)
            EtSelectAndEnsureVisibleKLogNode((PWE_KLOG_NODE)TreeNew_GetFlatNode(KLogTreeNewHandle, 0));
    }
}

INT_PTR CALLBACK EtpKlogTabErrorDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    )
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
        {

        }
        break;
    case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {

            }
        }
        break;
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORSTATIC:
        {
            SetBkMode((HDC)wParam, TRANSPARENT);
            return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);
        }
        break;
    }

    return FALSE;
}
