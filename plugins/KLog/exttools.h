#ifndef EXTTOOLS_H
#define EXTTOOLS_H

#define PHNT_VERSION PHNT_VISTA
#include <windows.h>
#include <locale.h>
#include <phdk.h>
#include <settings.h>
#include "ioctls.h"
#include "resource.h"

extern PPH_PLUGIN PluginInstance;

#define PLUGIN_NAME2 L"ProcessHacker.KLog"
#define SETTING_NAME_KLOG_TREE_LIST_COLUMNS (PLUGIN_NAME2 L".KLogTreeListColumns")
#define SETTING_NAME_KLOG_TREE_LIST_SORT (PLUGIN_NAME2 L".KLogTreeListSort")
#define SETTING_NAME_KLOG_AUTOSCROLL (PLUGIN_NAME2 L".KLogAutoScroll")

#define ETKLTNC_TIMESTAMP 0
#define ETKLTNC_TIME 1
#define ETKLTNC_PID 2
#define ETKLTNC_STARTEXIT 3
#define ETKLTNC_EXECUTABLE 4
#define ETKLTNC_CMDLINE 5
#define ETKLTNC_PARENTPID 6
#define ETKLTNC_EXITCODE 7
#define ETKLTNC_TIMEALIVE 8
#define ETKLTNC_MAXIMUM 9

// main
VOID EtInitializeKlogTab(
    VOID
    );

#endif
