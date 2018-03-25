#ifndef BTREE_H
#define BTREE_H

#include <phdk.h>
#include "klogtabp.h"

typedef struct BTnode
{
    struct BTnode *left, *right;
    DWORD PID;
    union
    {
        PWE_KLOG_NODE klognode;
        NTSTATUS exitcode;
    };
} BTnode;

BTnode *BTnew(PWE_KLOG_NODE klognode);
BTnode *BTnewExitCode(DWORD pid, NTSTATUS exitcode);
void BTinsert(BTnode **root, BTnode *child);
BTnode *BTsearch(BTnode *root, DWORD PID);
void BTfree(BTnode *root);

#endif