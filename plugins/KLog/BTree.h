#ifndef BTREE_H
#define BTREE_H

#include <phdk.h>
#include "klogtabp.h"

typedef struct BTnode
{
	struct BTnode *left, *right;
	DWORD PID;
	PWE_KLOG_NODE klognode;
} BTnode;

BTnode *BTnew(PWE_KLOG_NODE klognode);
void BTinsert(BTnode **root, BTnode *child);
BTnode *BTsearch(BTnode *root, DWORD PID);
void BTfree(BTnode *root);

#endif