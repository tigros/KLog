#include "BTree.h"

BTnode *BTnew(PWE_KLOG_NODE klognode)
{
    BTnode *n = malloc(sizeof(BTnode));
    n->PID = klognode->aklog.PID;
    n->klognode = klognode;
    n->left = n->right = NULL;
    return n;
}

void BTinsert(BTnode **root, BTnode *child)
{
    if (!*root)
        *root = child;
    else
        BTinsert(child->PID <= (*root)->PID ? &(*root)->left : &(*root)->right , child);
}

BTnode *BTsearch(BTnode *root, DWORD PID)
{
    return !root ? NULL : root->PID == PID ? root : BTsearch(PID > root->PID ? root->right : root->left , PID);
}

void BTfree(BTnode *root)
{
    if (root != NULL)
    {
        BTfree(root->left);
        BTfree(root->right);
        free(root);
        root = NULL;
    }
}
