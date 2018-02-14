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
    BTnode **node = root;

    while (*node != NULL)
    {
        if (child->PID <= (*node)->PID)
            node = &(*node)->left;
        else 
            node = &(*node)->right;
    }

    *node = child;
}

BTnode *BTsearch(BTnode *root, DWORD PID)
{
    BTnode *node = root;

    while (node != NULL)
    {
        if (node->PID == PID)
            return node;

        if (PID < node->PID)
            node = node->left;
        else
            node = node->right;
    }

    return NULL;
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
