#ifndef LINKEDLIST_H
#define LINKEDLIST_H

#define bufferSize 75000

typedef struct LLnode
{
    unsigned long size;
    char *buffer;
    struct LLnode *next;
} LLnode;

LLnode *LLcreate();
LLnode *LLappend(LLnode *head);
void LLappendLL(LLnode *head, LLnode *LL);
void LLfree(LLnode *head);

#endif