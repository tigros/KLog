#include <stdlib.h>
#include "linkedlist.h"

LLnode *LLcreate()
{
    LLnode *newnode = (LLnode *)malloc(sizeof(LLnode));
    if (!newnode)
    {
		return NULL;
	}

	newnode->size = 0;
	newnode->buffer = NULL;
    newnode->next = NULL;

    return newnode;
}

LLnode *LLappend(LLnode *head)
{
    if (head == NULL)
        return NULL;

    LLnode *cursor = head;
    while (cursor->next != NULL)
        cursor = cursor->next;

    LLnode *newnode = LLcreate();
    cursor->next = newnode;

	return newnode;
}

void LLappendLL(LLnode *head, LLnode *LL)
{
	if (head == NULL || LL == NULL)
		return;

	LLnode *cursor = head;
	while (cursor->next != NULL)
		cursor = cursor->next;

	cursor->next = LL;
}

void LLfree(LLnode *head)
{
	LLnode *cursor, *tmp;

	cursor = head;

	while (cursor != NULL)
	{
		tmp = cursor->next;
		if (cursor->buffer != NULL)
			free(cursor->buffer);
		free(cursor);
		cursor = tmp;
	}
}

