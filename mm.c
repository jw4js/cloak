#include <linux/slab.h>

#include "mm.h"

struct pte_list * copy_pte_list(struct pte_list * a)
{
	size_t sizeof_a = sizeof_pte_list(a);
	struct pte_list * b = kmalloc(sizeof_a,GFP_KERNEL);
	if(!b)
		return NULL;
	memcpy(b,a,sizeof_a);
	return b;
}

struct pte_list * get_pages(void * _a,void * _b)
{
	uintptr_t a = (uintptr_t)_a;
	uintptr_t b = (uintptr_t)_b;
	a = a &- PAGE_SIZE;
	b = (b + PAGE_SIZE - 1) &- PAGE_SIZE;
	u32 num_pages = (b - a) / PAGE_SIZE;
	struct pte_list * pte_list = kmalloc(sizeof(struct pte_list) + sizeof(pte_t) * num_pages,GFP_KERNEL);
	if(!pte_list)
		return NULL;
	pte_list->len = num_pages;
	u32 i;
	for(i = 0;i < num_pages;i++,a += PAGE_SIZE)
	{
		u32 _;
		pte_list->pte[i].pte = lookup_address(a,&_)->pte;
	}
	return pte_list;
}

struct pte_list * get_pages_set_rw(void * _a,void * _b)
{
	uintptr_t a = (uintptr_t)_a;
	uintptr_t b = (uintptr_t)_b;
	a = a &- PAGE_SIZE;
	b = (b + PAGE_SIZE - 1) &- PAGE_SIZE;
	u32 num_pages = (b - a) / PAGE_SIZE;
	struct pte_list * pte_list = kmalloc(sizeof(struct pte_list) + sizeof(pte_t) * num_pages,GFP_KERNEL);
	if(!pte_list)
		return NULL;
	pte_list->len = num_pages;
	u32 i;
	for(i = 0;i < num_pages;i++,a += PAGE_SIZE)
	{
		u32 _;
		pte_t * pte = lookup_address(a,&_);
		pte_list->pte[i].pte = pte->pte;
		pte->pte |= _PAGE_RW;
	}
	return pte_list;
}

void set_pages(void * _a,struct pte_list * pte_list)
{
	uintptr_t a = (uintptr_t)_a &- PAGE_SIZE;
	u32 i;
	for(i = 0;i < pte_list->len;i++,a += PAGE_SIZE)
	{
		u32 _;
		lookup_address(a,&_)->pte = pte_list->pte[i].pte;
	}
}