#include <linux/slab.h>

#include "patch.h"
#include "mm.h"

// TODO: race conditions when copying code
// TODO: handle no memory errors

int insert_hook(void * func,void * dest)
{
	struct inline_hook * hook = kmalloc(sizeof(struct inline_hook),GFP_KERNEL);
	if(!hook)
		goto no_mem;
	init_hook(&hook->func_header_new);
	hook->func_header_new.destination = dest;
	hook->func_header_new.control_struct = hook;
	hook->pte_list = get_pages_set_rw(func,func + sizeof(struct function_header));
	if(!hook->pte_list)
		goto free_hook;
	memcpy(hook->func_header_old,func,sizeof(hook->func_header_old));
	memcpy(func,&hook->func_header_new,sizeof(hook->func_header_new));
	return 0;
free_hook:
	kfree(hook);
no_mem:
	return -ENOMEM;
}

void remove_hook(void * func)
{
	struct inline_hook * hook = ((struct function_header *)func)->control_struct;
	memcpy(func,hook->func_header_old,sizeof(hook->func_header_old));
	set_pages(func,hook->pte_list);
	kfree(hook->pte_list);
	kfree(hook);
}

void * suspend_hook(void * func)
{
	struct inline_hook * hook = ((struct function_header *)func)->control_struct;
	memcpy(func,hook->func_header_old,sizeof(hook->func_header_old));
	return hook;
}

void resume_hook(void * func,void * _hook)
{
	struct inline_hook * hook = _hook;
	memcpy(func,&hook->func_header_new,sizeof(hook->func_header_new));
}