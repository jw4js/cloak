#include <linux/module.h>
#include "arch.h"

struct inline_hook
{
	u8 func_header_old[sizeof(struct function_header)];
	struct function_header func_header_new;
	struct pte_list * pte_list;
};

int insert_hook(void *,void *);
void remove_hook(void *);
void * suspend_hook(void *);
void resume_hook(void *,void *);