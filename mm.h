#include <linux/types.h>
#include <linux/mman.h>

struct pte_list
{
	u32 len;
	pte_t pte[];
};

static inline size_t sizeof_pte_list(struct pte_list * pte_list)
{
	return pte_list->len * sizeof(pte_t) + sizeof(struct pte_list);
}

struct pte_list * copy_pte_list(struct pte_list * a);
struct pte_list * get_pages(void * _a,void * _b);
void set_pages(void * _a,struct pte_list * pte_list);
struct pte_list * get_pages_set_rw(void * _a,void * _b);