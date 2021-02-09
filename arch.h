struct inline_hook;

#ifdef __amd64__
struct function_header
{
	u8 asm_a[2];
	void * destination;
	u8 asm_b[2];
	struct inline_hook * control_struct;
} __attribute__((packed));

static inline void init_hook(struct function_header * hook)
{
	*(u16 *)&hook->asm_a = 0xb848;
	*(u16 *)&hook->asm_b = 0xe0ff;
}
#endif
