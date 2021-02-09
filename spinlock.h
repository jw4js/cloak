#include <linux/spinlock.h>

#define spinlock_lock(lock,level) unsigned long __spinlock_flags##level;spin_lock_irqsave(&lock,__spinlock_flags##level)
#define spinlock_free(lock,level) spin_unlock_irqrestore(&lock,__spinlock_flags##level);