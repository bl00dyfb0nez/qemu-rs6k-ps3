/*
 * A guest-PC hook for the PS3 model.
 *
 * Part of the console's firmware runs as guest code, so the only place some
 * of its work can be seen is at a chosen address: the XMB resource loader's
 * inflate wrapper ends its z_stream before it returns, and by the next lv2
 * call nothing on the stack names the ranges it was handed.  Its entry is
 * where r3..r6 still hold them.
 *
 * The hook is a function pointer rather than a symbol so that a build with no
 * PS3 machine - and every other target in the tree - links unchanged: it is
 * NULL unless the machine installs it, and the cost while it is NULL is one
 * predictable test per translation block.
 */

#ifndef HW_PPC_PS3_PC_HOOK_H
#define HW_PPC_PS3_PC_HOOK_H

#include <stdint.h>

struct CPUState;

extern void (*ps3_pc_hook_fn)(struct CPUState *cs, uint64_t pc);

#endif /* HW_PPC_PS3_PC_HOOK_H */
