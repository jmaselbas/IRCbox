/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_GENERIC_BITS_PER_LONG
#define __ASM_GENERIC_BITS_PER_LONG

#ifdef CONFIG_64BIT
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif /* CONFIG_64BIT */

#endif /* __ASM_GENERIC_BITS_PER_LONG */
