/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_PPC_UNALIGNED_H
#define _ASM_PPC_UNALIGNED_H

#ifdef __KERNEL__

/*
 * The PowerPC can do unaligned accesses itself in big endian mode.
 */
#include <linux/unaligned/access_ok.h>
#include <linux/unaligned/generic.h>

#define get_unaligned   __get_unaligned_be
#define put_unaligned   __put_unaligned_be

#endif  /* __KERNEL__ */
#endif  /* _ASM_PPC_UNALIGNED_H */
