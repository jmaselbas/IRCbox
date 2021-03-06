/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_GENERIC_MEMORY_LAYOUT_H
#define __ASM_GENERIC_MEMORY_LAYOUT_H

#ifdef CONFIG_MEMORY_LAYOUT_DEFAULT
#define MALLOC_BASE (TEXT_BASE - CONFIG_MALLOC_SIZE)
#define STACK_BASE (TEXT_BASE - CONFIG_MALLOC_SIZE - CONFIG_STACK_SIZE)
#endif

#ifdef CONFIG_MEMORY_LAYOUT_FIXED
#define STACK_BASE CONFIG_STACK_BASE
#define MALLOC_BASE CONFIG_MALLOC_BASE
#endif

#ifdef CONFIG_OPTEE_SIZE
#define OPTEE_SIZE CONFIG_OPTEE_SIZE
#else
#define OPTEE_SIZE 0
#endif

#define HEAD_TEXT_BASE MALLOC_BASE
#define MALLOC_SIZE CONFIG_MALLOC_SIZE
#define STACK_SIZE  CONFIG_STACK_SIZE

#endif /* __ASM_GENERIC_MEMORY_LAYOUT_H */
