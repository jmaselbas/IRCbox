// SPDX-License-Identifier: GPL-2.0-only

/*
 * linux/arch/arm/mach-nomadik/clock.c
 *
 * Copyright (C) 2009 Alessandro Rubini
 */
#include <common.h>
#include <errno.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <init.h>
#include <linux/clkdev.h>

#include "clock.h"

/*
 * The nomadik board uses generic clocks, but the serial pl011 file
 * calls clk_enable(), clk_disable(), clk_get_rate(), so we provide them
 */
unsigned long clk_get_rate(struct clk *clk)
{
	return clk->rate;
}
EXPORT_SYMBOL(clk_get_rate);

int clk_set_rate(struct clk *clk, unsigned long rate)
{
	return 0;
}
EXPORT_SYMBOL(clk_set_rate);

/* enable and disable do nothing */
int clk_enable(struct clk *clk)
{
	return 0;
}
EXPORT_SYMBOL(clk_enable);

void clk_disable(struct clk *clk)
{
}
EXPORT_SYMBOL(clk_disable);

/* Create a clock structure with the given name */
int nmdk_clk_create(struct clk *clk, const char *dev_id)
{
	struct clk_lookup *clkdev;

	clkdev = clkdev_alloc(clk, NULL, dev_id);
	if (!clkdev)
		return -ENOMEM;
	clkdev_add(clkdev);
	return 0;
}
