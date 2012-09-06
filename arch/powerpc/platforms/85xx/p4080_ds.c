/*
 * P4080 DS Setup
 *
 * Maintained by Kumar Gala (see MAINTAINERS for contact information)
 *
 * Copyright 2009 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/phy.h>
#include <linux/gpio.h>

#include <asm/time.h>
#include <asm/machdep.h>
#include <asm/pci-bridge.h>
#include <mm/mmu_decl.h>
#include <asm/prom.h>
#include <asm/udbg.h>
#include <asm/mpic.h>

#include <linux/of_platform.h>
#include <sysdev/fsl_soc.h>
#include <sysdev/fsl_pci.h>
#include <asm/ehv_pic.h>

#include "corenet_ds.h"

/*
 * This is generic enough to be architecture independent, but we need it
 * here for now.
 */
static int halt_gpion = -EINVAL;
static int halt_trigger;

/*
 * Value is the trigger value. Initial state will be negated.
 */
void ppc_register_halt_gpio(int gpio, int trigger)
{
	int err;

	/* Double registering is bad, mmkay */
	if (WARN_ON(gpio_is_valid(halt_gpion)))
		return;

	err = gpio_request(gpio, "ppc-gpio-halt");
	if (err) {
		printk(KERN_ERR "ppc-gpio-halt: error requesting GPIO %d\n",
		       gpio);
		return;
	}

	gpio_direction_output(gpio, !trigger);

	/* Save it for later */
	halt_gpion = gpio;
	halt_trigger = trigger;

	printk(KERN_INFO "ppc-gpio-halt: registered GPIO %d (%d trigger)\n",
	       gpio, trigger);
}
EXPORT_SYMBOL(ppc_register_halt_gpio);

static void ppc_gpio_halt(void)
{
	printk("ppc-gpio-halt: Halt called\n");

	if (!gpio_is_valid(halt_gpion))
		return;

	printk("ppc-gpio-halt: triggering GPIO to halt/poweroff the machine.\n");

	gpio_set_value(halt_gpion, halt_trigger);
}

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init p4080_ds_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	/* Check if we're running under the Freescale hypervisor */
	if (of_flat_dt_is_compatible(root, "fsl,P4080DS-hv")) {
		ppc_md.init_IRQ = ehv_pic_init;
		ppc_md.get_irq = ehv_pic_get_irq;
		ppc_md.restart = fsl_hv_restart;
		ppc_md.power_off = fsl_hv_halt;
		ppc_md.halt = fsl_hv_halt;
		return 1;
	} else if (of_flat_dt_is_compatible(root, "fsl,P4080DS")) {
		if (of_flat_dt_is_compatible(root, "servergy,jade")) {
			ppc_md.halt = ppc_gpio_halt;
			ppc_md.power_off = ppc_gpio_halt;
		}

		return 1;
	}

	return 0;
}

define_machine(p4080_ds) {
	.name			= "P4080 DS",
	.probe			= p4080_ds_probe,
	.setup_arch		= corenet_ds_setup_arch,
	.init_IRQ		= corenet_ds_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_coreint_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
	.power_save		= e500_idle,
        .init_early             = corenet_ds_init_early,
};

machine_arch_initcall(p4080_ds, corenet_ds_publish_devices);
#ifdef CONFIG_SWIOTLB
machine_arch_initcall(p4080_ds, swiotlb_setup_bus_notifier);
#endif
