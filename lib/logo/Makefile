# SPDX-License-Identifier: GPL-2.0-only

OPTS_barebox-logo-w64.bblogo = -resize 64
bblogo-$(CONFIG_BAREBOX_LOGO_64) += barebox-logo-w64

OPTS_barebox-logo-w240.bblogo = -resize 240
bblogo-$(CONFIG_BAREBOX_LOGO_240) += barebox-logo-w240

OPTS_barebox-logo-w320.bblogo = -resize 320
bblogo-$(CONFIG_BAREBOX_LOGO_320) += barebox-logo-w320

OPTS_barebox-logo-w400.bblogo = -resize 400
bblogo-$(CONFIG_BAREBOX_LOGO_400) += barebox-logo-w400

OPTS_barebox-logo-w640.bblogo = -resize 640
bblogo-$(CONFIG_BAREBOX_LOGO_640) += barebox-logo-w640

obj-y += $(patsubst %,%.bblogo.o,$(bblogo-y))
extra-y += $(patsubst %,%.bblogo,$(bblogo-y))
extra-y += $(patsubst %,%.bblogo.S,$(bblogo-y))
extra-y += $(patsubst %,%.bblogo.o,$(bblogo-y))

obj-$(CONFIG_BAREBOX_LOGO) += logo.o

quiet_cmd_logo_S = LOGO.S  $@
cmd_logo_S =							\
(								\
	echo '\#include <asm-generic/barebox.lds.h>';		\
	echo '.section .bblogo.rodata.$(subst -,_,$(*F)),"a"';	\
	echo '.balign STRUCT_ALIGNMENT';			\
	echo '.global __bblogo_$(subst -,_,$(*F))_start';	\
	echo '__bblogo_$(subst -,_,$(*F))_start:';		\
	echo '.incbin "$<" ';					\
	echo '__bblogo_$(subst -,_,$(*F))_end:';		\
	echo '.global __bblogo_$(subst -,_,$(*F))_end';		\
	echo '.balign STRUCT_ALIGNMENT';			\
) > $@

%.bblogo.S: %.bblogo FORCE
	$(call if_changed,logo_S)

CONVERTOPTS += -background none

quiet_cmd_logo = PNG     $@
cmd_logo =							\
(								\
	convert $(OPTS_$(@F)) $(CONVERTOPTS) $< png:$@; \
)

%.bblogo: $(srctree)/Documentation/barebox.svg FORCE
	$(call if_changed,logo)

clean-files += *.bblogo *.bblogo.S
