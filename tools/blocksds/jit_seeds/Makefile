# SPDX-License-Identifier: CC0-1.0
# SPDX-FileContributor: melonDS fuzzing harness seeds

BLOCKSDS ?= /opt/blocksds/core
WONDERFUL_TOOLCHAIN ?= /opt/wonderful
ARM_NONE_EABI_PATH ?= $(WONDERFUL_TOOLCHAIN)/toolchain/gcc-arm-none-eabi/bin/

THUMB_SEEDS := arith branches memory table smc \
	thumb_branches thumb_calls thumb_stack thumb_shifts thumb_unaligned
ARM_SEEDS := arm_cond arm_ldm
SEEDS := $(THUMB_SEEDS) $(ARM_SEEDS)

SRCDIR := sources
BUILDDIR := build
SEED_PREFIX := seed_
SEEDS_DIR := ../../../seeds
EXTRACT := ../../aflplusplus/extract_arm9_blob.sh

PREFIX := $(ARM_NONE_EABI_PATH)arm-none-eabi-
CC := $(PREFIX)gcc
LD := $(PREFIX)gcc
OBJDUMP := $(PREFIX)objdump
MKDIR := mkdir
RM := rm -rf

ifeq ($(VERBOSE),1)
V :=
else
V := @
endif

ARCH := -mthumb -mcpu=arm946e-s+nofp
INCLUDES := -I$(SRCDIR)
CFLAGS := $(ARCH) -O2 -ffunction-sections -fdata-sections -fno-builtin -ffreestanding $(INCLUDES)
LDFLAGS := $(ARCH) -nostdlib -nostartfiles \
	-Wl,-T$(BLOCKSDS)/sys/crts/ds_arm9.mem \
	-Wl,-T$(BLOCKSDS)/sys/crts/ds_arm9.ld \
	-Wl,--gc-sections -Wl,--no-warn-rwx-segments -Wl,--use-blx

COMMON_OBJ := $(BUILDDIR)/seed_common.c.o
SEED_C_OBJS := $(addprefix $(BUILDDIR)/$(SEED_PREFIX),$(addsuffix .c.o,$(THUMB_SEEDS)))
SEED_ARM_OBJS := $(addprefix $(BUILDDIR)/$(SEED_PREFIX),$(addsuffix .arm.c.o,$(ARM_SEEDS)))
SEED_OBJS := $(SEED_C_OBJS) $(SEED_ARM_OBJS)
SEED_ELFS := $(addprefix $(BUILDDIR)/$(SEED_PREFIX),$(addsuffix .elf,$(SEEDS)))
SEED_NDS := $(addprefix $(BUILDDIR)/$(SEED_PREFIX),$(addsuffix .nds,$(SEEDS)))
SEED_BINS := $(addprefix $(SEEDS_DIR)/arm9_,$(addsuffix .bin,$(SEEDS)))

.PHONY: all seeds clean dump

all: $(SEED_NDS)

seeds: $(SEED_BINS)

$(BUILDDIR)/$(SEED_PREFIX)%.nds: $(BUILDDIR)/$(SEED_PREFIX)%.elf
	@echo "  NDSTOOL $@"
	$(V)$(BLOCKSDS)/tools/ndstool/ndstool -c $@ \
		-7 $(BLOCKSDS)/sys/arm7/main_core/arm7_maxmod.elf -9 $< \
		-b $(BLOCKSDS)/sys/icon.gif "JIT Seed $*;melonDS fuzz"

$(foreach seed,$(THUMB_SEEDS),$(eval $(BUILDDIR)/$(SEED_PREFIX)$(seed).elf: $(COMMON_OBJ) $(BUILDDIR)/$(SEED_PREFIX)$(seed).c.o))
$(foreach seed,$(ARM_SEEDS),$(eval $(BUILDDIR)/$(SEED_PREFIX)$(seed).elf: $(COMMON_OBJ) $(BUILDDIR)/$(SEED_PREFIX)$(seed).arm.c.o))

$(BUILDDIR)/$(SEED_PREFIX)%.elf:
	@echo "  LD      $@"
	$(V)$(LD) -o $@ $^ $(LDFLAGS) -Wl,-Map,$(BUILDDIR)/$(SEED_PREFIX)$*.map

$(SEEDS_DIR)/arm9_%.bin: $(BUILDDIR)/$(SEED_PREFIX)%.nds
	@$(MKDIR) -p $(SEEDS_DIR)
	$(V)$(EXTRACT) $< $@

$(BUILDDIR)/%.c.o : $(SRCDIR)/%.c
	@echo "  CC      $<"
	@$(MKDIR) -p $(@D)
	$(V)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILDDIR)/%.arm.c.o : $(SRCDIR)/%.arm.c
	@echo "  CC      $<"
	@$(MKDIR) -p $(@D)
	$(V)$(CC) $(CFLAGS) -marm -MMD -MP -c -o $@ $<

dump: $(SEED_ELFS)
	@echo "  OBJDUMP all"
	$(V)for elf in $(SEED_ELFS); do \
		$(OBJDUMP) -h -C -S $$elf > $$elf.dump; \
	done

clean:
	@echo "  CLEAN"
	$(V)$(RM) $(BUILDDIR)
	$(V)$(RM) $(SEED_BINS)

-include $(COMMON_OBJ:.o=.d) $(SEED_OBJS:.o=.d)
