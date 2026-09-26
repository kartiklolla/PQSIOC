# Bare-metal PQIOT/2 firmware for the LiteX VexRiscv simulator.
#
# Run from the top level (`make fw` / `make fw-net`), which first generates
# the LiteX SoC whose headers, libraries and flags this includes.
#
#   NET=0  pqiot-fw.bin      device + server on one CPU, in-memory pipes
#   NET=1  pqiot-fw-net.bin  device only, over the SoC's Ethernet (UDP)
#   BENCH=1 pqiot-fw-bench.bin  per-operation cycle counts (src/bench.c)

BUILD_DIR ?= ../build/litex-sim
include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

TOP     := $(abspath ..)
WOLFSSL := $(TOP)/build/wolfssl-src
CERTS   := $(TOP)/build/certs
NET     ?= 0
BENCH   ?= 0
ifeq ($(BENCH),1)
IMAGE   := pqiot-fw-bench
OBJDIR  := $(TOP)/build/fw-bench
APP     := main_bench.o bench.o
else ifeq ($(NET),1)
IMAGE   := pqiot-fw-net
OBJDIR  := $(TOP)/build/fw-net
APP     := main_net.o udp_stream.o session.o
CFLAGS  += -DPQIOT_FW_DEVICE_ONLY
else
IMAGE   := pqiot-fw
OBJDIR  := $(TOP)/build/fw
APP     := main.o pipes.o session.o
endif

CFLAGS += -O2 -DWOLFSSL_USER_SETTINGS -I$(CURDIR) -I$(OBJDIR) \
          -I$(TOP)/src -I$(WOLFSSL)
# wolfSSL is third-party: build it quietly, keep our own code's warnings.
WOLF_CFLAGS := $(filter-out -Wstrict-prototypes -Wold-style-definition \
                            -Wmissing-prototypes,$(CFLAGS)) -w

# All of wolfSSL; the linker's --gc-sections keeps only what we call.
WOLF_SRCS := $(wildcard $(WOLFSSL)/wolfcrypt/src/*.c) $(wildcard $(WOLFSSL)/src/*.c)
WOLF_OBJS := $(patsubst $(WOLFSSL)/%.c,$(OBJDIR)/wolfssl/%.o,$(WOLF_SRCS))
APP_OBJS  := $(addprefix $(OBJDIR)/,crt0.o $(APP) platform.o switch.o certs.o \
                                    pqiot.o)

COMMA = ,
REGULAR_LIBS = $(filter-out $(ALWAYS_LINK_LIBS),$(LIBS))
ALWAYS_LINK_LIBFLAGS = $(if $(ALWAYS_LINK_LIBS),-Wl$(COMMA)--whole-archive $(ALWAYS_LINK_LIBS:lib%=-l%) -Wl$(COMMA)--no-whole-archive)

all: $(OBJDIR)/$(IMAGE).bin

$(OBJDIR)/$(IMAGE).bin: $(OBJDIR)/$(IMAGE).elf
	$(OBJCOPY) -O binary $< $@

$(OBJDIR)/$(IMAGE).elf: $(APP_OBJS) $(WOLF_OBJS) linker.ld
	$(CC) $(LDFLAGS) -T linker.ld -N -o $@ $(APP_OBJS) $(WOLF_OBJS) \
		$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
		-Wl,--start-group $(REGULAR_LIBS:lib%=-l%) $(ALWAYS_LINK_LIBFLAGS) \
		-Wl,--end-group -Wl,--gc-sections -Wl,-Map,$@.map

# Per-build DRBG seed and clock (see platform.c). Made once per build dir:
# `make distclean` or deleting build/fw gives the next image a new seed.
$(OBJDIR)/fw_build.h:
	@mkdir -p $(@D)
	@{ printf '#define PQIOT_FW_SEED {'; \
	   od -An -tx1 -N32 /dev/urandom | tr -s ' \n' ' ' | \
	     sed 's/ *\([0-9a-f][0-9a-f]\)/0x\1,/g'; \
	   printf '}\n#define PQIOT_FW_BUILD_TIME %sLL\n' "$$(date +%s)"; } > $@

$(OBJDIR)/crt0.o: $(CPU_DIRECTORY)/crt0.S
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/switch.o: switch.S
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/certs.o: certs.S $(CERTS)/ca.pem $(CERTS)/server.pem \
                   $(CERTS)/server.key $(CERTS)/device.pem $(CERTS)/device.key
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(CERTS) -c -o $@ $<

$(OBJDIR)/%.o: %.c fw.h udp_stream.h user_settings.h $(OBJDIR)/fw_build.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: $(TOP)/src/%.c $(TOP)/src/pqiot.h $(TOP)/src/pki.h user_settings.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/wolfssl/%.o: $(WOLFSSL)/%.c user_settings.h
	@mkdir -p $(@D)
	$(CC) $(WOLF_CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJDIR)

.PHONY: all clean
