.PHONY: all clean

OUT ?= /opt/bloodhound/usdt-fixtures
CFLAGS := -O2 -fno-pie -no-pie -Wall -Wextra

all: $(OUT)/training-shell-v3 $(OUT)/training-shell-v3-unreadable $(OUT)/training-shell-v3-build-id-mismatch $(OUT)/training-shell-v3-no-probe $(OUT)/training-shell-v3-wrong-abi $(OUT)/training-shell-v3-semaphore $(OUT)/training-peer-v1

$(OUT):
	mkdir -p $@

$(OUT)/training-shell-v3: training-shell-v3.c | $(OUT)
	$(CC) $(CFLAGS) -static -Wl,--build-id=0x11223344556677889900aabbccddeeff00112233 -o $@ $<

$(OUT)/training-shell-v3-unreadable: training-shell-v3.c | $(OUT)
	$(CC) $(CFLAGS) -DUNREADABLE_COMMAND_NAME -static -Wl,--build-id=0x11223344556677889900aabbccddeeff00112233 -o $@ $<

$(OUT)/training-shell-v3-build-id-mismatch: training-shell-v3.c | $(OUT)
	$(CC) $(CFLAGS) -static -Wl,--build-id=0xaabbccddeeff0011223344556677889900aabbcc -o $@ $<

$(OUT)/training-shell-v3-no-probe: training-shell-v3-no-probe.c | $(OUT)
	$(CC) $(CFLAGS) -static -Wl,--build-id=0x11223344556677889900aabbccddeeff00112233 -o $@ $<

$(OUT)/training-shell-v3-wrong-abi: training-shell-v3.c | $(OUT)
	$(CC) $(CFLAGS) '-DUSDT_OPERANDS="8@%rdi"' -static -Wl,--build-id=0x11223344556677889900aabbccddeeff00112233 -o $@ $<

$(OUT)/training-shell-v3-semaphore: training-shell-v3.c | $(OUT)
	$(CC) $(CFLAGS) -DUSDT_SEMAPHORE=1 -static -Wl,--build-id=0x11223344556677889900aabbccddeeff00112233 -o $@ $<

$(OUT)/training-peer-v1: training-peer-v1.c | $(OUT)
	$(CC) $(CFLAGS) -static -Wl,--build-id=0x44556677889900aabbccddeeff00112233445566 -o $@ $<

clean:
	rm -f $(OUT)/training-shell-v3 $(OUT)/training-shell-v3-unreadable $(OUT)/training-shell-v3-build-id-mismatch $(OUT)/training-shell-v3-no-probe $(OUT)/training-shell-v3-wrong-abi $(OUT)/training-shell-v3-semaphore $(OUT)/training-peer-v1
