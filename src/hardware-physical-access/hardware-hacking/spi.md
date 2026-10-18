# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

SPI (Serial Peripheral Interface) is a synchronous serial bus commonly used for short-distance communication between integrated circuits. A controller supplies the clock and selects a peripheral, such as an EEPROM, sensor, or control device, using a chip-select signal.<sup>[[1]](#references)</sup>

Multiple peripherals can share the clock and data lines, normally with a separate chip-select per peripheral. The controller orchestrates transfers; peripherals normally do not communicate directly with each other over the SPI bus. Chip-select polarity and timing are device-specific; active-low selection is common but not universal. SPI does not define discovery, addressing, commands, or a single maximum transfer length, so always consult the target datasheet.<sup>[[1]](#references)</sup>

MOSI/COPI carries controller-to-peripheral data and MISO/CIPO carries peripheral-to-controller data. Both directions can shift simultaneously. The relationship between a command, address, dummy cycles, and returned data is defined by the peripheral—not by SPI—and depends on clock polarity and phase (modes 0–3). Do not assume that output begins exactly one clock after input ends.<sup>[[1]](#references)</sup>

## Dumping Firmware from EEPROMs

Dumping firmware can be useful for analyzing it and finding vulnerabilities. The correct image may be unavailable online or differ by model, hardware revision, or version, so extracting it directly from the physical device provides an exact assessment target.

A serial console can help, but its filesystem may be read-only and the target may lack analysis tools, including utilities needed to send/receive test traffic or extract binaries conveniently. An offline image preserves the complete flash layout and permits filesystem extraction and reverse engineering without modifying the running target.

During an authorized physical assessment, a verified dump can also support controlled modification and reflashing tests. This includes changing files or injecting a test payload/backdoor to demonstrate firmware-level persistence. Preserve multiple matching reads and the original image before any write: an incorrect voltage, chip selection, layout, or image can brick the device.

### CH341A EEPROM Programmer and Reader

This inexpensive USB tool can dump and reflash compatible serial EEPROM and SPI flash devices. It is commonly used with the SPI NOR flash chips that store PC BIOS/UEFI firmware and is convenient during time-limited physical access.

![drawing](../../images/board_image_ch341a.jpg)

Connect the flash memory to the CH341A and then connect the programmer to the computer. If the programmer itself is not detected, check the USB cable, OS permissions, and the appropriate CH341A driver before troubleshooting the target chip. Confirm the chip's voltage, pin 1, adapter wiring, and programmer output with the datasheets or a meter—do **not** rely on a rule such as placing VCC opposite the USB connector. Incorrect orientation or 5 V applied to a 3.3/1.8 V part can destroy it. In-circuit reads may also fail because the rest of the board loads or powers the bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Use software such as `flashrom` or G-Flash to read the chip. G-Flash is a minimal GUI and may auto-detect compatible devices, which can be convenient during quick acquisition, but confirm the detected model and voltage yourself. Specify the exact programmer and, when necessary, the exact chip model; perform at least two reads and compare their hashes before treating a dump as reliable.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

After dumping the firmware, the analysis can be done on the binary files. Tools like strings, hexdump, xxd, binwalk, etc. can be used to extract a lot of information about the firmware as well as the whole file system too.

For initial triage, Binwalk can scan for known signatures and extract supported embedded content:

```
binwalk -e <filename>
```

The output file may use `.bin`, `.rom`, or another extension; the extension does not establish the format.

> [!CAUTION]
> Note that firmware extraction is a delicate process and requires a lot of patience. Any mishandling can potentially corrupt the firmware or even erase it completely and make the device unusable. It is recommended to study the specific device before attempting to extract the firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Some datasheets label the target pins `DI` and `DO`: for a conventional single-data-line flash connection, controller **MOSI/COPI connects to DI** and controller **MISO/CIPO connects to DO**. Verify the target datasheet because dual/quad I/O parts reuse pins in other modes.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

In Windows or Linux you can use the program [**`flashrom`**](https://www.flashrom.org/Flashrom) to dump the content of the flash memory running something like:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Recent Bus Pirate documentation also shows optional `serialspeed` and `spispeed` parameters. Start conservatively if long wires or in-circuit loading make reads unstable.<sup>[[3]](#references)</sup>

### In-circuit reads when the controller shares the flash bus

A SOIC clip may feed the flash supply into the rest of the PCB. If the MCU is then powered and accesses the same chip, its SPI transfers can collide with the external programmer's transfers. A `No EEPROM/flash device found` result is therefore not proof that the flash is absent or unsupported. Check pinout, voltage and contact first, then determine whether the on-board controller is also active.<sup>[[4]](#references)</sup>

If a reset test pad is available, confirm its polarity and voltage with a meter before asserting it. Holding the MCU in reset can leave the flash accessible while stopping the competing SPI host. Alternatives are desoldering the chip or passively recording the MCU's reads; the latter cannot access unread regions or write the chip, and extra probe wiring can disturb a fast bus. An oscillator or boot-mode intervention is target-specific, not a substitute for checking the schematic and signals.<sup>[[4]](#references)</sup>

With the MCU held inactive, a Raspberry Pi with an enabled `spidev` interface can read through flashrom's `linux_spi` programmer. Change `-p` for a different adapter. Repeat the read and compare hashes before trusting it; SFDP autodetection and a successful read do **not** establish that erase, write, or write-protect operations work on an otherwise unsupported part.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Reconstructing SPI flash reads with a logic analyzer

When active reading is not possible, capture chip select, clock, controller-to-flash data and flash-to-controller data during boot or a chosen UI action. In PulseView, identify the active chip-select interval and clock first, then configure the SPI decoder's data channels using the flash pinout and verify a plausible command/address followed by returned bytes. Export the **MISO/flash-output** bytes with Binary Decoder Output View and preserve the decoded read addresses so each response can be placed at its corresponding flash offset. Capturing only menu-driven reads yields only the requested regions, not a complete flash image; do not concatenate responses as if they were contiguous without checking addresses.<sup>[[4]](#references)</sup>

For a dump that appears to contain graphics rather than executable code, continue with [raw display-asset triage](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy and mixed SPI/QSPI captures

For unlabeled probes, distinguish MOSI from MISO by the line carrying the opcode before response data, then verify the command against the flash datasheet. Sub-clock-width pulses may be probe noise rather than sampled bits, and extra clip wiring can make high-speed captures unreliable.<sup>[[5]](#references)</sup>

Saleae's SPI CSV export uses `enable` and `disable` to bracket a chip-select interval, with MOSI/MISO bytes in `result` rows. Group bytes by interval before decoding; concatenating all MISO data loses transaction addresses.<sup>[[5]](#references)</sup> A Scapy `Packet` can model the MOSI header with a `ByteEnumField` opcode and conditional address and dummy fields. For 24-bit NOR reads, `0x03` has an opcode and three address bytes, while `0x0B` adds a dummy byte. `len(req.self_build())` gives the modeled header length: on a single-lane read, `miso[header_length:]` is the flash response, while MOSI after the header is controller-side don't-care data.<sup>[[5]](#references)</sup> Place responses at their decoded addresses in an `0xFF`-filled image and track covered offsets separately. An unobserved byte is not evidence that the flash held `0xFF` there.<sup>[[5]](#references)[[6]](#references)</sup>

A W25Q-style `0x6B` (1-1-4) read uses one lane for the opcode and address but IO0–IO3 for response data. Activity on the former `/WP` and `/HOLD` pins is stronger evidence of a quad-mode switch than a faster clock alone; a single-lane analyzer can mis-decode the quad response.<sup>[[5]](#references)</sup> Export that phase with a QSPI analyzer configured for the command's lane widths and dummy cycles, then merge the single- and quad-lane reads by flash address.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` auto-detects both export formats, discards reads decoded at the wrong lane width, and reports read coverage.<sup>[[6]](#references)</sup> From its repository, after installing its dependencies, merge the captures with:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

The result remains a sparse observation, not a complete chip dump.<sup>[[5]](#references)[[6]](#references)</sup> To inspect writes separately, correlate `0x06` write-enable, `0x05` status polls, erase opcodes, and `0x02` page-program commands. Page-program data follows the address on MOSI and is not included by read-only reconstruction.<sup>[[5]](#references)</sup> Analyze the resulting image with [firmware analysis](../firmware-analysis/) while retaining read-coverage information.

## References

- [1] [Analog Devices — Introduction to SPI Interface](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI programmer and read/write options](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Brushing Up on Hardware Hacking Part 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Extending Scapy for Hardware Reverse Engineering](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPI trace capture and reconstruction](https://github.com/wrongbaud/spidump)
- [7] [QSPI Analyzer for Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)

{{#include ../../banners/hacktricks-training.md}}
