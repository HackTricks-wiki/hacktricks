# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

When an authorized assessment finds weak or missing firmware-signature verification, a modified firmware image can demonstrate the integrity impact. The following lab workflow adds a bind shell while retaining the original extraction, emulation, and repacking steps.<sup>[[2]](#references)[[3]](#references)</sup>

1. The firmware can be extracted using firmware-mod-kit (FMK).
2. The target firmware architecture and endianness should be identified.
3. A cross compiler can be built using Buildroot or other suitable methods for the environment.
4. The backdoor can be built using the cross compiler.
5. The backdoor can be copied to the extracted firmware /usr/bin directory.
6. The appropriate QEMU binary can be copied to the extracted firmware rootfs.
7. The backdoor can be emulated using chroot and QEMU.
8. The backdoor can be accessed via netcat.
9. The QEMU binary should be removed from the extracted firmware rootfs.
10. The modified firmware can be repackaged using FMK.
11. The backdoored firmware can be tested by emulating it with firmware analysis toolkit (FAT) and connecting to the target backdoor IP and port using netcat.

If a root shell has already been obtained through dynamic analysis, bootloader manipulation, or hardware security testing, precompiled test binaries such as implants or reverse shells can be executed. Metasploit's `msfvenom` can generate an architecture-specific payload for this validation workflow:<sup>[[4]](#references)</sup>

1. The target firmware architecture and endianness should be identified.
2. Msfvenom can be used to specify the target payload, attacker host IP, listening port number, filetype, architecture, platform, and the output file.
3. The payload can be transferred to the compromised device and ensured that it has execution permissions.
4. Metasploit can be prepared to handle incoming requests by starting msfconsole and configuring the settings according to the payload.
5. The meterpreter reverse shell can be executed on the compromised device.

## Unauthenticated transport bridges to privileged update protocols

A common embedded design mistake is exposing the **same internal command protocol over several transports** but enforcing authentication on only one of them. For example, USB may require challenge-response while BLE simply forwards unauthenticated **GATT writes** into the same privileged firmware-update handler.<sup>[[1]](#references)</sup>

Typical offensive workflow:

1. Enumerate the BLE GATT database and identify writable characteristics used by the official mobile app.
2. Sniff app traffic and look for **magic bytes / opcodes** that match the wired protocol.
3. Replay privileged commands over BLE **without pairing** and verify whether sensitive operations still work.
4. If firmware upgrade, config write, debug, or factory-test opcodes are reachable, treat BLE as a **radio-reachable admin port**.

Quick checks:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Things to verify while reversing:

- Does BLE require **pairing/bonding** or just a plain connection?
- Are all transports routed to the same internal dispatcher table?
- Are privileged opcodes filtered differently on USB / BLE / UART / Wi-Fi?
- Can the mobile app trigger firmware update, recovery, or diagnostic handlers remotely?

## Checksum-only firmware containers are still attacker-controlled firmware

A firmware container protected only by an **unkeyed checksum** (CRC32, SHA-256, MD5, etc.) provides corruption detection, **not authenticity**. If the attacker can reach the update routine, they can patch the image, recompute the checksum, and flash arbitrary code.<sup>[[1]](#references)</sup>

Red flags during RE:

- Update code validates only a trailing checksum blob such as `CHK2`, `CRC`, or `SHA256`.
- No signature verification or secure-boot root of trust is present.
- No device-bound MAC / HMAC / authenticated encryption is used.
- Recovery mode accepts the same unauthenticated image format.

Practical validation flow:

1. Extract the firmware container and identify bootloader, main firmware, and integrity metadata.
2. Modify a harmless string or banner in the image.
3. Recompute the checksum exactly as the updater expects.
4. Reflash the image through the normal update path.
5. Confirm the change on boot to prove arbitrary firmware replacement.

If this works over a remotely reachable transport such as BLE/Wi-Fi, the bug is effectively **unauthenticated OTA firmware replacement**.

## Fragmented update state and writable integrity metadata

An updater may verify a signed firmware header during installation but still boot images using only a stored integrity hash. On the Cypherock X1, the Bootloader invoked separate Firewall tasks to verify the header and place version/size in RAM, store the firmware signature in RAM, verify the written image, and finally hash the image into persistent Primary Bootloader Data. The signature itself was not persisted. These tasks could be called independently rather than enforcing one authenticated upgrade transaction.<sup>[[5]](#references)</sup>

With MCU code execution and Flash write access, the reported attack rewrote the application image, changed the version/size values in Bootloader RAM shared with the Firewall, then called the final metadata task to store the malicious image's hash and restore normal boot state. The normal boot integrity check accepted that hash without rechecking a signature. When reviewing a similar updater, trace **which component can invoke each task**, where verified values live, and whether the boot-time decision authenticates the *same image* whose hash is stored. This is narrower than a checksum-only image format: signature verification existed, but the state transition was not bound to it.<sup>[[5]](#references)</sup>

## Secure-element signatures over untrusted firmware measurements

A secure element does not attest running code merely by signing a hash supplied by that code. In the same wallet, the secure element signed the device serial number and then the XOR of a cloud nonce and a firmware hash provided through the MCU. Compromised firmware could present an expected hash to be signed while running different bytes. The companion client also submitted the firmware version to the cloud, so the verifier's expected-hash comparison still relied on an MCU-origin measurement rather than an independent read of Flash.<sup>[[5]](#references)</sup>

The device-side result was a separate trust boundary: the cloud checked the device, but the device did not authenticate the cloud's verdict. A modified client could report local success to a tampered device. Test the measurement provenance and response authentication separately; a valid secure-element signature and a success screen do not, by themselves, prove that the installed application is authentic.<sup>[[5]](#references)</sup>

For the protected-code disclosure that enabled analysis of this updater, see [Firewall copy-task firmware acquisition](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

When the target device is already trusted by the host over USB, malicious firmware may not need to implement a full new USB stack. A much easier pivot is often to **reuse existing HID support**.<sup>[[1]](#references)</sup>

Useful pattern:

1. Check whether the device already enumerates as a **HID Consumer Control** / media / vendor HID interface.
2. Locate the existing **HID report descriptor** in firmware.
3. Append or replace descriptor entries so the device also advertises **keyboard** capability.
4. Reuse existing firmware routines that already send HID reports instead of writing a new transport implementation.
5. Inject key press + key release reports to type commands on the host.

This turns firmware compromise into **host compromise** because the PC will trust the reflashed peripheral as a legitimate keyboard.

### Minimal assessment checklist

- Does `dmesg`, Device Manager, or USB descriptors show an existing HID interface?
- Is there spare room near the report descriptor or a relocatable descriptor table?
- Can existing media-control send routines be reused for keyboard reports?
- Does the host auto-accept the new keyboard interface after reflashing?

## Reliable payload execution inside RTOS firmware

Instead of inserting fragile trampolines into random code paths, look for **existing RTOS tasks** that are unused or low-impact in normal operation.<sup>[[1]](#references)</sup>

Why this is useful:

- The scheduler starts your payload naturally during boot.
- You avoid corrupting critical control flow.
- Delayed payloads are less likely to trigger watchdog resets than when run inside a latency-sensitive USB/network handler.

Good targets are diagnostic, factory-test, telemetry, or coprocessor service tasks that appear dormant in normal usage.

## Fast exploit iteration: repurpose benign protocol handlers

Once firmware patching is possible, a compact way to accelerate RE is to overwrite a harmless command handler (for example an **echo/debug opcode**) with custom **memory read / write / execute** primitives. This avoids full reflashing for every experiment and is especially useful when the device supports the modified handler over a fast wired transport.<sup>[[1]](#references)</sup>

Use this to:

- Verify scatter-loaded memory maps
- Inspect heap/task state live
- Test small payloads before burning them into flash
- Recover function pointers, strings, and descriptor tables safely

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - How to use `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [How And Why We Hacked Cypherock Hardware Wallet: The Full Story](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)

{{#include ../../banners/hacktricks-training.md}}
