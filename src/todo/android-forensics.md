# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

Prefer acquisition methods that preserve the device's state and document every action. If the device is locked, available options depend on the model, Android version, patch level, and whether access was configured before seizure. NIST recommends choosing a method according to the device and the authority for the examination.<sup>[[1]](#references)</sup>

- Check whether USB debugging was enabled and whether the acquisition workstation is already authorized. ADB access normally requires the user to unlock the device and confirm the workstation's RSA key.<sup>[[3]](#references)</sup>
- Consider whether biometric access remains available under the applicable legal and procedural rules.
- A **smudge attack** may reveal a graphical unlock pattern from residue on the screen, although later touches and cleaning reduce its reliability.<sup>[[2]](#references)</sup>
- Where authorized tooling supports the exact device and software build, it may attempt PIN, password, or pattern recovery or brute force. Hardware-backed credential verification, retry delays, and wipe policies make this highly device-specific, so do not substitute an iPhone technique or result for evidence that an Android device is supported.<sup>[[1]](#references)</sup>

## Data acquisition

On older devices, a legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) may produce a `.backup` file that Android Backup Extractor can unpack:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Do not assume this captures every application. ADB labels the command deprecated, and Android 12 excludes data from apps targeting API level 31 or later unless the app is debuggable.<sup>[[4]](#references)</sup>

### Root or physical debug access

With root access on a live device, first inventory the partitions and mounts; the commands below do not apply directly to a physical JTAG acquisition. The correct block device is hardware-dependent, so do not assume it is always `mmcblk0`. Image only the verified source to separate storage:<sup>[[1]](#references)</sup>

A JTAG acquisition instead uses the device's hardware test-access interface and compatible acquisition equipment to read accessible memory. Pinout, chipset support, device state, and the distinction between volatile and non-volatile targets are device-specific; document the hardware path and use a validated procedure for that model.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

For example, if the partition inventory confirms that `/dev/block/mmcblk0` is the whole flash device and the destination has sufficient space, the original acquisition command becomes:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Here, `df /data` helps associate `/data` with its mounted filesystem; it should not be treated as proof that `mmcblk0` is the correct whole-device source or that `4096` is the only valid `dd` block size.

Hash the result and record the exact command, device identifiers, time, and any changes made during acquisition.<sup>[[1]](#references)</sup>

### Memory

LiME can acquire physical memory from Linux and some Android devices, but its kernel module must be built for the target kernel and loaded with sufficient privileges. Module signing, kernel lockdown, and modern Android hardening may prevent it from loading.<sup>[[5]](#references)</sup>

The project's Android workflow pushes the matching module with ADB, forwards a TCP port, loads the module from a root shell, and captures the stream on the examination host:<sup>[[5]](#references)</sup>

```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```

LiME can instead write to device storage with `path=/sdcard/ram.lime`, but that changes the device's storage and requires enough free space. Record that side effect and hash the acquired image.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Guidelines on Mobile Device Forensics](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)

{{#include ../banners/hacktricks-training.md}}
