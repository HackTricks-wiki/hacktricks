# Android Forensics

{{#include ../banners/hacktricks-training.md}}

> **Scope of this page**  
> Practical tips and commands to acquire, preserve and analyse data from Android smartphones/tablets **without rooting them in an uncontrolled way**.  
> Commercial “all-in-one” suites such as Cellebrite UFED or Magnet AXIOM *won’t be covered in depth* – instead we focus on open-source or freely-available techniques that any responder can reproduce.

---

## 1. Device states & prerequisites

State terminology you will see in vendor white-papers:

| State | Meaning | Implications for DFIR |
|-------|---------|-----------------------|
| BFU   | *Before First Unlock* – the device has booted but **the user has never entered the pass-code** since power-on. | Only firmware & boot-loader partitions are readable. User data is protected by File-Based-Encryption (FBE) keys that live inside the TEE/SE and are released **after** successful unlock. |
| AFU   | *After First Unlock* – the device was unlocked at least once since boot. | FBE keys are in RAM → logical / agent-based extractions are possible as long as the screen does not lock again. |
| Locked | Screen protected by PIN/pattern/pass-phrase. | You need either the credential itself, a live bypass (e.g. *disabling Gatekeeper*), or a hardware exploit. |

Newer Android versions (≥ 12) **removed `adb backup`**, enforce *scoped storage* and tighten SELinux. When reading old blog posts always check the target OS version first.

---

## 2. Handling a locked device

1. **Check USB debugging** – if the green Android with *USB debugging connected* appears after plugging-in, you can immediately start a **logical acquisition** with `adb` (see next section).  
2. **Smudge & shoulder attacks** – still work on glossy screens.  
3. **Pattern/PIN brute force** – tools such as **[Andriller](https://github.com/andriller/andriller)** (updated 2024-11) allow hardware-accelerated offline cracking of `password.key` / `gatekeeper.*` hashes if you already imaged `/data/system*` (see section 4).
4. **Custom recovery temporary boot** (no data wipe):
   ```bash
   fastboot boot twrp-3.7.0-0.img   # device-specific recovery image
   adb pull /data/system
   ```
   Works on unlocked boot-loaders (Pixel, many OEMs with `fastboot flashing unlock`) or when an **EDL/firehose** session is possible (Qualcomm).
5. **Forensic reset protection (FRP)** – Google FRP triggers as soon as you factory-reset without the original Google account. Always *avoid* a wipe.

{{#ref}}
mobile-pentesting/android-app-pentesting/adb-commands.md
{{#endref}}

---

## 3. Logical / agent-based acquisition (no root required)

### 3.1 `adb shell` & bugreport

```bash
adb devices -l                 # verify connection
adb bugreport bug.zip          # full diagnostic dump (calls, SMS, Wi-Fi, Bluetooth…)  
adb pull /sdcard/DCIM/         # media that lives on shared storage
```

### 3.2 APK-Downgrade trick (Android 10-14)

Because `adb backup` is deprecated, modern forensic suites **downgrade an app to a debuggable version signed with the same key**, trigger the legacy backup API **only for that package**, then restore the original APK. You can script the same technique yourself:

```bash
pkg=com.whatsapp
adb shell pm path $pkg | awk -F":" '{print $2}' > /tmp/base.apk
adb shell pm uninstall -k --user 0 $pkg          # keep data
adb install -r -d whatsapp_v2.11.apk             # debuggable build
adb backup -f whatsapp.ab $pkg
adb install -r /tmp/base.apk                     # restore
```

The resulting `*.ab` file can be converted with `abe.jar` (see section 5).

---

## 4. Full file-system & physical imaging

### 4.1 From a custom recovery / root shell

```bash
adb root                               # needs eng build or recovery
adb shell su -c 'ls -l /dev/block/by-name'
adb shell su -c 'dd if=/dev/block/by-name/userdata \
                  of=/sdcard/userdata.img bs=4M'
adb pull /sdcard/userdata.img
```

### 4.2 Qualcomm EDL / Firehose (device locked, boot-loader closed)

```bash
python edl.py r partition --loader=sprog.mbn userdata.img
```
Requires the signed **firehose programmer** (`prog_nand_firehose_*`). Works even on fully locked devices but *cannot* decrypt FBE without keys.

### 4.3 JTAG / ISP / chip-off

Low-level techniques when the device is bricked or the eMMC is the only interest. Make sure to note down **eMMC CID** and remove *write-protect* pins.

---

## 5. Memory acquisition

`LiME` is still the de-facto standard. Build against the exact kernel headers (Android 14 → 6.1 kernels on Pixel 8):

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
adb push lime.ko /data/local/tmp
adb shell su -c 'insmod /data/local/tmp/lime.ko "path=tcp:4444 format=lime"'
nc -l 4444 > pixel8_2025-07-14.lime
```

Analyse with `volatility3 -f pixel8_*.lime --profile=LinuxARM64`.

---

## 6. Important artefacts (AFU state)

| Path | Contents |
|------|----------|
| `/data/system_ce/0/shortcut_service.db` | Recent app usage |
| `/data/misc/wifi/WifiConfigStore.db` | Saved WLAN PSKs incl. *Passpoint* profiles |
| `/data/system/users/0/settings_global.xml` | System settings, *adb_enabled*, etc. |
| `/data/system_de/0/accounts_de.db` | Google & third-party account tokens |
| `/data/system/locksettings.db` & `gatekeeper.*` | Credential hashes (scrypt + TEE signatures) |
| `/data/user_de/0/com.android.providers.telephony/databases/mmssms.db` | SMS/MMS |

(use `sqlite3` or `strings` if WAL present)

---

## 7. Encryption evolution & forensic impact

| Android version | Default | Comments |
|-----------------|---------|----------|
| ≤ 6.0 | **FDE** (dm-crypt) | Single key – bruteforcing possible offline on NAND image. |
| 7.0 – 9 | **FBE v1** | Separate keys per user & directory; credential stored in `gatekeeper.*`. |
| 10 – 12 | **FBE v2 + metadata encryption** | Adds `metadata` partition; brute-forcing almost impossible without TEE. |
| 13 – 14 | **FBE + Adoptable Inline Encryption (AIE)** | Hardware-bound keys (UFS inline) + *Protected by Default*; forces live acquisition (AFU). |

---

## 8. Open-source analysis tools

* **Mobile Verification Toolkit (MVT)** – spyware triage:  
  ```bash
  pipx install mvt
  mvt-android check-adb --output ~/mvt-out
  mvt-android download-apks --exclude-system-apps -o ~/mvt-out
  mvt-android analyse ~/mvt-out -i pegasus.stix2
  ```
* **Autopsy ≥ 4.21** – *Add Data Source → Logical Android Image* parses SMS, Calls, Accounts.
* **Andriller 3.7** – pattern/PIN dictionaries, protobuf WhatsApp chat decoder.

Commercial (mention only): Cellebrite UFED 9.x, Magnet AXIOM 9, Oxygen Detective 16, Grayshift GrayKey (AFU/BFU brute-force Pixel & iPhone).

---

## 9. Anti-forensic considerations

Attackers may:

* Enable **`adb shell sm set-virtual-disk true`** to move data into ephemeral virtual disks.
* Abuse **Work Profile** to keep evidence under separate user-IDs (needs parallel extraction of `/data/user/10`).
* Schedule **`LOCK_SETTINGS_RESET`** broadcast to wipe `locksettings.db` on reboot.

Be prepared to snapshot *before* leaving the AFU state.



## References

1. LiME – Linux Memory Extractor (2020-08-25 release).  
   https://github.com/504ensicsLabs/LiME
2. Mobile Verification Toolkit – Amnesty International (documentation, 2025-04).  
   https://docs.mvt.re
{{#include ../banners/hacktricks-training.md}}
