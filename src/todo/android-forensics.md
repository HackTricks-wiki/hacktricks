# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

デバイスの状態を保持し、すべての操作を記録できる acquisition method を優先します。デバイスがロックされている場合、利用可能な選択肢はモデル、Android のバージョン、patch level、押収前に access が設定されていたかどうかによって異なります。NIST は、デバイスと examination authority に応じて method を選択することを推奨しています。<sup>[[1]](#references)</sup>

- USB debugging が有効になっているか、また acquisition workstation がすでに認証済みかを確認します。ADB access には通常、ユーザーによるデバイスのロック解除と、workstation の RSA key の確認が必要です。<sup>[[3]](#references)</sup>
- 適用される法的および手続き上の規則の下で、biometric access が引き続き利用可能かを検討します。
- **smudge attack** により、画面に残った痕跡から graphical unlock pattern が判明する場合がありますが、その後のタッチや清掃によって信頼性が低下します。<sup>[[2]](#references)</sup>
- commercial または research 用の lock-bypass tooling は、対象のデバイスと software build を明示的にサポートしている場合にのみ使用します。

## Data acquisition

古いデバイスでは、legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) によって `.backup` file が生成され、Android Backup Extractor で unpack できる場合があります。<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
すべてのアプリケーションを網羅しているとは限りません。ADB はこの command を deprecated としています。また Android 12 では、app が debuggable でない限り、API level 31 以降を対象とする app の data は除外されます。<sup>[[4]](#references)</sup>

### Root または物理的な debug access

live device で root access を取得している場合は、まず partitions と mounts を inventory します。以下の commands は physical JTAG acquisition には直接適用できません。正しい block device は hardware に依存するため、常に `mmcblk0` だと assume しないでください。検証済みの source のみを別の storage に image します。<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
取得結果を Hash 化し、正確な command、device identifiers、時刻、および取得中に行った変更を記録します。<sup>[[1]](#references)</sup>

### Memory

LiME は Linux および一部の Android devices から physical memory を取得できますが、target kernel 用に kernel module を build し、十分な privileges で load する必要があります。Module signing、kernel lockdown、および最新の Android hardening により、load が阻止される場合があります。<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobile Device Forensics のガイドライン](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smartphone Touch Screens への Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
