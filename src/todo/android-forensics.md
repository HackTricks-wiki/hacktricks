# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## 잠긴 기기

기기의 상태를 보존하고 모든 작업을 기록하는 acquisition 방법을 우선 사용합니다. 기기가 잠겨 있는 경우, 사용 가능한 옵션은 모델, Android 버전, patch level, 압수 전에 access가 구성되었는지 여부에 따라 달라집니다. NIST는 기기와 examination 권한에 따라 방법을 선택할 것을 권장합니다.<sup>[[1]](#references)</sup>

- USB debugging이 활성화되어 있는지, acquisition workstation이 이미 authorized 상태인지 확인합니다. ADB access에는 일반적으로 사용자가 기기를 unlock하고 workstation의 RSA key를 확인해야 합니다.<sup>[[3]](#references)</sup>
- 해당 법적 및 절차적 규칙에 따라 biometric access가 여전히 가능한지 고려합니다.
- 화면에 남은 잔여물로부터 graphical unlock pattern을 알아낼 수 있는 **smudge attack**을 고려할 수 있지만, 이후의 터치와 청소로 신뢰성이 낮아집니다.<sup>[[2]](#references)</sup>
- 정확한 기기와 software build를 명시적으로 지원하는 경우에만 commercial 또는 research lock-bypass tooling을 사용합니다.

## 데이터 획득

구형 기기에서는 legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup)이 `.backup` 파일을 생성할 수 있으며, Android Backup Extractor로 이를 unpack할 수 있습니다:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
이것이 모든 애플리케이션을 포함한다고 가정해서는 안 됩니다. ADB는 해당 명령을 deprecated로 표시하며, Android 12에서는 앱이 debuggable이 아닌 경우 API level 31 이상을 대상으로 하는 앱의 데이터를 제외합니다.<sup>[[4]](#references)</sup>

### Root 또는 물리적 debug access

실행 중인 디바이스에 root access가 있는 경우, 먼저 파티션과 mount를 inventory해야 합니다. 아래 명령은 물리적 JTAG acquisition에 직접 적용되지 않습니다. 올바른 block device는 하드웨어에 따라 다르므로 항상 `mmcblk0`이라고 가정하지 마세요. 검증된 source만 별도의 storage에 image로 저장하세요:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
결과를 해시하고, acquisition 중 사용한 정확한 명령어, device 식별자, 시간 및 변경 사항을 기록합니다.<sup>[[1]](#references)</sup>

### Memory

LiME은 Linux 및 일부 Android devices에서 physical memory를 acquisition할 수 있지만, 해당 kernel module은 대상 kernel에 맞게 빌드하고 충분한 privileges로 로드해야 합니다. Module signing, kernel lockdown 및 최신 Android hardening으로 인해 로드되지 않을 수 있습니다.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobile Device Forensics 지침](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smartphone Touch Screens에 대한 Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
