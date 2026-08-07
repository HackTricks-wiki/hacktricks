# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 기본 정보

**macOS Big Sur (11.0)**부터 system volume은 **APFS snapshot hash tree**를 사용해 cryptographically sealed됩니다. 이를 **Sealed System Volume (SSV)**이라고 합니다. system partition은 **read-only**로 mount되며, 모든 modification은 seal을 깨뜨립니다. 이 seal은 boot 중에 검증됩니다.<sup>[[11]](#references)</sup>

SSV는 다음 기능을 제공합니다:
- **Tamper detection** — system binaries/frameworks에 대한 모든 modification은 손상된 cryptographic seal을 통해 감지할 수 있습니다.
- **Rollback protection** — boot process는 system snapshot의 integrity를 검증합니다.
- **Rootkit prevention** — root 권한이 있더라도 seal을 깨뜨리지 않고는 system volume의 files를 지속적으로 modification할 수 없습니다.

### SSV Status 확인
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### SSV Writer Entitlements

일부 Apple 시스템 바이너리에는 sealed system volume을 수정하거나 관리할 수 있는 entitlements가 있습니다:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 시스템 볼륨을 이전 snapshot으로 되돌림 |
| `com.apple.private.apfs.create-sealed-snapshot` | 시스템 업데이트 후 새로운 sealed snapshot을 생성 |
| `com.apple.rootless.install.heritable` | SIP로 보호되는 경로에 쓰기 (자식 프로세스가 상속) |
| `com.apple.rootless.install` | SIP로 보호되는 경로에 쓰기 |

### Finding SSV Writers
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
### Attack Scenarios

#### Snapshot Rollback Attack

공격자가 `com.apple.private.apfs.revert-to-snapshot` 권한이 있는 binary를 손상시키면 **system volume을 업데이트 이전 상태로 롤백하여**, 알려진 취약점을 복원할 수 있습니다:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback은 **security updates를 되돌려**, 이전에 패치된 kernel 및 system 취약점을 복원합니다. 이는 최신 macOS에서 가능한 작업 중 가장 위험한 작업 중 하나입니다.

#### System Binary Replacement

SIP bypass + SSV write capability를 사용하면 공격자는 다음을 수행할 수 있습니다.

1. system volume을 read-write로 mount
2. system daemon 또는 framework library를 trojaned version으로 교체
3. snapshot을 re-seal (또는 SIP가 이미 degraded 상태라면 broken seal을 수용)
4. rootkit이 reboot 이후에도 지속되며 userland detection tools에 보이지 않음

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd`의 `com.apple.rootless.install.heritable` entitlement를 악용하여 임의의 post-install scripts를 실행하는 SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd`가 SIP-protected folder에 post-install script를 `/tmp` 아래에 staging했지만, `/tmp` 자체는 SIP-protected 상태가 아니므로 해당 folder 위에 image를 mount하여 교체할 수 있었음 ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — read-only root-owned files에 대한 write를 허용하는 XNU의 copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basic Information

**DataVault**는 민감한 system databases를 보호하는 Apple의 protection layer입니다. **root조차도 DataVault-protected files에 접근할 수 없으며**, 특정 entitlements를 가진 process만 이를 read하거나 modify할 수 있습니다.<sup>[[4]](#references)</sup> 보호되는 stores에는 다음이 포함됩니다.

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection은 extended attributes 및 volume protection flags를 사용하여 **filesystem level**에서 적용되며, kernel이 이를 검증합니다.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault Controller 찾기
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### Attack Scenarios

#### Direct TCC Database Modification

공격자가 DataVault controller binary(예: `com.apple.private.tcc.manager`를 사용하는 process에 대한 code injection을 통해)를 compromise하면 **TCC database를 직접 수정하여** 모든 application에 원하는 TCC permission을 부여할 수 있습니다:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database 수정은 **궁극적인 privacy bypass**입니다. 어떤 권한이든 사용자 prompt나 눈에 보이는 indicator 없이 조용히 부여합니다. 역사적으로 macOS privilege escalation chain 여러 개가 TCC database write를 최종 payload로 사용했습니다.

#### Keychain Database Access

DataVault는 keychain backing file도 보호합니다. 침해된 DataVault controller는 다음을 수행할 수 있습니다.

1. raw keychain database file 읽기
2. encrypted keychain item 추출
3. 사용자의 password 또는 복구된 key를 사용해 offline decryption 시도

### DataVault/TCC Bypass가 관련된 실제 CVE

| CVE | 설명 |
|---|---|
| CVE-2024-44131 | privileged helper가 TCC-protected data에 접근하도록 하는 FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root 권한으로 `NFSHomeDirectory`가 attacker-controlled `TCC.db`를 가리키는 **새 user를 생성**할 수 있습니다. 로그인 시 `tccd`가 이를 사용하고 grant가 적용되어 다른 user의 data에 접근합니다 ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | 사용자의 home dir을 변경하여 attacker-controlled TCC.db를 심는 "powerdir" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | prompt 없이 app이 **donor bundle의 TCC grant를 상속**할 수 있게 하는 bundle-conclusion flaw. 실제 환경에서 **XCSSET**이 desktop screenshot을 촬영하는 데 악용했습니다 ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd`가 `$HOME`에서 DB path를 구성했기 때문에 `launchctl setenv HOME`으로 이를 attacker-controlled `TCC.db`로 redirect할 수 있었습니다 ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod`가 `com.apple.private.tcc.manager`를 **보유하고** library validation도 **비활성화**했기 때문에 `/Library/Audio/Plug-Ins/HAL`에 배치된 HAL plug-in이 임의의 TCC 권한을 부여할 수 있었습니다 ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## References

- [1] [Microsoft가 System Integrity Protection을 우회할 수 있는 새로운 macOS vulnerability, Shrootless를 발견](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass가 iCloud에서 data를 탈취](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOS Malware 분석: TCC Bypassing](https://blog.kandji.io/malware-bypass-tcc)
- [7] [새 macOS vulnerability인 "powerdir"가 unauthorized user data access로 이어질 수 있음](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSET malware에서 Zero-Day TCC bypass 발견](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework Bypassing](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA Update의 악몽 (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
