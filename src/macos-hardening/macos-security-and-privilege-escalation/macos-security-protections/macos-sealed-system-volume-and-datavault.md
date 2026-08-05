# macOS Sealed System Volume 및 DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 기본 정보

**macOS Big Sur (11.0)**부터 시스템 볼륨은 **APFS snapshot hash tree**를 사용해 암호학적으로 봉인됩니다. 이를 **Sealed System Volume (SSV)**이라고 합니다. 시스템 파티션은 **read-only**로 마운트되며, 수정하면 봉인이 손상되고 부팅 중 이를 검증합니다.

SSV는 다음 기능을 제공합니다:
- **Tamper detection** — 시스템 바이너리/framework가 수정되면 손상된 암호화 봉인을 통해 탐지할 수 있습니다
- **Rollback protection** — 부팅 프로세스가 시스템 snapshot의 무결성을 검증합니다
- **Rootkit prevention** — root 권한이 있어도 봉인을 손상하지 않고는 시스템 볼륨의 파일을 영구적으로 수정할 수 없습니다

### SSV 상태 확인
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
### SSV Writer 권한

Certain Apple system binaries have entitlements that allow them to modify or manage the sealed system volume:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 시스템 볼륨을 이전 snapshot으로 되돌림 |
| `com.apple.private.apfs.create-sealed-snapshot` | 시스템 업데이트 후 새 sealed snapshot을 생성함 |
| `com.apple.rootless.install.heritable` | SIP로 보호되는 경로에 작성함 (자식 프로세스에 상속됨) |
| `com.apple.rootless.install` | SIP로 보호되는 경로에 작성함 |

### SSV Writer 찾기
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

공격자가 `com.apple.private.apfs.revert-to-snapshot` 권한이 있는 `binary`를 장악하면 **system volume을 업데이트 이전 상태로 rollback**하여 알려진 취약점을 복원할 수 있습니다:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback은 **security updates를 사실상 취소**하여, 이전에 패치된 kernel 및 system vulnerability를 복원합니다. 이는 최신 macOS에서 가능한 작업 중 가장 위험한 작업 중 하나입니다.

#### System Binary Replacement

SIP bypass + SSV write capability를 사용하면 공격자는 다음을 수행할 수 있습니다.

1. system volume을 read-write로 mount
2. system daemon 또는 framework library를 trojanized version으로 교체
3. snapshot을 다시 seal (또는 SIP가 이미 degraded 상태라면 손상된 seal을 그대로 수용)
4. rootkit이 reboot 이후에도 지속되며 userland detection tool에서 보이지 않음

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd`의 `com.apple.rootless.install.heritable` entitlement를 악용하여 arbitrary post-install script를 실행하는 SIP bypass ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd`가 post-install script를 `/tmp` 아래 SIP-protected folder에 stage했지만, `/tmp` 자체는 SIP-protected 상태가 아니므로 해당 folder 위에 image를 mount하여 교체할 수 있었음 ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — read-only root-owned file에 대한 write를 허용하는 XNU의 copy-on-write race ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault**는 민감한 system database를 위한 Apple의 protection layer입니다. **root조차 DataVault-protected file에 access할 수 없으며**, 특정 entitlement를 가진 process만 이를 read 또는 modify할 수 있습니다. 보호되는 store에는 다음이 포함됩니다.

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decision |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decision |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection은 extended attribute와 volume protection flag를 사용하여 **filesystem level**에서 적용되며, kernel이 이를 검증합니다.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault 컨트롤러 찾기
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
### 공격 시나리오

#### Direct TCC Database Modification

공격자가 DataVault controller binary(예: `com.apple.private.tcc.manager`를 보유한 process에 대한 code injection을 통해)를 compromise하면 **TCC database를 직접 수정**하여 모든 application에 어떤 TCC permission이든 부여할 수 있습니다:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC database 수정은 **궁극적인 privacy bypass**입니다 — 사용자 prompt나 눈에 보이는 indicator 없이 모든 permission을 조용히 부여합니다. 역사적으로 여러 macOS privilege escalation chain은 최종 payload로 TCC database write를 수행했습니다.

#### Keychain Database Access

DataVault는 keychain backing file도 보호합니다. 침해된 DataVault controller는 다음을 수행할 수 있습니다.

1. 원시 keychain database file 읽기
2. 암호화된 keychain item 추출
3. 사용자의 password 또는 복구된 key를 사용해 offline decryption 시도

### DataVault/TCC Bypass가 관련된 실제 CVE

| CVE | 설명 |
|---|---|
| CVE-2024-44131 | 권한이 있는 helper가 TCC-protected data에 접근할 수 있게 하는 FileProvider symlink race ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | root 권한으로 `NFSHomeDirectory`가 attacker-controlled `TCC.db`를 가리키는 **새 user 생성**; login 시 `tccd`가 이를 사용하고 grant가 적용되어 다른 user의 data에 접근 ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | 사용자의 home dir을 변경하여 attacker-controlled TCC.db를 심는 "powerdir" ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | prompt 없이 app이 **donor bundle의 TCC grant를 상속**할 수 있게 하는 bundle-conclusion flaw; 실제 환경에서 **XCSSET**이 이를 악용하여 desktop screenshot 촬영 ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd`가 `$HOME`을 사용해 DB path를 구성했으므로 `launchctl setenv HOME`으로 attacker-controlled `TCC.db`를 가리키도록 변경 ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod`가 `com.apple.private.tcc.manager`를 **보유하고** library validation도 비활성화했으므로, `/Library/Audio/Plug-Ins/HAL`에 설치된 HAL plug-in이 임의의 TCC 권한을 부여할 수 있었음 ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
