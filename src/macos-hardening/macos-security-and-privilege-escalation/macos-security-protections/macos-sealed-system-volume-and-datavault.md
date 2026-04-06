# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 기본 정보

Starting with **macOS Big Sur (11.0)**, the system volume is cryptographically sealed using an **APFS snapshot hash tree**. This is called the **Sealed System Volume (SSV)**. The system partition is mounted **read-only** and any modification breaks the seal, which is verified during boot.

SSV는 다음을 제공합니다:
- **Tamper detection** — 시스템 바이너리/프레임워크에 대한 모든 수정은 깨진 암호학적 봉인을 통해 감지됩니다
- **Rollback protection** — 부팅 프로세스는 시스템 스냅샷의 무결성을 검증합니다
- **Rootkit prevention** — 심지어 root도 시스템 볼륨의 파일을 지속적으로 수정할 수 없습니다(봉인을 깨지 않는 한)

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

일부 Apple 시스템 바이너리는 봉인된 시스템 볼륨(SSV)을 수정하거나 관리할 수 있는 권한(entitlements)을 가집니다:

| Entitlement | 용도 |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 시스템 볼륨을 이전 스냅샷으로 되돌림 |
| `com.apple.private.apfs.create-sealed-snapshot` | 시스템 업데이트 후 새로운 봉인된 스냅샷 생성 |
| `com.apple.rootless.install.heritable` | SIP로 보호된 경로에 쓰기(자식 프로세스에 상속됨) |
| `com.apple.rootless.install` | SIP로 보호된 경로에 쓰기 |

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
### 공격 시나리오

#### Snapshot Rollback Attack

만약 공격자가 `com.apple.private.apfs.revert-to-snapshot` 권한을 가진 바이너리를 탈취하면, 그들은 **시스템 볼륨을 업데이트 이전 상태로 롤백하여**, 알려진 취약점을 복원할 수 있습니다:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> 스냅샷 롤백은 사실상 **보안 업데이트를 되돌려**, 이전에 패치된 커널 및 시스템 취약점을 복원합니다. 이는 최신 macOS에서 가능한 가장 위험한 작업 중 하나입니다.

#### 시스템 바이너리 교체

SIP 우회 + SSV 쓰기 권한으로 공격자는 다음을 수행할 수 있습니다:

1. 시스템 볼륨을 읽기-쓰기 모드로 마운트한다
2. 시스템 데몬이나 프레임워크 라이브러리를 트로이화된 버전으로 교체한다
3. 스냅샷을 다시 봉인(re-seal)하거나(또는 SIP가 이미 약화된 경우 손상된 봉인을 허용한다)
4. rootkit은 재부팅 후에도 지속되며 userland 탐지 도구에서는 보이지 않는다

### 실제 CVE 사례

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP 우회를 통해 `system_installd`로 SSV 수정을 허용 |
| CVE-2022-22583 | PackageKit의 스냅샷 처리 과정을 통한 SSV 우회 |
| CVE-2022-46689 | SIP로 보호된 파일에 쓰기를 허용하는 경쟁 조건 |

---

## DataVault

### 기본 정보

**DataVault**는 민감한 시스템 데이터베이스를 위한 Apple의 보호 계층입니다. 심지어 **root는 DataVault로 보호된 파일에 접근할 수 없습니다** — 특정 entitlements를 가진 프로세스만 읽거나 수정할 수 있습니다. 보호되는 저장소에는 다음이 포함됩니다:

| 보호된 데이터베이스 | 경로 | 내용 |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | 시스템 전체의 TCC 개인정보 허용 결정 |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | 사용자별 TCC 개인정보 허용 결정 |
| Keychain (system) | `/Library/Keychains/System.keychain` | 시스템 Keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | 사용자 Keychain |

DataVault 보호는 커널에 의해 검증되며 확장 속성과 볼륨 보호 플래그를 사용하여 **파일시스템 수준**에서 강제됩니다.

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
### Attack Scenarios

#### Direct TCC Database Modification

공격자가 DataVault controller binary를 탈취한 경우(예: `com.apple.private.tcc.manager`를 가진 프로세스에 code injection을 통해), 그들은 모든 애플리케이션에 모든 TCC 권한을 부여하기 위해 **TCC database를 직접 수정할 수 있습니다:**
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC 데이터베이스 수정은 **궁극적인 개인정보 우회**입니다 — 사용자 프롬프트나 눈에 보이는 표시 없이 모든 권한을 조용히 부여합니다. 역사적으로 여러 macOS 권한 상승 체인이 최종 페이로드로 TCC 데이터베이스 쓰기로 종료되었습니다.

#### Keychain Database Access

DataVault는 또한 Keychain을 뒷받침하는 파일들을 보호합니다. 손상된 DataVault 컨트롤러는 다음을 수행할 수 있습니다:

1. 원시 Keychain 데이터베이스 파일을 읽음
2. 암호화된 Keychain 항목을 추출
3. 사용자 비밀번호나 복구된 키를 사용해 오프라인 복호화를 시도

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | 설명 |
|---|---|
| CVE-2023-40424 | symlink를 통한 DataVault 보호 파일로의 TCC bypass |
| CVE-2023-32364 | Sandbox bypass가 TCC 데이터베이스 수정을 초래함 |
| CVE-2021-30713 | XCSSET malware가 TCC.db를 수정하여 발생한 TCC bypass |
| CVE-2020-9934 | 환경 변수 조작을 통한 TCC bypass |
| CVE-2020-29621 | Music app의 TCC bypass가 DataVault에 도달 |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
