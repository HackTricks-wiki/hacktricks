# macOS Sealed System Volume 및 DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 기본 정보

**macOS Big Sur (11.0)**부터 시스템 볼륨은 **APFS 스냅샷 해시 트리**를 사용해 암호학적으로 봉인됩니다. 이를 **Sealed System Volume (SSV)**이라고 합니다. 시스템 파티션은 **읽기 전용**으로 마운트되며, 수정하면 봉인이 깨지고 부팅 중에 이를 확인합니다.<sup>[[11]](#references)</sup>

SSV는 다음을 제공합니다:
- **변조 탐지** — 시스템 바이너리/프레임워크를 수정하면 Merkle 트리의 루트가 변경되고 Apple 서명 봉인이 무효화됩니다
- **부팅 시 인증** — 부팅 체인은 선택한 시스템 스냅샷이 루트 파일 시스템이 되기 전에 이를 검증합니다
- **rootkit 방어** — 인증된 root를 비활성화하거나 승인된 업데이트 경로를 침해하지 않는 한, root 권한으로도 인증된 시스템 스냅샷의 파일을 지속적으로 교체할 수 없습니다

SSV는 **System** 볼륨을 보호하며, 이에 연결된 쓰기 가능한 **Data** 볼륨은 보호하지 않습니다. Firmlink는 두 볼륨을 `/`에서 보이는 네임스페이스에 병합하므로, 쓰기 가능한 것처럼 보이는 경로만으로는 해당 객체가 봉인된 스냅샷에 속한다고 단정할 수 없습니다. FileVault와 Data Protection은 저장된 데이터의 기밀성을 보호하며, SSV 무결성과는 별개입니다.<sup>[[11]](#references)</sup>

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

### 유효한 시스템 뷰: SSV + Cryptex graft

최신 macOS 릴리스에서는 `/System` 아래에 표시되는 모든 실행 파일이 부팅된 SSV 스냅샷에서 비롯되는 것은 아닙니다. **Cryptexes**는 별도로 인증된 APFS 디스크 이미지로, 해당 콘텐츠가 선택된 디렉터리에 graft됩니다. 따라서 Rapid Security Responses는 기본 SSV를 다시 빌드하지 않고도 보안에 민감한 구성 요소를 교체할 수 있습니다. persistence를 조사하거나 시스템 코드를 비교할 때는 기본 스냅샷만 해시하지 말고, 현재 마운트된 항목과 Preboot Cryptex 저장소를 목록화하세요:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

부팅 체인과 Rapid Security Response에 대한 자세한 내용은 [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)를 참조하세요. 이 섹션에서는 SSV 경계 자체에 초점을 맞춥니다.

### SSV 쓰기 권한 Entitlement

일부 Apple 시스템 바이너리에는 봉인된 시스템 볼륨을 수정하거나 관리할 수 있는 entitlement가 있습니다.

| Entitlement | 목적 |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 시스템 볼륨을 이전 스냅샷으로 되돌림 |
| `com.apple.private.apfs.create-sealed-snapshot` | 시스템 업데이트 후 새 봉인 스냅샷 생성 |
| `com.apple.rootless.install.heritable` | SIP로 보호되는 경로에 쓰기(자식 프로세스에 상속됨) |
| `com.apple.rootless.install` | SIP로 보호되는 경로에 쓰기 |

### SSV 쓰기 권한 보유자 찾기

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

#### 스냅샷 롤백 공격

공격자가 `com.apple.private.apfs.revert-to-snapshot` 권한이 있는 바이너리를 침해하면 **시스템 볼륨을 업데이트 이전 상태로 롤백**하여 알려진 취약점을 복원할 수 있습니다:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> 스냅샷 롤백은 사실상 **보안 업데이트를 되돌려**, 이전에 패치된 커널 및 시스템 취약점을 복원합니다. 이는 최신 macOS에서 가능한 작업 중 가장 위험한 작업 중 하나입니다.

#### 시스템 바이너리 교체

SIP 우회와 SSV 쓰기 기능을 함께 확보하면 공격자는 다음을 수행할 수 있습니다.

1. 시스템 볼륨을 읽기-쓰기 모드로 마운트
2. 시스템 데몬이나 프레임워크 라이브러리를 트로이 목마 버전으로 교체
3. 스냅샷을 다시 봉인(또는 SIP가 이미 저하된 상태라면 봉인이 깨진 상태를 그대로 허용)
4. 루트킷은 재부팅 후에도 지속되며 사용자 영역 탐지 도구에 보이지 않음

### 실제 CVE

| CVE | 설명 |
|---|---|
| CVE-2021-30892 | **Shrootless** — `system_installd`의 `com.apple.rootless.install.heritable` entitlement를 악용해 임의의 설치 후 스크립트를 실행하는 SIP 우회 ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP 우회: `system_installd`가 설치 후 스크립트를 `/tmp` 아래의 SIP 보호 폴더에 배치했지만, `/tmp` 자체는 SIP로 보호되지 않아 해당 폴더 위에 이미지를 마운트해 폴더를 바꿀 수 있었음 ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU의 copy-on-write 경쟁 조건으로 읽기 전용 root 소유 파일에 쓸 수 있음 ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### 기본 정보

**DataVault**는 민감한 파일 및 디렉터리를 보호하는 entitlement 기반 파일시스템 보호 기능입니다. BSD 플래그 `UF_DATAVAULT` (`0x00000080`)는 객체를 읽고 쓰는 데 entitlement가 필요함을 표시합니다. 일반 DAC와 달리, 보호가 적용되는 동안에는 **root** 권한을 얻거나 Full Disk Access를 부여받는 것만으로 이 검사를 통과할 수 없습니다.<sup>[[4]](#references)[[13]](#references)</sup>

모든 보호된 데이터베이스를 “DataVault”의 동의어로 사용하지 마세요. TCC 데이터베이스는 TCC/FDA 및 SIP 관련 정책의 적용을 받으며([macOS TCC](macos-tcc/README.md) 참조), 키체인 항목 액세스도 Keychain ACL 및 암호화 보호에 따라 달라집니다([macOS Keychain](../../macos-red-teaming/macos-keychain.md) 참조). 실제 DataVault 사례는 Screen Time 저장소처럼 `/private/var/folders/.../0/` 아래의 서비스 소유 저장소에서 흔히 볼 수 있습니다. 상위 디렉터리에서 `stat`을 실행할 수 있다면 BSD 파일 플래그에 `datavault`로 표시됩니다.

### DataVault 컨트롤러 Entitlement

| Entitlement | 경계 |
|---|---|
| `com.apple.rootless.datavault.controller` | `UF_DATAVAULT` 객체에 액세스/관리<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC 결정을 관리합니다. 관련은 있지만 별개의 개인정보 보호 경계입니다. |
| `com.apple.private.tcc.allow` | entitlement 값에 지정된 일부 TCC 서비스를 우회합니다. |
| `com.apple.rootless.storage.TCC` | SIP로 보호되는 TCC 저장소에 씁니다. |

DataVault 컨트롤러 entitlement와 FDA, 백업, 인덱싱 또는 IPC 기능을 함께 갖춘 프로세스는 특히 주의해서 살펴볼 만합니다. 볼트를 직접 열려고 시도하는 대신, 보호된 객체를 일반 경로로 복사하는 confused-deputy 원시 기능을 찾아보세요.<sup>[[14]](#references)</sup>

### DataVault 컨트롤러 찾기

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

#### TCC 데이터베이스 직접 수정 (별도의 TCC 경계)

공격자가 TCC manager 프로세스(예: `com.apple.private.tcc.manager`를 보유한 프로세스에 code injection을 수행하는 방식)를 침해하면, **TCC 데이터베이스를 직접 수정해 어떤 애플리케이션에든 원하는 TCC 권한을 부여할 수 있습니다**:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> TCC database 수정은 **궁극적인 프라이버시 우회**입니다. 사용자에게 아무런 프롬프트나 눈에 보이는 표시도 없이 모든 권한을 부여합니다. 과거 여러 macOS 권한 상승 체인은 TCC database 쓰기를 최종 payload로 사용해 마무리되었습니다.

#### Keychain Database 접근

Keychain 백업 database에 대한 직접 접근은 비밀 정보에 대한 평문 접근과 같지 않습니다. 다른 권한 경계를 통해 공격자가 database를 복사할 수 있더라도, 키 자료와 항목 ACL은 여전히 공격해야 합니다. DataVault-controller entitlement만으로 충분하다고 가정하지 말고 전용 [macOS Keychain](../../macos-red-teaming/macos-keychain.md) 페이지를 참조하세요.

#### 백업 사본 경계: Time Machine

2026년 분석에서는 유용한 일반 패턴을 확인했습니다. `backupd`는 보호된 저장소를 복사할 수 있도록 `com.apple.rootless.datavault.controller`와 Full Disk Access를 모두 보유합니다. 테스트한 구성에서 `/private/var/folders`는 Time Machine 백업에 포함되었으며, 마운트된 백업 사본에는 라이브 DataVault 경계가 적용되지 않았습니다. 연구자는 이를 이용해 Screen Time SQLite 저장소를 찾고, 라이브 vault를 열지 않은 채 PIN 제한 정보를 평문으로 읽었습니다. 이를 **복사 경계 공격**으로 보세요. 더 낮은 수준의 보호가 적용되는 마운트 지점이나 경로에서 vault 데이터를 구체화할 수 있는 백업, 내보내기, 마이그레이션, 인덱싱, 진단용 대리 프로세스를 조사하세요.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

이 동작은 macOS 버전과 백업 레이아웃에 따라 달라집니다. 대상 빌드에서 검증하고, 암호화된 Time Machine 대상은 잠겨 있을 때만 복사본을 보호한다는 점을 기억하세요. 마운트되면 해당 대상의 접근 제어도 공격 표면의 일부가 됩니다.

### DataVault/TCC 우회와 관련된 실제 CVE

| CVE | 설명 |
|---|---|
| CVE-2024-44131 | FileProvider 심볼릭 링크 경쟁 상태로 권한이 높은 helper가 TCC로 보호되는 데이터에 접근할 수 있음 ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | root 권한으로 공격자가 제어하는 `TCC.db`를 가리키도록 `NFSHomeDirectory`를 설정한 새 사용자를 **생성**할 수 있음. 로그인 시 `tccd`가 이 파일을 사용하고 권한이 적용되어 다른 사용자의 데이터에 접근할 수 있음 ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": 사용자의 홈 디렉터리를 변경해 공격자가 제어하는 TCC.db를 심을 수 있음 ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | 앱이 메시지 없이 **donor bundle의 TCC 권한을 상속**하도록 하는 bundle conclusion 결함. **XCSSET**이 실제 공격에서 이를 악용해 데스크톱 스크린샷을 찍음 ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd`가 `$HOME`을 기준으로 DB 경로를 구성해 `launchctl setenv HOME`으로 공격자가 제어하는 `TCC.db`를 가리키도록 할 수 있었음 ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod`가 `com.apple.private.tcc.manager` 권한을 보유하면서 **라이브러리 검증도 비활성화**했으므로 `/Library/Audio/Plug-Ins/HAL`에 넣은 HAL 플러그인으로 임의의 TCC 권한을 부여할 수 있었음 ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft가 시스템 무결성 보호를 우회할 수 있는 새로운 macOS 취약점 Shrootless를 발견](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [기술 분석: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - 제대로 못 해도 하는 게 낫다](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple 플랫폼 보안 — 데이터 보호](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC 우회로 iCloud에서 데이터를 탈취](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - macOS 악성코드 밝혀내기: TCC 우회](https://blog.kandji.io/malware-bypass-tcc)
- [7] [새로운 macOS 취약점 "powerdir"로 인해 사용자 데이터에 무단으로 접근할 수 있음](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [XCSSET 악성코드에서 제로데이 TCC 우회 발견](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) 프레임워크 우회](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [음악을 재생해 TCC 우회하기, 일명 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA 업데이트의 악몽(APFS 스냅샷)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC 악용](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [자신의 Screen Time 암호를 우회하는 방법 — 소스 코드와 Time Machine/DataVault 분석](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
