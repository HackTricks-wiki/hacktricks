# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

**NVRAM** (Non-Volatile Random-Access Memory)은 일반적인 macOS 파일 시스템 외부에 펌웨어와 초기 부팅 상태를 저장합니다. 보안에 미치는 영향은 변수와 부팅 아키텍처 모두에 따라 달라집니다.

| 변수 | 용도 / 보안 관련성 |
|---|---|
| `boot-args` | 커널에 전달되는 인수입니다. 디버그 또는 보안을 약화시키는 인수는 부팅 정책에서 허용하지 않는 한 필터링됩니다. |
| `csr-active-config` | Intel Mac의 SIP bitmask입니다. Apple silicon에서는 해당 정책이 volume별 `LocalPolicy`에 저장되며, 이 변수에서 직접 신뢰하지 않습니다. |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI 부팅 대상입니다. |
| `boot-volume` | Apple silicon의 부팅 volume 선택 상태입니다. |
| `SystemAudioVolume`, `prev-lang:kbd` | 일반적인 영구 설정의 예입니다. |

중요한 차이점은 **NVRAM에 저장된 data**와 **부팅 chain에서 허용되는 보안 정책**의 차이입니다. Apple silicon에서는 Secure Enclave가 부팅 volume group별 `LocalPolicy`에 서명하며, Secure Storage Component에 저장된 nonce가 replay 방지를 제공합니다. 따라서 이름이 유사한 NVRAM property를 변경하는 것만으로는 허용된 부팅 정책이 다시 작성되지 않습니다.<sup>[[1]](#references)[[4]](#references)</sup>

## User Space에서 NVRAM 액세스

### 읽기 및 기준 수집
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
익숙하지 않은 모든 키를 악성으로 분류하지 마세요. 하드웨어, recoveryOS, 업데이트, Find My 및 부팅 실패로 인해 모델과 버전에 따라 달라지는 변수가 생성됩니다. **동일한 Mac**에서 이전에 수집한 기준값과 비교하고, 예상치 못한 binary blob, 변경된 부팅 선택 또는 보안을 약화하는 인수는 침해의 증거가 아니라 조사 단서로 간주하세요.

### NVRAM 쓰기

root는 일반 변수를 많이 생성하거나 변경할 수 있지만, 보호된 변수는 변수 namespace, SIP, 변수별 kernel 규칙 및 제한된 Apple entitlement에도 영향을 받습니다. 따라서 무해한 사용자 지정 키에 대해 `sudo`가 성공한다고 해서 해당 프로세스가 `boot-args`, SIP 또는 system-region 변수를 수정할 수 있다는 의미는 아닙니다.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> 테스트 중에는 `nvram -c`를 사용하지 마세요. 삭제 가능한 모든 변수를 삭제하도록 요청하며, 부팅/복구 동작을 변경할 수 있습니다. 일부 변수는 커널 전용이거나 entitlement로 보호되며, 읽을 때 숨겨지거나 NVRAM 재설정 중에만 삭제할 수 있습니다.

## NVRAM Entitlements 및 `CS_NVRAM_UNRESTRICTED`

exec 시점에 XNU는 `com.apple.rootless.restricted-nvram-variables.heritable`을 프로세스 플래그 **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`)에 매핑합니다. 이는 일반적인 유효 UID 0 검사와 동일하지 않습니다. 특정 변수나 작업에만 적용되는 더 제한적인 private entitlements도 있습니다.

`codesign`이 출력하는 일반적인 flags 줄에 의존하지 말고 entitlements를 검사하세요:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
권한이 있는 helper를 감사할 때는 **실제 client identity와 request path**를 추적하세요. 권한이 부여된 service의 confused-deputy bug는 `nvram`을 직접 호출하는 것보다 더 유용할 수 있지만, 접근 가능한 variable/operation은 여전히 XNU에 의해 제한될 수 있습니다.

## Intel SIP State와 Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Intel에서 `csr-active-config`는 `CSR_ALLOW_*` 예외를 인코딩합니다. 일반적으로 관련 있는 bit position은 다음과 같습니다:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
`csrutil status`로 적용된 설정을 확인할 수 있습니다. 원시 `nvram` 출력에서는 퍼센트로 인코딩된 little-endian 바이트가 사용될 수 있습니다. 보호 기능 및 bypass 관련 사항은 [macOS SIP](../macos-security-protections/macos-sip.md)를 참조하세요.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: 허용된 boot policy 검사

Apple silicon에서 Secure Enclave가 서명한 `LocalPolicy`의 `sip0`에는 이전에 NVRAM에 저장되었던 SIP policy 비트가 들어 있습니다. 그 외 관련 policy 필드는 `sip1`(SSV root-hash verification failure 허용), `sip2`(CTRR로 kernel memory를 lock하지 않음), `sip3`(iBoot의 `boot-args` allowlist 비활성화)입니다. 이러한 필드는 paired One True recoveryOS(1TR)에서만 변경할 수 있으며, `sip3`를 활성화하려면 Permissive Security로의 downgrade도 필요합니다.<sup>[[4]](#references)</sup>

열거 중에는 display 작업만 사용합니다:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> 감사 중에는 `bputil` policy-changing options를 사용하지 마세요. 일반적인 macOS 침해만으로는 위 필드를 조용히 활성화할 수 없어야 합니다. downgrade 경로에는 의도적으로 paired 1TR에 대한 물리적 접근과 owner authentication이 필요합니다.<sup>[[4]](#references)</sup>

## 보안 영향

### Post-Compromise Amplifier로서의 `boot-args`

kernel-debugging options, `kcsuffix=development` 또는 `amfi_get_out_of_my_way=1`과 같은 인자는 이후 boot stages를 약화할 수 있지만, platform이 이를 허용하는 경우에만 가능합니다. Apple silicon의 Full 또는 Reduced Security에서는 iBoot가 security-reducing arguments를 필터링합니다. unrestricted arguments를 사용하려면 앞서 설명한 `sip3` policy downgrade가 필요합니다. Intel에서는 SIP의 NVRAM restriction 역시 root shell을 자동으로 `boot-args` control 권한으로 간주하지 못하게 합니다.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
See [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) 및 [kernel debugging](macos-kernel-extensions.md)을 참고하여, 과거의 주장이 모든 macOS 릴리스에서 동일하게 동작한다고 가정하지 마세요.

### NVRAM 기반 `rc.trampoline` 실행

최근 연구에서는 NVRAM 데이터의 구체적인 사용 사례가 문서화되었습니다. Apple 플랫폼 바이너리인 `/System/Library/CoreServices/rc.trampoline`이 바로 그 사례입니다. launchd가 `rc.trampoline=1` boot argument를 확인하면, 이 boot task는 `IODeviceTree:/options`에서 `apple-trusted-trampoline` property를 읽어 임시 executable에 기록하고, 이를 suspended 상태로 시작한 뒤 code-signing 상태를 확인하고, 파일을 unlink한 다음 다시 resume합니다. 이 boot task는 child가 종료될 때까지 launchd를 차단합니다.<sup>[[5]](#references)</sup>

이는 **SIP bypass가 아니라 downgrade 이후의 persistence primitive**입니다. 입증된 경로에서는 boot task가 실행되고 `boot-args`를 설정할 수 있도록 SIP가 비활성화되어 있어야 했습니다. 또한 연구에서는 약 390KB의 value-size ceiling이 관찰되었습니다. 이 기법의 가치는 executable bytes를 일반적인 filesystem 외부에 저장하고, attacker가 이미 필요한 security downgrade를 획득한 후 boot 중에 이를 materialize할 수 있다는 점입니다.<sup>[[5]](#references)</sup>

필요한 두 artifact와 launchd event를 모두 탐색하세요:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
임의의 custom NVRAM 변수는 그 외에는 **storage**일 뿐입니다. firmware, Apple boot component 또는 별도의 persistence mechanism이 이를 사용하지 않는 한 아무것도 실행하지 않습니다. 이러한 구분은 `nvram attacker-config=...`와 같은 marker를 firmware code execution으로 과장하는 것을 방지합니다.

## Enumeration Script

<details>
<summary>NVRAM 및 Apple silicon boot-policy 감사</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Apple Platform Security Guide — 부팅 프로세스](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Apple silicon이 탑재된 Mac의 LocalPolicy 파일 내용](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — apple-trusted-trampoline을 사용한 NVRAM을 통한 Persist](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
