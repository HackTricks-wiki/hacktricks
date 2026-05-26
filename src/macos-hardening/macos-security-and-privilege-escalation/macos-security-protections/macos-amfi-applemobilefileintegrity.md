# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

이것은 시스템에서 실행 중인 코드의 무결성을 강제하는 데 중점을 두며, XNU의 코드 서명 검증 로직의 기반을 제공합니다. 또한 entitlements를 검사하고, debugging 허용이나 task port 획득 같은 다른 민감한 작업도 처리할 수 있습니다.

또한 일부 작업에서는 kext가 사용자 공간에서 실행 중인 daemon `/usr/libexec/amfid`에 접촉하는 것을 선호합니다. 이 신뢰 관계는 여러 jailbreak에서 악용되었습니다.

최근 macOS 버전에서는 AMFI가 더 이상 디스크 상의 독립적인 kext로 편하게 노출되지 않으므로, 보통 `/System/Library/Extensions`를 살펴보는 대신 **kernelcache** 또는 **KDK**를 기반으로 분석해야 합니다.

AMFI는 **MACF** policies를 사용하며, 시작되는 즉시 hooks를 등록합니다. 또한 로딩을 막거나 unloading하면 kernel panic을 유발할 수 있습니다. 그러나 AMFI를 약화시키는 몇 가지 boot arguments가 있습니다:

- `amfi_unrestricted_task_for_pid`: 필요한 entitlements 없이 task_for_pid를 허용
- `amfi_allow_any_signature`: 모든 code signature 허용
- `cs_enforcement_disable`: code signing enforcement를 시스템 전체에서 비활성화하는 인자
- `amfi_prevent_old_entitled_platform_binaries`: entitlements가 있는 platform binaries를 무효화
- `amfi_get_out_of_my_way`: AMFI를 완전히 비활성화

다음은 AMFI가 등록하는 MACF policies입니다:

- **`cred_check_label_update_execve:`** Label update가 수행되며 1을 반환
- **`cred_label_associate`**: AMFI의 mac label slot을 label로 업데이트
- **`cred_label_destroy`**: AMFI의 mac label slot 제거
- **`cred_label_init`**: AMFI의 mac label slot에 0을 이동
- **`cred_label_update_execve`:** 프로세스의 entitlements를 확인해 labels를 수정하도록 허용되어야 하는지 검사
- **`file_check_mmap`:** mmap이 메모리를 획득해 executable로 설정하는지 검사. 그런 경우 library validation이 필요한지 확인하고, 필요하면 library validation 함수를 호출
- **`file_check_library_validation`**: library validation 함수를 호출하며, 여기서는 platform binary가 다른 platform binary를 로드하는지, 또는 process와 새로 로드된 파일이 같은 TeamID를 가지는지 등을 검사. 특정 entitlements는 어떤 library든 로드할 수 있게 함
- **`policy_initbsd`**: trusted NVRAM Keys를 설정
- **`policy_syscall`**: binary가 unrestricted segments를 가지는지, env vars를 허용해야 하는지 같은 DYLD policies를 검사함. process가 `amfi_check_dyld_policy_self()`를 통해 시작될 때도 호출됨
- **`proc_check_inherit_ipc_ports`**: process가 새 binary를 실행할 때, 해당 process의 task port에 대해 SEND 권한을 가진 다른 process들이 그것을 계속 유지해야 하는지 검사. Platform binaries는 허용되며, `get-task-allow` entitlement가 있으면 허용되고, `task_for_pid-allow` entitles가 있는 경우와 같은 TeamID를 가진 binaries도 허용
- **`proc_check_expose_task`**: entitlements 강제
- **`amfi_exc_action_check_exception_send`**: debugger로 exception message가 전송됨
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling(debugging) 중 label 생명주기
- **`proc_check_get_task`**: 다른 process가 tasks port를 얻도록 허용하는 `get-task-allow`, 그리고 process가 다른 process들의 tasks ports를 얻도록 허용하는 `task_for_pid-allow` 같은 entitlements를 검사. 둘 다 없으면 `amfid permitunrestricteddebugging`까지 올라가 허용 여부를 확인
- **`proc_check_mprotect`**: `mprotect`가 `VM_PROT_TRUSTED` 플래그와 함께 호출되면 거부. 이는 해당 영역이 유효한 code signature를 가진 것처럼 취급되어야 함을 의미
- **`vnode_check_exec`**: 실행 파일이 메모리에 로드될 때 호출되며 `cs_hard | cs_kill`을 설정. 이로 인해 어떤 page라도 무효해지면 process가 종료됨
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` 및 `isVnodeQuarantined()` 확인
- **`vnode_check_setextattr`**: 위와 동일하게 + `com.apple.private.allow-bless` 및 internal-installer-equivalent entitlement
- **`vnode_check_signature`**: entitlements, trust cache, `amfid`를 사용해 XNU가 code signature를 확인하도록 호출하는 코드
- **`proc_check_run_cs_invalid`**: `ptrace()` 호출(`PT_ATTACH` 및 `PT_TRACE_ME`)을 가로챔. `get-task-allow`, `run-invalid-allow`, `run-unsigned-code` 중 어떤 entitlement가 있는지 확인하고, 없으면 debugging이 허용되는지 검사
- **`proc_check_map_anon`**: `mmap`이 **`MAP_JIT`** 플래그와 함께 호출되면, AMFI는 `dynamic-codesigning` entitlement를 검사

`AMFI.kext`는 다른 kernel extensions를 위한 API도 노출하며, 다음으로 그 dependencies를 찾을 수 있습니다:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

이것은 `AMFI.kext`가 user mode에서 code signatures를 확인할 때 사용하는 user mode에서 실행되는 daemon입니다.\
`AMFI.kext`가 daemon과 통신하기 위해 `HOST_AMFID_PORT`라는 special port를 통해 mach messages를 사용하며, 이것은 special port `18`입니다.

macOS에서는 이제 root processes가 special ports를 hijack하는 것이 더 이상 불가능한데, 이는 `SIP`로 보호되며 오직 launchd만 이를 얻을 수 있기 때문입니다. iOS에서는 응답을 되돌려 보내는 process가 `amfid`의 CDHash를 hardcoded로 가지고 있는지 검사합니다.

`amfid`가 binary를 확인하라는 요청을 받는 시점과 그 response를 `mach_msg`에 breakpoint를 설정해 debugging하여 확인할 수 있습니다.

special port를 통해 message를 받으면 **MIG**가 사용되어 각 function을 호출 중인 function으로 보냅니다. 주요 functions는 book 안에서 reverse되고 설명되었습니다.

### DYLD policy and library validation

최근 `dyld` versions는 `configureProcessRestrictions()`에서 매우 이른 시점에 `amfi_check_dyld_policy_self()`를 호출하여, process가 `DYLD_*` path variables, interposing, fallback paths, embedded variables를 사용할 수 있는지, 또는 failed library insertion을 허용할 수 있는지 AMFI에 묻습니다. 따라서 injection surface를 triage할 때는 Mach-O load commands만 검사하는 것으로는 충분하지 않으며, AMFI가 `dyld` policy로 변환할 entitlements와 runtime flags도 검사해야 합니다.

실용적인 triage loop는 다음과 같습니다:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
현대 macOS에서는 많은 Apple 바이너리가 더 이상 `com.apple.security.cs.disable-library-validation`를 직접 포함하지 않고, 대신 `com.apple.private.security.clear-library-validation`을 포함합니다. 이 경우 library validation은 `execve` 시점에 비활성화되지 않습니다: 프로세스는 자기 자신에 대해 `csops(..., CS_OPS_CLEAR_LV, ...)`를 호출해야 하며, XNU는 해당 entitlement가 있을 때만 호출 프로세스에 대해 그 동작을 허용합니다. 공격 관점에서 이는 중요합니다. 왜냐하면 대상이 명시적으로 LV를 해제하는 코드 경로에 도달한 **이후에만** injectable 상태가 될 수 있기 때문입니다(예: optional plugins를 로드하기 직전).

## Provisioning Profiles

provisioning profile은 code를 sign하는 데 사용할 수 있습니다. code를 sign하고 테스트하는 데 사용할 수 있는 **Developer** profile과, 모든 device에서 사용할 수 있는 **Enterprise** profile이 있습니다.

App이 Apple Store에 제출된 후 승인되면 Apple에 의해 signed되고 provisioning profile은 더 이상 필요하지 않습니다.

profile은 보통 `.mobileprovision` 또는 `.provisionprofile` 확장자를 사용하며, 다음과 같이 dump할 수 있습니다:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Although sometimes referred as certificated, these provisioning profiles have more than a certificate:

- **AppIDName:** 애플리케이션 식별자
- **AppleInternalProfile**: 이것이 Apple Internal 프로파일임을 지정
- **ApplicationIdentifierPrefix**: AppIDName 앞에 붙는 접두사 (TeamIdentifier와 동일)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 날짜
- **DeveloperCertificates**: (보통 하나의) certificate 배열, Base64 데이터로 인코딩됨
- **Entitlements**: 이 프로파일에 대해 허용되는 entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 만료 날짜
- **Name**: 애플리케이션 이름, AppIDName과 동일
- **ProvisionedDevices**: 이 프로파일이 유효한 UDID들의 배열 (developer certificates용)
- **ProvisionsAllDevices**: boolean (enterprise certificates에서는 true)
- **TeamIdentifier**: inter-app interaction 용도로 developer를 식별하는 데 사용되는 (보통 하나의) 영숫자 문자열 배열
- **TeamName**: developer를 식별하는 데 사용되는 사람이 읽을 수 있는 이름
- **TimeToLive**: certificate의 유효 기간(일)
- **UUID**: 이 프로파일의 Universally Unique Identifier
- **Version**: 현재 1로 설정됨

entitlements 항목에는 제한된 entitlements 집합이 포함되며, provisioning profile은 Apple private entitlements를 부여하지 않도록 해당 특정 entitlements만 제공할 수 있다.

profiles는 보통 `/var/MobileDeviceProvisioningProfiles`에 위치하며, **`security cms -D -i /path/to/profile`**로 확인할 수 있다

## **libmis.dylib**

이것은 `amfid`가 어떤 것을 허용할지 여부를 묻기 위해 호출하는 외부 library이다. 역사적으로는 backdoored된 버전을 실행하여 모든 것을 허용하게 만드는 방식으로 jailbreak에서 악용되어 왔다.

macOS에서는 이것이 `MobileDevice.framework` 안에 있다.

## AMFI Trust Caches

Trust caches는 iOS만의 개념이 아니다. 최신 macOS, 특히 **Apple silicon**에서는 static trust cache와 loadable trust caches가 Secure Boot chain의 일부다. Mach-O의 **CodeDirectory hash**가 여기에 존재하면, AMFI는 런타임 시 추가 진위 검사를 하지 않고도 launch time에 **platform privilege**를 부여할 수 있다. 이는 Apple이 platform binaries를 특정 OS version에 고정하고, 이전 Apple-signed binaries가 새 시스템에서 재사용(replay)되는 것을 막을 수 있음을 의미한다.

최근 macOS release에서는 trust-cache metadata가 **launch constraints**와도 연결되어 있어, 복사된 system apps와 잘못된 parent/location에서 시작된 binaries는 여전히 Apple-signed 상태라도 AMFI에 의해 거부될 수 있다. 자세한 extraction 및 reversing workflow는 다음에 설명한다:

{{#ref}}
macos-launch-environment-constraints.md
{{endref}}

iOS와 jailbreak research에서는 여전히 **loadable trust caches**를 사용해 ad-hoc signed binaries를 whitelist하는 전통적인 모델을 볼 수 있다.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
