# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext 및 amfid

시스템에서 실행되는 code의 무결성을 강제하며, XNU의 code signature verification 로직을 제공합니다. 또한 entitlements를 확인하고 debugging 허용 또는 task ports 획득과 같은 기타 민감한 작업을 처리할 수 있습니다.

또한 일부 작업의 경우 kext는 user space에서 실행 중인 daemon `/usr/libexec/amfid`에 연결하는 것을 선호합니다. 이 trust relationship은 여러 jailbreak에서 악용되었습니다.

최근 macOS 버전에서는 AMFI가 더 이상 독립적인 on-disk kext로 편리하게 노출되지 않으므로, reversing은 일반적으로 `/System/Library/Extensions`를 탐색하는 대신 **kernelcache** 또는 **KDK**를 대상으로 수행합니다.

AMFI는 **MACF** policies를 사용하며 시작되는 즉시 해당 hooks를 등록합니다. 또한 로딩을 방지하거나 unloading하면 kernel panic이 발생할 수 있습니다. 그러나 AMFI를 약화할 수 있는 boot arguments가 있습니다.

- `amfi_unrestricted_task_for_pid`: 필요한 entitlements 없이 task_for_pid가 허용되도록 함
- `amfi_allow_any_signature`: 모든 code signature 허용
- `cs_enforcement_disable`: code signing enforcement를 비활성화하는 system-wide argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements가 있는 platform binaries를 무효화
- `amfi_get_out_of_my_way`: amfi를 완전히 비활성화

다음은 AMFI가 등록하는 MACF policies 중 일부입니다:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update를 수행하고 1을 반환
- **`cred_label_associate`**: AMFI의 mac label slot을 label로 업데이트
- **`cred_label_destroy`**: AMFI의 mac label slot 제거
- **`cred_label_init`**: AMFI의 mac label slot에 0을 이동
- **`cred_label_update_execve`:** process의 entitlements를 확인하여 labels를 수정할 수 있는지 검사
- **`file_check_mmap`:** mmap이 memory를 획득하고 이를 executable로 설정하는지 확인합니다. 이 경우 library validation이 필요한지 확인하고, 필요하면 library validation function을 호출합니다.
- **`file_check_library_validation`**: library validation function을 호출합니다. 이 function은 platform binary가 다른 platform binary를 loading하는지, 또는 process와 새로 loaded된 file이 동일한 TeamID를 가지는지 등을 확인합니다. 특정 entitlements가 있으면 모든 library를 loading할 수도 있습니다.
- **`policy_initbsd`**: trusted NVRAM Keys 설정
- **`policy_syscall`**: binary에 unrestricted segments가 있는지, env vars를 허용해야 하는지 등 DYLD policies를 확인합니다. process가 `amfi_check_dyld_policy_self()`를 통해 시작될 때도 호출됩니다.
- **`proc_check_inherit_ipc_ports`**: process가 새 binary를 execute할 때, process의 task port에 대해 SEND rights를 가진 다른 processes가 해당 rights를 유지해야 하는지 확인합니다. Platform binaries, `get-task-allow` entitlement가 있는 경우, `task_for_pid-allow` entitlements가 있는 경우, 그리고 동일한 TeamID를 가진 binaries는 허용됩니다.
- **`proc_check_expose_task`**: entitlements 강제
- **`amfi_exc_action_check_exception_send`**: debugger로 exception message 전송
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling (debugging) 중 label lifecycle
- **`proc_check_get_task`**: 다른 processes가 process의 task port를 획득할 수 있도록 하는 `get-task-allow` 및 process가 다른 processes의 task ports를 획득할 수 있도록 하는 `task_for_pid-allow`와 같은 entitlements를 확인합니다. 둘 다 없으면 `amfid permitunrestricteddebugging`을 호출하여 허용 여부를 확인합니다.
- **`proc_check_mprotect`**: region이 유효한 code signature를 가진 것처럼 처리되어야 함을 나타내는 `VM_PROT_TRUSTED` flag와 함께 `mprotect`가 호출되면 거부
- **`vnode_check_exec`**: executable files가 memory에 loaded될 때 호출되며 `cs_hard | cs_kill`을 설정합니다. 이 경우 pages 중 하나라도 invalid 상태가 되면 process가 종료됩니다<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` 및 `isVnodeQuarantined()` 확인
- **`vnode_check_setextattr`**: get과 동일하며, `com.apple.private.allow-bless` 및 internal-installer-equivalent entitlement가 필요
- **`vnode_check_signature`**: entitlements, trust cache 및 `amfid`를 사용하여 XNU에 code signature를 확인하도록 호출하는 code<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` calls (`PT_ATTACH` 및 `PT_TRACE_ME`)를 intercept합니다. `get-task-allow`, `run-invalid-allow`, `run-unsigned-code` entitlements 중 하나라도 있는지 확인하며, 없으면 debugging이 허용되는지 확인합니다.
- **`proc_check_map_anon`**: **`MAP_JIT`** flag와 함께 mmap이 호출되면 AMFI는 `dynamic-codesigning` entitlement를 확인합니다.

`AMFI.kext`는 다른 kernel extensions를 위한 API도 expose하며, 다음과 같이 dependencies를 확인할 수 있습니다.
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

이는 `AMFI.kext`가 사용자 모드에서 code signature를 확인하는 데 사용하는 사용자 모드 데몬입니다.\
`AMFI.kext`가 해당 데몬과 통신하기 위해 포트 `HOST_AMFID_PORT`, 즉 특수 포트 `18`을 통해 mach 메시지를 사용합니다.

macOS에서는 이제 root 프로세스가 특수 포트를 hijack할 수 없다는 점에 유의해야 합니다. 특수 포트는 `SIP`로 보호되며 launchd만 이를 가져올 수 있습니다. iOS에서는 응답을 다시 보내는 프로세스가 `amfid`의 CDHash hardcoded 값을 가지고 있는지도 확인합니다.

`amfid`가 바이너리 검사를 요청받는 시점과 그 응답은 이를 debug하고 `mach_msg`에 breakpoint를 설정하여 확인할 수 있습니다.

특수 포트를 통해 메시지가 수신되면 **MIG**가 각 함수를 해당 함수로 전달하는 데 사용됩니다. 주요 함수들은 reverse되어 책 내부에서 설명되어 있습니다.

### DYLD policy 및 library validation

최근 `dyld` 버전은 `configureProcessRestrictions()`에서 매우 이른 단계에 `amfi_check_dyld_policy_self()`를 호출하여 프로세스가 `DYLD_*` path variable, interposing, fallback path, embedded variable을 사용할 수 있는지 또는 실패한 library insertion을 허용할 수 있는지를 AMFI에 질의합니다. 따라서 injection surface를 triage할 때는 Mach-O load command만 확인해서는 충분하지 않습니다. AMFI가 `dyld` policy로 변환할 entitlements와 runtime flag도 확인해야 합니다.

실용적인 triage loop는 다음과 같습니다:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
최신 macOS에서는 많은 Apple 바이너리가 더 이상 `com.apple.security.cs.disable-library-validation`을 직접 포함하지 않고, 대신 `com.apple.private.security.clear-library-validation`을 포함합니다. 이 경우 library validation은 `execve` 시점에 비활성화되지 않습니다. 프로세스는 스스로 `csops(..., CS_OPS_CLEAR_LV, ...)`를 호출해야 하며, XNU는 entitlement가 존재할 때만 호출 중인 프로세스에 해당 작업을 허용합니다. 공격 관점에서 이는 대상이 LV를 명시적으로 해제하는 코드 경로에 도달한 **이후에만** 주입 가능해질 수 있다는 점에서 중요합니다(예: optional plugin을 로드하기 직전).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

provisioning profile은 code 서명에 사용할 수 있습니다. code를 서명하고 테스트하는 데 사용할 수 있는 **Developer** profile과 모든 device에서 사용할 수 있는 **Enterprise** profile이 있습니다.

App이 Apple Store에 제출되어 승인되면 Apple이 서명하므로 provisioning profile은 더 이상 필요하지 않습니다.

profile은 일반적으로 `.mobileprovision` 또는 `.provisionprofile` 확장자를 사용하며 다음 명령으로 dump할 수 있습니다:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
때때로 certificated라고 불리지만, 이러한 provisioning profile에는 인증서 외에도 다음 항목이 포함됩니다:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Apple Internal profile임을 나타냄
- **ApplicationIdentifierPrefix**: AppIDName 앞에 추가됨(TeamIdentifier와 동일)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 생성 날짜
- **DeveloperCertificates**: Base64 데이터로 인코딩된 인증서 배열(일반적으로 하나)
- **Entitlements**: 이 profile에서 허용되는 entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 만료 날짜
- **Name**: Application Name이며, AppIDName과 동일
- **ProvisionedDevices**: 이 profile이 유효한 UDID 배열(developer certificates의 경우)
- **ProvisionsAllDevices**: boolean 값(enterprise certificates의 경우 true)
- **TeamIdentifier**: inter-app interaction 목적으로 developer를 식별하는 데 사용되는 영숫자 문자열 배열(일반적으로 하나)
- **TeamName**: developer를 식별하는 데 사용되는 사람이 읽을 수 있는 이름
- **TimeToLive**: certificate의 유효 기간(일)
- **UUID**: 이 profile의 Universally Unique Identifier
- **Version**: 현재 1로 설정됨

entitlements 항목에는 제한된 entitlements 집합만 포함되며, provisioning profile은 Apple의 private entitlements가 제공되는 것을 방지하기 위해 해당 특정 entitlements만 부여할 수 있습니다.

profile은 일반적으로 `/var/MobileDeviceProvisioningProfiles`에 있으며, **`security cms -D -i /path/to/profile`** 명령으로 확인할 수 있습니다.

## **libmis.dylib**

이는 `amfid`가 어떤 작업을 허용할지 여부를 확인하기 위해 호출하는 external library입니다. 과거 jailbreaking에서 모든 것을 허용하는 backdoored 버전을 실행하는 방식으로 악용되어 왔습니다.

macOS에서는 `MobileDevice.framework` 내부에 있습니다.

## AMFI Trust Caches

Trust caches는 iOS에만 존재하는 개념이 아닙니다. 최신 macOS, 특히 **Apple silicon**에서는 static trust cache와 loadable trust cache가 Secure Boot chain의 일부입니다. Mach-O의 **CodeDirectory hash**가 해당 캐시에 존재하면, AMFI는 실행 시 추가 authenticity checks를 수행하지 않고도 해당 파일에 **platform privilege**를 부여할 수 있습니다. 이는 Apple이 platform binary를 특정 OS version에 고정하고, 이전 Apple-signed binary가 최신 system에서 replay되는 것을 방지할 수 있다는 의미이기도 합니다.<sup>[[6]](#references)</sup>

최근 macOS release에서는 trust-cache metadata가 **launch constraints**에도 연결되어 있으므로, 복사된 system app과 binary는 여전히 Apple-signed 상태이더라도 잘못된 parent/location에서 시작되면 AMFI에 의해 거부될 수 있습니다. 자세한 extraction 및 reversing workflow는 다음 문서에서 다룹니다:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS 및 jailbreak research에서는 ad-hoc signed binary를 whitelist하기 위해 사용되는 전통적인 **loadable trust cache** 모델도 여전히 확인할 수 있습니다.

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
