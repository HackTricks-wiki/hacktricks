# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext 및 amfid

시스템에서 실행되는 code의 무결성을 강제하는 데 중점을 두며, XNU의 code signature verification 로직을 제공합니다. 또한 entitlements를 확인하고 debugging 허용 또는 task ports 획득과 같은 기타 민감한 작업을 처리할 수 있습니다.

또한 일부 작업의 경우 kext는 user space에서 실행 중인 daemon `/usr/libexec/amfid`에 연락하는 방식을 선호합니다. 이 trust relationship은 여러 jailbreak에서 악용되었습니다.

최근 macOS 버전에서는 AMFI가 더 이상 독립적인 on-disk kext로 편리하게 노출되지 않으므로, reversing은 일반적으로 `/System/Library/Extensions`를 탐색하는 대신 **kernelcache** 또는 **KDK**를 대상으로 수행합니다.

AMFI는 **MACF** policies를 사용하며 시작되는 순간 hooks를 등록합니다. 또한 로딩을 방지하거나 unload하면 kernel panic이 발생할 수 있습니다. 하지만 AMFI를 약화할 수 있는 boot arguments가 있습니다.

- `amfi_unrestricted_task_for_pid`: 필요한 entitlements 없이도 task_for_pid가 허용되도록 함
- `amfi_allow_any_signature`: 모든 code signature 허용
- `cs_enforcement_disable`: 시스템 전체에서 code signing enforcement를 비활성화하는 argument
- `amfi_prevent_old_entitled_platform_binaries`: entitlements가 있는 platform binaries를 무효화
- `amfi_get_out_of_my_way`: amfi를 완전히 비활성화

다음은 AMFI가 등록하는 MACF policies 중 일부입니다:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update가 수행되고 1을 반환
- **`cred_label_associate`**: AMFI의 mac label slot을 label로 업데이트
- **`cred_label_destroy`**: AMFI의 mac label slot 제거
- **`cred_label_init`**: AMFI의 mac label slot에 0 이동
- **`cred_label_update_execve:`**: process의 entitlements를 확인하여 labels를 수정할 수 있는지 확인
- **`file_check_mmap:`**: mmap이 memory를 획득하고 이를 executable로 설정하는지 확인합니다. 이 경우 library validation이 필요한지 확인하고, 필요하면 library validation function을 호출합니다.
- **`file_check_library_validation`**: library validation function을 호출합니다. 이 function은 platform binary가 다른 platform binary를 로드하는지, 또는 process와 새로 로드된 file이 동일한 TeamID를 가지는지 등을 확인합니다. 특정 entitlements가 있으면 모든 library를 로드할 수도 있습니다.
- **`policy_initbsd`**: trusted NVRAM Keys를 설정
- **`policy_syscall`**: binary에 unrestricted segments가 있는지, env vars를 허용해야 하는지와 같은 DYLD policies를 확인합니다. process가 `amfi_check_dyld_policy_self()`를 통해 시작될 때도 호출됩니다.
- **`proc_check_inherit_ipc_ports`**: process가 새 binary를 실행할 때, 해당 process의 task port에 대해 SEND rights를 가진 다른 processes가 이를 계속 유지해야 하는지 확인합니다. Platform binaries, `get-task-allow` entitlement가 있는 경우, `task_for_pid-allow` entitlements가 있는 경우 및 동일한 TeamID를 가진 binaries는 허용됩니다.
- **`proc_check_expose_task`**: entitlements를 강제
- **`amfi_exc_action_check_exception_send`**: debugger로 exception message를 전송
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling(debugging) 중 label lifecycle
- **`proc_check_get_task`**: 다른 processes가 process의 task port를 가져올 수 있도록 하는 `get-task-allow`, process가 다른 processes의 task ports를 가져올 수 있도록 하는 `task_for_pid-allow`와 같은 entitlements를 확인합니다. 둘 다 없으면 `amfid permitunrestricteddebugging`을 호출하여 허용 여부를 확인합니다.
- **`proc_check_mprotect`**: 해당 region을 유효한 code signature가 있는 것처럼 처리해야 함을 나타내는 `VM_PROT_TRUSTED` flag와 함께 `mprotect`가 호출되면 거부
- **`vnode_check_exec`**: executable files가 memory에 로드될 때 호출되며, pages 중 하나라도 유효하지 않게 되면 process를 종료하는 `cs_hard | cs_kill`을 설정합니다<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` 및 `isVnodeQuarantined()`를 확인
- **`vnode_check_setextattr`**: get과 동일하며 `com.apple.private.allow-bless` 및 internal-installer-equivalent entitlement가 필요
- **`vnode_check_signature`**: entitlements, trust cache 및 `amfid`를 사용하여 code signature를 확인하도록 XNU를 호출하는 code<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: `ptrace()` calls(`PT_ATTACH` 및 `PT_TRACE_ME`)를 intercept합니다. `get-task-allow`, `run-invalid-allow`, `run-unsigned-code` entitlements 중 하나라도 있는지 확인하며, 없으면 debugging이 허용되는지 확인합니다.
- **`proc_check_map_anon`**: **`MAP_JIT`** flag와 함께 mmap이 호출되면 AMFI는 `dynamic-codesigning` entitlement를 확인합니다.

`AMFI.kext`는 다른 kernel extensions를 위한 API도 노출하며, 다음 명령으로 dependencies를 찾을 수 있습니다:
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

`AMFI.kext`가 user mode에서 code signature를 확인하는 데 사용하는 user mode daemon입니다.\
`AMFI.kext`가 daemon과 통신하기 위해 port `HOST_AMFID_PORT`를 통한 mach messages를 사용하며, 이는 special port `18`입니다.

macOS에서는 `SIP`에 의해 보호되며 launchd만 가져갈 수 있으므로, 이제 root process가 special ports를 hijack하는 것이 더 이상 불가능하다는 점에 유의해야 합니다. iOS에서는 response를 다시 보내는 process가 `amfid`의 hardcoded CDHash를 가지고 있는지 확인합니다.

`amfid`가 binary 확인을 요청받는 시점과 그 response를 확인하려면 debug하고 `mach_msg`에 breakpoint를 설정하면 됩니다.

special port를 통해 message를 수신하면 **MIG**를 사용하여 각 function을 해당 function으로 전송합니다. 주요 function들은 reverse되어 book 내부에서 설명되어 있습니다.

### DYLD policy 및 library validation

최신 `dyld` versions는 `configureProcessRestrictions()`에서 매우 이른 단계에 `amfi_check_dyld_policy_self()`를 호출하여 process가 `DYLD_*` path variables, interposing, fallback paths, embedded variables를 사용할 수 있는지 또는 failed library insertion을 허용할 수 있는지 AMFI에 질의합니다. 따라서 injection surface를 triage할 때는 Mach-O load commands만 확인하는 것으로 충분하지 않으며, AMFI가 `dyld` policy로 변환할 entitlements와 runtime flags도 확인해야 합니다.

실용적인 triage loop는 다음과 같습니다:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
현대 macOS에서는 많은 Apple 바이너리가 더 이상 `com.apple.security.cs.disable-library-validation`을 직접 포함하지 않고, 대신 `com.apple.private.security.clear-library-validation`을 포함합니다. 이 경우 library validation은 `execve` 시점에 비활성화되지 않습니다. 프로세스가 자체적으로 `csops(..., CS_OPS_CLEAR_LV, ...)`를 호출해야 하며, XNU는 entitlement가 존재할 때만 호출 프로세스에 해당 작업을 허용합니다. Offensive 관점에서 이는 대상이 명시적으로 LV를 지우는 code path에 도달한 **후에만** injection이 가능해질 수 있다는 점에서 중요합니다(예를 들어 optional plugin을 로드하기 직전).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile은 code를 sign하는 데 사용할 수 있습니다. code를 sign하고 테스트하는 데 사용할 수 있는 **Developer** profiles와 모든 device에서 사용할 수 있는 **Enterprise** profiles가 있습니다.

App이 Apple Store에 제출되어 승인되면 Apple이 sign하므로 provisioning profile은 더 이상 필요하지 않습니다.

Profile은 일반적으로 `.mobileprovision` 또는 `.provisionprofile` 확장자를 사용하며 다음 명령으로 dump할 수 있습니다:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
때때로 certificated라고도 불리지만, 이러한 provisioning profile에는 certificate 외에도 다음 정보가 포함되어 있습니다:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Apple Internal profile임을 지정
- **ApplicationIdentifierPrefix**: AppIDName 앞에 추가되는 값(TeamIdentifier와 동일)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 날짜
- **DeveloperCertificates**: Base64 data로 인코딩된 certificate 배열(대개 하나)
- **Entitlements**: 이 profile에서 허용되는 entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 만료 날짜
- **Name**: Application Name이며, AppIDName과 동일
- **ProvisionedDevices**: 이 profile이 유효한 UDID 배열(developer certificate의 경우)
- **ProvisionsAllDevices**: boolean(enterprise certificate의 경우 true)
- **TeamIdentifier**: inter-app interaction 목적으로 developer를 식별하는 데 사용되는 영숫자 문자열 배열(대개 하나)
- **TeamName**: developer를 식별하는 데 사용되는 사람이 읽을 수 있는 이름
- **TimeToLive**: certificate의 유효 기간(일)
- **UUID**: 이 profile의 Universally Unique Identifier
- **Version**: 현재 1로 설정됨

entitlements 항목에는 제한된 entitlements 집합만 포함되며, Apple의 private entitlements가 제공되는 것을 방지하기 위해 provisioning profile은 해당 특정 entitlements만 부여할 수 있다는 점에 유의해야 합니다.

profiles는 일반적으로 `/var/MobileDeviceProvisioningProfiles`에 있으며, **`security cms -D -i /path/to/profile`** 명령으로 확인할 수 있습니다.

## **libmis.dylib**

이는 `amfid`가 어떤 동작을 허용할지 여부를 확인하기 위해 호출하는 external library입니다. 과거 jailbreaking에서 모든 것을 허용하는 backdoored version을 실행하는 방식으로 악용되어 왔습니다.

macOS에서는 `MobileDevice.framework` 내부에 있습니다.

## AMFI Trust Caches

Trust caches는 iOS에만 해당하는 개념이 아닙니다. 최신 macOS, 특히 **Apple silicon**에서는 static trust cache와 loadable trust caches가 Secure Boot chain의 일부입니다. Mach-O의 **CodeDirectory hash**가 해당 cache에 존재하면 AMFI는 launch 시점에 추가 authenticity checks를 수행하지 않고도 해당 파일에 **platform privilege**를 부여할 수 있습니다. 이는 또한 Apple이 platform binaries를 특정 OS version에 고정하고, 이전 Apple-signed binaries가 최신 system에서 replay되는 것을 방지할 수 있음을 의미합니다.<sup>[[6]](#references)</sup>

최근 macOS releases에서는 trust-cache metadata가 **launch constraints**와도 연결되어 있습니다. 따라서 복사된 system apps와 binaries가 잘못된 parent/location에서 시작되면 여전히 Apple-signed 상태이더라도 AMFI에 의해 거부될 수 있습니다. 자세한 extraction 및 reversing workflow는 다음 문서에서 다룹니다:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

iOS 및 jailbreak research에서는 ad-hoc signed binaries를 whitelist하는 데 사용되는 전통적인 **loadable trust caches** 모델도 여전히 확인할 수 있습니다.

## References

- [1] [XNU — `security/mac_policy.h` (AMFI가 등록하는 MACF policy ops 및 `mpo_policy_syscall` 포함)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (AMFI가 설정하는 `CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing 및 validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations 및 `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
