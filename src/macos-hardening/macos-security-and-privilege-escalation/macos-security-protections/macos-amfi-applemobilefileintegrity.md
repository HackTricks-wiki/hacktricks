# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext 및 amfid

시스템에서 실행되는 코드의 무결성을 보장하는 데 중점을 두며, XNU의 코드 서명 검증 뒤에 있는 논리를 제공합니다. 또한 권한을 확인하고 디버깅 허용 또는 작업 포트 획득과 같은 다른 민감한 작업을 처리할 수 있습니다.

게다가, 일부 작업의 경우 kext는 사용자 공간에서 실행되는 데몬 `/usr/libexec/amfid`에 연락하는 것을 선호합니다. 이 신뢰 관계는 여러 탈옥에서 악용되었습니다.

AMFI는 **MACF** 정책을 사용하며 시작되는 순간 후크를 등록합니다. 또한, 이를 로드하거나 언로드하는 것을 방지하면 커널 패닉이 발생할 수 있습니다. 그러나 AMFI를 약화시키는 몇 가지 부팅 인수가 있습니다:

- `amfi_unrestricted_task_for_pid`: 필요한 권한 없이 task_for_pid를 허용
- `amfi_allow_any_signature`: 모든 코드 서명을 허용
- `cs_enforcement_disable`: 코드 서명 집행을 비활성화하는 시스템 전체 인수
- `amfi_prevent_old_entitled_platform_binaries`: 권한이 있는 플랫폼 바이너리를 무효화
- `amfi_get_out_of_my_way`: amfi를 완전히 비활성화

다음은 등록되는 MACF 정책 중 일부입니다:

- **`cred_check_label_update_execve:`** 레이블 업데이트가 수행되며 1을 반환
- **`cred_label_associate`**: AMFI의 mac 레이블 슬롯을 레이블로 업데이트
- **`cred_label_destroy`**: AMFI의 mac 레이블 슬롯 제거
- **`cred_label_init`**: AMFI의 mac 레이블 슬롯에 0 이동
- **`cred_label_update_execve`:** 프로세스의 권한을 확인하여 레이블을 수정할 수 있는지 확인합니다.
- **`file_check_mmap`:** mmap이 메모리를 획득하고 이를 실행 가능으로 설정하는지 확인합니다. 이 경우 라이브러리 검증이 필요한지 확인하고, 필요하다면 라이브러리 검증 함수를 호출합니다.
- **`file_check_library_validation`**: 라이브러리 검증 함수를 호출하여 플랫폼 바이너리가 다른 플랫폼 바이너리를 로드하는지 또는 프로세스와 새로 로드된 파일이 동일한 TeamID를 가지고 있는지 확인합니다. 특정 권한은 모든 라이브러리를 로드할 수 있도록 허용합니다.
- **`policy_initbsd`**: 신뢰할 수 있는 NVRAM 키 설정
- **`policy_syscall`**: 바이너리에 제한 없는 세그먼트가 있는지, env 변수를 허용해야 하는지와 같은 DYLD 정책을 확인합니다... 이는 `amfi_check_dyld_policy_self()`를 통해 프로세스가 시작될 때도 호출됩니다.
- **`proc_check_inherit_ipc_ports`**: 프로세스가 새 바이너리를 실행할 때 다른 프로세스가 프로세스의 작업 포트에 대한 SEND 권한을 유지해야 하는지 확인합니다. 플랫폼 바이너리는 허용되며, `get-task-allow` 권한이 이를 허용하고, `task_for_pid-allow` 권한이 허용되며 동일한 TeamID를 가진 바이너리도 허용됩니다.
- **`proc_check_expose_task`**: 권한 집행
- **`amfi_exc_action_check_exception_send`**: 예외 메시지가 디버거에 전송됩니다.
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: 예외 처리(디버깅) 중 레이블 생명주기
- **`proc_check_get_task`**: `get-task-allow`와 같은 권한을 확인하여 다른 프로세스가 작업 포트를 가져오고 `task_for_pid-allow`가 프로세스가 다른 프로세스의 작업 포트를 가져올 수 있도록 허용하는지 확인합니다. 둘 다 해당되지 않으면 `amfid permitunrestricteddebugging`에 호출하여 허용되는지 확인합니다.
- **`proc_check_mprotect`**: `mprotect`가 `VM_PROT_TRUSTED` 플래그와 함께 호출되면 거부합니다. 이는 해당 영역이 유효한 코드 서명이 있는 것처럼 처리되어야 함을 나타냅니다.
- **`vnode_check_exec`**: 실행 파일이 메모리에 로드될 때 호출되며, `cs_hard | cs_kill`을 설정하여 페이지가 무효화되면 프로세스를 종료합니다.
- **`vnode_check_getextattr`**: MacOS: `com.apple.root.installed` 및 `isVnodeQuarantined()` 확인
- **`vnode_check_setextattr`**: get + com.apple.private.allow-bless 및 내부 설치자 동등 권한
- **`vnode_check_signature`**: 권한, 신뢰 캐시 및 `amfid`를 사용하여 코드 서명을 확인하기 위해 XNU를 호출하는 코드
- **`proc_check_run_cs_invalid`**: `ptrace()` 호출(`PT_ATTACH` 및 `PT_TRACE_ME`)을 가로챕니다. `get-task-allow`, `run-invalid-allow` 및 `run-unsigned-code`와 같은 권한을 확인하고, 없으면 디버깅이 허용되는지 확인합니다.
- **`proc_check_map_anon`**: mmap이 **`MAP_JIT`** 플래그와 함께 호출되면 AMFI는 `dynamic-codesigning` 권한을 확인합니다.

`AMFI.kext`는 다른 커널 확장을 위한 API도 노출하며, 다음을 통해 종속성을 찾을 수 있습니다:
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

이것은 `AMFI.kext`가 사용자 모드에서 코드 서명을 확인하는 데 사용할 사용자 모드 실행 데몬입니다.\
`AMFI.kext`가 데몬과 통신하기 위해 `HOST_AMFID_PORT`라는 특별한 포트 `18`를 통해 mach 메시지를 사용합니다.

macOS에서는 루트 프로세스가 특별한 포트를 가로채는 것이 더 이상 불가능하다는 점에 유의해야 합니다. 이는 `SIP`에 의해 보호되며 오직 launchd만이 이를 얻을 수 있습니다. iOS에서는 응답을 다시 보내는 프로세스가 `amfid`의 CDHash가 하드코딩되어 있는지 확인합니다.

`amfid`가 이진 파일을 확인하도록 요청될 때와 그 응답을 볼 수 있으며, 이를 디버깅하고 `mach_msg`에 중단점을 설정하여 확인할 수 있습니다.

특별한 포트를 통해 메시지가 수신되면 **MIG**가 호출하는 함수에 각 함수를 전송하는 데 사용됩니다. 주요 함수는 리버스 엔지니어링되어 책 안에서 설명되었습니다.

## Provisioning Profiles

프로비저닝 프로파일은 코드를 서명하는 데 사용할 수 있습니다. 코드 서명 및 테스트에 사용할 수 있는 **Developer** 프로파일과 모든 장치에서 사용할 수 있는 **Enterprise** 프로파일이 있습니다.

앱이 Apple Store에 제출된 후 승인되면 Apple에 의해 서명되며 더 이상 프로비저닝 프로파일이 필요하지 않습니다.

프로파일은 일반적으로 `.mobileprovision` 또는 `.provisionprofile` 확장자를 사용하며, 다음과 같이 덤프할 수 있습니다:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
비록 때때로 인증서(certificated)라고 불리지만, 이러한 프로비저닝 프로파일은 인증서 이상의 내용을 포함합니다:

- **AppIDName:** 애플리케이션 식별자
- **AppleInternalProfile**: 이를 Apple 내부 프로파일로 지정
- **ApplicationIdentifierPrefix**: AppIDName 앞에 추가됨 (TeamIdentifier와 동일)
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 날짜
- **DeveloperCertificates**: Base64 데이터로 인코딩된 (보통 하나의) 인증서 배열
- **Entitlements**: 이 프로파일에 허용된 권한
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 형식의 만료 날짜
- **Name**: 애플리케이션 이름, AppIDName과 동일
- **ProvisionedDevices**: 이 프로파일이 유효한 UDID의 배열 (개발자 인증서용)
- **ProvisionsAllDevices**: 불리언 (기업 인증서의 경우 true)
- **TeamIdentifier**: 인터 앱 상호작용 목적을 위해 개발자를 식별하는 데 사용되는 (보통 하나의) 알파벳 숫자 문자열 배열
- **TeamName**: 개발자를 식별하는 데 사용되는 사람이 읽을 수 있는 이름
- **TimeToLive**: 인증서의 유효 기간 (일 단위)
- **UUID**: 이 프로파일의 범용 고유 식별자
- **Version**: 현재 1로 설정됨

권한 항목은 제한된 권한 집합을 포함하며, 프로비저닝 프로파일은 Apple의 개인 권한을 부여하지 않도록 특정 권한만 부여할 수 있습니다.

프로파일은 일반적으로 `/var/MobileDeviceProvisioningProfiles`에 위치하며, **`security cms -D -i /path/to/profile`** 명령어로 확인할 수 있습니다.

## **libmis.dyld**

이는 `amfid`가 무언가를 허용해야 하는지 여부를 묻기 위해 호출하는 외부 라이브러리입니다. 이는 역사적으로 탈옥(jailbreaking)에서 모든 것을 허용하는 백도어 버전을 실행하여 남용되었습니다.

macOS에서는 `MobileDevice.framework` 내부에 있습니다.

## AMFI 신뢰 캐시

iOS AMFI는 **신뢰 캐시(Trust Cache)**라고 불리는, 임의로 서명된 알려진 해시 목록을 유지하며, 이는 kext의 `__TEXT.__const` 섹션에 있습니다. 매우 특정하고 민감한 작업에서는 외부 파일로 이 신뢰 캐시를 확장할 수 있습니다.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
