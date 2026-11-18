# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF**는 **Mandatory Access Control Framework**의 약자로, 컴퓨터를 보호하기 위해 운영 체제에 내장된 보안 시스템입니다. 이 시스템은 파일, 애플리케이션, 시스템 리소스 등 시스템의 특정 부분에 누가 또는 무엇이 접근할 수 있는지 **엄격한 규칙을 설정**합니다. 이러한 규칙을 자동으로 적용함으로써 MACF는 승인된 사용자와 프로세스만 특정 작업을 수행하도록 하여 무단 접근이나 악의적인 활동의 위험을 줄입니다.

MACF는 실제로 어떤 판단도 하지 않고 작업을 **가로채기**만 한다는 점에 유의하세요. 판단은 MACF가 호출하는 `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext`, `mcxalr.kext`와 같은 **policy modules**(커널 확장)에 맡깁니다.

- policy는 enforcing 방식일 수 있습니다(일부 작업에서 0이 아닌 값을 반환).
- policy는 monitoring 방식일 수 있습니다(이의를 제기하지 않도록 0을 반환하고, hook을 활용해 다른 작업을 수행).
- MACF static policy는 부팅 시 설치되며 절대 제거되지 않습니다.
- MACF dynamic policy는 KEXT(`kextload`)가 설치하며, 이론상 kextunload로 언로드할 수 있습니다.
- iOS에서는 static policy만 허용되고, macOS에서는 static 및 dynamic policy가 허용됩니다.<sup>[[7]](#references)</sup>

### Flow

1. 프로세스가 syscall/mach trap을 수행합니다.
2. 커널 내부에서 관련 함수가 호출됩니다.
3. 함수가 MACF를 호출합니다.
4. MACF는 해당 함수를 hook하도록 요청한 policy modules를 확인합니다.
5. MACF가 관련 policy를 호출합니다.
6. policy가 해당 작업을 허용할지 거부할지 나타냅니다.

> [!CAUTION]
> Apple만 MAC Framework KPI를 사용할 수 있습니다.

일반적으로 MACF를 사용해 권한을 확인하는 함수는 `MAC_CHECK` 매크로를 호출합니다. 예를 들어 소켓을 생성하는 syscall의 경우 `mac_socket_check_create` 함수를 호출하며, 이 함수는 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`를 호출합니다. 또한 `MAC_CHECK` 매크로는 security/mac_internal.h에서 다음과 같이 정의됩니다:<sup>[[3]](#references)</sup>
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
    error = 0;                                                           \
    MAC_POLICY_ITERATE({                                                 \
	    if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
	            MAC_CHECK_CALL(check, mpc);                          \
	            int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
	            MAC_CHECK_RSLT(check, mpc);                          \
	            error = mac_error_select(__step_err, error);         \
	    }                                                            \
    });                                                                  \
} while (0)
```

`check`를 `socket_check_create`로 변환하고 `(cred, domain, type, protocol)`에서 `args...`를 사용하면 다음을 얻습니다:

```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
    error = 0;                                                           \
    MAC_POLICY_ITERATE({                                                 \
	    if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
	            MAC_CHECK_CALL(socket_check_create, mpc);                          \
	            int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
	            MAC_CHECK_RSLT(socket_check_create, mpc);                          \
	            error = mac_error_select(__step_err, error);         \
	    }                                                            \
    });                                                                  \
} while (0)
```

helper 매크로를 확장하면 구체적인 제어 흐름을 확인할 수 있습니다:

```c
do {                                                // MAC_CHECK
    error = 0;
    do {                                            // MAC_POLICY_ITERATE
        struct mac_policy_conf *mpc;
        u_int i;
        for (i = 0; i < mac_policy_list.staticmax; i++) {
            mpc = mac_policy_list.entries[i].mpc;
            if (mpc == NULL) {
                continue;
            }
            if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
                DTRACE_MACF3(mac__call__socket_check_create,
                    void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
                int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
                DTRACE_MACF2(mac__rslt__socket_check_create,
                    void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
                error = mac_error_select(__step_err, error);
            }
        }
        if (mac_policy_list_conditional_busy() != 0) {
            for (; i <= mac_policy_list.maxindex; i++) {
                mpc = mac_policy_list.entries[i].mpc;
                if (mpc == NULL) {
                    continue;
                }
                if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
                    DTRACE_MACF3(mac__call__socket_check_create,
                        void *, mpc, int, error, int, MAC_ITERATE_CHECK);
                    int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
                    DTRACE_MACF2(mac__rslt__socket_check_create,
                        void *, mpc, int, __step_err);
                    error = mac_error_select(__step_err, error);
                }
            }
            mac_policy_list_unbusy();
        }
    } while (0);
} while (0);
```

다시 말해, `MAC_CHECK(socket_check_create, ...)`는 먼저 정적 정책을 순회하고, 조건에 따라 동적 정책을 잠근 뒤 순회하며, 각 훅 전후에 DTrace probe를 내보내고, `mac_error_select()`를 통해 모든 훅의 반환 코드를 하나의 `error` 결과로 통합합니다.


### Labels

MACF는 **labels**를 사용하며, 정책은 이를 확인해 특정 접근을 허용할지 결정합니다. labels 구조체 선언 코드는 [여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)에 있으며, [여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)의 **`struct ucred`** 내부 **`cr_label`** 부분에서 사용됩니다. label에는 플래그와 **MACF policies가 포인터를 할당하는 데 사용할 수 있는 슬롯**이 여러 개 포함됩니다. 예를 들어, Sandbox는 컨테이너 프로필을 가리킵니다.

## MACF Policies

MACF Policy는 **특정 커널 작업에 적용할 규칙과 조건을 정의합니다**.

커널 확장 프로그램은 `mac_policy_conf` 구조체를 설정한 다음 `mac_policy_register`를 호출해 등록할 수 있습니다. [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)에서 발췌:<sup>[[1]](#references)</sup>

```c
 #define mpc_t	struct mac_policy_conf *

/**
  @brief Mac policy configuration

  This structure specifies the configuration information for a
  MAC policy module.  A policy module developer must supply
  a short unique policy name, a more descriptive full name, a list of label
  namespaces and count, a pointer to the registered entry-point operations,
  any load time flags, and optionally, a pointer to a label slot identifier.

  The Framework will update the runtime flags (mpc_runtime_flags) to
  indicate that the module has been registered.

  If the label slot identifier (mpc_field_off) is NULL, the Framework
  will not provide label storage for the policy.  Otherwise, the
  Framework will store the label location (slot) in this field.

  The mpc_list field is used by the Framework and should not be
  modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
struct mac_policy_conf {
	const char		*mpc_name;		/** policy name */
	const char		*mpc_fullname;		/** full name */
	const char		**mpc_labelnames;	/** managed label namespaces */
	unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
	struct mac_policy_ops	*mpc_ops;		/** operation vector */
	int			 mpc_loadtime_flags;	/** load time flags */
	int			*mpc_field_off;		/** label slot */
	int			 mpc_runtime_flags;	/** run time flags */
	mpc_t			 mpc_list;		/** List reference */
	void			*mpc_data;		/** module data */
};
```

이러한 정책을 설정하는 커널 확장은 `mac_policy_register` 호출을 확인하면 쉽게 식별할 수 있습니다. 또한 확장의 디스어셈블리 코드를 확인하면 사용된 `mac_policy_conf` 구조체도 찾을 수 있습니다.

MACF 정책은 **동적으로** 등록 및 등록 해제할 수도 있습니다.

`mac_policy_conf`의 주요 필드 중 하나는 **`mpc_ops`**입니다. 이 필드는 정책이 어떤 작업에 관심이 있는지 지정합니다. 작업은 수백 가지이므로 모든 항목을 0으로 설정한 다음 정책에 필요한 항목만 선택할 수 있습니다. [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)를 참조하세요:<sup>[[1]](#references)</sup>

```c
struct mac_policy_ops {
	mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
	mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
	mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
	mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
	mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
	mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
	mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
	mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```

거의 모든 hook은 해당 작업 중 하나가 가로채일 때 MACF가 호출합니다. 하지만 **`mpo_policy_*`** hook은 예외입니다. **`mpo_hook_policy_init()`**은 등록 시(즉, `mac_policy_register()` 이후) 호출되는 callback이고, **`mpo_hook_policy_initbsd()`**는 BSD 서브시스템이 제대로 초기화된 뒤 늦은 등록 과정에서 호출됩니다.

또한 **`mpo_policy_syscall`** hook은 어떤 kext든 등록해 전용 **ioctl** 방식의 호출 **인터페이스**를 노출할 수 있습니다. 그러면 user client가 **policy name**과 정수 **code**, 선택적 **arguments**를 매개변수로 지정해 `mac_syscall` (#381)을 호출할 수 있습니다.\
예를 들어 **`Sandbox.kext`**는 이를 자주 사용합니다.

kext의 **`__DATA.__const*`**를 확인하면 policy 등록에 사용되는 `mac_policy_ops` 구조체를 식별할 수 있습니다. 이 구조체의 포인터가 `mpo_policy_conf` 내부의 특정 오프셋에 있고, 해당 영역에 NULL 포인터가 많이 있기 때문에 찾을 수 있습니다.

또한 모든 policy가 등록될 때마다 갱신되는 **`_mac_policy_list`** 구조체를 메모리에서 덤프해 policy를 설정한 kext 목록을 얻을 수도 있습니다.

`xnoop` 도구를 사용해 시스템에 등록된 모든 policy를 덤프할 수도 있습니다:

```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
	0: 0xfffffff044886f18:
		mpc_name: AppleImage4
		mpc_fullName: AppleImage4 hooks
		mpc_ops: mac_policy_ops@0xfffffff044886f68
	1: 0xfffffff0448d7d40:
		mpc_name: AMFI
		mpc_fullName: Apple Mobile File Integrity
		mpc_ops: mac_policy_ops@0xfffffff0448d72c8
	2: 0xfffffff044b0b950:
		mpc_name: Sandbox
		mpc_fullName: Seatbelt sandbox policy
		mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8 
```

그런 다음 다음을 사용해 check policy의 모든 검사 항목을 덤프합니다:

```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```

## XNU에서 MACF 초기화

### 초기 부트스트랩과 mac_policy_init()

- MACF는 매우 이른 시점에 초기화됩니다. XNU 시작 코드의 `bootstrap_thread`에서 `ipc_bootstrap` 이후 XNU는 `mac_policy_init()`(`mac_base.c`에 있음)을 호출합니다.
- `mac_policy_init()`은 전역 `mac_policy_list`(정책 슬롯의 배열 또는 목록)를 초기화하고, XNU 내에서 MAC(Mandatory Access Control) 인프라를 설정합니다.
- 이후 `mac_policy_initmach()`가 호출되어 내장되었거나 번들로 제공되는 정책의 커널 측 등록을 처리합니다.

### `mac_policy_initmach()`와 “보안 확장” 로드

- `mac_policy_initmach()`는 미리 로드되었거나 “정책 주입” 목록에 있는 커널 확장(kext)을 조사하고, 해당 확장의 Info.plist에서 `AppleSecurityExtension` 키를 확인합니다.
- Info.plist에 `<key>AppleSecurityExtension</key>`(또는 `true`)를 선언한 kext는 “보안 확장”으로 간주됩니다. 즉, MAC 정책을 구현하거나 MACF 인프라에 연결되는 확장입니다.
- 이 키를 가진 Apple kext의 예로는 **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** 등이 있습니다(앞서 나열한 것처럼).
- 커널은 해당 kext가 일찍 로드되도록 한 다음, 부팅 중 `mac_policy_register`를 통해 등록 루틴을 호출하여 `mac_policy_list`에 추가합니다.

  - 각 정책 모듈(kext)은 여러 MAC 작업(vnode 검사, exec 검사, 레이블 업데이트 등)에 대한 hook(`mpc_ops`)을 포함하는 `mac_policy_conf` 구조체를 제공합니다.
  - 로드 시점 플래그에는 `MPC_LOADTIME_FLAG_NOTLATE`가 포함될 수 있습니다. 이 플래그는 “일찍 로드되어야 함”을 의미하며, 늦은 등록 시도를 거부합니다.
  - 등록되면 각 모듈은 핸들을 받고 `mac_policy_list`의 슬롯 하나를 차지합니다.
  - 나중에 MAC hook이 호출되면(예: vnode 접근, exec 등) MACF는 등록된 모든 정책을 순회해 종합적인 결정을 내립니다.

- 특히 **AMFI**(Apple Mobile File Integrity)는 이러한 보안 확장입니다. 해당 Info.plist에는 보안 정책임을 나타내는 `AppleSecurityExtension`이 포함되어 있습니다.
- 커널 부팅 과정에서 커널 로드 로직은 여러 하위 시스템이 의존하기 전에 “보안 정책”(AMFI 등)이 이미 활성화되어 있도록 합니다. 예를 들어, 커널은 “AppleMobileFileIntegrity(AMFI), Sandbox, Quarantine 정책을 비롯한 보안 정책을 로드하여 이후 작업에 대비합니다.” 

```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```

## KPI dependency & com.apple.kpi.dsep in MAC policy kexts

MAC framework을 사용하는 kext(예: `mac_policy_register()` 등을 호출하는 kext)를 작성할 때는 kext linker(kxld)가 해당 심볼을 확인할 수 있도록 KPI(Kernel Programming Interfaces)에 대한 dependency를 선언해야 합니다. 따라서 `kext`가 MACF에 dependency가 있음을 선언하려면 `Info.plist`에 `com.apple.kpi.dsep`을 지정해야 합니다(`find . Info.plist | grep AppleSecurityExtension`). 그러면 kext가 `mac_policy_register`, `mac_policy_unregister`, MAC hook function pointer와 같은 심볼을 참조합니다. 이러한 심볼을 확인하려면 `com.apple.kpi.dsep`을 dependency로 나열해야 합니다.

예시 `Info.plist` 스니펫(.kext 내부):

```xml
<key>OSBundleLibraries</key>
<dict>
  <key>com.apple.kpi.dsep</key>
  <string>18.0</string>
  <key>com.apple.kpi.libkern</key>
  <string>18.0</string>
  <key>com.apple.kpi.bsd</key>
  <string>18.0</string>
  <key>com.apple.kpi.mach</key>
  <string>18.0</string>
  … (other kpi dependencies as needed)
</dict>
```



## 최신 macOS 릴리스의 MACF

최신 macOS에서 Apple 보안 정책은 일반적으로 독립된 `.kext` 번들로 느슨하게 분리된 형태라고 보기 어렵습니다. **macOS 11**부터 커널 확장(kext)은 **커널 컬렉션**에 연결됩니다. **Apple Silicon**에는 별도의 **SystemKC**가 없으며, 타사 kext는 **Auxiliary Kernel Collection (AuxKC)**에 빌드하고 재부팅해야만 로드할 수 있습니다. MACF를 조사할 때는 `kextstat` 같은 더 이상 사용되지 않는 도구보다 `kmutil`을 사용해 **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust**, **Quarantine** 등의 기본 제공 정책을 열거하는 편이 일반적으로 더 쉽습니다.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Apple Silicon에서 보안 kext가 BootKC에 없다면 다음으로 AuxKC를 확인하세요. 이는 `/System/Library/Extensions`에서 독립형 번들을 찾는 것보다 대체로 더 유용합니다.

## MACF Callouts

코드에서 **`#if CONFIG_MAC`** 조건부 블록처럼 MACF에 대한 callout을 정의하는 경우를 흔히 볼 수 있습니다. 또한 이러한 블록 안에서는 특정 작업을 수행할 권한을 **확인하기 위해** MACF를 호출하는 `mac_proc_check*` 호출을 찾을 수 있습니다. MACF callout의 형식은 다음과 같습니다: **`mac_<object>_<opType>_opName`**.

object는 다음 중 하나입니다: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType`은 일반적으로 작업을 허용하거나 거부하는 데 사용되는 `check`입니다. 하지만 kext가 지정된 작업에 반응하도록 하는 `notify`도 찾을 수 있습니다.

다음에서 예시를 확인할 수 있습니다: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
			    &maxprot);
			if (error) {
				(void)vnode_put(vp);
				goto bad;
			}
#endif /* MAC */
[...]
</code></pre>

그런 다음 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)에서 `mac_file_check_mmap`의 코드를 확인할 수 있습니다.

```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
    int flags, uint64_t offset, int *maxprot)
{
	int error;
	int maxp;

	maxp = *maxprot;
	MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
	if ((maxp | *maxprot) != *maxprot) {
		panic("file_check_mmap increased max protections");
	}
	*maxprot = maxp;
	return error;
}
```

이는 `MAC_CHECK` 매크로를 호출하며, 해당 코드는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>에서 확인할 수 있습니다.

```c
/*
 * MAC_CHECK performs the designated check by walking the policy
 * module list and checking with each as to how it feels about the
 * request.  Note that it returns its value via 'error' in the scope
 * of the caller.
 */
#define MAC_CHECK(check, args...) do {                              \
    error = 0;                                                      \
    MAC_POLICY_ITERATE({                                            \
	    if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
	            DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
	            int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
	            DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
	            error = mac_error_select(__step_err, error);         \
	    }                                                           \
    });                                                             \
} while (0)
```

등록된 정책을 순회하고 `mac_error_select()`를 사용해 결과를 결합합니다. 이후 검사에서 0을 반환해도 이전의 거부를 무효화할 수 없습니다. 여러 정책이 거부하면 함수는 우선순위에 따라 오류를 선택합니다(예: `EACCES`가 `EPERM`보다 우선).<sup>[[2]](#references)</sup>

> [!TIP]
> 하지만 모든 MACF callout이 동작을 거부하는 데만 사용되는 것은 아니라는 점을 기억하세요. 예를 들어 `mac_priv_grant`는 매크로 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)를 호출하며, 정책 중 하나라도 0으로 응답하면 요청된 권한을 부여합니다.
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

이 호출은 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h)에 정의된 수십 개의 **권한**을 확인하고 부여하기 위한 것입니다.\
일부 커널 코드는 프로세스의 KAuth credentials와 권한 코드 중 하나를 사용해 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c)의 `priv_check_cred()`를 호출합니다. 이 함수는 `mac_priv_check`를 호출해 어떤 정책이 권한 부여를 **거부**하는지 확인한 다음, `mac_priv_grant`를 호출해 어떤 정책이 해당 `privilege`를 부여하는지 확인합니다.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

이 훅을 사용하면 모든 시스템 호출을 가로챌 수 있습니다. `bsd/dev/[i386|arm]/systemcalls.c`에서 다음 코드가 포함된 선언된 함수 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)을 확인할 수 있습니다:

```c
#if CONFIG_MACF
	if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
		error = mac_proc_check_syscall_unix(proc, syscode);
		if (error) {
			goto skip_syscall;
		}
	}
#endif /* CONFIG_MACF */
```

호출 프로세스의 **비트마스크**를 확인하여 현재 syscall이 `mac_proc_check_syscall_unix`를 호출해야 하는지 판단합니다. syscall은 매우 자주 호출되므로 매번 `mac_proc_check_syscall_unix`를 호출하지 않도록 하는 것이 좋습니다.

프로세스의 syscall 비트마스크를 설정하는 함수 `proc_set_syscall_filter_mask()`는 Sandbox가 sandboxed process에 마스크를 설정할 때 호출됩니다.

## 노출된 MACF 시스템 호출

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151)에 정의된 일부 syscall을 통해 MACF와 상호작용할 수 있습니다:

```c
/*
 * Extended non-POSIX.1e interfaces that offer additional services
 * available from the userland and kernel MAC frameworks.
 */
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
    struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```

For offensive reversing에서 **`__mac_syscall`**은 여전히 userland에서 가장 중요한 chokepoint 중 하나입니다. 이 함수는 **policy name**(예: `"Sandbox"` 또는 `"AMFI"`), **policy별 selector/code**, 그리고 `mpo_policy_syscall`에서 처리할 **opaque argument blob**의 포인터를 전달합니다. userland에서 먼저 문서화되지 않은 작업을 reverse engineering한 뒤, kernel 구현으로 넘어갈 때 매우 유용합니다. Sandbox는 흔히 `__sandbox_ms`를 통해 이 함수에 도달하며, AMFI는 dyld policy 결정을 위해 같은 메커니즘을 사용합니다.<sup>[[2]](#references)[[5]](#references)</sup>

## 실전 offensive research 참고 사항

최근 macOS 버그는 MACF 자체를 직접 "무력화"하는 경우가 드뭅니다. 대신 대개 **MACF / Sandbox / TCC의 결정과 이후 발생하는 privileged action 사이의 desynchronisation**을 악용합니다.

### MACF 입력으로 사용되는 policy별 spawn 속성

`posix_spawnattr_setmacpolicyinfo_np()`는 policy name과 opaque bytes를 `posix_spawn()` 요청에 첨부합니다. XNU는 등록된 각 policy의 `mpc_name`을 기준으로 해당 bytes를 조회해 그 policy의 exec-label hook에 전달하며, launch-constraints hook도 일치하는 bytes를 읽습니다. 이는 `__mac_syscall`과는 별개인, 공격자가 제어하는 MACF 입력 경로입니다. 해당 policy가 이 bytes를 *추가적인 제한*으로 취급하는지, 아니면 부모 또는 executable에 적용된 기존 policy를 대체하도록 허용하는지 확인하세요.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

통제된 테스트를 하려면 제한된 parent에서 시작해 동일한 child를 policy별 속성 **없이** 그리고 **포함해** spawn하세요. 그런 다음 parent가 사용할 수 없는 resource에 대한 child의 유효 접근 권한을 비교하세요. spawn에 성공했다는 사실만으로 경계를 넘었다고 입증되는 것은 아닙니다.<sup>[[12]](#references)[[13]](#references)</sup>

policy를 reverse engineering할 때는 `mpo_cred_label_update_execve`와 `mpo_proc_check_launch_constraints`를 추적한 다음, 호출자가 해당 속성을 전달할 수 있는지 확인하세요.<sup>[[10]](#references)[[11]](#references)</sup> AMFI는 과거에 내장된 launch constraints 대신 전달된 launch constraints를 허용했습니다. Sandbox는 부모의 제한을 유지하는 대신, 이름으로 지정된 내장 profile을 child에 적용할 수 있었습니다.<sup>[[13]](#references)[[12]](#references)</sup> 두 동작 모두 패치되었으므로 현재 시스템에서도 여전히 가능하다고 가정하지 마세요.<sup>[[13]](#references)[[12]](#references)</sup>

AMFI 사례는 [launch-constraints 분석](macos-launch-environment-constraints.md)을, child의 유효 policy를 테스트하려면 [Sandbox debugging](macos-sandbox/macos-sandbox-debug-and-bypass/)을 참고하세요.

### Broker의 경로 검사와 실제 privileged action

반복해서 나타나는 패턴은 privileged daemon이 한 경로를 대상으로 **userland 사전 검사**(예: `sandbox_check_by_audit_token()`)를 수행한 뒤, 나중에 **다르거나 canonical form이 아닌 공격자 제어 경로**를 사용해 실제 privileged sink를 실행하는 것입니다. 최근 `diskarbitrationd` / `storagekitd` 연구가 좋은 예입니다. **directory traversal**과 **symlink swap**을 이용하면 공격자가 daemon의 sandbox 검증을 통과한 뒤 `~/Library/Application Support/com.apple.TCC` 같은 민감한 위치에 mount할 수 있습니다. 선택한 mount point에 따라 이 버그는 **sandbox escape**, **local privilege escalation** 또는 **TCC bypass**로 이어질 수 있습니다.<sup>[[6]](#references)</sup>

sandbox에서 접근할 수 있는 root broker를 감사할 때는 먼저 다음 항목을 grep하세요.

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, 경로 canonicalisation helper
- `mount`, `rename`, `copyfile`, helper-tool XPC method처럼 privileged sink이거나, 이후 root 권한으로 공격자가 제어하는 경로에 접근하는 항목

### private entitlement를 가진 trusted deputy

또 다른 실전 패턴은 MACF hook을 직접 공격하는 대신, 경계를 넘는 데 필요한 권한을 이미 가진 **trusted process**를 악용하는 것입니다. 최근 Safari/TCC 연구가 좋은 예입니다. 핵심 primitive는 "kernel에서 TCC를 비활성화"하는 것이 아니라, 로컬 policy/configuration을 수정해 **`com.apple.private.tcc.allow`**를 가진 Apple 서명 process가 공격자를 대신해 민감한 작업을 수행하도록 하는 것이었습니다.<sup>[[8]](#references)</sup> 실전에서는 다음 조건을 함께 갖춘 Apple daemon/app이 우선 감사 대상입니다.

- **private entitlement** 또는 FDA에 준하는 접근 권한
- 쓰기 가능한 config / database / mount point / policy file
- 이후 **Sandbox**, **AMFI**, **TCC** 또는 다른 MACF policy의 통제를 받는 민감한 작업

제품별 reverse engineering을 더 깊이 진행하려면 [macOS Sandbox](macos-sandbox/README.md) 및 [macOS TCC](macos-tcc/README.md) 전용 페이지를 참고하세요.



## References

- [1] [XNU — `security/mac_policy.h` (전체 MACF policy operations vector)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` 매크로)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (`priv_check`/`priv_grant`에서 사용하는 privilege code)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple 취약점 발견: diskarbitrationd 및 storagekitd 감사 파트 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference 도구](https://newosxbook.com/xxr/index.php)
- [8] [새로운 macOS 취약점 "HM Surf", 무단 데이터 접근으로 이어질 수 있어 (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — posix_spawn policy 속성 setter](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — policy별 exec-label 속성 dispatch](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — launch-constraints policy dispatch](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Executable을 Spawn해 Apple Sandbox 탈출하기](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [macOS에서 Launch Constraints 우회하기](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
