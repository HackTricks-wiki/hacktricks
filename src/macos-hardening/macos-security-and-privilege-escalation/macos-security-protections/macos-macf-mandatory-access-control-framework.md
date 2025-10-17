# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

**MACF**는 운영체제에 내장된 보안 시스템인 **Mandatory Access Control Framework(강제 접근 제어 프레임워크)**의 약자입니다. 이 시스템은 파일, 애플리케이션 및 시스템 리소스와 같은 시스템의 특정 부분에 누가 또는 무엇이 접근할 수 있는지에 대한 **엄격한 규칙을 설정**하여 컴퓨터를 보호하는 역할을 합니다. 이러한 규칙을 자동으로 적용함으로써 MACF는 권한이 있는 사용자와 프로세스만 특정 작업을 수행할 수 있도록 하여 무단 접근이나 악의적 활동의 위험을 줄입니다.

MACF는 실제로 결정을 내리지 않고 단순히 동작을 **가로챈다(intercepts)**는 점에 유의하세요. 실제 결정은 `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` 및 `mcxalr.kext`와 같이 호출되는 **policy modules**(kernel extensions)에 의해 내려집니다.

- 정책은 집행할 수 있다 (return 0 non-zero on some operation)
- 정책은 모니터링할 수 있다 (return 0, so as not to object but piggyback on hook to do something)
- MACF static policy는 부팅 시 설치되며 절대 제거되지 않는다
- MACF dynamic policy는 KEXT(kextload)에 의해 설치되며 이론적으로는 kextunloaded될 수 있다
- iOS에서는 static policy만 허용되며 macOS에서는 static + dynamic이 허용된다
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### 흐름

1. 프로세스가 syscall/mach trap을 수행한다
2. 관련 함수가 kernel 내부에서 호출된다
3. 함수가 MACF를 호출한다
4. MACF는 해당 함수에 훅을 요청한 정책 모듈들을 확인한다
5. MACF가 관련 정책들을 호출한다
6. 정책들이 해당 동작을 허용할지 거부할지 표시한다

> [!CAUTION]
> Apple만 MAC Framework KPI를 사용할 수 있습니다.

보통 MACF로 권한을 확인하는 함수들은 매크로 `MAC_CHECK`를 호출합니다. 예를 들어 소켓을 생성하는 syscall의 경우 `mac_socket_check_create`를 호출하고, 이 함수는 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`을 호출합니다. 또한 매크로 `MAC_CHECK`는 security/mac_internal.h에 다음과 같이 정의되어 있습니다:
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
참고로 `check`를 `socket_check_create`로, `args...`를 `(cred, domain, type, protocol)`로 변환하면:
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
도우미 매크로를 확장하면 구체적인 제어 흐름이 나타납니다:
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
다시 말해, `MAC_CHECK(socket_check_create, ...)`는 먼저 정적 정책을 순회하고, 조건적으로 잠금을 설정하여 동적 정책을 반복하며, 각 hook 주위에 DTrace 프로브를 발생시키고, 모든 hook의 반환 코드를 `mac_error_select()`를 통해 단일 `error` 결과로 병합합니다.


### Labels

MACF는 정책이 특정 접근을 허용할지 여부를 검사할 때 사용하는 **labels**를 사용합니다. labels 구조체 선언 코드는 [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), 이는 [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)의 **`struct ucred`** 내부 **`cr_label`** 부분에서 사용됩니다. 라벨은 플래그와 일정 수의 **slots**를 포함하며, 이는 **MACF policies to allocate pointers**가 포인터를 할당하는 데 사용할 수 있습니다. 예를 들어 Sanbox는 컨테이너 프로필을 가리킵니다

## MACF Policies

MACF Policy는 **특정 커널 작업에 적용될 규칙과 조건**을 정의합니다.

커널 확장(kernel extension)은 `mac_policy_conf` struct를 구성한 다음 `mac_policy_register`를 호출하여 등록할 수 있습니다. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered enty point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
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
이 정책들을 구성하는 커널 익스텐션은 `mac_policy_register` 호출을 확인하면 쉽게 식별할 수 있습니다. 또한 익스텐션의 디스어셈블을 확인하면 사용된 `mac_policy_conf` 구조체를 찾을 수 있습니다.

MACF 정책은 **동적으로** 등록 및 등록 해제될 수 있다는 점에 유의하세요.

`mac_policy_conf`의 주요 필드 중 하나는 **`mpc_ops`**입니다. 이 필드는 정책이 관심 있는 연산들을 지정합니다. 수백 개의 연산이 있기 때문에, 모든 항목을 0으로 초기화한 다음 정책이 관심 있는 항목만 선택할 수 있습니다. 자세한 내용은 [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
거의 모든 훅은 해당 작업들 중 하나가 가로채질 때 MACF에 의해 콜백됩니다. 그러나 **`mpo_policy_*`** 훅들은 예외인데, 이는 `mpo_hook_policy_init()`가 등록 시(즉 `mac_policy_register()` 이후) 호출되는 콜백이고 `mpo_hook_policy_initbsd()`는 BSD 서브시스템이 제대로 초기화된 후 늦은 등록 시에 호출되기 때문입니다.

또한, **`mpo_policy_syscall`** 훅은 어떤 kext든 private **ioctl** 스타일 호출 **interface**를 노출하기 위해 등록할 수 있습니다. 그러면 user client는 정수형 **code**와 선택적 **arguments**를 포함해 **policy name**을 파라미터로 지정하여 `mac_syscall` (#381)을 호출할 수 있습니다.\
예를 들어, **`Sandbox.kext`**가 이를 많이 사용합니다.

kext의 **`__DATA.__const*`**를 확인하면 정책을 등록할 때 사용된 `mac_policy_ops` 구조체를 식별할 수 있습니다. 이는 해당 포인터가 `mpo_policy_conf` 내부의 오프셋에 위치해 있고, 그 영역에 존재하는 NULL 포인터의 개수로도 찾을 수 있기 때문입니다.

또한, 등록된 각 정책마다 업데이트되는 구조체 **`_mac_policy_list`**를 메모리에서 덤프하면 정책을 구성한 kext들의 목록을 얻을 수 있습니다.

시스템에 등록된 모든 정책을 덤프하려면 도구 `xnoop`을 사용할 수도 있습니다:
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
그런 다음 check policy의 모든 체크를 다음으로 덤프합니다:
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
## XNU에서의 MACF 초기화

### 초기 부트스트랩과 mac_policy_init()

- MACF는 매우 초기 단계에서 초기화됩니다. XNU 시작 코드의 `bootstrap_thread`에서 `ipc_bootstrap` 이후에 XNU는 `mac_policy_init()`을 호출합니다(`mac_base.c`).
- `mac_policy_init()`은 전역 `mac_policy_list`(정책 슬롯의 배열 또는 리스트)를 초기화하고 XNU 내부에서 MAC(Mandatory Access Control) 인프라를 설정합니다.
- 이후 `mac_policy_initmach()`이 호출되어 내장되거나 번들된 정책들의 커널 측 등록을 처리합니다.

### `mac_policy_initmach()`와 “security extensions” 로딩

- `mac_policy_initmach()`은 사전 로드된(또는 “policy injection” 리스트에 있는) kernel extension(kext)을 검사하고 해당 Info.plist에서 `AppleSecurityExtension` 키를 확인합니다.
- Info.plist에 `<key>AppleSecurityExtension</key>`(또는 `true`)를 선언한 kext들은 “보안 확장”으로 간주됩니다 — 즉 MAC 정책을 구현하거나 MACF 인프라에 훅을 거는 것들입니다.
- 그 키를 포함하는 Apple kext의 예로는 **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** 등이 있습니다(등등).
- 커널은 이러한 kext들이 조기에 로드되도록 보장한 뒤 부팅 중에 이들의 등록 루틴을 호출(`mac_policy_register`를 통해)하여 `mac_policy_list`에 삽입합니다.

- 각 정책 모듈(kext)은 훅들(`mpc_ops`)을 포함한 `mac_policy_conf` 구조체를 제공하며, 이는 다양한 MAC 작업(vnode 검사, exec 검사, 라벨 업데이트 등)을 처리합니다.
- 로드 시 플래그에는 `MPC_LOADTIME_FLAG_NOTLATE`와 같이 “조기에 로드되어야 함”을 의미하는 값이 있을 수 있으며(따라서 늦은 등록 시도가 거부됩니다)...
- 등록이 완료되면 각 모듈은 핸들을 받고 `mac_policy_list`의 슬롯을 차지합니다.
- 이후 MAC 훅(예: vnode 접근, exec 등)이 호출될 때 MACF는 등록된 모든 정책을 순회하여 공동 결정을 내립니다.

- 특히 **AMFI**(Apple Mobile File Integrity)는 이러한 보안 확장 중 하나입니다. 해당 kext의 Info.plist에는 보안 정책임을 표시하는 `AppleSecurityExtension` 키가 포함되어 있습니다.
- 커널 부팅의 일환으로 커널 로드 로직은 많은 서브시스템이 의존하기 전에 “보안 정책”(AMFI 등)이 이미 활성화되어 있도록 보장합니다. 예를 들어 커널은 “앞으로의 작업을 위해 AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine 정책을 포함한 … 보안 정책을 로드함으로써 준비한다”고 합니다.
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
## KPI 종속성 및 MAC 정책 kext에서의 com.apple.kpi.dsep

MAC 프레임워크를 사용하는 kext를 작성할 때(예: `mac_policy_register()` 등 호출), kext 링커(kxld)가 해당 심볼을 해석할 수 있도록 KPI(Kernel Programming Interfaces)에 대한 종속성을 선언해야 합니다. 따라서 `kext`가 MACF에 의존함을 선언하려면 `Info.plist`에 `com.apple.kpi.dsep`를 명시해야 합니다(`find . Info.plist | grep AppleSecurityExtension`). 그러면 kext는 `mac_policy_register`, `mac_policy_unregister` 및 MAC 훅 함수 포인터와 같은 심볼을 참조하게 됩니다. 이러한 심볼을 해결하려면 `com.apple.kpi.dsep`를 종속성으로 나열해야 합니다.

Example Info.plist snippet (inside your .kext):
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
## MACF 호출

코드에서 **`#if CONFIG_MAC`** 같은 조건 블록 안에 MACF에 대한 호출이 정의된 것을 흔히 볼 수 있습니다. 또한, 이러한 블록 내부에서는 특정 작업을 수행할 권한을 확인하기 위해 MACF를 호출하는 `mac_proc_check*` 같은 호출을 찾을 수 있습니다. MACF 호출의 형식은 보통 **`mac_<object>_<opType>_opName`** 입니다.

객체(object)는 다음 중 하나입니다: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType`은 보통 작업을 허용하거나 거부하는 데 사용되는 `check` 입니다. 그러나 주어진 동작에 대해 kext가 반응하도록 허용하는 `notify`를 찾을 수도 있습니다.

You can find an example in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

그 다음 `mac_file_check_mmap`의 코드는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)에서 찾을 수 있습니다.
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
이는 `MAC_CHECK` 매크로를 호출하며, 해당 코드는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)에서 확인할 수 있습니다.
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
이 매크로는 등록된 모든 mac 정책을 순회하면서 각 정책의 함수를 호출하고 그 출력을 error 변수에 저장합니다. 이 error 값은 성공 코드에 의해 `mac_error_select`로만 재정의될 수 있으므로, 어떤 검사라도 실패하면 전체 검사가 실패하고 해당 작업은 허용되지 않습니다.

> [!TIP]
> 하지만 모든 MACF 콜아웃이 동작을 거부하기 위해서만 사용되는 것은 아니라는 점을 기억하세요. 예를 들어, `mac_priv_grant`는 매크로 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)를 호출하는데, 이 매크로는 어떤 정책이라도 0을 반환하면 요청된 권한을 부여합니다:
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

These callas are meant to check and provide (tens of) **권한** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
일부 커널 코드는 프로세스의 KAuth 자격증명과 권한 코드 중 하나를 가지고 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c)의 `priv_check_cred()`를 호출합니다. 이 호출은 `mac_priv_check`를 호출해 어떤 정책이 권한 부여를 **거부**하는지 확인하고, 그 다음 `mac_priv_grant`를 호출해 어떤 정책이 해당 `privilege`를 부여하는지 확인합니다.

### proc_check_syscall_unix

This hook allows to intercept all system calls. In `bsd/dev/[i386|arm]/systemcalls.c` it's possible to see the declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), which contains this code:
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
이는 호출 중인 프로세스의 **bitmask**에서 현재 syscall이 `mac_proc_check_syscall_unix`를 호출해야 하는지를 확인한다. syscalls는 매우 자주 호출되므로 매번 `mac_proc_check_syscall_unix`를 호출하는 것을 피하는 것이 유리하다.

참고로 프로세스의 bitmask syscalls를 설정하는 함수 `proc_set_syscall_filter_mask()`는 Sandbox가 sandboxed processes의 마스크를 설정할 때 호출된다.

## 노출된 MACF syscalls

일부 syscalls를 통해 MACF와 상호작용할 수 있으며, 이는 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151)에 정의되어 있다:
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
## 참고 자료

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
