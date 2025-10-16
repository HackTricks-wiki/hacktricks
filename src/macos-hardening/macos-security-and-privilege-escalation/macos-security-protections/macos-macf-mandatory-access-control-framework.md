# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

**MACF** stands for **Mandatory Access Control Framework**, 운영체제에 내장된 보안 시스템으로 컴퓨터를 보호하는 데 도움을 줍니다. 이는 파일, 애플리케이션, 시스템 리소스 등 시스템의 특정 부분에 누가 또는 무엇이 접근할 수 있는지를 규정하는 **엄격한 규칙을 설정**하여 동작합니다. 이러한 규칙을 자동으로 적용함으로써 MACF는 권한이 없는 접근이나 악의적 활동의 위험을 줄여 줍니다.

MACF 자체는 실제로 결정을 내리지는 않고 단지 동작을 **가로채(intercepts)** 하며, 결정은 `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` 및 `mcxalr.kext`와 같이 호출되는 **policy modules**(커널 확장)에 맡깁니다.

- 정책은 enforcing일 수 있음 (어떤 연산에 대해 0이 아닌 값을 반환)
- 정책은 monitoring일 수 있음 (반대하지 않기 위해 0을 반환하지만 훅을 이용해 무언가를 수행)
- MACF static policy는 부팅 시 설치되며 절대 제거되지 않음
- MACF dynamic policy는 KEXT에 의해 설치됨(kextload)이며 가설적으로는 kextunload될 수 있음
- iOS에서는 static policy만 허용되며 macOS에서는 static + dynamic이 허용됨
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)

### 흐름

1. 프로세스가 syscall/mach trap을 수행
2. 관련 함수가 커널 내부에서 호출됨
3. 함수가 MACF를 호출
4. MACF는 그 함수 훅을 요청한 정책 모듈들을 확인
5. MACF가 관련 정책들을 호출
6. 정책들이 해당 동작을 허용할지 거부할지 표시

> [!CAUTION]
> Apple만이 MAC Framework KPI를 사용할 수 있습니다.

보통 MACF로 권한을 확인하는 함수들은 매크로 `MAC_CHECK`를 호출합니다. 예를 들어 소켓을 생성하는 syscall의 경우 `mac_socket_check_create`를 호출하고, 이는 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`를 호출합니다. 또한 매크로 `MAC_CHECK`는 security/mac_internal.h에 다음과 같이 정의되어 있습니다:
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
참고로 `check`을 `socket_check_create`로 바꾸고 `args...`를 `(cred, domain, type, protocol)`로 변환하면 다음과 같습니다:
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
헬퍼 매크로를 확장하면 구체적인 제어 흐름이 표시됩니다:
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
다시 말해, `MAC_CHECK(socket_check_create, ...)`는 먼저 static policies를 순회하고, 조건에 따라 dynamic policies를 잠근 뒤 반복(iterate)하며, 각 hook 주위에 DTrace 프로브를 발생시키고, 각 hook의 반환 코드를 `mac_error_select()`를 통해 단일 `error` 결과로 통합합니다.


### 레이블

MACF는 정책들이 접근 허용 여부를 판단할 때 사용하는 **레이블**을 사용합니다. 레이블 구조체 선언 코드는 [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), 이는 [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)에 있는 **`struct ucred`**의 **`cr_label`** 부분에서 사용됩니다. 레이블은 플래그와 MACF 정책들이 포인터를 할당하는 데 사용할 수 있는 여러 개의 **슬롯**을 포함합니다. 예를 들어 Sanbox는 컨테이너 프로파일을 가리킵니다.

## MACF 정책

MACF Policy는 특정 커널 동작에 적용될 **규칙과 조건**을 정의합니다.

커널 확장(kernel extension)은 `mac_policy_conf` struct를 구성한 다음 `mac_policy_register`를 호출하여 등록할 수 있습니다. 다음은 [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)에서 발췌한 내용입니다:
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
이 정책들을 구성하는 커널 익스텐션은 `mac_policy_register` 호출을 확인하면 쉽게 식별할 수 있다. 또한 익스텐션을 디스어셈블하면 사용된 `mac_policy_conf` struct도 찾을 수 있다.

MACF 정책은 **동적으로** 등록되고 등록 해제될 수 있다는 점에 유의하라.

`mac_policy_conf`의 주요 필드 중 하나는 **`mpc_ops`**이다. 이 필드는 정책이 관심 있는 operations를 지정한다. 수백 개의 항목이 있으므로, 모든 항목을 0으로 초기화한 다음 정책이 필요로 하는 항목만 선택할 수 있다. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
대부분의 훅은 해당 작업들 중 하나가 가로채질 때 MACF에 의해 호출됩니다. 그러나 **`mpo_policy_*`** 훅은 예외인데, `mpo_hook_policy_init()`은 등록 시(즉 `mac_policy_register()` 이후)에 호출되는 콜백이고 `mpo_hook_policy_initbsd()`는 BSD 서브시스템이 제대로 초기화된 이후 늦은 등록 과정에서 호출됩니다.

또한, **`mpo_policy_syscall`** 훅은 어떤 kext라도 등록하여 사설 **ioctl** 스타일 호출 **interface**를 노출할 수 있습니다. 그러면 사용자 클라이언트는 정수 **code**와 선택적 **arguments**와 함께 **policy name**을 파라미터로 지정하여 `mac_syscall` (#381)을 호출할 수 있습니다.\
예를 들어, **`Sandbox.kext`** 가 이를 많이 사용합니다.

kext의 **`__DATA.__const*`**를 검사하면 정책 등록 시 사용된 `mac_policy_ops` 구조체를 식별할 수 있습니다. `mpo_policy_conf` 내부의 오프셋에 포인터가 위치하고, 해당 영역에 들어있는 NULL 포인터의 수로도 찾을 수 있기 때문입니다.

또한 등록된 각 정책마다 갱신되는 struct **`_mac_policy_list`**를 메모리에서 덤프하면 정책을 설정한 kext 목록을 얻을 수 있습니다.

시스템에 등록된 모든 정책을 덤프하려면 `xnoop` 도구를 사용할 수도 있습니다:
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
그런 다음 check policy의 모든 체크 항목을 다음 명령으로 덤프합니다:
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

- MACF는 매우 빨리 초기화됩니다. XNU 시작 코드의 `bootstrap_thread`에서 `ipc_bootstrap` 이후에 XNU는 `mac_policy_init()`을 호출합니다(`mac_base.c` 안).
- `mac_policy_init()`는 전역 `mac_policy_list`(정책 슬롯의 배열 또는 리스트)를 초기화하고 XNU 내에서 MAC(Mandatory Access Control)을 위한 인프라를 설정합니다.
- 이후 `mac_policy_initmach()`가 호출되어 빌트인 또는 번들된 정책들의 커널 쪽 등록을 처리합니다.

### `mac_policy_initmach()`와 loading “security extensions”

- `mac_policy_initmach()`는 사전 로드된(또는 “policy injection” 리스트에 있는) kernel extensions (kexts)을 검사하고 그들의 Info.plist에서 키 `AppleSecurityExtension`을 확인합니다.
- Info.plist에 `<key>AppleSecurityExtension</key>`(또는 `true`)를 선언한 kexts는 “security extensions”로 간주됩니다 — 즉 MAC 정책을 구현하거나 MACF 인프라에 훅을 거는 것들입니다.
- 그 키를 가진 Apple kext의 예로는 **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** 등이 있습니다 (이미 나열하신 바와 같이).
- 커널은 해당 kext들이 조기에 로드되도록 보장한 뒤, 부팅 중에 등록 루틴(`mac_policy_register`를 통해)을 호출하여 `mac_policy_list`에 삽입합니다.

- 각 정책 모듈(kext)은 `mac_policy_conf` 구조체를 제공하며, 다양한 MAC 작업(vnode 체크, exec 체크, 라벨 업데이트 등)을 위한 훅들(`mpc_ops`)을 포함합니다.
- 로드 시 플래그에는 `MPC_LOADTIME_FLAG_NOTLATE`가 포함될 수 있으며, 이는 “조기에 로드되어야 함”을 의미합니다(따라서 늦은 등록 시도는 거부됩니다).
- 등록되면 각 모듈은 핸들을 받고 `mac_policy_list`의 슬롯을 차지합니다.
- 나중에 MAC 훅이 호출되면(예: vnode 접근, exec 등) MACF는 모든 등록된 정책을 순회하여 합의된 결정을 내립니다.

- 특히 **AMFI**(Apple Mobile File Integrity)는 그런 security extension입니다. 그 Info.plist에는 `AppleSecurityExtension`이 포함되어 있어 보안 정책으로 표시됩니다.
- 커널 부팅 과정의 일부로, 커널 로드 로직은 많은 서브시스템이 의존하기 전에 "security policy"(AMFI 등)가 이미 활성화되어 있는지 확인합니다. 예를 들어, 커널은 "앞으로의 작업을 위해 AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine 정책을 포함한 … security policy를 로드함으로써 준비한다"고 합니다.
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
## KPI 의존성 및 com.apple.kpi.dsep (MAC policy kexts에서)

MAC framework를 사용하는 kext를 작성할 때(예: `mac_policy_register()` 등을 호출하는 경우), kext 링커(kxld)가 해당 심볼을 해결할 수 있도록 KPI(Kernel Programming Interfaces)에 대한 의존성을 선언해야 합니다. 따라서 `kext`가 MACF에 의존함을 선언하려면 `Info.plist`에 `com.apple.kpi.dsep`를 명시해야 합니다(`find . Info.plist | grep AppleSecurityExtension`). 그러면 kext는 `mac_policy_register`, `mac_policy_unregister` 및 MAC 훅 함수 포인터 같은 심볼을 참조합니다. 이러한 심볼을 해결하려면 `com.apple.kpi.dsep`를 의존성으로 나열해야 합니다.

예시 Info.plist 스니펫(당신의 .kext 내부):
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

코드 내에서 **`#if CONFIG_MAC`** 같은 조건 블록에서 MACF에 대한 호출을 찾는 경우가 흔합니다. 또한 이러한 블록 안에서는 특정 동작을 수행할 권한을 확인하기 위해 MACF를 호출하는 `mac_proc_check*` 같은 호출을 찾을 수 있습니다. 또한 MACF 호출의 형식은 다음과 같습니다: **`mac_<object>_<opType>_opName`**.

The object is one of the following: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType`은 보통 `check`이며, 이는 동작을 허용하거나 거부하는 데 사용됩니다. 그러나 `notify`를 찾을 수도 있는데, 이는 kext가 해당 동작에 반응하도록 허용합니다.

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

Then, it's possible to find the code of `mac_file_check_mmap` in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Which will go over all the registered mac policies calling their functions and storing the output inside the error variable, which will only be overridable by `mac_error_select` by success codes so if any check fails the complete check will fail and the action won't be allowed.

> [!TIP]
> 하지만 모든 MACF 호출이 동작을 거부하는 데에만 사용되는 것은 아닙니다. 예를 들어, `mac_priv_grant`는 매크로 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)를 호출하는데, 이 매크로는 어떤 정책이라도 0을 반환하면 요청된 privilege를 허용합니다:
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

These callas are meant to check and provide (tens of) **privileges** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
일부 커널 코드는 프로세스의 KAuth 자격증명과 권한 코드 중 하나를 사용해 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c)에 있는 `priv_check_cred()`를 호출하며, 이는 `mac_priv_check`를 호출해 어떤 정책이 권한 부여를 **거부**하는지 확인한 뒤, `mac_priv_grant`를 호출해 어떤 정책이 그 `권한`을 허용하는지 확인합니다.

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
이는 호출 프로세스의 **비트마스크**에서 현재 syscall이 `mac_proc_check_syscall_unix`를 호출해야 하는지 확인한다. 이는 syscalls가 매우 자주 호출되므로 매번 `mac_proc_check_syscall_unix`를 호출하지 않도록 하는 것이 효율적이기 때문이다.

참고로 프로세스의 비트마스크 syscalls를 설정하는 함수 `proc_set_syscall_filter_mask()`는 Sandbox가 샌드박스된 프로세스들에 마스크를 설정하기 위해 호출된다는 점에 유의하라.

## 노출된 MACF syscalls

다음에 정의된 일부 syscalls를 통해 MACF와 상호작용할 수 있다: [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## 참조

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
