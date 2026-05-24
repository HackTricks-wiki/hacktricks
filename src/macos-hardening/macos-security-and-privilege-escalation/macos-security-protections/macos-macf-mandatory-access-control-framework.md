# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF**는 **Mandatory Access Control Framework**의 약자로, 운영 체제에 내장된 보안 시스템으로 컴퓨터를 보호하는 데 도움을 줍니다. 이는 **시스템의 특정 부분, 예를 들어 파일, 애플리케이션, 시스템 리소스에 누가 또는 무엇이 접근할 수 있는지에 대해 엄격한 규칙을 설정**하는 방식으로 동작합니다. 이러한 규칙을 자동으로 강제함으로써, MACF는 권한이 있는 사용자와 프로세스만 특정 작업을 수행할 수 있도록 보장하고, 무단 접근이나 악의적인 활동의 위험을 줄입니다.

MACF는 실제로는 어떤 결정을 내리지 않으며, 단지 동작을 **가로채기(intercepts)**만 하고, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` 및 `mcxalr.kext` 같은 **policy modules**(kernel extensions)에 결정을 맡깁니다.

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- A MACF static policy is installed in boot and will NEVER be removed
- A MACF dynamic policy is installed by a KEXT (kextload) and may hypothetically be kextunloaded
- In iOS only static policies are allowed and in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process performs a syscall/mach trap
2. The relevant function is called inside the kernel
3. Function calls MACF
4. MACF checks policy modules that requested to hook that function in their policy
5. MACF calls the relevant policies
6. Policies indicates if they allow or deny the action

> [!CAUTION]
> Apple is the only one that can use the MAC Framework KPI.

Usually the functions checking permissions with MACF will call the macro `MAC_CHECK`. Like in the case of syscall to create a socket which will call the function which `mac_socket_check_create` which calls `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Moreover, the macro `MAC_CHECK` is defined in security/mac_internal.h as:
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
참고로 `check`를 `socket_check_create`로, 그리고 `(cred, domain, type, protocol)`에서 `args...`를 변환하면 다음을 얻습니다:
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
helper macro를 확장하면 구체적인 control flow가 드러난다:
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
In other words, `MAC_CHECK(socket_check_create, ...)`는 먼저 static policies를 훑고, 조건부로 dynamic policies를 lock하고 순회하며, 각 hook 주변에 DTrace probes를 발생시키고, `mac_error_select()`를 통해 각 hook의 return code를 하나의 `error` result로 통합한다.


### Labels

MACF는 **labels**를 사용하며, 정책들은 이 labels를 보고 어떤 access를 허용할지 여부를 판단한다. labels struct 선언 코드는 [여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)에서 찾을 수 있으며, 이 구조체는 **`struct ucred`** 내부의 [**여기**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)의 **`cr_label`** 부분에서 사용된다. label에는 flags와, **MACF policies가 pointers를 할당하는 데 사용할 수 있는** 여러 개의 **slots**를 담는 number가 포함된다. 예를 들어 Sanbox는 container profile을 가리킨다.

## MACF Policies

MACF Policy는 **특정 kernel operations에 적용될 rule과 conditions**를 정의한다.

kernel extension은 `mac_policy_conf` struct를 설정한 뒤 `mac_policy_register`를 호출해 등록할 수 있다. [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)에서:
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
`mac_policy_register` 호출을 확인하면 이러한 정책을 구성하는 커널 확장(kernel extension)을 쉽게 식별할 수 있습니다. 또한 해당 확장을 disassemble해 보면 사용된 `mac_policy_conf` struct도 찾을 수 있습니다.

MACF 정책은 **동적으로** 등록 및 해제될 수도 있다는 점에 주의하세요.

`mac_policy_conf`의 주요 필드 중 하나는 **`mpc_ops`**입니다. 이 필드는 정책이 관심을 가지는 operation을 지정합니다. 이것들은 수백 개나 있으므로, 모두 0으로 만든 다음 정책이 관심 있는 것들만 선택하는 것이 가능합니다. [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)에서:
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
거의 모든 hook은 해당 operation이 intercept될 때 MACF에 의해 callback됩니다. 그러나 **`mpo_policy_*`** hooks는 예외인데, **`mpo_hook_policy_init()`**는 registration 시 호출되는 callback이기 때문입니다(`mac_policy_register()` 이후). 또한 **`mpo_hook_policy_initbsd()`**는 BSD subsystem이 제대로 initialised된 뒤 late registration 동안 호출됩니다.

또한 **`mpo_policy_syscall`** hook은 private **ioctl** 스타일 call **interface**를 노출하기 위해 어떤 kext든 등록할 수 있습니다. 그러면 user client는 integer **code**와 optional **arguments**를 parameter로 지정하여 `mac_syscall` (#381)을 호출할 수 있습니다.\
예를 들어, **`Sandbox.kext`**는 이를 많이 사용합니다.

kext의 **`__DATA.__const*`**를 확인하면 policy를 등록할 때 사용되는 `mac_policy_ops` structure를 식별할 수 있습니다. 그 pointer가 `mpo_policy_conf` 내부의 offset에 있고, 해당 영역에 NULL pointer가 얼마나 들어있는지도 확인할 수 있기 때문에 찾을 수 있습니다.

또한 메모리에서 struct **`_mac_policy_list`**를 덤프하면 policy를 configured한 kext 목록도 얻을 수 있습니다. 이 struct는 등록되는 모든 policy마다 업데이트됩니다.

또한 `xnoop` tool을 사용해 시스템에 등록된 모든 policy를 덤프할 수도 있습니다:
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
그다음 다음과 같이 check policy의 모든 체크를 dump합니다:
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

### 초기 부트스트랩과 `mac_policy_init()`

- MACF는 매우 이른 시점에 초기화된다. `bootstrap_thread`(XNU 시작 코드)에서 `ipc_bootstrap` 이후 XNU는 `mac_policy_init()`(`mac_base.c`에 있음)를 호출한다.
- `mac_policy_init()`는 전역 `mac_policy_list`(policy 슬롯들의 배열 또는 리스트)를 초기화하고, XNU 내 MAC(Mandatory Access Control)을 위한 인프라를 설정한다.
- 이후 `mac_policy_initmach()`가 호출되며, 이는 built-in 또는 bundled policy의 kernel 측 registration을 처리한다.

### `mac_policy_initmach()`와 “security extensions” 로딩

- `mac_policy_initmach()`는 미리 로드된 kernel extensions(kexts) 또는 “policy injection” 리스트에 있는 kexts를 검사하고, `Info.plist`에서 `AppleSecurityExtension` key를 확인한다.
- `Info.plist`에 `<key>AppleSecurityExtension</key>`(또는 `true`)를 선언한 kexts는 “security extensions”로 간주된다. 즉, MAC policy를 구현하거나 MACF infrastructure에 hook되는 것들이다.
- 해당 key를 가진 Apple kexts의 예로는 **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** 등이 있다(이미 나열한 것들).
- kernel은 이 kexts가 early load되도록 보장한 뒤, boot 중에 `mac_policy_register`를 통해 이들의 registration routine을 호출하여 `mac_policy_list`에 삽입한다.

- 각 policy module(kext)는 `mac_policy_conf` structure를 제공하며, 다양한 MAC operation(vnode checks, exec checks, label updates 등)을 위한 hooks(`mpc_ops`)를 포함한다.
- load time flags에는 `MPC_LOADTIME_FLAG_NOTLATE`가 포함될 수 있는데, 이는 “반드시 early에 로드되어야 함”(즉, late registration 시도는 거부됨)을 의미한다.
- 한 번 등록되면 각 module은 handle을 얻고 `mac_policy_list`의 slot을 차지한다.
- 이후 MAC hook이 호출될 때(예: vnode access, exec 등), MACF는 등록된 모든 policy를 순회하며 공동 결정을 내린다.

- 특히 **AMFI**(Apple Mobile File Integrity)는 이러한 security extension이다. 그 `Info.plist`에는 security policy로 표시하는 `AppleSecurityExtension`이 포함된다.
- kernel boot의 일부로, kernel load logic은 많은 subsystem이 의존하기 전에 “security policy”(AMFI 등)가 이미 활성화되도록 보장한다. 예를 들어, kernel은 “AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy를 포함한 security policy를 로드하여 앞으로의 작업을 준비한다.”
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

MAC framework를 사용하는 kext를 작성할 때(`mac_policy_register()` 등을 호출), 해당 심볼을 kext linker(kxld)가 해석할 수 있도록 KPI(Kernel Programming Interfaces)에 대한 의존성을 선언해야 합니다. 따라서 `kext`가 MACF에 의존한다고 선언하려면 `Info.plist`에 `com.apple.kpi.dsep`를 사용해 이를 명시해야 합니다(`find . Info.plist | grep AppleSecurityExtension`). 그러면 kext는 `mac_policy_register`, `mac_policy_unregister`, 그리고 MAC hook 함수 포인터 같은 심볼을 참조하게 됩니다. 이를 해석하려면 `com.apple.kpi.dsep`를 의존성으로 나열해야 합니다.

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
## 최신 macOS 릴리스에서의 MACF

최신 macOS에서 Apple 보안 정책은 보통 느슨하게 분리된 `.kext` 번들로 다루는 방식보다 적합하지 않습니다. **macOS 11**부터는 커널 확장이 **kernel collections**에 연결되며, **Apple Silicon**에서는 별도의 **SystemKC**가 없고, 서드파티 kext는 **Auxiliary Kernel Collection (AuxKC)**에 빌드된 뒤 재부팅해야만 로드 가능합니다. MACF 연구 관점에서 이는 **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust**, **Quarantine** 같은 내장 정책을 `kextstat` 같은 deprecated 도구보다 `kmutil`로 열거하는 것이 보통 더 쉽다는 뜻입니다.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon에서는 security kext가 BootKC에 없으면 다음으로 AuxKC를 확인하세요. 이는 일반적으로 `/System/Library/Extensions` 아래에서 standalone bundle을 찾는 것보다 더 유용합니다.

## MACF Callouts

코드에서 다음과 같은 형태로 MACF에 대한 callout을 찾는 경우가 흔합니다: **`#if CONFIG_MAC`** 조건 블록. 또한 이 블록들 안에서는 특정 작업을 수행할 권한을 **check**하기 위해 MACF를 호출하는 `mac_proc_check*` 호출을 찾을 수 있습니다. 더 나아가, MACF callout의 형식은 **`mac_<object>_<opType>_opName`** 입니다.

object는 다음 중 하나입니다: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType`은 보통 check이며, 이는 동작을 허용하거나 거부하는 데 사용됩니다. 하지만 `notify`도 찾을 수 있는데, 이는 kext가 주어진 동작에 반응할 수 있게 해줍니다.

예시는 다음에서 확인할 수 있습니다: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

그 შემდეგ, 다음에서 `mac_file_check_mmap`의 코드를 찾을 수 있습니다: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
이는 `MAC_CHECK` 매크로를 호출하는 것으로, 해당 코드는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)에서 찾을 수 있다
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
Which will go over all the registered MAC policies calling their functions and storing the output inside the error variable, which will only be overridable by `mac_error_select` by success codes so if any check fails the complete check will fail and the action won't be allowed.

> [!TIP]
> However, remember that not all MACF callouts are used only to deny actions. For example, `mac_priv_grant` calls the macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), which will grant the requested privilege if any policy answers with a 0:
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
>    }); \
> } while (0)
> ```

### priv_check & priv_grant

These callas are meant to check and provide (tens of) **privileges** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Some kernel code would call `priv_check_cred()` from [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) with the KAuth credentials of the process and one of the privileges code which will call `mac_priv_check` to see if any policy **denies** giving the privilege and then it calls `mac_priv_grant` to see if any policy grants the `privilege`.

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
호출하는 프로세스의 **bitmask**를 확인하여 현재 syscall이 `mac_proc_check_syscall_unix`를 호출해야 하는지 검사한다. 이는 syscall이 매우 자주 호출되기 때문에, 매번 `mac_proc_check_syscall_unix`를 호출하는 것을 피하는 것이 중요하기 때문이다.

함수 `proc_set_syscall_filter_mask()`, which set the bitmask syscalls in a process is called by Sandbox to set masks on sandboxed processes.

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151)에 정의된 몇몇 syscall을 통해 MACF와 상호작용할 수 있다:
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
공격적 리버싱에서 **`__mac_syscall`**은 여전히 가장 좋은 userland chokepoint 중 하나이다. 이 함수는 **policy name**(예: `"Sandbox"` 또는 `"AMFI"`), **policy-specific selector/code**, 그리고 `mpo_policy_syscall`에서 처리될 **opaque argument blob**에 대한 포인터를 전달한다. 이는 userland에서 알려지지 않은 작업을 먼저 리버싱한 뒤, 나중에 kernel implementation으로 전환할 때 매우 유용하다. Sandbox는 일반적으로 `__sandbox_ms`를 통해 이 경로에 도달하고, AMFI는 동일한 메커니즘을 dyld policy decision에 사용한다.

## Practical offensive research notes

최근 macOS 버그는 거의 "MACF를 직접 깨는" 방식이 아니다. 대신 보통 **MACF / Sandbox / TCC decision과 그 뒤에 발생하는 privileged action 사이의 desynchronisation**을 악용한다.

### Broker path checks vs real privileged action

반복적으로 보이는 패턴은 privileged daemon이 경로의 한 버전에 대해 **userland pre-check**(예: `sandbox_check_by_audit_token()`)를 수행한 뒤, 나중에 **다른 또는 non-canonical attacker-controlled path**를 사용해 실제 privileged sink를 실행하는 것이다. 최근 `diskarbitrationd` / `storagekitd` 연구가 좋은 예다. **directory traversal**과 **symlink swaps**를 이용해 공격자는 daemon의 sandbox validation을 통과한 다음, `~/Library/Application Support/com.apple.TCC` 같은 민감한 위치 위에 mount할 수 있고, 이로써 취약점은 선택한 mount point에 따라 **sandbox escape**, **local privilege escalation** 또는 **TCC bypass**가 된다.

sandbox에서 도달 가능한 root broker를 감사할 때는 먼저 다음을 grep하라:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`, helper-tool XPC methods 같은 privileged sinks, 또는 나중에 attacker-controlled paths를 root로 건드리는 모든 것

### Trusted deputies with private entitlements

또 다른 실용적 패턴은 MACF hooks를 직접 공격하는 대신, 경계를 넘는 데 필요한 권한을 이미 가진 **trusted process**를 악용하는 것이다. 최근 Safari/TCC 연구가 좋은 예다. 중요한 primitive는 "kernel에서 TCC를 비활성화"하는 것이 아니라, **`com.apple.private.tcc.allow`**를 가진 Apple-signed process가 대신 민감한 작업을 수행하도록 로컬 policy/configuration을 수정하는 것이었다. 실제로 고가치 auditing 대상은 다음을 결합한 Apple daemons/apps이다:

- **private entitlements** 또는 FDA-like reach
- writable config / database / mount point / policy file
- **Sandbox**, **AMFI**, **TCC** 또는 다른 MACF policy에 의해 중재되는 이후의 sensitive operation

더 깊은 product-specific reversing은 [macOS Sandbox](macos-sandbox/README.md)와 [macOS TCC](macos-tcc/README.md) 전용 페이지를 확인하라.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
