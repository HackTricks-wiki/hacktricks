# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF**는 **Mandatory Access Control Framework**의 약자로, 운영 체제에 내장된 보안 시스템으로 컴퓨터를 보호하는 데 도움을 줍니다. 이는 시스템의 특정 부분, 예를 들어 파일, 애플리케이션, 시스템 리소스에 누가 또는 무엇이 접근할 수 있는지에 대해 **엄격한 규칙을 설정**하는 방식으로 작동합니다. 이러한 규칙을 자동으로 강제함으로써 MACF는 승인된 사용자와 프로세스만 특정 동작을 수행할 수 있게 하여, 무단 접근이나 악의적 활동의 위험을 줄입니다.

MACF는 실제로 어떤 결정을 내리지는 않으며, 단지 동작을 **가로채기**만 합니다. 결정은 `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext`, `mcxalr.kext` 같은 **policy modules**(kernel extensions)에게 맡깁니다.

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
`check`를 `socket_check_create`로, 그리고 `(cred, domain, type, protocol)`의 `args...`로 변환하면 다음을 얻습니다:
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
헬퍼 매크로를 확장하면 구체적인 제어 흐름이 드러난다:
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
In other words, `MAC_CHECK(socket_check_create, ...)`는 먼저 static policies를 훑고, 필요에 따라 dynamic policies를 lock한 뒤 순회하며, 각 hook 주변에 DTrace probes를 발생시키고, 모든 hook의 return code를 `mac_error_select()`를 통해 하나의 `error` 결과로 합칩니다.


### Labels

MACF는 **labels**를 사용하며, 이후 접근을 허용할지 여부를 검사하는 policies가 이를 사용합니다. labels struct 선언의 코드는 [여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)에서 찾을 수 있으며, 이는 **`cr_label`** 부분의 **`struct ucred`** 내부에서 [여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) 사용됩니다. label에는 flags와, **MACF policies가 pointers를 할당하는 데 사용할 수 있는** 여러 개의 **slots**가 들어 있습니다. 예를 들어 Sanbox는 container profile을 가리킵니다

## MACF Policies

MACF Policy는 **특정 kernel operations에 적용될 rule과 conditions**를 정의합니다.

kernel extension은 `mac_policy_conf` struct를 구성한 뒤 `mac_policy_register`를 호출해 등록할 수 있습니다. [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)에서:
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
`mac_policy_register` 호출을 확인하면 이러한 정책을 구성하는 커널 확장을 쉽게 식별할 수 있다. 또한 확장의 disassemble을 확인하면 사용된 `mac_policy_conf` struct도 찾을 수 있다.

MACF 정책은 **동적으로** 등록 및 등록 해제될 수도 있다는 점에 주의하라.

`mac_policy_conf`의 주요 필드 중 하나는 **`mpc_ops`**이다. 이 필드는 정책이 관심을 갖는 opreations를 지정한다. 수백 개가 있으므로, 모두 0으로 만든 다음 정책이 관심 있는 것만 선택할 수 있다. [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)에서:
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
거의 모든 hooks는 해당 작업 중 하나가 가로채질 때 MACF에 의해 다시 호출됩니다. 그러나 **`mpo_policy_*`** hooks는 예외입니다. `mpo_hook_policy_init()`은 등록 시 호출되는 callback이므로(`mac_policy_register()` 이후) 예외이며, `mpo_hook_policy_initbsd()`는 BSD subsystem이 제대로 초기화된 뒤 늦은 등록(late registration) 단계에서 호출됩니다.

또한, **`mpo_policy_syscall`** hook은 어떤 kext라도 private **ioctl** 스타일 호출 **interface**를 노출하기 위해 등록할 수 있습니다. 그러면 user client는 **policy name**과 정수 **code**, 그리고 선택적 **arguments**를 파라미터로 지정하여 `mac_syscall` (#381)을 호출할 수 있습니다.\
예를 들어, **`Sandbox.kext`**는 이를 매우 많이 사용합니다.

kext의 **`__DATA.__const*`**를 확인하면 정책을 등록할 때 사용되는 `mac_policy_ops` 구조체를 식별할 수 있습니다. 이것은 `mpo_policy_conf` 내부의 오프셋에 포인터가 있고, 해당 영역에 NULL 포인터가 많이 존재하기 때문에 찾을 수 있습니다.

또한, 메모리에서 struct **`_mac_policy_list`**를 덤프하면 policy를 설정한 kext 목록도 얻을 수 있습니다. 이 구조체는 등록되는 모든 policy마다 업데이트됩니다.

또한 `xnoop` 도구를 사용해 시스템에 등록된 모든 policies를 덤프할 수도 있습니다:
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
그리고 나서 다음으로 check policy의 모든 검사를 덤프합니다:
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

- MACF는 매우 초기에 초기화된다. XNU 시작 코드의 `bootstrap_thread`에서 `ipc_bootstrap` 이후 XNU는 `mac_policy_init()`(`mac_base.c`에 있음)를 호출한다.
- `mac_policy_init()`는 전역 `mac_policy_list`(policy 슬롯들의 배열 또는 리스트)를 초기화하고, XNU 내부에서 MAC(Mandatory Access Control)을 위한 인프라를 설정한다.
- 이후 `mac_policy_initmach()`가 호출되며, 이는 내장되었거나 번들로 제공되는 policies에 대한 kernel 측 등록을 처리한다.

### `mac_policy_initmach()`와 “security extensions” 로딩

- `mac_policy_initmach()`는 사전 로드된 kernel extensions(kexts)나 “policy injection” 목록에 있는 것들을 검사하고, 그들의 Info.plist에서 `AppleSecurityExtension` 키를 확인한다.
- Info.plist에 `<key>AppleSecurityExtension</key>`(또는 `true`)를 선언한 kext는 “security extensions”로 간주된다. 즉, MAC policy를 구현하거나 MACF 인프라에 hook되는 것들이다.
- 해당 키를 가진 Apple kext의 예로는 **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** 등이 있다(이미 나열한 것처럼).
- kernel은 이러한 kext들이 조기에 로드되도록 보장한 다음, boot 동안 이들의 registration routines를 (`mac_policy_register`를 통해) 호출하여 `mac_policy_list`에 삽입한다.

- 각 policy module(kext)은 다양한 MAC operation(vnode 검사, exec 검사, label 업데이트 등)을 위한 hooks(`mpc_ops`)를 포함한 `mac_policy_conf` 구조체를 제공한다.
- load time flags에는 `MPC_LOADTIME_FLAG_NOTLATE`가 포함될 수 있으며, 이는 “반드시 early에 로드되어야 함”(따라서 late registration 시도는 거부됨)을 의미한다.
- 한 번 등록되면 각 module은 handle을 받으며 `mac_policy_list`에서 슬롯을 차지한다.
- 이후 MAC hook이 호출될 때(예: vnode access, exec 등), MACF는 등록된 모든 policies를 순회하며 공동 결정을 내린다.

- 특히 **AMFI**(Apple Mobile File Integrity)는 이런 security extension이다. 그 Info.plist에는 security policy임을 표시하는 `AppleSecurityExtension`이 포함된다.
- kernel boot의 일부로, kernel load logic은 많은 subsystems가 그것에 의존하기 전에 “security policy”(AMFI 등)가 이미 활성화되도록 보장한다. 예를 들어, kernel은 “AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy를 포함한 security policy를 로드하여 앞으로의 작업을 준비한다.”
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

MAC framework를 사용하는 kext를 작성할 때(즉, `mac_policy_register()` 등을 호출할 때), 해당 심볼들을 kext linker(kxld)가 해석할 수 있도록 KPI(Kernel Programming Interfaces) 의존성을 선언해야 합니다. 따라서 `kext`가 MACF에 의존한다고 선언하려면 `Info.plist`에 `com.apple.kpi.dsep`를 포함해 표시해야 합니다 (`find . Info.plist | grep AppleSecurityExtension`), 그러면 kext는 `mac_policy_register`, `mac_policy_unregister`, 그리고 MAC hook function pointers 같은 심볼을 참조하게 됩니다. 이것들을 해석하려면 `com.apple.kpi.dsep`를 dependency로 나열해야 합니다.

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
## 최신 macOS 릴리스의 MACF

최신 macOS에서는 Apple 보안 정책을 보통 느슨한 독립 `.kext` 번들로 다루는 방식이 가장 적절하지 않습니다. **macOS 11**부터 kernel extensions는 **kernel collections**에 연결되며; **Apple Silicon**에서는 별도의 **SystemKC**가 없고, 서드파티 kext는 **Auxiliary Kernel Collection (AuxKC)**에 빌드된 뒤 재부팅해야만 로드 가능합니다. MACF 연구 관점에서 이는 **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** 또는 **Quarantine** 같은 내장 정책을 `kextstat` 같은 더 이상 쓰이지 않는 도구보다 `kmutil`로 열거하는 것이 보통 더 쉽다는 뜻입니다.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon에서는 security kext가 BootKC에 없으면, 다음으로 AuxKC를 확인하세요. 이는 보통 `/System/Library/Extensions` 아래에서 독립적인 bundle을 찾는 것보다 더 유용합니다.

## MACF Callouts

코드에서 MACF에 대한 callout을 찾는 것은 흔한 일이며, 예를 들어 **`#if CONFIG_MAC`** 조건 블록 안에 정의되어 있습니다. 또한, 이 블록 안에서는 MACF를 호출하는 `mac_proc_check*` 호출을 찾을 수 있는데, 이는 특정 작업을 수행할 **권한을 확인**하기 위한 것입니다. 더불어, MACF callout의 형식은 **`mac_<object>_<opType>_opName`** 입니다.

object는 다음 중 하나입니다: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType`은 보통 check이며, 작업을 허용하거나 거부하는 데 사용됩니다. 하지만 `notify`도 찾을 수 있는데, 이는 kext가 주어진 작업에 반응하도록 합니다.

예시는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) 에서 확인할 수 있습니다:

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

그 다음에는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) 에서 `mac_file_check_mmap`의 코드를 찾을 수 있습니다.
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
이는 `MAC_CHECK` 매크로를 호출하는 것으로, 해당 코드는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)에서 찾을 수 있습니다.
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
이것은 등록된 모든 MAC 정책을 순회하며 각 함수들을 호출하고 결과를 error 변수에 저장하며, 이 값은 `mac_error_select`에 의해 성공 코드로만 덮어쓸 수 있으므로, 어떤 체크라도 실패하면 전체 체크가 실패하고 동작은 허용되지 않습니다.

> [!TIP]
> 하지만 모든 MACF callout이 단지 동작을 거부하는 데만 사용되는 것은 아니라는 점을 기억하세요. 예를 들어, `mac_priv_grant`는 매크로 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)를 호출하는데, 이는 어떤 정책이 0으로 응답하면 요청된 privilege를 부여합니다:
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

이 callas는 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h)에 정의된 **privileges**를 검사하고 제공하기 위한 것입니다.\
일부 커널 코드는 프로세스의 KAuth credentials와 하나의 privileges 코드를 사용해 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c)에서 `priv_check_cred()`를 호출하며, 이는 `mac_priv_check`를 호출해 어떤 정책이 privilege 부여를 **거부**하는지 확인한 다음 `mac_priv_grant`를 호출해 어떤 정책이 `privilege`를 부여하는지 확인합니다.

### proc_check_syscall_unix

이 hook은 모든 system calls를 가로챌 수 있게 해줍니다. `bsd/dev/[i386|arm]/systemcalls.c`에서 선언된 함수 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)을 볼 수 있으며, 여기에는 다음 코드가 포함되어 있습니다:
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
호출 프로세스의 **bitmask**에서 현재 syscall이 `mac_proc_check_syscall_unix`를 호출해야 하는지 확인한다. 이는 syscalls가 매우 자주 호출되기 때문에, 매번 `mac_proc_check_syscall_unix`를 호출하는 것을 피하는 것이 유용하기 때문이다.

함수 `proc_set_syscall_filter_mask()`, 즉 프로세스의 bitmask syscalls를 설정하는 함수는 Sandbox가 sandboxed processes에 mask를 설정하기 위해 호출한다.

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151)에 정의된 몇몇 syscalls를 통해 MACF와 상호작용할 수 있다:
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
오펜시브 reversing에서는 **`__mac_syscall`**이 여전히 가장 좋은 userland chokepoint 중 하나다. 이것은 **policy name**(예: `"Sandbox"` 또는 `"AMFI"`), **policy-specific selector/code**, 그리고 `mpo_policy_syscall`이 처리할 **opaque argument blob**에 대한 포인터를 전달한다. 이는 userland에서 문서화되지 않은 작업을 먼저 reversing하고, 나중에만 kernel implementation으로 pivot할 때 매우 유용하다. Sandbox는 보통 `__sandbox_ms`를 통해 여기에 도달하고, AMFI는 dyld policy 결정에 같은 메커니즘을 사용한다.

## Practical offensive research notes

최근 macOS bug들은 MACF를 직접 "break"하는 경우가 드물다. 대신 보통 **MACF / Sandbox / TCC decision과 나중에 발생하는 privileged action 사이의 desynchronisation**을 악용한다.

### Broker path checks vs real privileged action

반복적으로 보이는 패턴은 privileged daemon이 한 버전의 path에 대해 **userland pre-check**(예: `sandbox_check_by_audit_token()`)를 수행한 뒤, 나중에 **다른 또는 비정규화된 attacker-controlled path**로 실제 privileged sink를 실행하는 것이다. 최근 `diskarbitrationd` / `storagekitd` 연구가 좋은 예다: **directory traversal**과 **symlink swaps**를 이용해 attacker가 daemon의 sandbox validation을 통과한 뒤, `~/Library/Application Support/com.apple.TCC` 같은 민감한 위치 위로 mount할 수 있으며, 이를 통해 bug는 선택한 mount point에 따라 **sandbox escape**, **local privilege escalation** 또는 **TCC bypass**가 된다.

sandbox에서 도달 가능한 root broker를 audit할 때는 먼저 다음을 grep하라:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`, helper-tool XPC methods 같은 privileged sinks, 또는 나중에 attacker-controlled paths를 root로 touch하는 모든 것

### Trusted deputies with private entitlements

또 다른 실용적인 패턴은 MACF hooks를 직접 공격하지 않고, 경계를 넘는 데 필요한 권한을 이미 가진 **trusted process**를 악용하는 것이다. 최근 Safari/TCC 연구가 좋은 예다: 흥미로운 primitive는 "kernel에서 TCC를 disable"하는 것이 아니라, **`com.apple.private.tcc.allow`**를 가진 Apple-signed process가 대신 민감한 동작을 수행하도록 local policy/configuration을 수정하는 것이었다. 실제로 high-value auditing target은 다음을 결합한 Apple daemons/apps다:

- **private entitlements** 또는 FDA-like reach
- writable config / database / mount point / policy file
- **Sandbox**, **AMFI**, **TCC** 또는 다른 MACF policy에 의해 중재되는 나중의 sensitive operation

더 깊은 product-specific reversing은 [macOS Sandbox](macos-sandbox/README.md)와 [macOS TCC](macos-tcc/README.md) 전용 페이지를 확인하라.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
