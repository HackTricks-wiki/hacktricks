# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

**MACF**는 **Mandatory Access Control Framework**의 약자로, 컴퓨터를 보호하기 위해 운영 체제에 내장된 security system입니다. 이는 파일, 애플리케이션, system resource 등 system의 특정 부분에 누가 또는 무엇이 access할 수 있는지에 대한 **엄격한 규칙을 설정**하는 방식으로 작동합니다. 이러한 규칙을 자동으로 적용함으로써 MACF는 승인된 user와 process만 특정 작업을 수행할 수 있도록 하여, unauthorized access 또는 malicious activity의 위험을 줄입니다.

MACF는 실제로 어떤 decision도 내리지 않고 단지 action을 **intercept**할 뿐이며, decision은 `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext`, `mcxalr.kext`와 같이 MACF가 호출하는 **policy module**(kernel extension)에 맡깁니다.

- Policy는 enforcing일 수 있습니다(일부 operation에서 0이 아닌 값을 return)
- Policy는 monitoring일 수 있습니다(반대하지 않도록 0을 return하고, hook에 piggyback하여 무언가를 수행)
- MACF static policy는 boot 시 설치되며 절대 제거되지 않습니다
- MACF dynamic policy는 KEXT에 의해 설치되고(kextload), 이론적으로 kextunload할 수 있습니다
- iOS에서는 static policy만 허용되며, macOS에서는 static + dynamic이 허용됩니다.<sup>[[7]](#references)</sup>

### Flow

1. Process가 syscall/mach trap을 수행합니다
2. 관련 function이 kernel 내부에서 호출됩니다
3. Function이 MACF를 호출합니다
4. MACF가 해당 function을 hook하도록 policy에서 요청한 policy module을 확인합니다
5. MACF가 관련 policy를 호출합니다
6. Policy가 해당 action을 허용할지 deny할지 표시합니다

> [!CAUTION]
> Apple만 MAC Framework KPI를 사용할 수 있습니다.

일반적으로 MACF로 permission을 확인하는 function은 `MAC_CHECK` macro를 호출합니다. 예를 들어 socket을 생성하는 syscall의 경우 `mac_socket_check_create` function을 호출하고, 이 function은 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`를 호출합니다. 또한 `MAC_CHECK` macro는 security/mac_internal.h에서 다음과 같이 정의됩니다:<sup>[[3]](#references)</sup>
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
`check`를 `socket_check_create`로 변환하고 `args...`를 `(cred, domain, type, protocol)`로 변환하면 다음을 얻습니다:
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
helper 매크로를 확장하면 구체적인 제어 흐름이 나타납니다:
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
다시 말해, `MAC_CHECK(socket_check_create, ...)`는 먼저 static policies를 순회하고, 필요에 따라 동적으로 lock을 획득한 후 dynamic policies를 순회하며, 각 hook 주변에서 DTrace probes를 발생시키고, `mac_error_select()`를 통해 모든 hook의 반환 코드를 하나의 `error` 결과로 통합합니다.


### Labels

MACF는 **labels**를 사용하며, 이후 접근을 허용할지 여부를 확인하는 policies가 이를 사용합니다. labels struct 선언 코드는 [여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)에서 확인할 수 있으며, 이는 **`struct ucred`** 내부의 [여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)에 있는 **`cr_label`** 부분에서 사용됩니다. label에는 flags와 **MACF policies가 포인터를 할당하는 데** 사용할 수 있는 여러 **slots**가 포함됩니다. 예를 들어 Sandbox는 container profile을 가리킵니다.

## MACF Policies

MACF Policy는 특정 kernel operation에 적용할 **규칙과 조건을 정의**합니다.

kernel extension은 `mac_policy_conf` struct를 구성한 다음 `mac_policy_register`를 호출하여 이를 등록할 수 있습니다. [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
이러한 정책을 구성하는 kernel extension은 `mac_policy_register` 호출을 확인하면 쉽게 식별할 수 있습니다. 또한 extension의 disassemble을 확인하면 사용된 `mac_policy_conf` struct도 찾을 수 있습니다.

MACF policies는 **동적으로** 등록 및 등록 해제될 수도 있다는 점에 유의해야 합니다.

`mac_policy_conf`의 주요 필드 중 하나는 **`mpc_ops`**입니다. 이 필드는 해당 policy가 관심을 가지는 operation을 지정합니다. 수백 개의 operation이 있으므로, 모든 operation을 0으로 설정한 다음 policy가 관심을 가지는 operation만 선택할 수 있습니다. [여기](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)에서 확인할 수 있습니다:<sup>[[1]](#references)</sup>
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
거의 모든 hook은 해당 연산 중 하나가 가로채질 때 MACF에 의해 callback됩니다. 그러나 **`mpo_policy_*`** hook은 예외입니다. **`mpo_hook_policy_init()`**은 등록 시점(`mac_policy_register()` 이후)에 호출되는 callback이고, **`mpo_hook_policy_initbsd()`**는 BSD subsystem이 제대로 초기화된 이후 late registration 중에 호출되기 때문입니다.

또한 **`mpo_policy_syscall`** hook은 모든 kext에서 등록하여 private **ioctl** 스타일 호출 **interface**를 노출할 수 있습니다. 그러면 user client가 **policy name**과 정수 **code**, 선택적 **arguments**를 매개변수로 지정하여 `mac_syscall` (#381)을 호출할 수 있습니다.\
예를 들어 **`Sandbox.kext`**는 이를 많이 사용합니다.

kext의 **`__DATA.__const*`**를 확인하면 policy 등록 시 사용되는 `mac_policy_ops` 구조체를 식별할 수 있습니다. 이 구조체의 pointer가 `mpo_policy_conf` 내부의 특정 offset에 있으며, 해당 영역에 존재하는 NULL pointer의 개수로도 식별할 수 있기 때문입니다.

또한 메모리에서 **`_mac_policy_list`** 구조체를 덤프하여 policy를 구성한 kext 목록을 가져올 수도 있습니다. 이 구조체는 등록되는 각 policy에 따라 업데이트됩니다.

`xnoop` 도구를 사용하여 시스템에 등록된 모든 policy를 덤프할 수도 있습니다:
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
그런 다음 다음을 사용해 check policy의 모든 검사를 dump합니다:
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

### 초기 bootstrap 및 mac_policy_init()

- MACF는 매우 이른 시점에 초기화됩니다. `bootstrap_thread`(XNU startup code 내)에서 `ipc_bootstrap` 이후 XNU는 `mac_policy_init()`(`mac_base.c` 내)를 호출합니다.
- `mac_policy_init()`는 전역 `mac_policy_list`(policy slot의 배열 또는 목록)를 초기화하고 XNU 내 MAC(Mandatory Access Control)을 위한 인프라를 설정합니다.
- 이후 `mac_policy_initmach()`가 호출되며, 이는 built-in 또는 bundled policy의 kernel 측 policy registration을 처리합니다.

### `mac_policy_initmach()` 및 “security extensions” 로딩

- `mac_policy_initmach()`는 미리 로드된(또는 “policy injection” 목록에 있는) kernel extension(kext)을 확인하고 해당 kext의 Info.plist에서 `AppleSecurityExtension` 키를 검사합니다.
- Info.plist에 `<key>AppleSecurityExtension</key>`(또는 `true`)를 선언한 kext는 “security extensions”로 간주됩니다. 즉, MAC policy를 구현하거나 MACF 인프라에 hook하는 kext입니다.
- 이 키를 포함하는 Apple kext의 예로는 **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** 등이 있으며, 앞서 나열한 것들도 포함됩니다.
- kernel은 이러한 kext가 early stage에 로드되도록 보장한 다음, boot 중 `mac_policy_register`를 통해 registration routines를 호출하여 해당 kext를 `mac_policy_list`에 삽입합니다.

- 각 policy module(kext)은 다양한 MAC operation(vnode checks, exec checks, label updates 등)을 위한 hook(`mpc_ops`)이 포함된 `mac_policy_conf` 구조체를 제공합니다.
- load time flag에는 `MPC_LOADTIME_FLAG_NOTLATE`가 포함될 수 있으며, 이는 “early stage에 로드되어야 함”을 의미합니다(따라서 late registration 시도는 거부됩니다).
- registration이 완료되면 각 module은 handle을 할당받고 `mac_policy_list`의 slot 하나를 차지합니다.
- 이후 MAC hook이 호출되면(예: vnode access, exec 등) MACF는 등록된 모든 policy를 순회하여 collective decision을 내립니다.

- 특히 **AMFI**(Apple Mobile File Integrity)는 이러한 security extension 중 하나입니다. 해당 Info.plist에는 이를 security policy로 표시하는 `AppleSecurityExtension`이 포함되어 있습니다.
- kernel boot 과정에서 kernel load logic은 여러 subsystem이 이를 필요로 하기 전에 “security policy”(AMFI 등)가 이미 활성화되어 있도록 보장합니다. 예를 들어 kernel은 “AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy를 포함한 security policy를 로드하여 task를 준비합니다.”
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
## MAC policy kexts의 KPI dependency 및 com.apple.kpi.dsep

MAC framework을 사용하는 kext(예: `mac_policy_register()` 등을 호출하는 kext)를 작성할 때는 kext linker(kxld)가 해당 심볼을 확인할 수 있도록 KPI(Kernel Programming Interfaces)에 대한 dependency를 선언해야 합니다. 따라서 MACF에 dependency가 있는 `kext`를 선언하려면 `Info.plist`에서 `com.apple.kpi.dsep`를 지정해야 하며(`find . Info.plist | grep AppleSecurityExtension`), 그러면 해당 kext는 `mac_policy_register`, `mac_policy_unregister`와 같은 심볼 및 MAC hook function pointer를 참조하게 됩니다. 이러한 심볼을 확인하려면 `com.apple.kpi.dsep`를 dependency로 나열해야 합니다.

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

최신 macOS에서 Apple 보안 정책은 일반적으로 느슨한 독립형 `.kext` 번들로 접근하는 것이 가장 적절하지 않습니다. **macOS 11**부터 kernel extension은 **kernel collections**에 링크되며, **Apple Silicon**에서는 별도의 **SystemKC**가 존재하지 않습니다. 또한 서드파티 kext는 **Auxiliary Kernel Collection (AuxKC)**에 빌드되고 재부팅한 후에만 로드할 수 있습니다. MACF 연구에서는 이러한 이유로 **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** 또는 **Quarantine**과 같은 기본 제공 정책을 `kextstat` 같은 deprecated tooling보다 `kmutil`을 사용해 열거하는 편이 일반적으로 더 쉽습니다.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon에서 security kext가 BootKC에 없다면 다음으로 AuxKC를 확인하세요. `/System/Library/Extensions` 아래에서 standalone bundle을 찾는 것보다 일반적으로 더 유용합니다.

## MACF Callouts

다음과 같은 **`#if CONFIG_MAC`** conditional block로 정의된 MACF callout을 코드에서 흔히 찾을 수 있습니다. 또한 이러한 block 내부에서는 특정 작업을 수행할 **권한을 확인**하기 위해 MACF를 호출하는 `mac_proc_check*` 호출을 찾을 수 있습니다. MACF callout의 형식은 다음과 같습니다: **`mac_<object>_<opType>_opName`**.

object는 다음 중 하나입니다: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType`은 일반적으로 작업을 허용하거나 거부하는 데 사용되는 check입니다. 그러나 `notify`도 찾을 수 있으며, 이는 kext가 주어진 작업에 반응할 수 있도록 합니다.

다음에서 예제를 확인할 수 있습니다: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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
`MAC_CHECK` 매크로를 호출하며, 해당 매크로의 코드는 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>에서 확인할 수 있습니다.
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
이는 등록된 모든 mac 정책을 순회하며 해당 함수들을 호출하고 결과를 `error` 변수에 저장합니다. 이 변수는 성공 코드에 의해서만 `mac_error_select`에 의해 재정의될 수 있으므로, 하나라도 검사가 실패하면 전체 검사가 실패하고 해당 작업은 허용되지 않습니다.

> [!TIP]
> 그러나 모든 MACF callout이 작업을 거부하는 데만 사용되는 것은 아닙니다. 예를 들어, `mac_priv_grant`는 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) 매크로를 호출하며, 이 매크로는 어느 policy든 0으로 응답하면 요청된 privilege를 부여합니다:
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

이 callout들은 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h)에 정의된 수십 개의 **privilege**를 검사하고 제공하기 위한 것입니다.\
일부 kernel 코드는 프로세스의 KAuth credentials 및 privilege code 중 하나를 사용하여 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c)의 `priv_check_cred()`를 호출합니다. 이 함수는 `mac_priv_check`를 호출하여 어떤 policy가 privilege 제공을 **거부**하는지 확인한 다음, `mac_priv_grant`를 호출하여 어떤 policy가 해당 `privilege`를 부여하는지 확인합니다.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

이 hook을 사용하면 모든 system call을 가로챌 수 있습니다. `bsd/dev/[i386|arm]/systemcalls.c`에서는 선언된 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) 함수를 확인할 수 있으며, 이 함수에는 다음 코드가 포함되어 있습니다:
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
호출 프로세스의 **bitmask**를 확인하여 현재 syscall이 `mac_proc_check_syscall_unix`를 호출해야 하는지 판단합니다. syscall은 매우 자주 호출되므로 매번 `mac_proc_check_syscall_unix`를 호출하지 않도록 하는 것이 중요합니다.

프로세스에서 syscall bitmask를 설정하는 함수 `proc_set_syscall_filter_mask()`는 Sandbox가 sandboxed process에 mask를 설정할 때 호출됩니다.

## Exposed MACF syscalls

다음 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151)에 정의된 syscall을 통해 MACF와 상호작용할 수 있습니다:
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
공격적 reversing에서 **`__mac_syscall`**은 여전히 최고의 userland 초크포인트 중 하나입니다. 이 함수는 **policy name**(예: `"Sandbox"` 또는 `"AMFI"`), **policy-specific selector/code**, 그리고 `mpo_policy_syscall`에서 처리할 **opaque argument blob**에 대한 포인터를 전달합니다. 이는 먼저 userland에서 undocumented operation을 reversing한 다음, 나중에 kernel implementation으로 전환할 때 매우 유용합니다. Sandbox는 일반적으로 `__sandbox_ms`를 통해 여기에 도달하며, AMFI도 dyld policy decision에 동일한 메커니즘을 사용합니다.<sup>[[2]](#references)[[5]](#references)</sup>

## 실전 offensive research 참고 사항

최근 macOS bug는 MACF를 직접 "break"하는 경우가 드뭅니다. 대신 일반적으로 **MACF / Sandbox / TCC decision과 이후 발생하는 privileged action 사이의 desynchronisation**을 악용합니다.

### Broker path checks와 실제 privileged action

반복적으로 나타나는 패턴은 privileged daemon이 **userland pre-check**(예: `sandbox_check_by_audit_token()`)를 한 버전의 path에 대해 수행한 다음, 나중에 **서로 다르거나 non-canonical한 attacker-controlled path**를 사용해 실제 privileged sink를 실행하는 것입니다. 최근 `diskarbitrationd` / `storagekitd` research가 좋은 예입니다. **directory traversal**과 **symlink swaps**를 함께 사용하면 attacker가 daemon의 sandbox validation을 통과한 뒤 `~/Library/Application Support/com.apple.TCC`와 같은 민감한 위치에 mount할 수 있습니다. 이를 통해 선택한 mount point에 따라 해당 bug를 **sandbox escape**, **local privilege escalation** 또는 **TCC bypass**로 전환할 수 있습니다.<sup>[[6]](#references)</sup>

sandbox에서 접근할 수 있는 root broker를 audit할 때는 먼저 다음을 grep하세요.

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- `mount`, `rename`, `copyfile`, helper-tool XPC methods와 같은 privileged sinks, 또는 이후 root 권한으로 attacker-controlled paths를 처리하는 모든 항목

### Private entitlements를 보유한 trusted deputies

또 다른 실전 패턴은 MACF hooks를 직접 공격하는 대신, boundary를 넘는 데 필요한 권한을 이미 보유한 **trusted process**를 악용하는 것입니다. 최근 Safari/TCC research가 좋은 예입니다. 핵심 primitive는 "kernel에서 TCC를 disable"하는 것이 아니라, **`com.apple.private.tcc.allow`**를 보유한 Apple-signed process가 사용자를 대신해 민감한 action을 수행하도록 local policy/configuration을 수정하는 것이었습니다.<sup>[[8]](#references)</sup> 실제로 높은 가치가 있는 auditing target은 다음 요소를 결합한 Apple daemon/app입니다.

- **private entitlements** 또는 FDA와 유사한 reach
- writable config / database / mount point / policy file
- 이후 **Sandbox**, **AMFI**, **TCC** 또는 다른 MACF policy가 중재하는 민감한 operation

더 심층적인 product-specific reversing은 [macOS Sandbox](macos-sandbox/README.md) 및 [macOS TCC](macos-tcc/README.md)의 전용 페이지를 확인하세요.

## References

- [1] [XNU — `security/mac_policy.h` (the full MACF policy operations vector)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (privilege codes used by `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool](https://newosxbook.com/xxr/index.php)
- [8] [New macOS vulnerability, "HM Surf", could lead to unauthorized data access (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)

{{#include ../../../banners/hacktricks-training.md}}
