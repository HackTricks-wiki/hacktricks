# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** का मतलब **Mandatory Access Control Framework** है, जो ऑपरेटिंग सिस्टम में बना एक security system है, जो आपके computer की सुरक्षा में मदद करता है। यह **सख्त rules सेट करके काम करता है कि कौन या क्या system के certain parts, जैसे files, applications, और system resources, access कर सकता है**। इन rules को automatically लागू करके, MACF सुनिश्चित करता है कि सिर्फ authorized users और processes ही specific actions कर सकें, जिससे unauthorized access या malicious activities का risk कम होता है।

ध्यान दें कि MACF वास्तव में कोई decision नहीं लेता, क्योंकि यह सिर्फ actions को **intercept** करता है; decisions वह **policy modules** (kernel extensions) पर छोड़ देता है जिन्हें यह call करता है, जैसे `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` और `mcxalr.kext`।

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

आमतौर पर permissions को MACF के साथ check करने वाली functions macro `MAC_CHECK` को call करेंगी। जैसे socket create करने के लिए syscall के case में, यह function `mac_socket_check_create` को call करेगा, जो `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` को call करता है। इसके अलावा, macro `MAC_CHECK` को security/mac_internal.h में इस तरह define किया गया है:
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
ध्यान दें कि `check` को `socket_check_create` में और `(cred, domain, type, protocol)` में `args...` को बदलने पर आपको मिलता है:
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
हेल्पर macros को expand करने पर concrete control flow दिखता है:
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
In other words, `MAC_CHECK(socket_check_create, ...)` पहले static policies को walk करता है, फिर conditionally dynamic policies को lock करके iterate करता है, हर hook के आसपास DTrace probes emit करता है, और `mac_error_select()` के जरिए हर hook के return code को एक single `error` result में collapse करता है।


### Labels

MACF **labels** का use करता है, जिन्हें बाद में policies यह check करने के लिए use करती हैं कि access grant करना चाहिए या नहीं। labels struct declaration का code [यहाँ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) मिल सकता है, जिसे फिर **`struct ucred`** के अंदर [**यहाँ**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`cr_label`** part में use किया जाता है। label में flags और **slots** की एक संख्या होती है, जिन्हें **MACF policies** pointers allocate करने के लिए use कर सकती हैं। For example Sanbox will point to the container profile

## MACF Policies

A MACF Policy defined **rule and conditions to be applied in certain kernel operations**.

A kernel extension could configure a `mac_policy_conf` struct and then register it calling `mac_policy_register`. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
`mac_policy_register` के कॉल्स की जाँच करके इन policies को configure करने वाले kernel extensions को पहचानना आसान है। इसके अलावा, extension के disassemble की जाँच करके उपयोग किए गए `mac_policy_conf` struct को भी ढूँढना संभव है।

ध्यान दें कि MACF policies को **dynamically** register और unregister भी किया जा सकता है।

`mac_policy_conf` के मुख्य fields में से एक **`mpc_ops`** है। यह field specify करती है कि policy किन operations में interested है। ध्यान दें कि इनके hundreds हैं, इसलिए सभी को zero करके फिर सिर्फ वे चुनना संभव है जिनमें policy interested है। [यहाँ से](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
लगभग सभी hooks को MACF द्वारा callback किया जाएगा जब उन operations में से कोई एक intercepted होती है। हालांकि, **`mpo_policy_*`** hooks एक exception हैं क्योंकि **`mpo_hook_policy_init()`** registration पर बुलाया जाने वाला callback है (यानी **`mac_policy_register()`** के बाद), और **`mpo_hook_policy_initbsd()`** late registration के दौरान बुलाया जाता है जब BSD subsystem सही तरीके से initialize हो चुका होता है।

इसके अलावा, **`mpo_policy_syscall`** hook किसी भी kext द्वारा register किया जा सकता है ताकि एक private **ioctl** style call **interface** expose किया जा सके। फिर, एक user client **mac_syscall** (#381) को कॉल कर सकेगा, जिसमें parameters के रूप में **policy name** के साथ एक integer **code** और optional **arguments** दिए जाएंगे।\
उदाहरण के लिए, **`Sandbox.kext`** इसका बहुत उपयोग करता है।

kext के **`__DATA.__const*`** की जांच करके उस `mac_policy_ops` structure को identify करना संभव है जो policy register करते समय उपयोग होती है। इसे इसलिए ढूंढा जा सकता है क्योंकि उसका pointer `mpo_policy_conf` के अंदर एक offset पर होता है और इसलिए भी क्योंकि उस area में NULL pointers की संख्या होती है।

इसके अलावा, memory से struct **`_mac_policy_list`** को dump करके उन kexts की list प्राप्त करना भी संभव है जिन्होंने एक policy configure की है, क्योंकि इसे हर बार एक policy register होने पर update किया जाता है।

आप system में registered सभी policies को dump करने के लिए tool `xnoop` का भी उपयोग कर सकते हैं:
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
और फिर सभी checks of check policy को इसके साथ dump करें:
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
## XNU में MACF initialization

### Early bootstrap और `mac_policy_init()`

- MACF बहुत जल्दी initialize हो जाता है। `bootstrap_thread` में (XNU startup code में), `ipc_bootstrap` के बाद, XNU `mac_policy_init()` (`mac_base.c` में) को call करता है।
- `mac_policy_init()` global `mac_policy_list` (policy slots का एक array या list) को initialize करता है और XNU के भीतर MAC (Mandatory Access Control) के लिए infrastructure set up करता है।
- बाद में, `mac_policy_initmach()` invoke होता है, जो built-in या bundled policies के लिए policy registration के kernel-side को handle करता है।

### `mac_policy_initmach()` और “security extensions” को load करना

- `mac_policy_initmach()` preloaded kernel extensions (kexts) की जांच करता है (या “policy injection” list में मौजूद ones) और उनकी Info.plist में `AppleSecurityExtension` key को inspect करता है।
- जो kexts अपनी Info.plist में `<key>AppleSecurityExtension</key>` (या `true`) declare करते हैं, उन्हें “security extensions” माना जाता है — यानी वे जो MAC policy implement करते हैं या MACF infrastructure में hook करते हैं।
- उस key वाले Apple kexts के examples में **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, आदि शामिल हैं (जैसा आपने पहले list किया था)।
- Kernel यह सुनिश्चित करता है कि ये kexts early load हों, फिर boot के दौरान उनकी registration routines (`mac_policy_register` के जरिए) call करता है, और उन्हें `mac_policy_list` में insert करता है।

- हर policy module (kext) एक `mac_policy_conf` structure provide करता है, जिसमें विभिन्न MAC operations (vnode checks, exec checks, label updates, आदि) के लिए hooks (`mpc_ops`) होते हैं।
- load time flags में `MPC_LOADTIME_FLAG_NOTLATE` शामिल हो सकता है, जिसका मतलब है “इसे early load होना ही चाहिए” (इसलिए late registration attempts reject हो जाते हैं)।
- एक बार register होने के बाद, हर module को एक handle मिलता है और वह `mac_policy_list` में एक slot occupy करता है।
- बाद में जब कोई MAC hook invoke होता है (उदाहरण के लिए, vnode access, exec, आदि), MACF सभी registered policies पर iterate करता है ताकि collective decisions लिए जा सकें।

- खास तौर पर, **AMFI** (Apple Mobile File Integrity) ऐसी ही एक security extension है। इसकी Info.plist में `AppleSecurityExtension` होता है, जो इसे security policy के रूप में mark करता है।
- Kernel boot का हिस्सा होने के नाते, kernel load logic यह सुनिश्चित करता है कि कई subsystems के उस पर depend करने से पहले “security policy” (AMFI, आदि) पहले से active हो। उदाहरण के लिए, kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

जब आप MAC framework का उपयोग करने वाला एक kext लिखते हैं (अर्थात `mac_policy_register()` आदि को कॉल करते हुए), तो आपको KPIs (Kernel Programming Interfaces) पर dependencies घोषित करनी होंगी ताकि kext linker (kxld) उन symbols को resolve कर सके। इसलिए `kext` को MACF पर depend कराने के लिए आपको `Info.plist` में `com.apple.kpi.dsep` के साथ इसे इंगित करना होगा (`find . Info.plist | grep AppleSecurityExtension`), फिर kext `mac_policy_register`, `mac_policy_unregister`, और MAC hook function pointers जैसे symbols को refer करेगा। इन्हें resolve करने के लिए, आपको `com.apple.kpi.dsep` को एक dependency के रूप में सूचीबद्ध करना होगा।

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
## आधुनिक macOS रिलीज़ पर MACF

आधुनिक macOS पर, Apple security policies को आमतौर पर loose standalone `.kext` bundles के रूप में नहीं देखना चाहिए। **macOS 11** के बाद से, kernel extensions को **kernel collections** में link किया जाता है; **Apple Silicon** पर अलग **SystemKC** नहीं होता, और third-party kexts तभी loadable होते हैं जब उन्हें **Auxiliary Kernel Collection (AuxKC)** में build किया जाए और reboot किया जाए। MACF research के लिए इसका मतलब है कि built-in policies जैसे **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** या **Quarantine** को आमतौर पर `kmutil` के साथ enumerate करना, `kextstat` जैसे deprecated tooling की तुलना में, आसान होता है।
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> On Apple Silicon, if a security kext is not in the BootKC, check the AuxKC next. This is usually more useful than hunting for a standalone bundle under `/System/Library/Extensions`.

## MACF Callouts

It's common to find callouts to MACF defined in code like: **`#if CONFIG_MAC`** conditional blocks. Moreover, inside these blocks it's possible to find calls to `mac_proc_check*` which calls MACF to **check for permissions** to perform certain actions. Moreover, the format of the MACF callouts is: **`mac_<object>_<opType>_opName`**.

The object is one of the following: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
The `opType` is usually check which will be used to allow or deny the action. However, it's also possible to find `notify`, which will allow the kext to react to the given action.

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
जो `MAC_CHECK` macro को कॉल कर रहा है, जिसका code [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) में पाया जा सकता है
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
जिसमें सभी registered MAC policies पर iterate करके उनकी functions को call किया जाता है और output को error variable के अंदर store किया जाता है, जिसे केवल `mac_error_select` success codes के जरिए override कर सकता है; इसलिए अगर कोई भी check fail होता है, तो पूरा check fail हो जाएगा और action allowed नहीं होगा।

> [!TIP]
> हालांकि, याद रखें कि सभी MACF callouts सिर्फ actions deny करने के लिए ही उपयोग नहीं होते। उदाहरण के लिए, `mac_priv_grant` macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) को call करता है, जो requested privilege grant करेगा अगर कोई भी policy 0 के साथ answer करती है:
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

ये callas [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) में defined (tens of) **privileges** को check और provide करने के लिए बनाए गए हैं।\
कुछ kernel code, process के KAuth credentials और privileges code में से किसी एक के साथ [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) से `priv_check_cred()` call करेगा, जो `mac_priv_check` call करता है ताकि पता चल सके कि कोई policy privilege देने से **deny** करती है या नहीं; फिर यह `mac_priv_grant` call करता है यह देखने के लिए कि कोई policy `privilege` grant करती है या नहीं।

### proc_check_syscall_unix

यह hook सभी system calls को intercept करने की अनुमति देता है। `bsd/dev/[i386|arm]/systemcalls.c` में declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) देखी जा सकती है, जिसमें यह code है:
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
जो calling process में **bitmask** की जाँच करेगा कि क्या current syscall को `mac_proc_check_syscall_unix` कॉल करना चाहिए। ऐसा इसलिए है क्योंकि syscalls बहुत frequently call होते हैं, इसलिए हर बार `mac_proc_check_syscall_unix` को कॉल करने से बचना interesting है।

ध्यान दें कि function `proc_set_syscall_filter_mask()`, जो एक process में bitmask syscalls set करता है, Sandbox द्वारा sandboxed processes पर masks set करने के लिए call किया जाता है।

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) में defined कुछ syscalls के through MACF के साथ interact करना possible है:
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
ऑफेंसिव reversing के लिए, **`__mac_syscall`** अभी भी सबसे अच्छे userland chokepoints में से एक है। इसमें एक **policy name** होता है (उदाहरण के लिए `"Sandbox"` या `"AMFI"`), एक **policy-specific selector/code**, और **opaque argument blob** के लिए एक pointer होता है, जिसे `mpo_policy_syscall` हैंडल करेगा। यह userland से undocumented operations को पहले reverse करने और बाद में kernel implementation की ओर pivot करने में बहुत उपयोगी है। Sandbox आम तौर पर इसे `__sandbox_ms` के जरिए एक्सेस करता है, और AMFI dyld policy decisions के लिए इसी mechanism का उपयोग करता है।

## Practical offensive research notes

हाल के macOS bugs सीधे तौर पर बहुत कम ही "MACF" को तोड़ते हैं। इसके बजाय, वे आम तौर पर **MACF / Sandbox / TCC decision और बाद में होने वाली privileged action के बीच desynchronisation** का दुरुपयोग करते हैं।

### Broker path checks vs real privileged action

एक बार-बार दिखने वाला pattern यह है कि एक privileged daemon पहले एक **userland pre-check** करता है (उदाहरण के लिए `sandbox_check_by_audit_token()`) किसी path के एक version पर, और बाद में real privileged sink को एक **अलग या non-canonical attacker-controlled path** के साथ execute करता है। हाल के `diskarbitrationd` / `storagekitd` research इसका एक अच्छा example है: **directory traversal** + **symlink swaps** attacker को daemon की sandbox validation पास करने देते हैं और फिर `~/Library/Application Support/com.apple.TCC` जैसी sensitive locations पर mount करने देते हैं, जिससे bug चुने गए mount point के आधार पर **sandbox escape**, **local privilege escalation** या **TCC bypass** में बदल जाता है।

जब sandbox से reachable root brokers का audit करें, तो पहले इनके लिए grep करें:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks जैसे `mount`, `rename`, `copyfile`, helper-tool XPC methods, या कुछ भी जो बाद में attacker-controlled paths को root के रूप में touch करता है

### Trusted deputies with private entitlements

एक और practical pattern यह है कि MACF hooks पर सीधे attack करने के बजाय एक **trusted process** का दुरुपयोग किया जाए जिसके पास पहले से boundary पार करने के लिए जरूरी rights हों। हाल का Safari/TCC research इसका एक अच्छा example है: interesting primitive "kernel में TCC disable करना" नहीं था, बल्कि local policy/configuration को modify करना था ताकि **`com.apple.private.tcc.allow`** वाला Apple-signed process आपकी ओर से sensitive action execute करे। व्यावहारिक रूप से, high-value auditing targets वे Apple daemons/apps हैं जो combine करते हैं:

- **private entitlements** या FDA-like reach
- एक writable config / database / mount point / policy file
- बाद में होने वाली sensitive operation, जिसे **Sandbox**, **AMFI**, **TCC** या किसी अन्य MACF policy द्वारा mediated किया जाता है

गहराई से product-specific reversing के लिए, [macOS Sandbox](macos-sandbox/README.md) और [macOS TCC](macos-tcc/README.md) पर dedicated pages देखें।

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
