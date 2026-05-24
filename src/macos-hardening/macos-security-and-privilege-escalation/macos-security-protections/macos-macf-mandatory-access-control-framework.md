# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** का मतलब **Mandatory Access Control Framework** है, जो ऑपरेटिंग सिस्टम में built-in एक security system है, जो आपके computer को protect करने में मदद करता है। यह **इस बारे में सख्त rules सेट करके काम करता है कि कौन या क्या system के कुछ हिस्सों, जैसे files, applications, और system resources, को access कर सकता है**। इन rules को automatically enforce करके, MACF सुनिश्चित करता है कि केवल authorized users और processes ही specific actions perform कर सकें, जिससे unauthorized access या malicious activities का risk कम होता है।

ध्यान दें कि MACF वास्तव में कोई decisions नहीं लेता, क्योंकि यह सिर्फ actions को **intercept** करता है; decisions यह उन **policy modules** (kernel extensions) पर छोड़ देता है जिन्हें यह `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` और `mcxalr.kext` जैसे modules को call करता है।

- एक policy enforcing हो सकती है (कुछ operation पर 0 non-zero return)
- एक policy monitoring हो सकती है (0 return करे, ताकि object न करे लेकिन hook पर piggyback करके कुछ करे)
- एक MACF static policy boot में install होती है और कभी remove नहीं होगी
- एक MACF dynamic policy KEXT (kextload) द्वारा install होती है और hypothetically kextunloaded हो सकती है
- iOS में केवल static policies allowed हैं और macOS में static + dynamic
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process एक syscall/mach trap perform करता है
2. संबंधित function kernel के अंदर call होता है
3. Function MACF को call करता है
4. MACF उन policy modules को check करता है जिन्होंने अपनी policy में उस function को hook करने का request किया था
5. MACF relevant policies को call करता है
6. Policies बताती हैं कि वे action को allow करती हैं या deny

> [!CAUTION]
> Apple ही एकमात्र है जो MAC Framework KPI का use कर सकता है।

आमतौर पर MACF के साथ permissions check करने वाले functions macro `MAC_CHECK` को call करेंगे। जैसे socket create करने वाले syscall के मामले में, वह function `mac_socket_check_create` को call करेगा, जो `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` को call करता है। इसके अलावा, macro `MAC_CHECK` `security/mac_internal.h` में इस प्रकार defined है:
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
दूसरे शब्दों में, `MAC_CHECK(socket_check_create, ...)` पहले static policies को walk करता है, conditionally lock करता है और dynamic policies पर iterate करता है, हर hook के आसपास DTrace probes emit करता है, और हर hook के return code को `mac_error_select()` के जरिए एक single `error` result में collapse करता है।


### Labels

MACF **labels** का उपयोग करता है, जिन्हें बाद में policies यह जांचने के लिए इस्तेमाल करती हैं कि उन्हें कुछ access grant करना चाहिए या नहीं। labels struct declaration का code [यहाँ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) पाया जा सकता है, जिसे फिर **`struct ucred`** के अंदर [**यहाँ**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`cr_label`** हिस्से में उपयोग किया जाता है। label में flags और **slots** की एक संख्या होती है, जिनका उपयोग **MACF policies द्वारा pointers allocate** करने के लिए किया जा सकता है। उदाहरण के लिए Sanbox container profile की ओर point करेगा

## MACF Policies

एक MACF Policy **rule और conditions** को परिभाषित करती है जिन्हें कुछ kernel operations पर लागू किया जाना है।

एक kernel extension `mac_policy_conf` struct configure कर सकती है और फिर `mac_policy_register` call करके register कर सकती है। [यहाँ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) से:
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
इन policies को configure करने वाले kernel extensions की पहचान `mac_policy_register` पर calls को देखकर आसानी से की जा सकती है। इसके अलावा, extension का disassemble check करके used `mac_policy_conf` struct भी पाया जा सकता है।

ध्यान दें कि MACF policies को **dynamically** register और unregister भी किया जा सकता है।

`mac_policy_conf` के main fields में से एक **`mpc_ops`** है। यह field बताती है कि policy किन operations में interested है। ध्यान दें कि इनमें सैकड़ों होते हैं, इसलिए सभी को zero करके फिर सिर्फ वही select करना संभव है जिनमें policy interested है। [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) से:
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
लगभग सभी hooks को MACF द्वारा callback किया जाएगा जब उन operations में से कोई intercept किया जाता है। हालांकि, **`mpo_policy_*`** hooks एक exception हैं क्योंकि `mpo_hook_policy_init()` एक callback है जो registration पर call होता है (यानी `mac_policy_register()` के बाद), और `mpo_hook_policy_initbsd()` late registration के दौरान call होता है, जब BSD subsystem properly initialise हो चुका होता है।

इसके अलावा, **`mpo_policy_syscall`** hook को कोई भी kext register कर सकता है ताकि एक private **ioctl** style call **interface** expose किया जा सके। फिर, एक user client `mac_syscall` (#381) को call कर सकेगा, जिसमें parameters के रूप में **policy name** के साथ एक integer **code** और optional **arguments** होंगे।\
उदाहरण के लिए, **`Sandbox.kext`** इसका बहुत उपयोग करता है।

kext के **`__DATA.__const*`** को check करके `mac_policy_ops` structure identify किया जा सकता है, जिसका उपयोग policy register करते समय किया जाता है। इसे ढूँढना संभव है क्योंकि इसका pointer `mpo_policy_conf` के अंदर एक offset पर होता है और इसलिए भी क्योंकि उस area में NULL pointers की संख्या होती है।

इसके अलावा, memory से struct **`_mac_policy_list`** dump करके उन kexts की list भी प्राप्त की जा सकती है जिन्होंने कोई policy configure की है, क्योंकि यह हर registered policy के साथ update होती है।

आप `xnoop` tool का उपयोग करके भी system में registered सभी policies dump कर सकते हैं:
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
और फिर check policy की सभी checks को इस तरह dump करें:
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

### Early bootstrap और mac_policy_init()

- MACF बहुत जल्दी initialized होता है। `bootstrap_thread` में (XNU startup code में), `ipc_bootstrap` के बाद, XNU `mac_policy_init()` को call करता है (`mac_base.c` में)।
- `mac_policy_init()` global `mac_policy_list` (policy slots का एक array या list) को initialize करता है और XNU के भीतर MAC (Mandatory Access Control) के लिए infrastructure set up करता है।
- बाद में, `mac_policy_initmach()` invoke किया जाता है, जो built-in या bundled policies के लिए policy registration के kernel side को handle करता है।

### `mac_policy_initmach()` और “security extensions” loading

- `mac_policy_initmach()` preloaded kernel extensions (kexts) या “policy injection” list में मौजूद kexts की जांच करता है और उनके Info.plist में `AppleSecurityExtension` key inspect करता है।
- जिन kexts के Info.plist में `<key>AppleSecurityExtension</key>` (या `true`) declare होता है, उन्हें “security extensions” माना जाता है — यानी वे जो MAC policy implement करते हैं या MACF infrastructure में hook होते हैं।
- इस key वाले Apple kexts के उदाहरणों में **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, आदि शामिल हैं (जैसा कि आपने पहले सूचीबद्ध किया)।
- Kernel सुनिश्चित करता है कि ये kexts early load हों, फिर boot के दौरान उनकी registration routines (`mac_policy_register` के जरिए) call करता है, और उन्हें `mac_policy_list` में insert करता है।

- हर policy module (kext) एक `mac_policy_conf` structure प्रदान करता है, जिसमें विभिन्न MAC operations (vnode checks, exec checks, label updates, etc.) के लिए hooks (`mpc_ops`) होते हैं।
- load time flags में `MPC_LOADTIME_FLAG_NOTLATE` शामिल हो सकता है, जिसका मतलब है “must be loaded early” (इसलिए late registration attempts reject कर दिए जाते हैं)।
- एक बार register होने पर, हर module को एक handle मिलता है और वह `mac_policy_list` में एक slot occupy करता है।
- जब बाद में कोई MAC hook invoke होता है (उदाहरण के लिए, vnode access, exec, etc.), तो MACF सभी registered policies पर iterate करके collective decisions लेता है।

- विशेष रूप से, **AMFI** (Apple Mobile File Integrity) ऐसा ही एक security extension है। इसके Info.plist में `AppleSecurityExtension` होता है, जो इसे एक security policy के रूप में mark करता है।
- kernel boot के हिस्से के रूप में, kernel load logic यह सुनिश्चित करता है कि कई subsystems के उस पर depend करने से पहले “security policy” (AMFI, etc.) पहले से active हो। उदाहरण के लिए, kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

जब आप ऐसा kext लिखते हैं जो MAC framework का उपयोग करता है (यानी `mac_policy_register()` आदि को कॉल करता है), तो आपको KPIs (Kernel Programming Interfaces) पर dependencies घोषित करनी होती हैं ताकि kext linker (kxld) उन symbols को resolve कर सके। इसलिए, `kext` को MACF पर depend कराने के लिए आपको इसे `Info.plist` में `com.apple.kpi.dsep` के साथ indicate करना होगा (`find . Info.plist | grep AppleSecurityExtension`), फिर kext `mac_policy_register`, `mac_policy_unregister`, और MAC hook function pointers जैसे symbols को refer करेगा। इन्हें resolve करने के लिए, आपको `com.apple.kpi.dsep` को dependency के रूप में list करना होगा।

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

आधुनिक macOS पर, Apple security policies को आमतौर पर loose standalone `.kext` bundles के रूप में नहीं देखा जाता। **macOS 11** के बाद से, kernel extensions को **kernel collections** में link किया जाता है; **Apple Silicon** पर अलग **SystemKC** नहीं होता, और third-party kexts तभी loadable बनते हैं जब उन्हें **Auxiliary Kernel Collection (AuxKC)** में build करके एक reboot किया जाए। MACF research के लिए इसका मतलब है कि built-in policies जैसे **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** या **Quarantine** आमतौर पर `kextstat` जैसे deprecated tooling की तुलना में `kmutil` से enumerate करना आसान होता है।
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

यह common है कि code में MACF के callouts **`#if CONFIG_MAC`** conditional blocks के अंदर defined मिलते हैं। इसके अलावा, इन blocks के अंदर `mac_proc_check*` के calls मिल सकते हैं, जो MACF को कुछ actions perform करने के लिए **permissions check** करने के लिए call करते हैं। इसके अलावा, MACF callouts का format है: **`mac_<object>_<opType>_opName`**।

object इनमें से एक होता है: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` आमतौर पर check होता है, जिसे action को allow या deny करने के लिए use किया जाएगा। हालांकि, `notify` भी मिल सकता है, जो kext को दिए गए action पर react करने देगा।

आप एक example [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) में पा सकते हैं:

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

फिर, `mac_file_check_mmap` का code [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) में मिल सकता है
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
जो सभी registered MAC policies पर जाकर उनकी functions को call करेगा और output को error variable में store करेगा, जिसे केवल `mac_error_select` success codes के जरिए override कर सकता है, इसलिए अगर कोई भी check fail होता है तो complete check fail होगा और action allowed नहीं होगा।

> [!TIP]
> हालांकि, याद रखें कि सभी MACF callouts सिर्फ actions को deny करने के लिए ही उपयोग नहीं होते। उदाहरण के लिए, `mac_priv_grant` macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) को call करता है, जो किसी भी policy के `0` answer देने पर requested privilege grant कर देगा:
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

ये callas [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) में defined (दर्ज) tens of **privileges** को check और provide करने के लिए हैं।\
कुछ kernel code process के KAuth credentials और privilege code में से किसी एक के साथ [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) से `priv_check_cred()` call करेगा, जो `mac_priv_check` को call करके देखेगा कि क्या कोई policy privilege देने से **deny** करती है, और फिर `mac_priv_grant` को call करेगा यह देखने के लिए कि क्या कोई policy `privilege` grant करती है।

### proc_check_syscall_unix

यह hook सभी system calls को intercept करने की अनुमति देता है। `bsd/dev/[i386|arm]/systemcalls.c` में declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) देखना संभव है, जिसमें यह code शामिल है:
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
जो calling process के **bitmask** में जांच करेगा कि current syscall को `mac_proc_check_syscall_unix` को call करना चाहिए या नहीं। ऐसा इसलिए है क्योंकि syscalls बहुत frequently call होते हैं, इसलिए हर बार `mac_proc_check_syscall_unix` को call करने से बचना दिलचस्प होता है।

ध्यान दें कि function `proc_set_syscall_filter_mask()`, जो process में bitmask syscalls सेट करता है, Sandbox द्वारा sandboxed processes पर masks सेट करने के लिए call किया जाता है।

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
ऑफेंसिव reversing के लिए, **`__mac_syscall`** अभी भी सबसे अच्छे userland chokepoints में से एक है। यह एक **policy name** (जैसे `"Sandbox"` या `"AMFI"`), एक **policy-specific selector/code**, और **opaque argument blob** के लिए pointer लेता है, जिसे `mpo_policy_syscall` द्वारा handle किया जाएगा। यह userland से undocumented operations को पहले reverse करने और बाद में kernel implementation में pivot करने के लिए बहुत उपयोगी है। Sandbox आमतौर पर इसे `__sandbox_ms` के जरिए reach करता है, और AMFI dyld policy decisions के लिए इसी mechanism का उपयोग करता है।

## Practical offensive research notes

Recent macOS bugs बहुत कम बार सीधे "MACF को break" करते हैं। इसके बजाय, वे आमतौर पर **एक MACF / Sandbox / TCC decision और बाद में होने वाली privileged action के बीच desynchronisation** का abuse करते हैं।

### Broker path checks vs real privileged action

एक recurring pattern है जहाँ एक privileged daemon पहले **userland pre-check** करता है (उदाहरण के लिए `sandbox_check_by_audit_token()`) path के एक version पर, और बाद में असली privileged sink को **different या non-canonical attacker-controlled path** के साथ execute करता है। Recent `diskarbitrationd` / `storagekitd` research इसका अच्छा example है: **directory traversal** plus **symlink swaps** attacker को daemon की sandbox validation pass करने देते हैं, और फिर `~/Library/Application Support/com.apple.TCC` जैसी sensitive locations पर mount करने देते हैं, जिससे bug चुने गए mount point के अनुसार **sandbox escape**, **local privilege escalation** या **TCC bypass** बन जाता है।

Sandbox से reachable root brokers का audit करते समय, पहले इनके लिए grep करें:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks जैसे `mount`, `rename`, `copyfile`, helper-tool XPC methods, या ऐसी कोई चीज़ जो बाद में attacker-controlled paths को root के रूप में touch करे

### Trusted deputies with private entitlements

एक और practical pattern यह है कि MACF hooks पर सीधे attack करने के बजाय एक **trusted process** का abuse किया जाए जिसके पास पहले से boundary cross करने के लिए जरूरी rights हों। Recent Safari/TCC research इसका अच्छा example है: interesting primitive "kernel में TCC disable करना" नहीं था, बल्कि local policy/configuration को modify करना था ताकि एक Apple-signed process जिसके पास **`com.apple.private.tcc.allow`** है, आपके behalf पर sensitive action perform करे। Practical तौर पर, high-value auditing targets वे Apple daemons/apps हैं जो combine करते हैं:

- **private entitlements** या FDA-like reach
- एक writable config / database / mount point / policy file
- बाद में होने वाली sensitive operation जो **Sandbox**, **AMFI**, **TCC** या किसी अन्य MACF policy द्वारा mediated हो

Deeper product-specific reversing के लिए, dedicated pages देखें: [macOS Sandbox](macos-sandbox/README.md) और [macOS TCC](macos-tcc/README.md)।

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
