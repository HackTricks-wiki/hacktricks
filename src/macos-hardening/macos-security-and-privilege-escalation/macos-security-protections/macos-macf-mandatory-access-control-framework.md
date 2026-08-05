# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** का अर्थ **Mandatory Access Control Framework** है, जो operating system में बनाया गया एक security system है और आपके computer की सुरक्षा में सहायता करता है। यह **इस बारे में सख्त rules निर्धारित करके काम करता है कि कौन या क्या system के कुछ हिस्सों**, जैसे files, applications और system resources, को access कर सकता है। इन rules को automatically लागू करके, MACF यह सुनिश्चित करता है कि केवल authorized users और processes ही specific actions कर सकें, जिससे unauthorized access या malicious activities का risk कम होता है।

ध्यान दें कि MACF वास्तव में कोई decision नहीं लेता, क्योंकि यह केवल actions को **intercept** करता है। यह decisions को **policy modules** (kernel extensions) पर छोड़ देता है, जिन्हें यह `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` और `mcxalr.kext` की तरह call करता है।

- कोई policy enforcing हो सकती है (किसी operation पर 0 non-zero return करना)
- कोई policy monitoring कर सकती है (0 return करना, ताकि आपत्ति न जताए, लेकिन कुछ करने के लिए hook पर piggyback कर सके)
- एक MACF static policy boot में install की जाती है और उसे कभी भी remove नहीं किया जाएगा
- एक MACF dynamic policy किसी KEXT (`kextload`) द्वारा install की जाती है और hypothetically उसे kextunloaded किया जा सकता है
- iOS में केवल static policies allowed हैं, जबकि macOS में static + dynamic policies allowed हैं।
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process एक syscall/mach trap perform करता है
2. Kernel के अंदर relevant function call किया जाता है
3. Function MACF को call करता है
4. MACF उन policy modules को check करता है जिन्होंने अपनी policy में उस function को hook करने का request किया था
5. MACF relevant policies को call करता है
6. Policies indicate करती हैं कि वे action को allow या deny करती हैं

> [!CAUTION]
> Apple ही एकमात्र ऐसी entity है जो MAC Framework KPI का उपयोग कर सकती है।

आमतौर पर MACF के साथ permissions check करने वाले functions macro `MAC_CHECK` को call करते हैं। जैसे socket create करने के syscall के मामले में, जो `mac_socket_check_create` function को call करेगा और यह `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` को call करता है। इसके अलावा, macro `MAC_CHECK` को security/mac_internal.h में इस प्रकार define किया गया है:<sup>[3]</sup>
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
ध्यान दें कि `check` को `socket_check_create` में और `args...` को `(cred, domain, type, protocol)` में बदलने पर आपको मिलता है:
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
helper macros को expand करने पर वास्तविक control flow दिखाई देता है:
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
दूसरे शब्दों में, `MAC_CHECK(socket_check_create, ...)` पहले static policies को देखता है, फिर conditional रूप से locks लगाकर dynamic policies पर iterate करता है, प्रत्येक hook के आसपास DTrace probes emit करता है, और `mac_error_select()` के माध्यम से प्रत्येक hook के return code को एकल `error` result में समाहित करता है।


### Labels

MACF **labels** का उपयोग करता है, जिनका उपयोग policies यह जाँचने के लिए करती हैं कि उन्हें access grant करना चाहिए या नहीं। labels struct declaration का code [यहाँ पाया जा सकता है](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), जिसे फिर [**यहाँ**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) मौजूद **`struct ucred`** के अंदर **`cr_label`** भाग में उपयोग किया जाता है। label में flags और **slots** की एक संख्या होती है, जिनका उपयोग **MACF policies pointers allocate करने के लिए** कर सकती हैं। उदाहरण के लिए, Sanbox container profile की ओर point करेगा।

## MACF Policies

एक MACF Policy कुछ kernel operations में लागू किए जाने वाले **rules और conditions को define करती है**।

एक kernel extension `mac_policy_conf` struct को configure कर सकता है और फिर `mac_policy_register` को call करके उसे register कर सकता है। [यहाँ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) से:<sup>[1]</sup>
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
इन policies को configure करने वाले kernel extensions की पहचान `mac_policy_register` को किए गए calls की जाँच करके आसानी से की जा सकती है। इसके अलावा, extension के disassemble की जाँच करके इस्तेमाल किए गए `mac_policy_conf` struct को भी ढूँढना संभव है।

ध्यान दें कि MACF policies को **dynamically** register और unregister भी किया जा सकता है।

`mac_policy_conf` के मुख्य fields में से एक **`mpc_ops`** है। यह field बताती है कि policy किन operations में interested है। ध्यान दें कि ऐसे hundreds of operations होते हैं, इसलिए इन सभी को zero करना और फिर केवल उन operations को select करना संभव है जिनमें policy interested है। [यहाँ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) से:<sup>[1]</sup>
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
लगभग सभी hooks को MACF द्वारा वापस call किया जाएगा, जब उन operations में से किसी को intercept किया जाएगा। हालांकि, **`mpo_policy_*`** hooks एक exception हैं, क्योंकि **`mpo_hook_policy_init()`** registration के समय call किया जाने वाला callback है (इसलिए **`mac_policy_register()`** के बाद), और **`mpo_hook_policy_initbsd()`** late registration के दौरान call किया जाता है, जब BSD subsystem ठीक से initialise हो चुका होता है।

इसके अलावा, **`mpo_policy_syscall`** hook को कोई भी kext एक private **ioctl** style call **interface** expose करने के लिए register कर सकता है। इसके बाद, एक user client parameters के रूप में **policy name**, एक integer **code** और optional **arguments** specify करके `mac_syscall` (#381) call कर सकेगा।\
उदाहरण के लिए, **`Sandbox.kext`** इसका बहुत अधिक उपयोग करता है।

kext के **`__DATA.__const*`** को check करके policy register करते समय उपयोग की जाने वाली `mac_policy_ops` structure की पहचान करना संभव है। इसे ढूंढना संभव है, क्योंकि इसका pointer **`mpo_policy_conf`** के अंदर एक offset पर होता है और इसलिए भी क्योंकि उस area में NULL pointers की संख्या मौजूद होगी।

इसके अलावा, memory से **`_mac_policy_list`** struct को dump करके उन kexts की list प्राप्त करना भी संभव है, जिन्होंने कोई policy configure की है। यह struct register की जाने वाली प्रत्येक policy के साथ update होता है।

आप system में registered सभी policies को dump करने के लिए `xnoop` tool का भी उपयोग कर सकते हैं:
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
और फिर check policy की सभी checks को dump करें:
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

- MACF बहुत जल्द initialised हो जाता है। `bootstrap_thread` (XNU startup code में) में, `ipc_bootstrap` के बाद, XNU `mac_policy_init()` (`mac_base.c` में) को call करता है।
- `mac_policy_init()` global `mac_policy_list` (policy slots की array या list) को initialize करता है और XNU के भीतर MAC (Mandatory Access Control) के लिए infrastructure तैयार करता है।
- बाद में `mac_policy_initmach()` invoke किया जाता है, जो built-in या bundled policies के लिए policy registration के kernel side को संभालता है।

### `mac_policy_initmach()` और “security extensions” को load करना

- `mac_policy_initmach()` उन kernel extensions (kexts) की जांच करता है जो पहले से preload हैं (या “policy injection” list में हैं) और उनके Info.plist में `AppleSecurityExtension` key को inspect करता है।
- जिन kexts के Info.plist में `<key>AppleSecurityExtension</key>` (या `true`) घोषित होता है, उन्हें “security extensions” माना जाता है — यानी ऐसे extensions जो MAC policy implement करते हैं या MACF infrastructure में hook करते हैं।
- इस key वाले Apple kexts के उदाहरणों में **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** और अन्य शामिल हैं (जैसा कि आपने पहले सूचीबद्ध किया था)।
- Kernel यह सुनिश्चित करता है कि ये kexts जल्दी load हों, फिर boot के दौरान उनकी registration routines (via `mac_policy_register`) को call करता है और उन्हें `mac_policy_list` में insert करता है।

- प्रत्येक policy module (kext) एक `mac_policy_conf` structure प्रदान करता है, जिसमें विभिन्न MAC operations (vnode checks, exec checks, label updates आदि) के लिए hooks (`mpc_ops`) होते हैं।
- Load time flags में `MPC_LOADTIME_FLAG_NOTLATE` शामिल हो सकता है, जिसका अर्थ है “जल्दी load होना आवश्यक है” (इसलिए बाद में किए गए registration attempts reject कर दिए जाते हैं)।
- Register होने के बाद, प्रत्येक module को एक handle मिलता है और वह `mac_policy_list` में एक slot occupy करता है।
- बाद में जब कोई MAC hook invoke होता है (उदाहरण के लिए, vnode access, exec आदि), तो MACF सभी registered policies को iterate करके collective decisions लेता है।

- विशेष रूप से, **AMFI** (Apple Mobile File Integrity) ऐसा ही एक security extension है। इसके Info.plist में `AppleSecurityExtension` शामिल होता है, जो इसे security policy के रूप में mark करता है।
- Kernel boot के दौरान, kernel load logic यह सुनिश्चित करता है कि कई subsystems के उस पर निर्भर होने से पहले “security policy” (AMFI आदि) पहले से active हो। उदाहरण के लिए, kernel “tasks के लिए पहले से तैयारी करते हुए … security policy, जिसमें AppleMobileFileIntegrity (AMFI), Sandbox और Quarantine policy शामिल हैं,” को load करता है।
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
## MAC policy kexts में KPI dependency और com.apple.kpi.dsep

MAC framework का उपयोग करने वाला kext लिखते समय (जैसे `mac_policy_register()` आदि को call करना), आपको KPIs (Kernel Programming Interfaces) पर dependencies घोषित करनी होंगी, ताकि kext linker (kxld) उन symbols को resolve कर सके। इसलिए किसी `kext` को MACF पर निर्भर घोषित करने के लिए आपको इसे `Info.plist` में `com.apple.kpi.dsep` के साथ indicate करना होगा (`find . Info.plist | grep AppleSecurityExtension`), जिसके बाद kext `mac_policy_register`, `mac_policy_unregister` और MAC hook function pointers जैसे symbols को refer करेगा। इन्हें resolve करने के लिए आपको `com.apple.kpi.dsep` को dependency के रूप में list करना होगा।

Example Info.plist snippet (अपने .kext के अंदर):
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
## आधुनिक macOS releases पर MACF

आधुनिक macOS पर Apple security policies को आमतौर पर अलग-अलग loose `.kext` bundles के रूप में देखना सबसे उपयुक्त तरीका नहीं है। **macOS 11** से kernel extensions को **kernel collections** में link किया जाता है; **Apple Silicon** पर अलग **SystemKC** नहीं होता, और third-party kexts केवल **Auxiliary Kernel Collection (AuxKC)** में build किए जाने और reboot के बाद ही loadable बनते हैं। MACF research के लिए इसका अर्थ है कि **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** या **Quarantine** जैसी built-in policies को deprecated tooling जैसे `kextstat` की तुलना में `kmutil` से enumerate करना आमतौर पर आसान होता है।
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Apple Silicon पर, यदि कोई security kext BootKC में नहीं है, तो अगला check AuxKC में करें। यह `/System/Library/Extensions` के अंतर्गत standalone bundle खोजने से आमतौर पर अधिक उपयोगी होता है।

## MACF Callouts

कोड में **`#if CONFIG_MAC`** conditional blocks के रूप में परिभाषित MACF के callouts मिलना आम है। इसके अलावा, इन blocks के अंदर `mac_proc_check*` के calls मिल सकते हैं, जो कुछ actions को करने की **permissions check** करने के लिए MACF को call करते हैं। MACF callouts का format इस प्रकार होता है: **`mac_<object>_<opType>_opName`**।

Object निम्न में से कोई एक होता है: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`।\
`opType` आमतौर पर check होता है, जिसका उपयोग action को allow या deny करने के लिए किया जाता है। हालांकि, `notify` भी मिल सकता है, जो kext को दिए गए action पर react करने की अनुमति देता है।

आप इसका एक example [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) में देख सकते हैं:

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

इसके बाद, [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) में `mac_file_check_mmap` का code मिल सकता है।
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
जो `MAC_CHECK` macro को call करता है, जिसका code [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[3]</sup> पर पाया जा सकता है।
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
जो सभी registered mac policies पर जाकर उनके functions को call करेगा और output को `error` variable में store करेगा। इसे केवल `mac_error_select` द्वारा success codes के माध्यम से override किया जा सकेगा; इसलिए यदि कोई भी check fail होता है, तो पूरा check fail हो जाएगा और action को allow नहीं किया जाएगा।

> [!TIP]
> हालांकि, याद रखें कि सभी MACF callouts का उपयोग केवल actions को deny करने के लिए नहीं किया जाता। उदाहरण के लिए, `mac_priv_grant` macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) को call करता है, जो requested privilege को grant कर देगा यदि कोई भी policy 0 के साथ उत्तर देती है:
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

इन callouts का उद्देश्य [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) में defined दर्जनों **privileges** को check और provide करना है।\
कुछ kernel code process के KAuth credentials और privilege codes में से किसी एक को लेकर [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) से `priv_check_cred()` call करेगा। यह `mac_priv_check` को call करके देखेगा कि कोई policy privilege देने से **deny** तो नहीं करती, और फिर यह देखने के लिए `mac_priv_grant` call करेगा कि कोई policy `privilege` grant करती है या नहीं।<sup>[4]</sup>

### proc_check_syscall_unix

यह hook सभी system calls को intercept करने की अनुमति देता है। `bsd/dev/[i386|arm]/systemcalls.c` में declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) देखना संभव है, जिसमें यह code है:
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
जो calling process के **bitmask** में जाँच करेगा कि current syscall को `mac_proc_check_syscall_unix` call करना चाहिए या नहीं। ऐसा इसलिए है क्योंकि syscalls बहुत frequently call की जाती हैं, इसलिए हर बार `mac_proc_check_syscall_unix` को call करने से बचना उपयोगी है।

ध्यान दें कि function `proc_set_syscall_filter_mask()`, जो किसी process में syscalls का bitmask set करता है, Sandbox द्वारा sandboxed processes पर masks set करने के लिए call किया जाता है।

## Exposed MACF syscalls

कुछ syscalls के माध्यम से MACF के साथ interact करना संभव है, जो [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) में defined हैं:
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
Offensive reversing के लिए, **`__mac_syscall`** अभी भी सबसे अच्छे userland chokepoints में से एक है। इसमें एक **policy name** (उदाहरण के लिए `"Sandbox"` या `"AMFI"`), एक **policy-specific selector/code`, और **opaque argument blob** का pointer होता है, जिसे `mpo_policy_syscall` handle करेगा। यह userland से undocumented operations को पहले reverse करने और केवल बाद में kernel implementation की ओर pivot करने में बहुत उपयोगी है। Sandbox आमतौर पर इसे `__sandbox_ms` के माध्यम से call करता है, और AMFI dyld policy decisions के लिए इसी mechanism का उपयोग करता है।<sup>[2][5]</sup>

## Practical offensive research notes

Recent macOS bugs शायद ही कभी सीधे "MACF को break" करते हैं। इसके बजाय, वे आमतौर पर **MACF / Sandbox / TCC decision और बाद में होने वाली privileged action के बीच desynchronisation** का दुरुपयोग करते हैं।

### Broker path checks vs real privileged action

एक recurring pattern में privileged daemon किसी path के एक version पर **userland pre-check** करता है (उदाहरण के लिए `sandbox_check_by_audit_token()`), और बाद में किसी **different या non-canonical attacker-controlled path** के साथ वास्तविक privileged sink execute करता है। हालिया `diskarbitrationd` / `storagekitd` research इसका अच्छा उदाहरण है: **directory traversal** और **symlink swaps** attacker को daemon की sandbox validation पास करने देते हैं और फिर `~/Library/Application Support/com.apple.TCC` जैसे sensitive locations पर mount करने देते हैं। इससे चुने गए mount point के आधार पर bug **sandbox escape**, **local privilege escalation** या **TCC bypass** में बदल जाता है।<sup>[6]</sup>

Sandbox से reachable root brokers का auditing करते समय, पहले इन पर grep करें:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks जैसे `mount`, `rename`, `copyfile`, helper-tool XPC methods, या ऐसी कोई भी चीज़ जो बाद में attacker-controlled paths को root के रूप में touch करती हो

### Trusted deputies with private entitlements

एक अन्य practical pattern MACF hooks पर सीधे हमला करने से बचना और इसके बजाय ऐसे **trusted process** का दुरुपयोग करना है, जिसके पास boundary पार करने के लिए आवश्यक rights पहले से मौजूद हों। हालिया Safari/TCC research इसका अच्छा उदाहरण है: महत्वपूर्ण primitive "kernel में TCC disable करना" नहीं था, बल्कि local policy/configuration को इस तरह modify करना था कि **`com.apple.private.tcc.allow`** वाला Apple-signed process आपकी ओर से sensitive action perform करे। व्यवहार में, high-value auditing targets वे Apple daemons/apps हैं जो इन चीज़ों को combine करते हैं:

- **private entitlements** या FDA-like reach
- एक writable config / database / mount point / policy file
- बाद में होने वाला sensitive operation, जिसे **Sandbox**, **AMFI**, **TCC** या किसी अन्य MACF policy द्वारा mediate किया जाता है

Product-specific reversing की अधिक गहराई के लिए [macOS Sandbox](macos-sandbox/README.md) और [macOS TCC](macos-tcc/README.md) के dedicated pages देखें।

## References

- [1] [XNU — `security/mac_policy.h` (full MACF policy operations vector)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (privilege codes used by `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
