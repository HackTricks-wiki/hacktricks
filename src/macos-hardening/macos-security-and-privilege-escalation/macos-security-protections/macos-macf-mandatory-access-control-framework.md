# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** का पूरा नाम **Mandatory Access Control Framework** है, जो ऑपरेटिंग सिस्टम में बना एक security सिस्टम है और आपके कंप्यूटर की सुरक्षा में मदद करता है। यह सिस्टम सिस्टम के कुछ हिस्सों तक — जैसे फाइलें, applications, और system resources — किसे या क्या को access करने की अनुमति है, इसके बारे में सख्त नियम सेट करके काम करता है। इन नियमों को स्वतः लागू करके, MACF सुनिश्चित करता है कि केवल अधिकृत users और processes ही विशिष्ट actions कर सकें, जिससे unauthorized access या malicious गतिविधियों का जोखिम घटता है।

नोट करें कि MACF खुद निर्णय नहीं लेता; यह केवल actions को intercept करता है और निर्णय उन policy modules (kernel extensions) को छोड़ देता है जिन्हें यह कॉल करता है, जैसे `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` और `mcxalr.kext`।

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- एक MACF static policy बूट के समय इंस्टॉल होती है और कभी हटाई नहीं जा सकती
- एक MACF dynamic policy को एक KEXT (kextload) द्वारा इंस्टॉल किया जाता है और सिद्धांततः इसे kextunload किया जा सकता है
- iOS में केवल static policies की अनुमति है और macOS में static + dynamic दोनों
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process एक syscall/mach trap करता है
2. संबंधित function kernel के अंदर बुलाया जाता है
3. Function MACF को कॉल करता है
4. MACF उन policy modules की जाँच करता है जिन्होंने अपनी policy में उस function को hook करने का अनुरोध किया है
5. MACF संबंधित policies को कॉल करता है
6. Policies यह संकेत देती हैं कि वे action की अनुमति देती हैं या deny करती हैं

> [!CAUTION]
> Apple ही एकमात्र है जो MAC Framework KPI का उपयोग कर सकती है।

आमतौर पर MACF के साथ permissions की जांच करने वाले functions macro `MAC_CHECK` को कॉल करेंगे। जैसे कि socket बनाने के syscall के मामले में जो उस function को कॉल करेगा जो `mac_socket_check_create` है और वह `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` को कॉल करता है। इसके अलावा, macro `MAC_CHECK` को security/mac_internal.h में परिभाषित किया गया है:
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
हेल्पर मैक्रो का विस्तार ठोस नियंत्रण प्रवाह दिखाता है:
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
दूसरे शब्दों में, `MAC_CHECK(socket_check_create, ...)` सबसे पहले स्थैतिक नीतियों को चलाता है, आवश्यकता के अनुसार गतिशील नीतियों को लॉक करके उन पर इटरेट करता है, प्रत्येक hook के चारों ओर DTrace probes को जारी करता है, और प्रत्येक hook के return code को `mac_error_select()` के माध्यम से एकल `error` परिणाम में समेकित कर देता है।

### लेबल्स

MACF ऐसे **लेबल्स** का उपयोग करता है जिन्हें नीतियाँ यह तय करने के लिए प्रयोग करती हैं कि उन्हें किसी एक्सेस की अनुमति देनी चाहिए या नहीं। labels struct declaration का कोड [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), जो फिर **`struct ucred`** के अंदर [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) में **`cr_label`** हिस्से में उपयोग किया जाता है। लेबल में फ्लैग्स और कुछ संख्या में **slots** होते हैं जिन्हें **MACF policies** पॉइंटर आवंटित करने के लिए उपयोग कर सकती हैं। उदाहरण के लिए Sanbox container profile की ओर संकेत करेगा

## MACF नीतियाँ

एक MACF Policy विशेष kernel operations में लागू किए जाने वाले **नियम और शर्तें** को परिभाषित करती है।

एक kernel extension `mac_policy_conf` struct को कॉन्फ़िगर कर सकता है और फिर `mac_policy_register` को कॉल करके इसे रजिस्टर कर सकता है। From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
इन नीतियों को कॉन्फ़िगर करने वाले kernel extensions की पहचान `mac_policy_register` कॉल्स की जाँच करके करना आसान है। इसके अलावा, extension के disassemble की जाँच करके यह भी पता लगाया जा सकता है कि कौन सा `mac_policy_conf` struct उपयोग किया गया है।

Note that MACF policies can be registered and unregistered also **dynamically**.

`mac_policy_conf` के मुख्य फ़ील्ड्स में से एक **`mpc_ops`** है। यह फ़ील्ड निर्दिष्ट करता है कि नीति किन operations में रुचि रखती है। ध्यान दें कि उनकी सैकड़ों एंट्रीज़ हो सकती हैं, इसलिए इन्हें पूरी तरह zero करके केवल उन्हीं को चुना जा सकता है जिनमें नीति रुचि रखती है। From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Almost all the hooks will be called back by MACF when one of those operations are intercepted. However, **`mpo_policy_*`** hooks are an exception because `mpo_hook_policy_init()` is a callback called upon registration (so after `mac_policy_register()`) and `mpo_hook_policy_initbsd()` is called during late registration once the BSD subsystem has initialised properly.

हालाँकि, **`mpo_policy_*`** hooks एक अपवाद हैं क्योंकि `mpo_hook_policy_init()` एक callback है जो registration पर कॉल होता है (यानी `mac_policy_register()` के बाद) और `mpo_hook_policy_initbsd()` लेट registration के दौरान तब कॉल होता है जब BSD subsystem सही तरह से initialise हो चुका होता है।

Moreover, the **`mpo_policy_syscall`** hook can be registered by any kext to expose a private **ioctl** style call **interface**. Then, a user client will be able to call `mac_syscall` (#381) specifying as parameters the **policy name** with an integer **code** and optional **arguments**.\
For example, the **`Sandbox.kext`** uses this a lot.

इसके अलावा, **`mpo_policy_syscall`** hook को किसी भी kext द्वारा रजिस्टर किया जा सकता है ताकि एक private **ioctl** style call **interface** expose किया जा सके। फिर, एक user client `mac_syscall` (#381) को कॉल कर सकेगा जिसमें parameters के रूप में **policy name**, एक integer **code** और वैकल्पिक **arguments** दिए जाएंगे।\
उदाहरण के लिए, **`Sandbox.kext`** इसका बहुत उपयोग करती है।

Checking the kext's **`__DATA.__const*`** is possible to identify the `mac_policy_ops` structure used when registering the policy. It's possible to find it because its pointer is at an offset inside `mpo_policy_conf` and also because the amount of NULL pointers that will be in that area.

kext के **`__DATA.__const*`** की जाँच करके उस `mac_policy_ops` structure की पहचान करना संभव है जो policy रजिस्टर करने के लिए उपयोग होता है। इसे ढूँढना इसलिए आसान होता है क्योंकि इसका pointer `mpo_policy_conf` के अंदर एक offset पर होता है और उस क्षेत्र में मौजूद NULL pointers की संख्या से भी यह पता चलता है।

Moreover, it's also possible to get the list of kexts that have configured a policy by dumping from memory the struct **`_mac_policy_list`** which is updated with every policy that is registered.

इसके अलावा, उन kexts की सूची भी प्राप्त की जा सकती है जिन्होंने policy configure की है, memory से struct **`_mac_policy_list`** को dump करके, जिसे हर रजिस्टर हुई policy के साथ update किया जाता है।

You could also use the tool `xnoop` to dump all the policies registered in the system:

आप system में रजिस्टर सभी policies को dump करने के लिए tool `xnoop` का भी उपयोग कर सकते हैं:
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
और फिर check policy के सभी checks को इस कमांड के साथ dump करें:
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
## XNU में MACF का आरंभ

### प्रारंभिक bootstrap और `mac_policy_init()`

- MACF बहुत जल्द आरंभ हो जाता है। `bootstrap_thread` (XNU startup code में), `ipc_bootstrap` के बाद, XNU `mac_policy_init()` (`mac_base.c` में) को कॉल करता है।
- `mac_policy_init()` वैश्विक `mac_policy_list` (नीतियों के स्लॉट का एक array या list) को आरंभ करता है और XNU के भीतर MAC (Mandatory Access Control — अनिवार्य पहुँच नियंत्रण) के लिए इंफ्रास्ट्रक्चर सेटअप करता है।
- बाद में, `mac_policy_initmach()` को बुलाया जाता है, जो built-in या bundled नीतियों के लिए kernel पक्ष पर policy registration को संभालता है।

### `mac_policy_initmach()` और “security extensions” का लोड होना

- `mac_policy_initmach()` उन kernel extensions (kexts) की जांच करता है जो preloaded हैं (या “policy injection” list में हैं) और उनके Info.plist में key `AppleSecurityExtension` के लिए देखता है।
- वे kexts जो अपने Info.plist में `<key>AppleSecurityExtension</key>` (या `true`) घोषित करते हैं उन्हें “security extensions” माना जाता है — यानी ऐसे kexts जो MAC policy को लागू करते हैं या MACF इंफ्रास्ट्रक्चर में hook करते हैं।
- उस key वाले Apple kexts के उदाहरणों में **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** शामिल हैं, आदि (जैसा आपने पहले सूचीबद्ध किया)।
- kernel यह सुनिश्चित करता है कि वे kexts जल्दी लोड हों, फिर boot के दौरान उनके registration routines (`mac_policy_register` के माध्यम से) को कॉल करता है और उन्हें `mac_policy_list` में डाल देता है।

- प्रत्येक policy module (kext) एक `mac_policy_conf` structure प्रदान करता है, जिसमें विभिन्न MAC operations (vnode checks, exec checks, label updates, आदि) के लिए hooks (`mpc_ops`) होते हैं।
- लोड टाइम flags में `MPC_LOADTIME_FLAG_NOTLATE` शामिल हो सकता है, जिसका अर्थ है “must be loaded early” (ताकि देर से registration प्रयासों को अस्वीकार किया जा सके)।
- एक बार register होने पर, हर module को एक handle मिलता है और वह `mac_policy_list` में एक स्लॉट ले लेता है।
- जब बाद में कोई MAC hook invoke होता है (उदाहरण के लिए, vnode access, exec, आदि), तो MACF समस्त registered policies पर iterate करके सामूहिक निर्णय लेता है।

- विशेष रूप से, **AMFI** (Apple Mobile File Integrity) एक ऐसा security extension है। इसके Info.plist में `AppleSecurityExtension` शामिल है जो इसे security policy के रूप में चिन्हित करता है।
- kernel boot के हिस्से के रूप में, kernel का load logic यह सुनिश्चित करता है कि “security policy” (AMFI आदि) कई सबसिस्टम्स उसके ऊपर निर्भर होने से पहले ही सक्रिय हो। उदाहरण के लिए, kernel “आगे के कार्यों के लिए तैयार होने हेतु … security policy को लोड करता है, जिसमें AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy शामिल हैं।”
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
## KPI निर्भरता और com.apple.kpi.dsep MAC policy kexts में

जब आप ऐसा `kext` लिखते हैं जो MAC framework का उपयोग करता है (जैसे `mac_policy_register()` आदि को कॉल करना), तो आपको KPIs (Kernel Programming Interfaces) पर निर्भरता घोषित करनी चाहिए ताकि kext linker (kxld) उन symbols को resolve कर सके। इसलिए किसी `kext` को MACF पर निर्भर घोषित करने के लिए आपको इसे `Info.plist` में `com.apple.kpi.dsep` के रूप में संकेत करना होगा (`find . Info.plist | grep AppleSecurityExtension`)। इसके बाद kext उन symbols को संदर्भित करेगा जैसे `mac_policy_register`, `mac_policy_unregister`, और MAC hook function pointers. इन्हें resolve करने के लिए आपको `com.apple.kpi.dsep` को dependency के रूप में सूचीबद्ध करना होगा।

उदाहरण Info.plist स्निपेट (आपके `.kext` के अंदर):
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
## MACF कॉलआउट्स

कोड में MACF के कॉलआउट्स मिलना आम है, जैसे: **`#if CONFIG_MAC`** conditional blocks. इसके अलावा, इन ब्लॉक्स के अंदर `mac_proc_check*` जैसी कॉलें मिल सकती हैं जो MACF को कुछ क्रियाएँ करने के लिए **अनुमति की जाँच** करने के लिए कॉल करती हैं। इसके अलावा, MACF कॉलआउट्स का फॉर्मैट होता है: **`mac_<object>_<opType>_opName`**.

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

फिर, आप `mac_file_check_mmap` का कोड यहाँ पा सकते हैं: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
जो `MAC_CHECK` macro को कॉल कर रहा है, जिसका कोड [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) में पाया जा सकता है
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
>    });                                                             \
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
यह कॉलिंग प्रोसेस के **bitmask** में जाँच करेगा कि क्या वर्तमान syscall को `mac_proc_check_syscall_unix` कॉल करना चाहिए। यह इसलिए है क्योंकि syscalls इतनी बार कॉल होते हैं कि हर बार `mac_proc_check_syscall_unix` को कॉल करने से बचना उपयोगी होता है।

ध्यान दें कि फ़ंक्शन `proc_set_syscall_filter_mask()`, जो किसी प्रोसेस में bitmask syscalls सेट करता है, को Sandbox द्वारा sandboxed processes पर मास्क सेट करने के लिए कॉल किया जाता है।

## प्रदर्शित MACF syscalls

MACF के साथ कुछ syscalls के माध्यम से इंटरैक्ट करना संभव है जो [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) में परिभाषित हैं:
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
## संदर्भ

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
