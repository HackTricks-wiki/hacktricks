# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** stands for **Mandatory Access Control Framework**, जो ऑपरेटिंग सिस्टम में एक सुरक्षा प्रणाली है जो आपके कंप्यूटर की सुरक्षा में मदद करती है। यह सिस्टम के कुछ हिस्सों के लिए यह तय करके काम करता है कि किसे या क्या को पहुँच मिल सकती है — जैसे फ़ाइलें, ऐप्लिकेशन और सिस्टम संसाधन — और इन पर कड़े नियम लागू करता है। इन नियमों को स्वचालित रूप से लागू करके, MACF सुनिश्चित करता है कि केवल अधिकृत उपयोगकर्ता और प्रक्रियाएँ ही विशिष्ट क्रियाएँ कर सकें, जिससे अनधिकृत पहुँच या दुर्भावनापूर्ण गतिविधियों का जोखिम कम होता है।

ध्यान दें कि MACF वास्तव में कोई निर्णय नहीं लेता क्योंकि यह केवल क्रियाओं पर **हस्तक्षेप** करता है; निर्णय उन **पॉलिसी मॉड्यूल्स** (kernel extensions) को छोड़ देता है जिन्हें यह कॉल करता है, जैसे `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` और `mcxalr.kext`।

- एक पॉलिसी लागू करने वाली (enforcing) हो सकती है (कुछ ऑपरेशनों पर 0 या non-zero रिटर्न कर सकती है)
- एक पॉलिसी मॉनिटरिंग (monitoring) भी हो सकती है (0 लौटाती है, ताकि आपत्ति न करे पर hook का उपयोग कर कुछ किया जा सके)
- एक MACF static पॉलिसी बूट पर इंस्टॉल होती है और इसे NEVER हटाया जाएगा
- एक MACF dynamic पॉलिसी KEXT द्वारा इंस्टॉल होती है (kextload) और सैद्धांतिक रूप से kextunloaded हो सकती है
- iOS में केवल static पॉलिसियाँ अनुमति है और macOS में static + dynamic दोनों
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process एक syscall/mach trap करता है
2. संबंधित फ़ंक्शन kernel के अंदर कॉल किया जाता है
3. फ़ंक्शन MACF को कॉल करता है
4. MACF उन policy modules को चेक करता है जिन्होंने अपनी पॉलिसी में उस फ़ंक्शन को hook करने का अनुरोध किया था
5. MACF संबंधित पॉलिसियों को कॉल करता है
6. पॉलिसियाँ संकेत देती हैं कि वे उस क्रिया की अनुमति देती हैं या अस्वीकार करती हैं

> [!CAUTION]
> Apple ही एकमात्र है जो MAC Framework KPI का उपयोग कर सकता है।

आमतौर पर MACF के साथ permissions चेक करने वाले फ़ंक्शन macro `MAC_CHECK` को कॉल करते हैं। उदाहरण के लिए socket बनाने के syscall के मामले में वह उस फ़ंक्शन को कॉल करेगा जो `mac_socket_check_create` है, जो `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` को कॉल करता है। इसके अलावा, macro `MAC_CHECK` को security/mac_internal.h में इस तरह परिभाषित किया गया है:
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
ध्यान दें कि `check` को `socket_check_create` में बदलने और `args...` को `(cred, domain, type, protocol)` में रखने पर आपको मिलता है:
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
helper macros का विस्तार करने पर concrete control flow दिखता है:
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
In other words, `MAC_CHECK(socket_check_create, ...)` पहले static नीतियों पर चलता है, शर्तानुसार dynamic नीतियों को लॉक और iterate करता है, हर hook के चारों ओर DTrace probes emit करता है, और हर hook के return code को `mac_error_select()` के माध्यम से एक ही `error` परिणाम में समाहित कर देता है।


### Labels

MACF **लेबल्स** का उपयोग करता है जिन्हें फिर नीतियाँ यह जाँचने के लिए प्रयोग करती हैं कि उन्हें किसी access को अनुमति देनी चाहिए या नहीं। labels struct declaration का कोड [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), जिसे बाद में **`struct ucred`** के अंदर [**यहाँ**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`cr_label`** भाग में उपयोग किया जाता है। label में flags और कुछ **slots** होते हैं जिन्हें **MACF policies to allocate pointers** के लिए उपयोग किया जा सकता है। उदाहरण के लिए Sanbox container profile की ओर पॉइंटर करेगा

## MACF Policies

A MACF Policy कुछ kernel operations में लागू होने वाले नियम और शर्तें परिभाषित करता है।

एक kernel extension `mac_policy_conf` struct को configure कर सकता है और फिर उसे `mac_policy_register` को कॉल करके register कर सकता है। From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
इन नीतियों को कॉन्फ़िगर करने वाले kernel extensions की पहचान `mac_policy_register` कॉल्स की जाँच करके आसानी से की जा सकती है। इसके अलावा, extension की डिसअसेंबली जाँचने से उपयोग किए गए `mac_policy_conf` struct को भी पाया जा सकता है।

ध्यान दें कि MACF policies को **डायनामिक रूप से** रजिस्टर और अनरजिस्टर भी किया जा सकता है।

`mac_policy_conf` के मुख्य फील्ड्स में से एक **`mpc_ops`** है। यह फ़ील्ड बताती है कि नीति किन ऑपरेशनों में रुचि रखती है। ध्यान दें कि इनमें सैकड़ों ऑपरेशन होते हैं, इसलिए इन्हें सभी को शून्य करना और फिर केवल उन ऑपरेशनों को चुनना संभव है जिनमें नीति रुचि रखती है। From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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

उनमें से किसी ऑपरेशन के इंटरसेप्ट होने पर लगभग सभी hooks को MACF द्वारा वापस कॉल किया जाएगा। हालांकि, **`mpo_policy_*`** hooks अपवाद हैं क्योंकि `mpo_hook_policy_init()` एक callback है जो registration के समय (यानी `mac_policy_register()` के बाद) बुलाया जाता है और `mpo_hook_policy_initbsd()` लेट रजिस्ट्रेशन के दौरान तब बुलाया जाता है जब BSD सबसिस्टम ठीक से initialise हो चुका होता है।

Moreover, the **`mpo_policy_syscall`** hook can be registered by any kext to expose a private **ioctl** style call **interface**. Then, a user client will be able to call `mac_syscall` (#381) specifying as parameters the **policy name** with an integer **code** and optional **arguments**.\
For example, the **`Sandbox.kext`** uses this a lot.

इसके अलावा, **`mpo_policy_syscall`** hook को किसी भी kext द्वारा रजिस्टर किया जा सकता है ताकि एक निजी **ioctl** style कॉल **interface** एक्सपोज़ किया जा सके। फिर, एक user client `mac_syscall` (#381) को कॉल कर सकेगा, जिसमें parameters के रूप में **policy name**, एक integer **code** और वैकल्पिक **arguments** दिए जा सकते हैं।\
उदाहरण के लिए, **`Sandbox.kext`** इसका बहुत उपयोग करता है।

Checking the kext's **`__DATA.__const*`** is possible to identify the `mac_policy_ops` structure used when registering the policy. It's possible to find it because its pointer is at an offset inside `mpo_policy_conf` and also because the amount of NULL pointers that will be in that area.

kext के **`__DATA.__const*`** की जांच करके उस `mac_policy_ops` संरचना की पहचान की जा सकती है जिसका उपयोग policy रजिस्टर करते समय किया गया था। इसे ढूँढना संभव है क्योंकि इसका pointer `mpo_policy_conf` के अंदर एक offset पर होता है और उस क्षेत्र में मौजूद NULL pointers की संख्या से भी पहचान होती है।

Moreover, it's also possible to get the list of kexts that have configured a policy by dumping from memory the struct **`_mac_policy_list`** which is updated with every policy that is registered.

इसके अलावा, मैमोरी से struct **`_mac_policy_list`** को dump करके उन kexts की सूची भी प्राप्त की जा सकती है जिन्होंने policy configure की है, क्योंकि यह हर रजिस्टर की गई policy के साथ update होता है।

You could also use the tool `xnoop` to dump all the policies registered in the system:

आप सिस्टम में रजिस्टर की गई सभी policies को dump करने के लिए tool `xnoop` का भी उपयोग कर सकते हैं:
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
और फिर check policy के सभी checks को dump करें:
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
## XNU में MACF इनिशियलाइज़ेशन

### प्रारम्भिक bootstrap और mac_policy_init()

- MACF बहुत जल्द इनिशियलाइज़ हो जाता है। `bootstrap_thread` (XNU startup code में), `ipc_bootstrap` के बाद, XNU `mac_policy_init()` (`mac_base.c` में) को कॉल करता है।
- `mac_policy_init()` global `mac_policy_list` (policy slots की एक array या list) को इनिशियलाइज़ करता है और XNU के भीतर MAC (अनिवार्य पहुँच नियंत्रण - Mandatory Access Control) के लिए इंफ्रास्ट्रक्चर सेटअप करता है।
- बाद में, `mac_policy_initmach()` को इनवोक किया जाता है, जो built-in या bundled policies के लिए kernel पक्ष पर policy registration को संभालता है।

### `mac_policy_initmach()` और लोड करना “security extensions”

- `mac_policy_initmach()` उन kernel extensions (kexts) की जाँच करता है जो preloaded हैं (या एक “policy injection” सूची में हैं) और उनके Info.plist में key `AppleSecurityExtension` के लिए निरीक्षण करता है।
- वे kexts जो अपने Info.plist में `<key>AppleSecurityExtension</key>` (या `true`) घोषित करते हैं, उन्हें “security extensions” माना जाता है — यानी वे जो MAC policy को implement करते हैं या MACF इंफ्रास्ट्रक्चर में hook करते हैं।
- उस key वाले Apple kexts के उदाहरणों में **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** आदि शामिल हैं (जैसा आपने पहले सूचीबद्ध किया था)।
- Kernel यह सुनिश्चित करता है कि वे kexts जल्दी लोड हों, फिर boot के दौरान उनके registration routines (`mac_policy_register` के माध्यम से) को कॉल करता है और उन्हें `mac_policy_list` में डालता है।

- प्रत्येक policy module (kext) एक `mac_policy_conf` structure प्रदान करता है, जिसमें विभिन्न MAC operations (vnode checks, exec checks, label updates, आदि) के लिए hooks (`mpc_ops`) होते हैं।
- load time flags में `MPC_LOADTIME_FLAG_NOTLATE` शामिल हो सकता है जिसका अर्थ है “must be loaded early” (ताकि देर से होने वाले registration प्रयास अस्वीकार कर दिए जाएं)।
- एक बार register हो जाने पर, प्रत्येक module को एक handle मिलता है और वह `mac_policy_list` में एक slot लेता है।
- जब बाद में कोई MAC hook invoke होता है (उदाहरण के लिए, vnode access, exec, आदि), तो MACF सामूहिक निर्णय लेने के लिए सभी registered policies पर iterate करता है।

- विशेष रूप से, **AMFI** (Apple Mobile File Integrity) ऐसा ही एक security extension है। इसके Info.plist में `AppleSecurityExtension` शामिल होता है जो इसे एक security policy के रूप में चिह्नित करता है।
- kernel boot के हिस्से के रूप में, kernel load logic यह सुनिश्चित करता है कि कई subsystems के निर्भर होने से पहले “security policy” (AMFI आदि) पहले से सक्रिय हो। उदाहरण के लिए, kernel "आगे के कार्यों की तैयारी के लिए … security policy लोड करके, जिसमें AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy शामिल हैं।"
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

जब आप ऐसा kext लिख रहे होते हैं जो MAC framework का उपयोग करता है (जैसे `mac_policy_register()` आदि को कॉल करना), तो आपको KPIs (Kernel Programming Interfaces) पर निर्भरताएँ घोषित करनी चाहिए ताकि kext linker (kxld) उन symbols को resolve कर सके। इसलिए, किसी `kext` को MACF पर निर्भर घोषित करने के लिए आपको इसे `Info.plist` में `com.apple.kpi.dsep` के साथ सूचित करना होगा (`find . Info.plist | grep AppleSecurityExtension`), तब वह kext ऐसे प्रतीकों का संदर्भ देगा जैसे `mac_policy_register`, `mac_policy_unregister`, और MAC hook function pointers। उनका समाधान करने के लिए, आपको `com.apple.kpi.dsep` को एक dependency के रूप में सूचीबद्ध करना होगा।

उदाहरण Info.plist स्निपेट (आपके .kext के अंदर):
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
## MACF कॉलआउट

यह सामान्य है कि कोड में MACF के कॉलआउट ऐसे conditional ब्लॉक्स में परिभाषित होते हैं: **`#if CONFIG_MAC`**। इसके अलावा, इन ब्लॉक्स के भीतर `mac_proc_check*` जैसे कॉल्स मिल सकते हैं जो MACF को किसी क्रिया को निष्पादित करने के लिए अनुमतियाँ जांचने (**check for permissions**) के लिए कॉल करते हैं। इसके अलावा, MACF कॉलआउट का स्वरूप है: **`mac_<object>_<opType>_opName`**।

Object निम्नलिखित में से एक है: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` आम तौर पर `check` होता है जो क्रिया को अनुमति देने या अस्वीकार करने के लिए उपयोग किया जाता है। हालांकि, `notify` भी मिल सकता है, जो kext को दिए गए क्रिया पर प्रतिक्रिया करने की अनुमति देगा।

आप एक उदाहरण [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) में पा सकते हैं:

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

फिर, आप `mac_file_check_mmap` का कोड [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) में पा सकते हैं।
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
जो सभी रजिस्टर्ड mac नीतियों पर जाकर उनके फ़ंक्शन कॉल करेगा और आउटपुट को error वेरिएबल में स्टोर करेगा, जिसे केवल `mac_error_select` सफलता कोड्स द्वारा ओवरराइड किया जा सकता है — इसलिए अगर कोई भी चेक फेल होता है तो पूरा चेक फेल माना जाएगा और वह कार्रवाई अनुमति प्राप्त नहीं होगी।

> [!TIP]
> हालाँकि ध्यान रखें कि सभी MACF कॉलआउट्स केवल क्रियाओं को अस्वीकार करने के लिए इस्तेमाल नहीं होते। उदाहरण के लिए, `mac_priv_grant` मैक्रो [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) को कॉल करता है, जो अनुरोधित privilege को तभी अनुदान (grant) करेगा जब कोई भी policy 0 के साथ उत्तर दे:
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
कुछ kernel कोड प्रोसेस के KAuth क्रेडेन्शियल्स और privileges कोड में से एक के साथ [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) से `priv_check_cred()` को कॉल करते हैं, जो यह देखने के लिए `mac_priv_check` को कॉल करेगा कि क्या कोई policy उस privilege को देने से **अस्वीकार** करती है, और फिर यह जांचने के लिए `mac_priv_grant` को कॉल करता है कि क्या कोई policy उस `privilege` को अनुदान करती है।

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
जो कॉल करने वाली प्रक्रिया के **bitmask** में यह जांच करेगा कि क्या वर्तमान syscall को `mac_proc_check_syscall_unix` कॉल करना चाहिए। यह इसलिए है क्योंकि syscalls इतनी बार कॉल होते हैं कि हर बार `mac_proc_check_syscall_unix` को कॉल करने से बचना फायदेमंद होता है।

ध्यान दें कि फ़ंक्शन `proc_set_syscall_filter_mask()`, जो किसी प्रक्रिया में bitmask syscalls सेट करता है, को Sandbox द्वारा sandboxed प्रक्रियाओं पर masks सेट करने के लिए कॉल किया जाता है।

## प्रकटीकृत MACF syscalls

MACF के साथ कुछ syscalls के माध्यम से इंटरैक्ट करना संभव है, जो [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) में परिभाषित हैं:
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

- [**\*OS Internals वॉल्यूम III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
