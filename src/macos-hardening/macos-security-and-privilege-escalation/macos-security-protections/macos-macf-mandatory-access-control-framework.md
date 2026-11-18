# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** का अर्थ **Mandatory Access Control Framework** है। यह ऑपरेटिंग सिस्टम में बना एक सुरक्षा सिस्टम है, जो आपके कंप्यूटर की सुरक्षा में मदद करता है। यह **इस बारे में सख्त नियम तय करके काम करता है कि कौन या क्या सिस्टम के कुछ हिस्सों**, जैसे फ़ाइलों, एप्लिकेशन और सिस्टम संसाधनों तक पहुँच सकता है। इन नियमों को अपने-आप लागू करके, MACF सुनिश्चित करता है कि केवल अधिकृत उपयोगकर्ता और प्रोसेस ही विशिष्ट कार्रवाइयाँ कर सकें, जिससे अनधिकृत पहुँच या दुर्भावनापूर्ण गतिविधियों का जोखिम कम होता है।

ध्यान दें कि MACF वास्तव में कोई निर्णय नहीं लेता, क्योंकि यह केवल कार्रवाइयों को **intercept** करता है। यह निर्णय उन **policy modules** (kernel extensions) पर छोड़ता है जिन्हें यह कॉल करता है, जैसे `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` और `mcxalr.kext`।

- कोई policy enforcing हो सकती है (कुछ ऑपरेशन पर 0 के अलावा कोई मान लौटाती है)
- कोई policy monitoring कर सकती है (आपत्ति न करने के लिए 0 लौटाती है, लेकिन किसी काम को करने के लिए hook का सहारा लेती है)
- MACF static policy boot के दौरान इंस्टॉल होती है और इसे कभी हटाया नहीं जाएगा
- MACF dynamic policy को KEXT (kextload) इंस्टॉल करता है और सैद्धांतिक रूप से इसे kextunload किया जा सकता है
- iOS में केवल static policies की अनुमति है, जबकि macOS में static और dynamic दोनों की अनुमति है।<sup>[[7]](#references)</sup>

### Flow

1. प्रोसेस एक syscall/mach trap करता है
2. Kernel के अंदर संबंधित फ़ंक्शन को कॉल किया जाता है
3. फ़ंक्शन MACF को कॉल करता है
4. MACF उन policy modules की जाँच करता है जिन्होंने अपनी policy में उस फ़ंक्शन को hook करने का अनुरोध किया था
5. MACF संबंधित policies को कॉल करता है
6. Policies बताती हैं कि वे कार्रवाई की अनुमति देती हैं या उसे अस्वीकार करती हैं

> [!CAUTION]
> MAC Framework KPI का उपयोग केवल Apple कर सकता है।

आमतौर पर, MACF के साथ permissions की जाँच करने वाले फ़ंक्शन `MAC_CHECK` macro को कॉल करते हैं। उदाहरण के लिए, socket बनाने के syscall के मामले में, यह `mac_socket_check_create` फ़ंक्शन को कॉल करता है, जो `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` को कॉल करता है। इसके अलावा, `MAC_CHECK` macro को security/mac_internal.h में इस तरह परिभाषित किया गया है:<sup>[[3]](#references)</sup>
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

helper macros को expand करने पर ठोस control flow दिखाई देता है:

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

दूसरे शब्दों में, `MAC_CHECK(socket_check_create, ...)` पहले static policies को चलाता है, फिर dynamic policies पर सशर्त रूप से lock लगाकर उन्हें iterate करता है, हर hook के आसपास DTrace probes जारी करता है, और `mac_error_select()` के ज़रिए हर hook के return code को एकल `error` परिणाम में समेटता है।

### Labels

MACF **labels** का उपयोग करता है, जिनका इस्तेमाल policies यह जाँचने के लिए करती हैं कि उन्हें access देना चाहिए या नहीं। Labels struct declaration का code [यहाँ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) मिल सकता है। इसका उपयोग [यहाँ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) **`struct ucred`** के अंदर, **`cr_label`** वाले हिस्से में किया जाता है। Label में flags और **slots** की एक संख्या होती है, जिनका उपयोग **MACF policies pointers allocate करने के लिए** कर सकती हैं। उदाहरण के लिए, Sanbox container profile की ओर point करेगा।

## MACF Policies

MACF Policy ऐसे **rules और conditions परिभाषित करती है जिन्हें कुछ kernel operations में लागू किया जाना है**।

एक kernel extension `mac_policy_conf` struct configure करके, फिर `mac_policy_register` call करके उसे register कर सकती है। [यहाँ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) से:<sup>[[1]](#references)</sup>

```c
 #define mpc_t	struct mac_policy_conf *

/**
  @brief Mac policy configuration

  This structure specifies the configuration information for a
  MAC policy module.  A policy module developer must supply
  a short unique policy name, a more descriptive full name, a list of label
  namespaces and count, a pointer to the registered entry-point operations,
  any load time flags, and optionally, a pointer to a label slot identifier.

  The Framework will update the runtime flags (mpc_runtime_flags) to
  indicate that the module has been registered.

  If the label slot identifier (mpc_field_off) is NULL, the Framework
  will not provide label storage for the policy.  Otherwise, the
  Framework will store the label location (slot) in this field.

  The mpc_list field is used by the Framework and should not be
  modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
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

`mac_policy_register` को कॉल्स चेक करके इन policies को configure करने वाले kernel extensions की पहचान करना आसान है। इसके अलावा, extension को disassemble करके इस्तेमाल किए गए `mac_policy_conf` struct को भी ढूँढना संभव है।

ध्यान दें कि MACF policies को **डायनामिक रूप से** भी register और unregister किया जा सकता है।

`mac_policy_conf` के मुख्य fields में से एक **`mpc_ops`** है। यह field बताती है कि policy किन operations में रुचि रखती है। इनकी संख्या सैकड़ों में है, इसलिए सभी entries को zero करके फिर केवल उन्हीं को select करना संभव है जिनकी policy को ज़रूरत है। [यहाँ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) से:<sup>[[1]](#references)</sup>

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

लगभग सभी hooks को MACF द्वारा callback किया जाएगा, जब उन operations में से किसी को intercept किया जाता है। हालांकि, **`mpo_policy_*`** hooks इसका अपवाद हैं, क्योंकि `mpo_hook_policy_init()` एक callback है जिसे registration के समय (अर्थात `mac_policy_register()` के बाद) call किया जाता है, जबकि `mpo_hook_policy_initbsd()` को late registration के दौरान call किया जाता है, जब BSD subsystem ठीक से initialize हो चुका होता है।

इसके अलावा, किसी भी kext द्वारा **`mpo_policy_syscall`** hook register करके एक निजी **ioctl**-शैली का call **interface** उपलब्ध कराया जा सकता है। इसके बाद user client, parameters के रूप में **policy name**, integer **code** और वैकल्पिक **arguments** देकर `mac_syscall` (#381) call कर सकता है।\
उदाहरण के लिए, **`Sandbox.kext`** इसका बहुत उपयोग करता है।

Policy register करते समय उपयोग किए गए `mac_policy_ops` structure की पहचान करने के लिए kext के **`__DATA.__const*`** की जांच की जा सकती है। इसे ढूंढना संभव है, क्योंकि इसका pointer `mpo_policy_conf` के भीतर एक offset पर होता है, और उस क्षेत्र में मौजूद NULL pointers की संख्या से भी इसकी पहचान की जा सकती है।

इसके अलावा, memory से **`_mac_policy_list`** struct dump करके उन kexts की सूची प्राप्त करना भी संभव है जिन्होंने policy configure की है। यह struct हर register की गई policy के साथ update होता है।

सिस्टम में register की गई सभी policies dump करने के लिए `xnoop` tool का भी उपयोग किया जा सकता है:

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

और फिर check policy के सभी checks को इस कमांड से dump करें:

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

## XNU में MACF का initialization

### Early bootstrap और mac_policy_init()

- MACF बहुत जल्दी initialize होता है। `bootstrap_thread` (XNU startup code में), `ipc_bootstrap` के बाद, XNU `mac_policy_init()` (`mac_base.c` में) को call करता है।
- `mac_policy_init()` global `mac_policy_list` (policy slots की एक array या list) को initialize करता है और XNU के भीतर MAC (Mandatory Access Control) के लिए infrastructure सेट करता है।
- बाद में `mac_policy_initmach()` invoke किया जाता है, जो built-in या bundled policies के लिए kernel-side policy registration को संभालता है।

### `mac_policy_initmach()` और “security extensions” को load करना

- `mac_policy_initmach()` उन kernel extensions (kexts) की जाँच करता है जो पहले से load हैं (या “policy injection” list में हैं), और उनके Info.plist में `AppleSecurityExtension` key को देखता है।
- जिन kexts के Info.plist में `<key>AppleSecurityExtension</key>` (या `true`) घोषित होता है, उन्हें “security extensions” माना जाता है — यानी वे extensions जो MAC policy लागू करते हैं या MACF infrastructure में hook करते हैं।
- इस key वाले Apple kexts के उदाहरणों में **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** और अन्य शामिल हैं (जैसा कि आपने पहले सूचीबद्ध किया था)।
- Kernel यह सुनिश्चित करता है कि ये kexts जल्दी load हों, फिर boot के दौरान उनके registration routines ( `mac_policy_register` के ज़रिए) call करता है और उन्हें `mac_policy_list` में जोड़ता है।

  - हर policy module (kext) एक `mac_policy_conf` structure देता है, जिसमें विभिन्न MAC operations (vnode checks, exec checks, label updates आदि) के लिए hooks (`mpc_ops`) होते हैं।
  - Load-time flags में `MPC_LOADTIME_FLAG_NOTLATE` शामिल हो सकता है, जिसका अर्थ है “इसे जल्दी load होना चाहिए” (इसलिए देर से किए गए registration attempts अस्वीकार कर दिए जाते हैं)।
  - Register होने के बाद, हर module को एक handle मिलता है और वह `mac_policy_list` में एक slot लेता है।
  - बाद में जब कोई MAC hook invoke होता है (उदाहरण के लिए, vnode access, exec आदि के लिए), तो MACF सामूहिक निर्णय लेने के लिए सभी registered policies पर iterate करता है।

- विशेष रूप से, **AMFI** (Apple Mobile File Integrity) ऐसा ही एक security extension है। इसके Info.plist में `AppleSecurityExtension` होता है, जो इसे security policy के रूप में चिह्नित करता है।
- Kernel boot के दौरान, kernel का load logic यह सुनिश्चित करता है कि कई subsystems के इस पर निर्भर होने से पहले “security policy” (AMFI आदि) सक्रिय हो जाए। उदाहरण के लिए, kernel “आगे आने वाले tasks की तैयारी के लिए … security policy, जिसमें AppleMobileFileIntegrity (AMFI), Sandbox और Quarantine policy शामिल हैं” load करता है। 

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

MAC framework का उपयोग करने वाला kext लिखते समय (यानी `mac_policy_register()` आदि को कॉल करते समय), आपको KPIs (Kernel Programming Interfaces) पर dependencies घोषित करनी होंगी, ताकि kext linker (kxld) उन symbols को resolve कर सके। इसलिए, `kext` को MACF पर निर्भर घोषित करने के लिए, आपको `Info.plist` में `com.apple.kpi.dsep` का उल्लेख करना होगा (`find . Info.plist | grep AppleSecurityExtension`); इसके बाद kext `mac_policy_register`, `mac_policy_unregister` और MAC hook function pointers जैसे symbols को refer करेगा। इन्हें resolve करने के लिए, आपको `com.apple.kpi.dsep` को dependency के रूप में सूचीबद्ध करना होगा।

उदाहरण के लिए, आपके .kext के अंदर `Info.plist` का snippet:

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



## आधुनिक macOS रिलीज़ में MACF

आधुनिक macOS में, Apple की security policies को आमतौर पर अलग-थलग `.kext` bundles के रूप में देखना सबसे अच्छा तरीका नहीं है। **macOS 11** से kernel extensions को **kernel collections** में लिंक किया जाता है; **Apple Silicon** पर कोई अलग **SystemKC** नहीं होता, और third-party kexts केवल **Auxiliary Kernel Collection (AuxKC)** में build किए जाने और reboot के बाद ही load किए जा सकते हैं। MACF research के लिए इसका मतलब है कि **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** या **Quarantine** जैसी built-in policies की सूची deprecated tooling, जैसे `kextstat`, के बजाय `kmutil` से निकालना आमतौर पर आसान होता है।

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Apple Silicon पर, यदि कोई security kext BootKC में नहीं है, तो अगला AuxKC जाँचें। यह आमतौर पर `/System/Library/Extensions` के अंतर्गत standalone bundle खोजने से अधिक उपयोगी होता है।

## MACF Callouts

कोड में इस तरह के callouts मिलना आम है: **`#if CONFIG_MAC`** conditional blocks। इसके अलावा, इन blocks के अंदर `mac_proc_check*` के calls मिल सकते हैं, जो MACF को कुछ कार्रवाइयाँ करने की **permissions जाँचने** के लिए call करते हैं। MACF callouts का format यह है: **`mac_<object>_<opType>_opName`**।

`object` इनमें से एक है: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`।\
`opType` आमतौर पर `check` होता है, जिसका उपयोग कार्रवाई को अनुमति देने या अस्वीकार करने के लिए किया जाता है। हालाँकि, `notify` भी मिल सकता है, जो kext को दी गई कार्रवाई पर प्रतिक्रिया देने की अनुमति देता है।

आपको इसका एक उदाहरण [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) में मिल सकता है:

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

इसके बाद, `mac_file_check_mmap` का code [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) में देखा जा सकता है।

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

जो `MAC_CHECK` macro को call कर रहा है, जिसका code [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> में देखा जा सकता है।

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

यह registered policies पर चलता है और उनके results को `mac_error_select()` के साथ जोड़ता है। बाद की जाँच से मिलने वाला zero return, पहले से किए गए denial को override नहीं कर सकता; यदि कई policies deny करती हैं, तो function precedence के आधार पर error चुनता है (उदाहरण के लिए, `EACCES` को `EPERM` से पहले)।<sup>[[2]](#references)</sup>

> [!TIP]
> हालाँकि, याद रखें कि सभी MACF callouts का उपयोग केवल actions को deny करने के लिए नहीं होता। उदाहरण के लिए, `mac_priv_grant` macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) को call करता है, जो किसी भी policy के 0 के साथ जवाब देने पर अनुरोधित privilege grant कर देगा:
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

इन calls का उद्देश्य [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) में परिभाषित (कई) **privileges** की जाँच करना और उन्हें प्रदान करना है।\
कुछ kernel code, process के KAuth credentials और privilege codes में से किसी एक के साथ [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) के `priv_check_cred()` को call करेगा। यह `mac_priv_check` को call करके देखेगा कि कोई policy privilege देने से **इनकार** तो नहीं करती, और फिर `mac_priv_grant` को call करके देखेगा कि कोई policy `privilege` देती है या नहीं।<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

यह hook सभी system calls को intercept करने की अनुमति देता है। `bsd/dev/[i386|arm]/systemcalls.c` में घोषित function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) को देखा जा सकता है, जिसमें यह code है:

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

जो calling process के **bitmask** में जाँचता है कि मौजूदा syscall को `mac_proc_check_syscall_unix` call करना चाहिए या नहीं। ऐसा इसलिए है क्योंकि syscalls बहुत बार call किए जाते हैं, इसलिए हर बार `mac_proc_check_syscall_unix` call करने से बचना उपयोगी है।

ध्यान दें कि `proc_set_syscall_filter_mask()` function, जो किसी process में syscalls के bitmask सेट करता है, Sandbox द्वारा sandboxed processes पर masks सेट करने के लिए call किया जाता है।

## Exposed MACF syscalls

[security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) में परिभाषित कुछ syscalls के ज़रिए MACF के साथ interact करना संभव है:

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

Offensive reversing के लिए, **`__mac_syscall`** अब भी userland के सबसे अच्छे chokepoints में से एक है। यह एक **policy name** (उदाहरण के लिए `"Sandbox"` या `"AMFI"`), एक **policy-specific selector/code`, और **opaque argument blob** का pointer लेकर जाता है, जिसे `mpo_policy_syscall` संभालता है। Userland से undocumented operations को पहले reverse करने और बाद में kernel implementation तक जाने के लिए यह बहुत उपयोगी है। Sandbox आम तौर पर `__sandbox_ms` के ज़रिए यहाँ पहुँचता है, और dyld policy decisions के लिए AMFI भी यही mechanism इस्तेमाल करता है।<sup>[[2]](#references)[[5]](#references)</sup>

## व्यावहारिक offensive research नोट्स

हाल के macOS bugs शायद ही कभी सीधे "MACF को तोड़ते" हैं। इसके बजाय, वे आम तौर पर MACF / Sandbox / TCC के decision और बाद में होने वाली privileged action के बीच **desynchronisation** का दुरुपयोग करते हैं।

### MACF input के रूप में policy-specific spawn attributes

`posix_spawnattr_setmacpolicyinfo_np()` किसी `posix_spawn()` request के साथ policy name और opaque bytes जोड़ता है। XNU हर registered policy के `mpc_name` से इन bytes को lookup करता है और उन्हें उस policy के exec-label hook तक पहुँचाता है; launch-constraints hook भी matching bytes पढ़ता है। यह `__mac_syscall` से अलग, attacker-controlled MACF input path है। जाँचें कि policy इन bytes को *अतिरिक्त restriction* मानती है या इन्हें parent अथवा executable की मौजूदा policy की जगह लागू होने देती है।<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

एक नियंत्रित test के लिए, किसी restricted parent से शुरू करें और उसी child को policy-specific attribute के **बिना** और **साथ** spawn करें। ऐसे resource तक child की प्रभावी पहुँच की तुलना करें, जिसका parent इस्तेमाल नहीं कर सकता; केवल सफल spawn होना यह साबित नहीं करता कि boundary पार हुई।<sup>[[12]](#references)[[13]](#references)</sup>

Policy को reverse करते समय, `mpo_cred_label_update_execve` और `mpo_proc_check_launch_constraints` को trace करें, फिर जाँचें कि caller attribute दे सकता है या नहीं।<sup>[[10]](#references)[[11]](#references)</sup> AMFI ऐतिहासिक रूप से built-in constraints की जगह दिए गए launch constraints स्वीकार करता था; Sandbox parent की restrictions बनाए रखने के बजाय child पर named built-in profile लागू कर सकता था।<sup>[[13]](#references)[[12]](#references)</sup> दोनों behaviors patch किए जा चुके हैं, इसलिए मौजूदा systems पर इनमें से किसी को भी मानकर न चलें।<sup>[[13]](#references)[[12]](#references)</sup>

AMFI मामले के लिए [launch-constraints analysis](macos-launch-environment-constraints.md) और child की प्रभावी policy को test करने के लिए [Sandbox debugging](macos-sandbox/macos-sandbox-debug-and-bypass/) देखें।

### Broker path checks बनाम वास्तविक privileged action

एक आम pattern यह है कि कोई privileged daemon पहले किसी path के एक version पर **userland pre-check** (उदाहरण के लिए `sandbox_check_by_audit_token()`) करता है और बाद में **अलग या non-canonical attacker-controlled path** के साथ असली privileged sink चलाता है। हालिया `diskarbitrationd` / `storagekitd` research इसका अच्छा उदाहरण है: **directory traversal** और **symlink swaps** की मदद से attacker daemon की sandbox validation पार कर सकता है और फिर `~/Library/Application Support/com.apple.TCC` जैसी संवेदनशील जगहों पर mount कर सकता है। चुने गए mount point के आधार पर, इससे bug **sandbox escape**, **local privilege escalation** या **TCC bypass** बन जाता है।<sup>[[6]](#references)</sup>

Sandbox से reachable root brokers का audit करते समय, पहले इनकी खोज करें:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks, जैसे `mount`, `rename`, `copyfile`, helper-tool XPC methods, या ऐसा कोई भी code जो बाद में attacker-controlled paths को root के रूप में access करता हो

### Private entitlements वाले trusted deputies

एक अन्य व्यावहारिक pattern MACF hooks पर सीधे हमला करने के बजाय ऐसे **trusted process** का दुरुपयोग करना है, जिसके पास boundary पार करने के लिए पहले से आवश्यक rights हों। हालिया Safari/TCC research इसका अच्छा उदाहरण है: दिलचस्प primitive "kernel में TCC disable करना" नहीं था, बल्कि local policy/configuration में बदलाव करना था ताकि **`com.apple.private.tcc.allow`** वाला Apple-signed process आपकी ओर से संवेदनशील action करे।<sup>[[8]](#references)</sup> व्यवहार में, audit के लिए high-value targets वे Apple daemons/apps हैं जो इन चीज़ों को मिलाते हैं:

- **private entitlements** या FDA जैसी पहुँच
- writable config / database / mount point / policy file
- बाद में होने वाला ऐसा sensitive operation, जिसे **Sandbox**, **AMFI**, **TCC** या कोई अन्य MACF policy mediate करती है

Product-specific reversing की गहराई में जाने के लिए [macOS Sandbox](macos-sandbox/README.md) और [macOS TCC](macos-tcc/README.md) के dedicated pages देखें।



## References

- [1] [XNU — `security/mac_policy.h` (पूरा MACF policy operations vector)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (`priv_check`/`priv_grant` द्वारा इस्तेमाल किए जाने वाले privilege codes)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Apple Vulnerabilities का खुलासा: diskarbitrationd और storagekitd Audit, भाग 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference tool](https://newosxbook.com/xxr/index.php)
- [8] [नया macOS vulnerability, "HM Surf", अनधिकृत data access का कारण बन सकता है (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — posix_spawn policy attribute setter](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — policy-specific exec-label attribute dispatch](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — launch-constraints policy dispatch](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [एक executable को spawn करके Apple Sandbox से बच निकलना](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [macOS पर Launch Constraints को bypass करना](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
