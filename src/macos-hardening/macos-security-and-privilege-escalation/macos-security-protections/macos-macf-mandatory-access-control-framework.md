# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** का मतलब है **Mandatory Access Control Framework**, जो एक सुरक्षा प्रणाली है जो ऑपरेटिंग सिस्टम में निर्मित है ताकि आपके कंप्यूटर की सुरक्षा की जा सके। यह **कठोर नियम निर्धारित करके काम करता है कि कौन या क्या सिस्टम के कुछ हिस्सों, जैसे फ़ाइलें, अनुप्रयोग और सिस्टम संसाधन, तक पहुँच सकता है**। इन नियमों को स्वचालित रूप से लागू करके, MACF सुनिश्चित करता है कि केवल अधिकृत उपयोगकर्ता और प्रक्रियाएँ विशिष्ट क्रियाएँ कर सकें, जिससे अनधिकृत पहुँच या दुर्भावनापूर्ण गतिविधियों का जोखिम कम होता है।

ध्यान दें कि MACF वास्तव में कोई निर्णय नहीं लेता क्योंकि यह केवल **क्रियाओं को अवरुद्ध** करता है, यह निर्णय **नीति मॉड्यूल** (कर्नेल एक्सटेंशन) पर छोड़ देता है जिसे यह कॉल करता है जैसे `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` और `mcxalr.kext`।

### Flow

1
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
कर्नेल एक्सटेंशन को इन नीतियों को कॉन्फ़िगर करते हुए पहचानना आसान है `mac_policy_register` कॉल की जांच करके। इसके अलावा, एक्सटेंशन के डिस्सेम्बल की जांच करने पर `mac_policy_conf` स्ट्रक्चर भी पाया जा सकता है।

ध्यान दें कि MACF नीतियों को **गतिशील** रूप से भी पंजीकृत और अपंजीकृत किया जा सकता है।

`mac_policy_conf` के मुख्य क्षेत्रों में से एक है **`mpc_ops`**। यह क्षेत्र निर्दिष्ट करता है कि नीति किन ऑपरेशनों में रुचि रखती है। ध्यान दें कि इनमें सैकड़ों हैं, इसलिए सभी को शून्य करना संभव है और फिर केवल उन पर ध्यान केंद्रित करना जो नीति के लिए महत्वपूर्ण हैं। [यहां](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) से:
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
लगभग सभी हुक MACF द्वारा वापस बुलाए जाएंगे जब इनमें से कोई एक ऑपरेशन इंटरसेप्ट किया जाता है। हालाँकि, **`mpo_policy_*`** हुक एक अपवाद हैं क्योंकि `mpo_hook_policy_init()` एक कॉलबैक है जो पंजीकरण पर कॉल किया जाता है (तो `mac_policy_register()` के बाद) और `mpo_hook_policy_initbsd()` लेट पंजीकरण के दौरान कॉल किया जाता है जब BSD सबसिस्टम सही ढंग से प्रारंभ हो चुका होता है।

इसके अलावा, **`mpo_policy_syscall`** हुक को किसी भी kext द्वारा एक निजी **ioctl** शैली कॉल **interface** को उजागर करने के लिए पंजीकृत किया जा सकता है। फिर, एक उपयोगकर्ता क्लाइंट `mac_syscall` (#381) को कॉल कर सकेगा जिसमें **policy name** के रूप में एक पूर्णांक **code** और वैकल्पिक **arguments** निर्दिष्ट किए जाएंगे।\
उदाहरण के लिए, **`Sandbox.kext`** इसका बहुत उपयोग करता है।

kext के **`__DATA.__const*`** की जांच करके `mac_policy_ops` संरचना की पहचान करना संभव है जो नीति को पंजीकृत करते समय उपयोग की जाती है। इसे खोजना संभव है क्योंकि इसका पॉइंटर `mpo_policy_conf` के अंदर एक ऑफसेट पर है और साथ ही उस क्षेत्र में NULL पॉइंटर्स की मात्रा के कारण भी।

इसके अलावा, यह भी संभव है कि उन kexts की सूची प्राप्त की जाए जिन्होंने एक नीति को कॉन्फ़िगर किया है, जो कि मेमोरी से संरचना **`_mac_policy_list`** को डंप करके अपडेट की जाती है।

## MACF Initialization

MACF बहुत जल्दी प्रारंभ होता है। इसे XNU के `bootstrap_thread` में सेट किया गया है: `ipc_bootstrap` के बाद `mac_policy_init()` को कॉल किया जाता है जो `mac_policy_list` को प्रारंभ करता है और कुछ क्षणों बाद `mac_policy_initmach()` को कॉल किया जाता है। अन्य चीजों के बीच, यह फ़ंक्शन सभी Apple kexts को प्राप्त करेगा जिनकी Info.plist में `AppleSecurityExtension` कुंजी है जैसे `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` और `TMSafetyNet.kext` और उन्हें लोड करता है।

## MACF Callouts

कोड में **`#if CONFIG_MAC`** शर्तीय ब्लॉकों के रूप में MACF के लिए कॉलआउट्स मिलना सामान्य है। इसके अलावा, इन ब्लॉकों के अंदर `mac_proc_check*` को कॉल करने के लिए कॉल मिलना संभव है जो MACF को **permissions** की जांच करने के लिए कॉल करता है ताकि कुछ क्रियाएँ की जा सकें। इसके अलावा, MACF कॉलआउट्स का प्रारूप है: **`mac_<object>_<opType>_opName`**।

ऑब्जेक्ट निम्नलिखित में से एक है: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`।\
`opType` आमतौर पर चेक होता है जिसका उपयोग क्रिया को अनुमति देने या अस्वीकार करने के लिए किया जाएगा। हालाँकि, `notify` भी मिल सकता है, जो kext को दी गई क्रिया पर प्रतिक्रिया करने की अनुमति देगा।

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

फिर, आप [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) में `mac_file_check_mmap` का कोड पा सकते हैं।
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
जो `MAC_CHECK` मैक्रो को कॉल कर रहा है, जिसका कोड [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) में पाया जा सकता है।
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
जो सभी पंजीकृत मैक नीतियों को उनके कार्यों को कॉल करते हुए और आउटपुट को त्रुटि चर में संग्रहीत करते हुए जाएगा, जिसे केवल `mac_error_select` द्वारा सफलता कोड के द्वारा ओवरराइड किया जा सकेगा, इसलिए यदि कोई जांच विफल होती है तो पूरी जांच विफल हो जाएगी और क्रिया की अनुमति नहीं दी जाएगी।

> [!TIP]
> हालाँकि, याद रखें कि सभी MACF कॉलआउट केवल क्रियाओं को अस्वीकार करने के लिए उपयोग नहीं किए जाते हैं। उदाहरण के लिए, `mac_priv_grant` मैक्रो [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) को कॉल करता है, जो यदि कोई नीति 0 के साथ उत्तर देती है तो अनुरोधित विशेषाधिकार प्रदान करेगा:
>
> ```c
> /*
>  * MAC_GRANT निर्दिष्ट जांच करता है नीति
>  * मॉड्यूल सूची को चलाकर और प्रत्येक के साथ यह जांचता है कि
>  * अनुरोध के बारे में इसकी क्या राय है। MAC_CHECK के विपरीत,
>  * यह यदि कोई नीतियाँ '0' लौटाती हैं तो प्रदान करता है,
>  * और अन्यथा EPERM लौटाता है। ध्यान दें कि यह अपने मान को
>  * कॉल करने वाले के दायरे में 'त्रुटि' के माध्यम से लौटाता है।
>  */
> #define MAC_GRANT(check, args...) do {                              \
>     error = EPERM;                                                  \
>     MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>     });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

ये कॉल विशेषाधिकारों की जांच और प्रदान करने के लिए बनाए गए हैं (जो [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) में परिभाषित हैं)।\
कुछ कर्नेल कोड `priv_check_cred()` को [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) से कॉल करेगा, जिसमें प्रक्रिया के KAuth क्रेडेंशियल और विशेषाधिकार कोड में से एक होगा, जो `mac_priv_check` को कॉल करेगा यह देखने के लिए कि क्या कोई नीति विशेषाधिकार देने से **अस्वीकृत** करती है और फिर यह `mac_priv_grant` को कॉल करेगा यह देखने के लिए कि क्या कोई नीति `privilege` प्रदान करती है।

### proc_check_syscall_unix

यह हुक सभी सिस्टम कॉल को इंटरसेप्ट करने की अनुमति देता है। `bsd/dev/[i386|arm]/systemcalls.c` में घोषित कार्य [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) को देखना संभव है, जिसमें यह कोड है:
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
जो कॉलिंग प्रक्रिया में **बिटमास्क** की जांच करेगा कि क्या वर्तमान syscall को `mac_proc_check_syscall_unix` को कॉल करना चाहिए। इसका कारण यह है कि syscalls इतनी बार कॉल किए जाते हैं कि `mac_proc_check_syscall_unix` को हर बार कॉल करने से बचना दिलचस्प है।

ध्यान दें कि फ़ंक्शन `proc_set_syscall_filter_mask()` जो एक प्रक्रिया में बिटमास्क syscalls सेट करता है, Sandbox द्वारा सैंडबॉक्स की गई प्रक्रियाओं पर मास्क सेट करने के लिए कॉल किया जाता है।

## एक्सपोज़ MACF syscalls

MACF के साथ इंटरैक्ट करना संभव है कुछ syscalls के माध्यम से जो [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) में परिभाषित हैं:
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
