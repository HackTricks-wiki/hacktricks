# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** inasimama kwa **Mandatory Access Control Framework**, ambayo ni mfumo wa usalama uliojengwa ndani ya operating system ili kusaidia kulinda kompyuta yako. Inafanya kazi kwa kuweka **kanuni kali kuhusu nani au nini kinaweza kufikia sehemu fulani za system**, kama vile files, applications, na system resources. Kwa kutekeleza kanuni hizi kiotomatiki, MACF huhakikisha kwamba watumiaji na processes zilizoidhinishwa pekee ndizo zinaweza kufanya actions maalum, kupunguza hatari ya unauthorized access au malicious activities.

Note that MACF doesn't really make any decisions as it just **intercepts** actions, it leaves the decisions to the **policy modules** (kernel extensions) it calls like `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` and `mcxalr.kext`.

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
Kumbuka kwamba ukibadilisha `check` kuwa `socket_check_create` na `args...` kuwa `(cred, domain, type, protocol)` unapata:
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
Kupanua helper macros kunaonyesha concrete control flow:
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
Kwa maneno mengine, `MAC_CHECK(socket_check_create, ...)` hupitia kwanza policies tuli, kisha kwa masharti hufunga na kurudia juu ya dynamic policies, hutoa DTrace probes kuzunguka kila hook, na huunganisha return code ya kila hook kuwa result moja ya `error` kupitia `mac_error_select()`.


### Labels

MACF hutumia **labels** ambazo policies zinazokagua kama zinapaswa kutoa access fulani au la zitazitumia. Msimbo wa tamko la `labels` struct unaweza [kupatikana hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), ambao baadaye hutumika ndani ya **`struct ucred`** [**hapa**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) katika sehemu ya **`cr_label`**. Label ina flags na idadi ya **slots** ambazo zinaweza kutumiwa na **MACF policies to allocate pointers**. Kwa mfano Sanbox itaonyesha kwenye container profile

## MACF Policies

MACF Policy iliyofafanuliwa **rule and conditions to be applied in certain kernel operations**.

Kiendelezi cha kernel kinaweza kusanidi `mac_policy_conf` struct kisha kukisajili kwa kuita `mac_policy_register`. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Ni rahisi kutambua kernel extensions zinazosanidi sera hizi kwa kuangalia calls to `mac_policy_register`. Zaidi ya hayo, kwa kuangalia disassemble ya extension pia inawezekana kupata `mac_policy_conf` struct inayotumika.

Tambua kwamba sera za MACF zinaweza kusajiliwa na kuondolewa pia **dynamically**.

Moja ya fields kuu za `mac_policy_conf` ni **`mpc_ops`**. Fied hii hubainisha ni opreations zipi sera inazipenda. Tambua kwamba kuna hundres nyingi kati ya hizo, kwa hiyo inawezekana kuziweka zote kuwa zero kisha kuchagua tu zile ambazo sera inazipenda. Kutoka [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Takriban zote hooks zitaitwa tena na MACF wakati moja ya operations hizo zinapozuiwa. Hata hivyo, hooks **`mpo_policy_*`** ni tofauti kwa sababu **`mpo_hook_policy_init()`** ni callback inayoitwa wakati wa registration (kwa hiyo baada ya **`mac_policy_register()`**) na **`mpo_hook_policy_initbsd()`** inaitwa wakati wa late registration mara tu BSD subsystem inapokuwa imeinitialise vizuri.

Zaidi ya hayo, hook **`mpo_policy_syscall`** inaweza kusajiliwa na kext yoyote ili kufichua private **ioctl** style call **interface**. Kisha, user client ataweza kuita **`mac_syscall`** (#381) akitaja kama parameters **policy name** pamoja na integer **code** na optional **arguments**.\
Kwa mfano, **`Sandbox.kext`** hutumia hii sana.

Kuangalia **`__DATA.__const*`** ya kext kunawezekana ili kutambua structure ya `mac_policy_ops` inayotumika wakati wa kusajili policy. Inawezekana kuipata kwa sababu pointer yake iko kwenye offset ndani ya `mpo_policy_conf` na pia kwa sababu ya idadi ya NULL pointers ambazo zitakuwa katika eneo hilo.

Zaidi ya hayo, pia inawezekana kupata list ya kexts ambazo zimeconfigure policy kwa kudump kutoka memory struct **`_mac_policy_list`** ambayo inasasishwa kwa kila policy inayosajiliwa.

Unaweza pia kutumia tool `xnoop` kudump policies zote zilizosajiliwa kwenye system:
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
Kisha dondosha ukaguzi wote wa sera ya ukaguzi kwa:
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
## Initalization ya MACF katika XNU

### Bootstrap ya awali na `mac_policy_init()`

- MACF huanzishwa mapema sana. Katika `bootstrap_thread` (katika msimbo wa kuanza wa XNU), baada ya `ipc_bootstrap`, XNU huita `mac_policy_init()` (katika `mac_base.c`).
- `mac_policy_init()` huanzisha `mac_policy_list` ya kimataifa (array au list ya policy slots) na kusanidi miundombinu ya MAC (Mandatory Access Control) ndani ya XNU.
- Baadaye, `mac_policy_initmach()` huitwa, ambayo hushughulikia upande wa kernel wa usajili wa policy kwa policies zilizojengwa ndani au zilizounganishwa.

### `mac_policy_initmach()` na kupakia “security extensions”

- `mac_policy_initmach()` huchunguza kernel extensions (kexts) zilizopakiwa mapema (au zilizo kwenye orodha ya “policy injection”) na huchambua Info.plist yao kwa key `AppleSecurityExtension`.
- Kexts zinazoeleza `<key>AppleSecurityExtension</key>` (au `true`) katika Info.plist yao huchukuliwa kuwa “security extensions” — yaani, zile zinazosimamia MAC policy au kuingia kwenye miundombinu ya MACF.
- Mifano ya Apple kexts zenye key hiyo ni pamoja na **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, miongoni mwa mengine (kama ulivyokwisha orodhesha).
- Kernel huhakikisha kwamba kexts hizo zinapakiwa mapema, kisha huita routines zao za usajili (kupitia `mac_policy_register`) wakati wa boot, na kuziingiza kwenye `mac_policy_list`.

- Kila policy module (kext) hutoa `mac_policy_conf` structure, yenye hooks (`mpc_ops`) kwa MAC operations mbalimbali (vnode checks, exec checks, label updates, n.k.).
- Load time flags zinaweza kujumuisha `MPC_LOADTIME_FLAG_NOTLATE` kumaanisha “lazima ipakwe mapema” (hivyo majaribio ya usajili wa kuchelewa hukataliwa).
- Mara baada ya kusajiliwa, kila module hupata handle na kuchukua slot kwenye `mac_policy_list`.
- Wakati MAC hook inapoitwa baadaye (kwa mfano, vnode access, exec, n.k.), MACF hupitia policies zote zilizosajiliwa ili kufanya maamuzi ya pamoja.

- Hususan, **AMFI** (Apple Mobile File Integrity) ni security extension kama hiyo. Info.plist yake ina `AppleSecurityExtension` ikimaanisha kuwa ni security policy.
- Kama sehemu ya kernel boot, load logic ya kernel huhakikisha kwamba “security policy” (AMFI, n.k.) tayari iko active kabla ya subsystems nyingi kutegemea hilo. Kwa mfano, kernel “hujiandaa kwa kazi zilizo mbele kwa kupakia … security policy, ikijumuisha AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

Wakati wa kuandika kext inayotumia MAC framework (yaani, kuita `mac_policy_register()` n.k.), lazima utangaze dependencies kwenye KPIs (Kernel Programming Interfaces) ili kext linker (kxld) iweze kutatua hizo symbols. Hivyo ili kutangaza kuwa `kext` inategemea MACF unahitaji kuionyesha kwenye `Info.plist` kwa `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), kisha kext itarejelea symbols kama `mac_policy_register`, `mac_policy_unregister`, na MAC hook function pointers. Ili kuzitatua, lazima uorodheshe `com.apple.kpi.dsep` kama dependency.

Mfano wa snippet ya Info.plist (ndani ya .kext yako):
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
## MACF kwenye matoleo ya kisasa ya macOS

Kwenye macOS ya kisasa, sera za usalama za Apple kwa kawaida hazifai kuchunguzwa kama `.kext` bundles huru zisizo na uhusiano. Tangu **macOS 11**, kernel extensions huunganishwa ndani ya **kernel collections**; kwenye **Apple Silicon** hakuna **SystemKC** tofauti, na third-party kexts huwa loadable tu baada ya kujengwa ndani ya **Auxiliary Kernel Collection (AuxKC)** na reboot. Kwa utafiti wa MACF hii ina maana kwamba sera zilizojengwa ndani kama **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** au **Quarantine** kwa kawaida ni rahisi zaidi kuzitafuta kwa `kmutil` kuliko kwa tooling iliyo deprecated kama `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Kwenye Apple Silicon, ikiwa security kext haiko kwenye BootKC, angalia AuxKC kwanza. Hii kawaida huwa muhimu zaidi kuliko kutafuta standalone bundle chini ya `/System/Library/Extensions`.

## MACF Callouts

Ni kawaida kupata callouts za MACF zilizofafanuliwa kwenye code kama: **`#if CONFIG_MAC`** conditional blocks. Zaidi ya hayo, ndani ya blocks hizi inawezekana kupata calls za `mac_proc_check*` ambazo huita MACF ili **kuchunguza permissions** za kutekeleza baadhi ya actions. Pia, format ya MACF callouts ni: **`mac_<object>_<opType>_opName`**.

The object ni moja ya hizi: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
The `opType` kawaida ni check ambayo itatumika kuruhusu au kukataa action. Hata hivyo, pia inawezekana kupata `notify`, ambayo itaruhusu kext kujibu kwa action iliyotolewa.

Unaweza kupata mfano katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Kisha, inawezekana kupata code ya `mac_file_check_mmap` katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Ambayo inaita macro `MAC_CHECK`, ambayo msimbo wake unaweza kupatikana katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Which will kupitia todas las policies registered MAC calling their functions and storing the output ndani ya variable `error`, ambayo itabadilishwa tu na `mac_error_select` kwa success codes, hivyo ikiwa check yoyote itafeli, complete check itafeli na action haitaruhusiwa.

> [!TIP]
> Hata hivyo, kumbuka kwamba si callouts zote za MACF hutumika tu kukataa actions. Kwa mfano, `mac_priv_grant` inaita macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), ambayo itatoa requested privilege ikiwa policy yoyote itajibu kwa 0:
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

These callas zinakusudiwa kucheck na kutoa (tens of) **privileges** zilizofafanuliwa katika [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Baadhi ya kernel code ingeita `priv_check_cred()` kutoka [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) na KAuth credentials za process na mojawapo ya privilege codes ambayo itaaita `mac_priv_check` kuona kama policy yoyote **inakataa** kutoa privilege kisha inaita `mac_priv_grant` kuona kama policy yoyote inatoa `privilege`.

### proc_check_syscall_unix

This hook inaruhusu ku-intercept system calls zote. Katika `bsd/dev/[i386|arm]/systemcalls.c` inawezekana kuona function iliyotangazwa [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), ambayo ina code hii:
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
Ambayo yataangalia katika **bitmask** ya mchakato unaoitwa ikiwa syscall ya sasa inapaswa kuita `mac_proc_check_syscall_unix`. Hii ni kwa sababu syscalls huitwa mara kwa mara sana kiasi kwamba ni muhimu kuepuka kuita `mac_proc_check_syscall_unix` kila mara.

Kumbuka kwamba kazi `proc_set_syscall_filter_mask()`, ambayo huweka bitmask ya syscalls katika mchakato, inaitwa na Sandbox ili kuweka masks kwenye michakato iliyopo ndani ya sandbox.

## Exposed MACF syscalls

Inawezekana kuingiliana na MACF kupitia baadhi ya syscalls zilizofafanuliwa katika [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Kwa offensive reversing, **`__mac_syscall`** bado ni moja ya userland chokepoints bora zaidi. Hubeba **policy name** (kwa mfano `"Sandbox"` au `"AMFI"`), **policy-specific selector/code**, na pointer kwenda kwenye **opaque argument blob** ambayo itashughulikiwa na `mpo_policy_syscall`. Hii ni muhimu sana wakati wa reversing operations zisizo na documentation kutoka userland kwanza na baadaye tu kuingia kwenye kernel implementation. Sandbox mara nyingi huitumia kupitia `__sandbox_ms`, na AMFI hutumia mechanism hiyo hiyo kwa dyld policy decisions.

## Practical offensive research notes

Recent macOS bugs mara chache sana "break MACF" moja kwa moja. Badala yake, kwa kawaida hutumia **desynchronisation kati ya MACF / Sandbox / TCC decision na privileged action inayotokea baadaye**.

### Broker path checks vs real privileged action

Pattern inayojirudia ni privileged daemon kufanya **userland pre-check** (kwa mfano `sandbox_check_by_audit_token()`) kwenye version moja ya path, na baadaye kutekeleza real privileged sink kwa **path tofauti au non-canonical iliyo controlled na attacker**. Utafiti wa hivi karibuni wa `diskarbitrationd` / `storagekitd` ni mfano mzuri: **directory traversal** pamoja na **symlink swaps** humruhusu attacker kupita sandbox validation ya daemon kisha kuweka mount juu ya sensitive locations kama `~/Library/Application Support/com.apple.TCC`, na hivyo kugeuza bug kuwa **sandbox escape**, **local privilege escalation** au **TCC bypass** kulingana na mount point iliyochaguliwa.

Unapoaudit root brokers zinazofikiwa kutoka sandbox, kwanza tafuta kwa `grep`:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks kama `mount`, `rename`, `copyfile`, helper-tool XPC methods, au chochote ambacho baadaye hugusa paths zinazodhibitiwa na attacker kama root

### Trusted deputies with private entitlements

Pattern nyingine ya vitendo ni kuepuka kushambulia MACF hooks moja kwa moja na badala yake kutumia **trusted process** ambayo tayari ina rights zinazohitajika kuvuka boundary. Utafiti wa hivi karibuni wa Safari/TCC ni mfano mzuri: primitive ya kuvutia haikuwa "disable TCC in the kernel", bali kubadilisha local policy/configuration ili Apple-signed process yenye **`com.apple.private.tcc.allow`** ifanye sensitive action kwa niaba yako. Kwa vitendo, high-value auditing targets ni Apple daemons/apps zinazochanganya:

- **private entitlements** au FDA-like reach
- writable config / database / mount point / policy file
- operesheni nyeti ya baadaye inayosimamiwa na **Sandbox**, **AMFI**, **TCC** au MACF policy nyingine

Kwa deeper product-specific reversing, angalia kurasa mahsusi za [macOS Sandbox](macos-sandbox/README.md) na [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
