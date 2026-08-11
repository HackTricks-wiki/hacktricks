# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

**MACF** inamaanisha **Mandatory Access Control Framework**, ambayo ni mfumo wa usalama uliojengwa ndani ya operating system ili kusaidia kulinda computer yako. Hufanya kazi kwa kuweka **kanuni kali kuhusu nani au nini kinaweza kufikia sehemu fulani za mfumo**, kama vile files, applications na system resources. Kwa kutekeleza kanuni hizi kiotomatiki, MACF huhakikisha kwamba users na processes walioidhinishwa pekee wanaweza kutekeleza actions mahususi, hivyo kupunguza hatari ya unauthorized access au malicious activities.

Kumbuka kwamba MACF kwa hakika haifanyi maamuzi yoyote, kwani **hu-intercept** actions tu; huacha maamuzi hayo kwa **policy modules** (kernel extensions) inazozita, kama vile `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` na `mcxalr.kext`.

- Policy inaweza kuwa enforcing (kurudisha 0 non-zero kwenye operation fulani)
- Policy inaweza kuwa monitoring (kurudisha 0, ili isipinge lakini itumie hook kufanya jambo fulani)
- MACF static policy huwekwa wakati wa boot na HAIWEZI kuondolewa
- MACF dynamic policy huwekwa na KEXT (kextload) na kinadharia inaweza kextunloaded
- Kwenye iOS, static policies pekee ndizo zinaruhusiwa, na kwenye macOS static + dynamic.<sup>[[7]](#references)</sup>

### Mtiririko

1. Process hutekeleza syscall/mach trap
2. Function husika huitwa ndani ya kernel
3. Function huita MACF
4. MACF hukagua policy modules zilizoomba ku-hook function hiyo kwenye policy yao
5. MACF huita policies husika
6. Policies huonyesha ikiwa zinaruhusu au zinakataa action hiyo

> [!CAUTION]
> Apple pekee ndiye anayeweza kutumia MAC Framework KPI.

Kwa kawaida, functions zinazokagua permissions kwa kutumia MACF zitaita macro `MAC_CHECK`. Kama ilivyo kwenye syscall ya kuunda socket, ambayo itaita function `mac_socket_check_create`, ambayo nayo huita `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Zaidi ya hayo, macro `MAC_CHECK` imefafanuliwa katika security/mac_internal.h kama ifuatavyo:<sup>[[3]](#references)</sup>
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
Kupanua helper macros kunaonyesha mtiririko halisi wa udhibiti:
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
Kwa maneno mengine, `MAC_CHECK(socket_check_create, ...)` hupitia static policies kwanza, hufunga kwa masharti na kuzunguka dynamic policies, hutoa DTrace probes kuzunguka kila hook, na kuunganisha return code za kila hook kuwa matokeo moja ya `error` kupitia `mac_error_select()`.


### Labels

MACF hutumia **labels** ambazo policies zinazokagua ikiwa zinapaswa kutoa access fulani au la zitatumia. Code ya tangazo la labels struct inaweza [kupatikana hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), ambayo hutumika ndani ya **struct ucred** [hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) katika sehemu ya **`cr_label`**. Label ina flags na idadi ya **slots** zinazoweza kutumiwa na **MACF policies kutenga pointers**. Kwa mfano, Sanbox itaelekeza kwenye container profile

## MACF Policies

MACF Policy hufafanua **rule na conditions zitakazotumika katika kernel operations fulani**.

Kernel extension inaweza kusanidi struct ya `mac_policy_conf` na kisha kuisajili kwa kuiita `mac_policy_register`. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Ni rahisi kutambua kernel extensions zinazosanidi policies hizi kwa kuchunguza calls za `mac_policy_register`. Zaidi ya hayo, kwa kuchunguza disassemble ya extension, inawezekana pia kupata struct ya `mac_policy_conf` inayotumika.

Kumbuka kwamba MACF policies zinaweza kusajiliwa na kuondolewa pia **dynamically**.

Mojawapo ya fields kuu za `mac_policy_conf` ni **`mpc_ops`**. Field hii hubainisha ni operations zipi zinazovutia policy. Kuna operations nyingi sana, hivyo inawezekana kuweka entries zote kuwa zero, kisha kuchagua zile tu ambazo policy inahitaji. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Takribani hooks zote zitaitwa tena na MACF wakati mojawapo ya operesheni hizo zinapozuiwa. Hata hivyo, hooks za **`mpo_policy_*`** ni exception kwa sababu `mpo_hook_policy_init()` ni callback inayoitwa wakati wa usajili (yaani, baada ya `mac_policy_register()`), na `mpo_hook_policy_initbsd()` huitwa wakati wa late registration baada ya BSD subsystem kuinitialise ipasavyo.

Aidha, hook ya **`mpo_policy_syscall`** inaweza kusajiliwa na kext yoyote ili kufichua **ioctl** style call **interface** ya binafsi. Kisha user client ataweza kuita `mac_syscall` (#381) akibainisha kama parameters **policy name** yenye **code** ya integer na **arguments** za hiari.\
Kwa mfano, **`Sandbox.kext`** hutumia hii mara nyingi.

Kukagua **`__DATA.__const*`** ya kext kunawezesha kutambua muundo wa `mac_policy_ops` uliotumiwa wakati wa kusajili policy. Inawezekana kuupata kwa sababu pointer yake iko kwenye offset ndani ya `mpo_policy_conf`, na pia kwa sababu ya idadi ya NULL pointers zitakazokuwa katika eneo hilo.

Aidha, inawezekana kupata orodha ya kexts ambazo zimesanidi policy kwa kufanya dump kutoka memory ya struct **`_mac_policy_list`**, ambayo husasishwa kwa kila policy inayosajiliwa.

Unaweza pia kutumia tool `xnoop` kufanya dump ya policies zote zilizosajiliwa kwenye mfumo:
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
Na kisha dump checks zote za check policy kwa:
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
## Uanzishaji wa MACF katika XNU

### Bootstrap ya mapema na mac_policy_init()

- MACF huanzishwa mapema sana. Katika `bootstrap_thread` (katika msimbo wa kuanzisha XNU), baada ya `ipc_bootstrap`, XNU huita `mac_policy_init()` (katika `mac_base.c`).
- `mac_policy_init()` huanzisha `mac_policy_list` ya kimataifa (array au orodha ya policy slots) na kuweka miundombinu ya MAC (Mandatory Access Control) ndani ya XNU.
- Baadaye, `mac_policy_initmach()` huitwa; hushughulikia upande wa kernel wa usajili wa policies zilizojengwa ndani au zilizounganishwa.

### `mac_policy_initmach()` na kupakia “security extensions”

- `mac_policy_initmach()` huchunguza kernel extensions (kexts) zilizopakiwa awali (au zilizo kwenye orodha ya “policy injection”) na kukagua Info.plist zao ili kutafuta key `AppleSecurityExtension`.
- Kexts zinazotangaza `<key>AppleSecurityExtension</key>` (au `true`) katika Info.plist zao huchukuliwa kuwa “security extensions” — yaani, zinazotekeleza MAC policy au kuunganishwa na miundombinu ya MACF.
- Mifano ya Apple kexts zilizo na key hiyo ni pamoja na **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, miongoni mwa nyingine (kama ulivyoorodhesha tayari).
- Kernel huhakikisha kwamba kexts hizo zinapakiwa mapema, kisha huita routines zao za usajili (kupitia `mac_policy_register`) wakati wa boot, na kuziingiza kwenye `mac_policy_list`.

- Kila policy module (kext) hutoa muundo wa `mac_policy_conf`, wenye hooks (`mpc_ops`) za MAC operations mbalimbali (ukaguzi wa vnode, ukaguzi wa exec, masasisho ya label, na kadhalika).
- Load time flags zinaweza kujumuisha `MPC_LOADTIME_FLAG_NOTLATE`, yenye maana ya “lazima ipakiwe mapema” (hivyo majaribio ya usajili wa baadaye hukataliwa).
- Baada ya kusajiliwa, kila module hupata handle na kuchukua slot katika `mac_policy_list`.
- MAC hook inapoitwa baadaye (kwa mfano, wakati wa vnode access, exec, na kadhalika), MACF hurudia policies zote zilizosajiliwa ili kufanya maamuzi ya pamoja.

- Hasa, **AMFI** (Apple Mobile File Integrity) ni security extension ya aina hiyo. Info.plist yake inajumuisha `AppleSecurityExtension`, inayoitambulisha kama security policy.
- Kama sehemu ya kernel boot, loading logic ya kernel huhakikisha kwamba “security policy” (AMFI, na kadhalika) tayari iko active kabla ya subsystems nyingi kuitegemea. Kwa mfano, kernel “hujiandaa kwa tasks zinazofuata kwa kupakia … security policy, ikijumuisha AppleMobileFileIntegrity (AMFI), Sandbox, na Quarantine policy.”
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
## Dependency ya KPI na com.apple.kpi.dsep katika MAC policy kexts

Unapoandika kext inayotumia MAC framework (yaani, ikiita `mac_policy_register()` n.k.), lazima utangaze dependencies kwenye KPIs (Kernel Programming Interfaces) ili kext linker (kxld) iweze kutatua symbols hizo. Kwa hiyo, ili kutangaza kuwa `kext` inategemea MACF, lazima uonyeshe hilo kwenye `Info.plist` kwa kutumia `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), kisha kext itarejelea symbols kama `mac_policy_register`, `mac_policy_unregister`, na MAC hook function pointers. Ili kuzitatua, lazima uorodheshe `com.apple.kpi.dsep` kama dependency.

Mfano wa sehemu ya Info.plist (ndani ya .kext yako):
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

Kwenye macOS ya kisasa, security policies za Apple kwa kawaida hazichunguzwi vizuri zaidi kama bundles huru za `.kext`. Tangu **macOS 11**, kernel extensions huunganishwa kwenye **kernel collections**; kwenye **Apple Silicon** hakuna **SystemKC** tofauti, na kexts za third-party huwa loadable tu baada ya kujengwa ndani ya **Auxiliary Kernel Collection (AuxKC)** na kufanya reboot. Kwa utafiti wa MACF, hii inamaanisha kuwa policies zilizojengwa ndani kama **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** au **Quarantine** kwa kawaida ni rahisi kuorodheshwa kwa `kmutil` kuliko kwa tooling iliyopitwa na wakati kama `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Kwenye Apple Silicon, ikiwa security kext haipo kwenye BootKC, kagua AuxKC inayofuata. Hii kwa kawaida huwa na manufaa zaidi kuliko kutafuta bundle inayojitegemea chini ya `/System/Library/Extensions`.

## MACF Callouts

Ni jambo la kawaida kupata callouts za MACF zilizofafanuliwa kwenye code kama vile: **`#if CONFIG_MAC`** conditional blocks. Zaidi ya hayo, ndani ya blocks hizi inawezekana kupata calls za `mac_proc_check*`, ambazo huiita MACF ili **kuangalia ruhusa** za kutekeleza vitendo fulani. Pia, muundo wa MACF callouts ni: **`mac_<object>_<opType>_opName`**.

Object ni mojawapo ya zifuatazo: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` kwa kawaida huwa check, ambayo itatumika kuruhusu au kukataa kitendo. Hata hivyo, inawezekana pia kupata `notify`, ambayo itaruhusu kext kuitikia kitendo kilichotolewa.

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
Ambayo inaita macro ya `MAC_CHECK`, ambayo code yake inaweza kupatikana katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
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
Ambayo itapitia sera zote za mac zilizosajiliwa, ikiita functions zake na kuhifadhi output ndani ya error variable, ambayo inaweza kubadilishwa na `mac_error_select` pekee kupitia success codes; hivyo, ikiwa check yoyote itashindikana, check nzima itashindikana na action haitaruhusiwa.

> [!TIP]
> Hata hivyo, kumbuka kwamba si MACF callouts zote hutumika tu kukataa actions. Kwa mfano, `mac_priv_grant` huita macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), ambayo itatoa privilege iliyoombwa ikiwa policy yoyote itajibu kwa 0:
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

Callouts hizi zimekusudiwa kuangalia na kutoa **privileges** (makumi kati yake) zilizofafanuliwa katika [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Baadhi ya kernel code inaweza kuita `priv_check_cred()` kutoka [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c), ikiipa KAuth credentials za process na mojawapo ya privilege codes, ambayo itaita `mac_priv_check` ili kuona kama policy yoyote **inakataa** kutoa privilege, kisha itaaita `mac_priv_grant` ili kuona kama policy yoyote inatoa `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Hook hii inaruhusu ku-intercept system calls zote. Katika `bsd/dev/[i386|arm]/systemcalls.c`, inawezekana kuona function iliyotangazwa [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), iliyo na code hii:
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
Ambayo itakagua **bitmask** katika process inayopiga simu ili kubaini kama syscall ya sasa inapaswa kuita `mac_proc_check_syscall_unix`. Hii ni kwa sababu syscalls huitwa mara nyingi sana, hivyo ni muhimu kuepuka kuita `mac_proc_check_syscall_unix` kila wakati.

Kumbuka kwamba function `proc_set_syscall_filter_mask()`, ambayo huweka bitmask ya syscalls katika process, huitwa na Sandbox ili kuweka masks kwenye processes zilizo sandboxed.

## syscalls za MACF zilizo wazi

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
Kwa **offensive reversing**, **`__mac_syscall`** bado ni mojawapo ya chokepoint bora za userland. Hubeba **jina la policy** (kwa mfano `"Sandbox"` au `"AMFI"`), selector/code maalum wa **policy**, na pointer inayoelekeza kwenye **opaque argument blob** itakayoshughulikiwa na `mpo_policy_syscall`. Hii ni muhimu sana wakati wa kureverse operations zisizo na nyaraka kutoka userland kwanza, kisha baadaye kuhamia kwenye implementation ya kernel. Sandbox kwa kawaida huifikia kupitia `__sandbox_ms`, na AMFI hutumia mechanism hiyo hiyo kwa maamuzi ya policy ya dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Vidokezo vya practical offensive research

Bugs za hivi karibuni za macOS mara chache "huvunja MACF" moja kwa moja. Badala yake, kwa kawaida hutumia **desynchronisation kati ya uamuzi wa MACF / Sandbox / TCC na action yenye privilege inayotekelezwa baadaye**.

### Ukaguzi wa path wa broker dhidi ya action halisi yenye privilege

Mwelekeo unaojirudia ni daemon yenye privilege kufanya **userland pre-check** (kwa mfano `sandbox_check_by_audit_token()`) kwenye toleo moja la path, kisha baadaye kutekeleza sink halisi yenye privilege kwa kutumia **path tofauti au isiyo canonical inayodhibitiwa na attacker**. Utafiti wa hivi karibuni wa `diskarbitrationd` / `storagekitd` ni mfano mzuri: **directory traversal** pamoja na **symlink swaps** humwezesha attacker kupita validation ya sandbox ya daemon, kisha kufanya mount juu ya maeneo nyeti kama `~/Library/Application Support/com.apple.TCC`, na kugeuza bug hiyo kuwa **sandbox escape**, **local privilege escalation** au **TCC bypass**, kutegemea mount point iliyochaguliwa.<sup>[[6]](#references)</sup>

Unapokagua root brokers zinazofikika kutoka sandbox, anza kwa kutumia grep kutafuta:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers za path canonicalisation
- sinks zenye privilege kama `mount`, `rename`, `copyfile`, methods za helper-tool XPC, au kitu chochote ambacho baadaye hugusa paths zinazodhibitiwa na attacker kama root

### Trusted deputies zenye private entitlements

Mwelekeo mwingine wa practical ni kuepuka kushambulia MACF hooks moja kwa moja na badala yake kutumia vibaya **process inayoaminika** ambayo tayari ina rights zinazohitajika kuvuka boundary. Utafiti wa hivi karibuni wa Safari/TCC ni mfano mzuri: primitive ya kuvutia haikuwa "kuzima TCC kwenye kernel", bali kurekebisha local policy/configuration ili process iliyosainiwa na Apple yenye **`com.apple.private.tcc.allow`** ikutendee action nyeti.<sup>[[8]](#references)</sup> Kwa vitendo, targets zenye thamani kubwa za auditing ni Apple daemons/apps zinazochanganya:

- **private entitlements** au reach inayofanana na FDA
- config / database / mount point / policy file inayoweza kuandikwa
- operation nyeti ya baadaye inayodhibitiwa na **Sandbox**, **AMFI**, **TCC** au policy nyingine ya MACF

Kwa reversing ya kina zaidi inayolenga bidhaa mahususi, angalia kurasa maalum za [macOS Sandbox](macos-sandbox/README.md) na [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (vector kamili ya MACF policy operations)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macros za `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (codes za privilege zinazotumiwa na `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Kugundua Apple Vulnerabilities: Ukaguzi wa diskarbitrationd na storagekitd, Sehemu ya 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — zana ya XNU Cross Reference](https://newosxbook.com/xxr/index.php)
- [8] [Athari mpya ya macOS, "HM Surf", inaweza kusababisha ufikiaji wa data bila idhini (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
