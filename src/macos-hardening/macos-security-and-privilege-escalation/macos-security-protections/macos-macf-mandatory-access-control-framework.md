# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

**MACF** inamaanisha **Mandatory Access Control Framework**, ambayo ni mfumo wa usalama uliojengwa ndani ya operating system ili kusaidia kulinda kompyuta yako. Hufanya kazi kwa kuweka **kanuni kali kuhusu nani au nini kinaweza kufikia sehemu fulani za mfumo**, kama vile files, applications na system resources. Kwa kutekeleza kanuni hizi kiotomatiki, MACF huhakikisha kuwa users na processes walioidhinishwa pekee wanaweza kutekeleza actions mahususi, hivyo kupunguza hatari ya unauthorized access au malicious activities.

Kumbuka kuwa MACF haifanyi maamuzi yenyewe kwa kweli, kwa sababu **hukamata** actions, na huacha maamuzi hayo kwa **policy modules** (kernel extensions) inazoziita kama `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` na `mcxalr.kext`.

- Policy inaweza kuwa enforcing (kurudisha 0 non-zero kwenye operation fulani)
- Policy inaweza kuwa monitoring (kurudisha 0, ili isipinge lakini itumie hook kufanya jambo)
- MACF static policy husakinishwa wakati wa boot na HAIWEZI kamwe kuondolewa
- MACF dynamic policy husakinishwa na KEXT (kextload) na kinadharia inaweza kuondolewa kwa kextunload
- Kwenye iOS, static policies pekee ndizo zinazoruhusiwa, na kwenye macOS static + dynamic.<sup>[[7]](#references)</sup>

### Mtiririko

1. Process hufanya syscall/mach trap
2. Function husika huitwa ndani ya kernel
3. Function huita MACF
4. MACF hukagua policy modules zilizoomba ku-hook function hiyo kwenye policy yao
5. MACF huita policies husika
6. Policies huashiria ikiwa zinaruhusu au zinakataa action

> [!CAUTION]
> Apple pekee ndiye anayeweza kutumia MAC Framework KPI.

Kwa kawaida, functions zinazokagua permissions kwa kutumia MACF zitaita macro `MAC_CHECK`. Kwa mfano, syscall ya kuunda socket itaita function `mac_socket_check_create`, ambayo huita `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Zaidi ya hayo, macro `MAC_CHECK` inafafanuliwa katika security/mac_internal.h kama ifuatavyo:<sup>[[3]](#references)</sup>
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
Kwa maneno mengine, `MAC_CHECK(socket_check_create, ...)` hupitia policies tuli kwanza, hufunga kwa masharti na kupitia policies zinazobadilika, hutoa probes za DTrace kuzunguka kila hook, na kuunganisha return code za kila hook kuwa matokeo moja ya `error` kupitia `mac_error_select()`.


### Labels

MACF hutumia **labels**, ambazo policies hutumia kuangalia kama zinapaswa kutoa access fulani au la. Code ya declaration ya labels struct inaweza [kupatikana hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), na hutumika ndani ya **struct ucred** [hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) katika sehemu ya **`cr_label`**. Label ina flags na idadi fulani ya **slots** zinazoweza kutumiwa na **MACF policies kutenga pointers**. Kwa mfano, Sandbox itaelekeza kwenye container profile.

## MACF Policies

MACF Policy hufafanua **rule na conditions zitakazotumika katika kernel operations fulani**.

Kernel extension inaweza kusanidi struct ya `mac_policy_conf` na kisha kuisajili kwa kuita `mac_policy_register`. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Ni rahisi kutambua kernel extensions zinazosanidi policies hizi kwa kuangalia calls za `mac_policy_register`. Zaidi ya hayo, kwa kukagua disassemble ya extension, inawezekana pia kupata struct ya `mac_policy_conf` inayotumika.

Kumbuka kwamba MACF policies zinaweza kusajiliwa na kuondolewa pia **dynamically**.

Mojawapo ya fields kuu za `mac_policy_conf` ni **`mpc_ops`**. Field hii hubainisha ni operations zipi policy inazohitaji. Kumbuka kwamba kuna mamia ya operations hizo, kwa hivyo inawezekana kuziweka zote kuwa zero, kisha kuchagua zile tu ambazo policy inazihitaji. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Karibu hooks zote zitaitwa callback na MACF wakati moja ya operesheni hizo inainterceptiwa. Hata hivyo, hooks za **`mpo_policy_*`** ni exception kwa sababu `mpo_hook_policy_init()` ni callback inayoitwa wakati wa registration (kwa hiyo baada ya `mac_policy_register()`), na `mpo_hook_policy_initbsd()` inaitwa wakati wa late registration baada ya BSD subsystem kuinitialise ipasavyo.

Zaidi ya hayo, hook ya **`mpo_policy_syscall`** inaweza kusajiliwa na kext yoyote ili kufichua **interface** ya calls za binafsi za aina ya **ioctl**. Kisha user client ataweza kuita `mac_syscall` (#381) akibainisha kama parameters **policy name** yenye integer **code** na **arguments** za hiari.\
Kwa mfano, **`Sandbox.kext`** hutumia hii mara nyingi.

Kukagua **`__DATA.__const*`** ya kext kunawezesha kutambua muundo wa `mac_policy_ops` unaotumiwa wakati wa kusajili policy. Inawezekana kuupata kwa sababu pointer yake iko kwenye offset ndani ya `mpo_policy_conf`, na pia kwa sababu ya idadi ya NULL pointers zitakazokuwa katika eneo hilo.

Zaidi ya hayo, inawezekana pia kupata orodha ya kexts zilizoconfigure policy kwa kudump kutoka kwenye memory struct **`_mac_policy_list`**, ambayo husasishwa kwa kila policy inayosajiliwa.

Unaweza pia kutumia tool `xnoop` kudump policies zote zilizosajiliwa kwenye mfumo:
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

- MACF inaanzishwa mapema sana. Katika `bootstrap_thread` (kwenye msimbo wa uanzishaji wa XNU), baada ya `ipc_bootstrap`, XNU huita `mac_policy_init()` (katika `mac_base.c`).
- `mac_policy_init()` huanzisha `mac_policy_list` ya kimataifa (array au list ya policy slots) na kuweka miundombinu ya MAC (Mandatory Access Control) ndani ya XNU.
- Baadaye, `mac_policy_initmach()` huitwa; hushughulikia upande wa kernel wa usajili wa policy kwa policies zilizojengwa ndani au zilizowekwa pamoja.

### `mac_policy_initmach()` na kupakia “security extensions”

- `mac_policy_initmach()` huchunguza kernel extensions (kexts) zilizopakiwa mapema (au zilizo kwenye “policy injection” list) na kukagua Info.plist zao kwa key ya `AppleSecurityExtension`.
- Kexts zinazotangaza `<key>AppleSecurityExtension</key>` (au `true`) katika Info.plist zao huchukuliwa kuwa “security extensions” — yaani, zinazotekeleza MAC policy au kuunganishwa na miundombinu ya MACF.
- Mifano ya Apple kexts zilizo na key hiyo ni pamoja na **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, na nyingine, kama ulivyotaja awali.
- Kernel huhakikisha kwamba kexts hizo zinapakiwa mapema, kisha huita taratibu zao za usajili (kupitia `mac_policy_register`) wakati wa boot, na kuziingiza kwenye `mac_policy_list`.

- Kila policy module (kext) hutoa muundo wa `mac_policy_conf`, wenye hooks (`mpc_ops`) kwa shughuli mbalimbali za MAC (ukaguzi wa vnode, ukaguzi wa exec, masasisho ya label, na kadhalika).
- Load time flags zinaweza kujumuisha `MPC_LOADTIME_FLAG_NOTLATE`, inayomaanisha “lazima ipakiwe mapema” (hivyo majaribio ya usajili wa baadaye hukataliwa).
- Baada ya kusajiliwa, kila module hupewa handle na kuchukua slot katika `mac_policy_list`.
- MAC hook inapoitwa baadaye (kwa mfano, wakati wa vnode access, exec, na kadhalika), MACF hurudia policies zote zilizosajiliwa ili kufanya maamuzi ya pamoja.

- Hasa, **AMFI** (Apple Mobile File Integrity) ni security extension ya aina hiyo. Info.plist yake inajumuisha `AppleSecurityExtension`, ikiiainisha kama security policy.
- Kama sehemu ya kernel boot, loading logic ya kernel huhakikisha kwamba “security policy” (AMFI, na kadhalika) tayari iko active kabla ya subsystems nyingi kuitegemea. Kwa mfano, kernel “hujiandaa kwa tasks zinazofuata kwa kupakia … security policy, ikijumuisha AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Utegemezi wa KPI na com.apple.kpi.dsep katika MAC policy kexts

Unapoandika kext inayotumia MAC framework (yaani, ikiita `mac_policy_register()` n.k.), lazima utangaze utegemezi kwenye KPIs (Kernel Programming Interfaces) ili kext linker (kxld) iweze kutatua symbols hizo. Kwa hiyo, ili kutangaza kwamba `kext` inategemea MACF, unahitaji kuionyesha katika `Info.plist` kwa kutumia `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), kisha kext itarejelea symbols kama `mac_policy_register`, `mac_policy_unregister`, na MAC hook function pointers. Ili kuzitatua, lazima uorodheshe `com.apple.kpi.dsep` kama utegemezi.

Mfano wa kipande cha Info.plist (ndani ya .kext yako):
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

Kwenye macOS ya kisasa, sera za usalama za Apple kwa kawaida hazichunguzwi vizuri zaidi kama vifurushi huru vya `.kext`. Tangu **macOS 11**, kernel extensions huunganishwa kwenye **kernel collections**; kwenye **Apple Silicon** hakuna **SystemKC** tofauti, na kexts za wahusika wengine huwa zinaweza kupakiwa tu baada ya kujengwa ndani ya **Auxiliary Kernel Collection (AuxKC)** na kuwashwa upya. Kwa utafiti wa MACF, hii inamaanisha kwamba sera zilizojengewa ndani kama **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** au **Quarantine** kwa kawaida ni rahisi kuorodhesha kwa kutumia `kmutil` kuliko kutumia tooling iliyopitwa na wakati kama `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Kwenye Apple Silicon, ikiwa security kext haipo kwenye BootKC, kagua AuxKC inayofuata. Hii kwa kawaida huwa na manufaa zaidi kuliko kutafuta standalone bundle chini ya `/System/Library/Extensions`.

## MACF Callouts

Ni kawaida kupata callouts za MACF zikifafanuliwa kwenye code kama vile blocks za masharti za **`#if CONFIG_MAC`**. Zaidi ya hayo, ndani ya blocks hizi inawezekana kupata calls za `mac_proc_check*` ambazo huiita MACF ili **kuangalia ruhusa** za kutekeleza actions fulani. Pia, muundo wa MACF callouts ni: **`mac_<object>_<opType>_opName`**.

Object ni mojawapo ya zifuatazo: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` kwa kawaida ni check ambayo itatumika kuruhusu au kukataa action. Hata hivyo, inawezekana pia kupata `notify`, ambayo itaruhusu kext kuitikia action iliyotolewa.

Unaweza kupata mfano kwenye [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Kisha, inawezekana kupata code ya `mac_file_check_mmap` kwenye [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Ambayo inaita macro ya `MAC_CHECK`, ambayo msimbo wake unaweza kupatikana kwenye [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
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
Ambayo itapitia policies zote za mac zilizosajiliwa, ikiita functions zake na kuhifadhi matokeo ndani ya variable ya error, ambayo inaweza kubadilishwa tu na `mac_error_select` kupitia success codes; hivyo, ikiwa check yoyote itashindikana, check nzima itashindikana na action haitaruhusiwa.

> [!TIP]
> Hata hivyo, kumbuka kwamba si callouts zote za MACF hutumika tu kukataa actions. Kwa mfano, `mac_priv_grant` inaita macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), ambayo itatoa privilege iliyoombwa ikiwa policy yoyote itajibu kwa 0:
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

Calls hizi zimekusudiwa ku-check na kutoa (makumi ya) **privileges** zilizofafanuliwa katika [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Baadhi ya kernel code inaweza kuita `priv_check_cred()` kutoka [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) ikiwa na KAuth credentials za process pamoja na privilege code moja, ambayo itaita `mac_priv_check` ili kuona kama policy yoyote **inazuia** kutolewa kwa privilege, kisha ita-ita `mac_priv_grant` ili kuona kama policy yoyote inatoa `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Hook hii inaruhusu ku-intercept system calls zote. Katika `bsd/dev/[i386|arm]/systemcalls.c`, inawezekana kuona function iliyotangazwa [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), ambayo ina code hii:
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
Ambayo itaangalia kwenye **bitmask** ya mchakato unaoiita ikiwa syscall ya sasa inapaswa kuita `mac_proc_check_syscall_unix`. Hii ni kwa sababu syscalls huitwa mara nyingi sana, hivyo ni muhimu kuepuka kuita `mac_proc_check_syscall_unix` kila wakati.

Kumbuka kwamba function `proc_set_syscall_filter_mask()`, ambayo huweka bitmask ya syscalls kwenye mchakato, huitwa na Sandbox ili kuweka masks kwenye processes zilizowekewa sandbox.

## Syscalls za MACF zilizo wazi

Inawezekana kuingiliana na MACF kupitia baadhi ya syscalls zilizofafanuliwa kwenye [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Kwa reversing ya offensive, **`__mac_syscall`** bado ni mojawapo ya sehemu bora za userland za kupitisha shughuli. Hubeba **jina la policy** (kwa mfano `"Sandbox"` au `"AMFI"`), **selector/code maalum ya policy**, na pointer kuelekea **opaque argument blob** itakayoshughulikiwa na `mpo_policy_syscall`. Hii ni muhimu sana unapofanya reversing ya operations zisizo na documentation kutoka userland kwanza, kisha baadaye kuhamia kwenye implementation ya kernel. Sandbox mara nyingi huifikia kupitia `__sandbox_ms`, na AMFI hutumia mechanism hiyo hiyo kwa maamuzi ya dyld policy.<sup>[[2]](#references)[[5]](#references)</sup>

## Practical offensive research notes

Bugs za hivi karibuni za macOS mara chache "huvunja MACF" moja kwa moja. Badala yake, kwa kawaida hutumia **desynchronisation kati ya uamuzi wa MACF / Sandbox / TCC na action yenye privileged inayotekelezwa baadaye**.

### Broker path checks vs real privileged action

Pattern inayojirudia ni daemon yenye privileged kufanya **userland pre-check** (kwa mfano `sandbox_check_by_audit_token()`) kwenye toleo moja la path, kisha baadaye kutekeleza real privileged sink kwa kutumia **path tofauti au isiyo-canonical inayodhibitiwa na attacker**. Utafiti wa hivi karibuni kuhusu `diskarbitrationd` / `storagekitd` ni mfano mzuri: **directory traversal** pamoja na **symlink swaps** humwezesha attacker kupita sandbox validation ya daemon, kisha kufanya mount juu ya maeneo nyeti kama `~/Library/Application Support/com.apple.TCC`, na kugeuza bug hiyo kuwa **sandbox escape**, **local privilege escalation** au **TCC bypass**, kulingana na mount point iliyochaguliwa.<sup>[[6]](#references)</sup>

Unapoaudit root brokers zinazoweza kufikiwa kutoka sandbox, anza kwa kufanya grep ya:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks kama `mount`, `rename`, `copyfile`, helper-tool XPC methods, au chochote kinachogusa baadaye paths zinazodhibitiwa na attacker kama root

### Trusted deputies with private entitlements

Pattern nyingine ya practical ni kuepuka kushambulia MACF hooks moja kwa moja na badala yake kutumia **trusted process** ambayo tayari ina rights zinazohitajika kuvuka boundary. Utafiti wa hivi karibuni kuhusu Safari/TCC ni mfano mzuri: primitive ya kuvutia haikuwa "kuzima TCC kwenye kernel", bali kurekebisha local policy/configuration ili process iliyosainiwa na Apple yenye **`com.apple.private.tcc.allow`** ifanye sensitive action kwa niaba yako.<sup>[[8]](#references)</sup> Kwa vitendo, targets zenye thamani kubwa za auditing ni Apple daemons/apps zinazochanganya:

- **private entitlements** au reach inayofanana na FDA
- config / database / mount point / policy file inayoweza kuandikwa
- sensitive operation ya baadaye inayosimamiwa na **Sandbox**, **AMFI**, **TCC** au policy nyingine ya MACF

Kwa reversing ya kina inayohusiana na product fulani, angalia pages maalum kuhusu [macOS Sandbox](macos-sandbox/README.md) na [macOS TCC](macos-tcc/README.md).

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
