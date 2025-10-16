# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**MACF** inamaanisha **Mandatory Access Control Framework**, ambayo ni mfumo wa usalama uliojengewa ndani ya mfumo wa uendeshaji kusaidia kulinda kompyuta yako. Inafanya kazi kwa kuweka **kanuni kali kuhusu nani au nini kinaweza kufikia sehemu fulani za mfumo**, kama vile faili, programu, na rasilimali za mfumo. Kwa kutekeleza kanuni hizi moja kwa moja, MACF inahakikisha kuwa ni watumiaji na michakato iliyoidhinishwa tu wanaoweza kufanya vitendo maalum, hivyo kupunguza hatari ya ufikiaji usioidhinishwa au shughuli zenye malintent.

Kumbuka kwamba MACF haifanyi maamuzi yenyewe kwani inakamata tu vitendo; inaacha maamuzi kwa **policy modules** (kernel extensions) inayoita kama `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` and `mcxalr.kext`.

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- A MACF static policy is installed in boot and will NEVER be removed
- A MACF dynamic policy is installed by a KEXT (kextload) and may hypothetically be kextunloaded
- In iOS only static policies are allowed and in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Mtiririko

1. Mchakato hufanya syscall/mach trap
2. Kazi husika inaitwa ndani ya kernel
3. Kazi inaita MACF
4. MACF hukagua policy modules zilizokuomba ku-hook kazi hiyo katika sera zao
5. MACF inaita sera husika
6. Sera zinaonyesha kama zinakubali au kukataa hatua hiyo

> [!CAUTION]
> Apple ndiye pekee anayeweza kutumia MAC Framework KPI.

Kawaida kazi zinazokagua ruhusa kwa MACF zitaitisha macro `MAC_CHECK`. Kama ilivyo katika kesi ya syscall ya kuunda socket ambayo itaita kazi `mac_socket_check_create` ambayo inaita `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Zaidi ya hayo, macro `MAC_CHECK` imefafanuliwa katika security/mac_internal.h kama:
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
Kumbuka kwamba ukiibadilisha `check` kuwa `socket_check_create` na `args...` kuwa `(cred, domain, type, protocol)` unapata:
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
Kupanua helper macros kunaonyesha mtiririko wa udhibiti halisi:
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
Kwa maneno mengine, `MAC_CHECK(socket_check_create, ...)` hupitia kwanza sera za statiki, kwa masharti hufunga na kurudia juu ya sera za dynamic, hutoa DTrace probes karibu na kila hook, na huweka msimbo wa kurudisha wa kila hook pamoja kuwa matokeo moja ya `error` kupitia `mac_error_select()`.

### Lebuli

MACF inatumia **lebuli** ambazo sera zitakazokagua ikiwa zinapaswa kutoa ruhusa au la zitazitumia. Msimbo wa tamko la struct la lebuli unaweza kupatikana [hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), ambao baadaye unatumika ndani ya **`struct ucred`** katika [**hapa**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) katika sehemu ya **`cr_label`**. Lebuli ina bendera na idadi ya **slots** ambazo zinaweza kutumika na **MACF policies to allocate pointers**. Kwa mfano Sandbox itahusu container profile.

## Sera za MACF

Sera ya MACF inabainisha **kanuni na masharti yatakayotekelezwa katika baadhi ya shughuli za kernel**.

Extension ya kernel inaweza kusanidi `mac_policy_conf` struct kisha kuisajili kwa kuita `mac_policy_register`. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Ni rahisi kutambua kernel extensions zinazopanga sera hizi kwa kukagua miito ya `mac_policy_register`. Zaidi ya hayo, kwa kukagua disassembly ya extension pia inawezekana kupata struct ya `mac_policy_conf` inayotumika.

Kumbuka kwamba sera za MACF zinaweza kusajiliwa na kuondolewa pia **kwa wakati wa utekelezaji**.

Mmoja wa nyanja kuu za `mac_policy_conf` ni **`mpc_ops`**. Sehemu hii inaeleza ni operesheni gani sera inazovutiwa nazo. Kumbuka kuna mamia yao, kwa hivyo inawezekana kuziweka zote kuwa sifuri kisha kuchagua tu zile ambazo sera inavutiwa nazo. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Karibu hooks zote zitatumiwa (zitaitwa) na MACF wakati moja ya operesheni hizo itakapokamatwa. Hata hivyo, **`mpo_policy_*`** hooks ni tofauti kwa sababu `mpo_hook_policy_init()` ni callback inayoitwa wakati wa usajili (hivyo baada ya `mac_policy_register()`) na `mpo_hook_policy_initbsd()` inaitwa wakati wa usajili wa kuchelewa mara subsystem ya BSD itakapokuwa imeanzishwa kikamilifu.

Zaidi ya hayo, hook **`mpo_policy_syscall`** inaweza kusajiliwa na kext yoyote ili kufichua kiolesura cha aina ya wito la **ioctl**. Kisha, user client itaweza kuita `mac_syscall` (#381) ikibainisha kama vigezo **policy name** pamoja na integer **code** na **arguments** za hiari.\
Kwa mfano, **`Sandbox.kext`** inatumia hili sana.

Kupitia kuangalia **`__DATA.__const*`** ya kext ni uwezekano kutambua muundo `mac_policy_ops` uliotumika wakati wa usajili wa sera. Inawezekana kuupata kwa sababu pointer yake iko kwenye offset ndani ya `mpo_policy_conf` na pia kutokana na idadi ya NULL pointers zitakazokuwepo katika eneo hilo.

Zaidi ya hayo, pia inawezekana kupata orodha ya kexts ambazo zimeanzisha sera kwa dump kutoka memory muundo **`_mac_policy_list`** ambao unasasishwa kwa kila sera inayosajiliwa.

Unaweza pia kutumia chombo `xnoop` ku-dump sera zote zilizojisajili katika mfumo:
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
Kisha dump all the checks of check policy kwa:
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

### Uanzishaji wa mapema na mac_policy_init()

- MACF inaanzishwa mapema sana. Katika `bootstrap_thread` (katika msimbo wa kuanzisha XNU), baada ya `ipc_bootstrap`, XNU inaita `mac_policy_init()` (katika `mac_base.c`).
- `mac_policy_init()` inaanzisha `mac_policy_list` ya kimataifa (array au orodha ya slots za sera) na kuandaa miundombinu ya MAC (Mandatory Access Control) ndani ya XNU.
- Baadaye, `mac_policy_initmach()` inaitwa, ambayo inashughulikia upande wa kernel wa usajili wa sera kwa sera zilizojengwa ndani au zilizobundled.

### `mac_policy_initmach()` and loading “security extensions”

- `mac_policy_initmach()` inakagua kernel extensions (kexts) ambazo zimepreload (au katika orodha ya “policy injection”) na inachunguza Info.plist yao kwa key `AppleSecurityExtension`.
- Kexts ambazo zinaeleza `<key>AppleSecurityExtension</key>` (au `true`) katika Info.plist yao zinachukuliwa kuwa “security extensions” — yaani zile zinazotekeleza sera ya MAC au kuingiza hook katika miundombinu ya MACF.
- Mifano ya kexts za Apple zenye key hiyo ni pamoja na **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, miongoni mwa zingine.
- Kernel inahakikisha kexts hizo zinapakiwa mapema, kisha inaita routines zao za usajili (kwa kupitia `mac_policy_register`) wakati wa boot, na kuziingiza kwenye `mac_policy_list`.

- kila module ya sera (kext) hutoa muundo wa `mac_policy_conf`, wenye hooks (`mpc_ops`) kwa shughuli mbalimbali za MAC (ukagua vnode, ukaguzi wa exec, masasisho ya label, n.k.).
- bendera za wakati wa upakiaji zinaweza kujumuisha `MPC_LOADTIME_FLAG_NOTLATE` ambayo inamaanisha “inapaswa kupakiwa mapema” (hivyo majaribio ya usajili wa kuchelewa yanakataliwa).
- Mara imejisajili, kila module hupata handle na kuchukua slot katika `mac_policy_list`.
- Wakati hook ya MAC inapoitwa baadaye (kwa mfano, kufikia vnode, exec, n.k.), MACF hupitia sera zote zilizosajiliwa kufanya maamuzi kwa pamoja.

- Kwa kawaida, **AMFI** (Apple Mobile File Integrity) ni extension ya usalama kama hiyo. Info.plist yake inajumuisha `AppleSecurityExtension` ikimfanya kuwa sera ya usalama.
- Kama sehemu ya boot ya kernel, logic ya upakiaji ya kernel inahakikisha kwamba “security policy” (AMFI, n.k.) tayari inafanya kazi kabla subsystems nyingi kuitegemea. Kwa mfano, kernel “inajiandaa kwa kazi zinazofuata kwa kupakia … security policy, ikiwa ni pamoja na AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Tegemezi la KPI & com.apple.kpi.dsep katika MAC policy kexts

Unapoongeza kext inayotumia MAC framework (kwa mfano kuwaita `mac_policy_register()` n.k.), lazima utaje utegemezi kwenye KPI (Kernel Programming Interfaces) ili linker ya kext (kxld) iweze kutatua alama hizo. Hivyo, ili kubainisha kwamba `kext` inategemea MACF unahitaji kuionyesha ndani ya `Info.plist` kwa `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); kisha kext itarejea alama kama `mac_policy_register`, `mac_policy_unregister`, na MAC hook function pointers. Ili kuzitatua, lazima uorode `com.apple.kpi.dsep` kama utegemezi.
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
## Mitoaji ya MACF

Ni kawaida kupata mitoaji ya MACF iliyofafanuliwa katika code kama: **`#if CONFIG_MAC`** conditional blocks. Zaidi ya hayo, ndani ya blocks hizi inawezekana kupata mwito wa `mac_proc_check*` ambao unamwita MACF ili **kuangalia ruhusa** za kutekeleza vitendo fulani. Muundo wa mitoaji ya MACF ni: **`mac_<object>_<opType>_opName`**.

Kitu (object) ni mojawapo ya zifuatazo: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` kawaida huwa `check` ambayo itatumika kuruhusu au kukataa hatua. Hata hivyo, pia inawezekana kupata `notify`, ambayo itayaruhusu kext kujibu tendo hilo.

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

Kisha, inawezekana kupata msimbo wa `mac_file_check_mmap` katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Ambayo inaita macro ya `MAC_CHECK`, ambayo msimbo wake unaweza kupatikana katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Ambazo zitapitia sera zote za mac zilizosajiliwa, zikitoa wito kwa funguo zao na kuhifadhi matokeo ndani ya variable ya `error`, ambayo inaweza kubadilishwa tu na `mac_error_select` kwa misimbo ya mafanikio; hivyo, ikiwa ukaguzi wowote utafaulu ukaguzi mzima utafeli na kitendo haitaruhusiwa.

> [!TIP]
> Hata hivyo, kumbuka kuwa si miito yote ya MACF inatumiwa tu kukataa vitendo. Kwa mfano, `mac_priv_grant` inaita macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), ambayo itampa ruhusa iliyotakiwa ikiwa sera yoyote itajibu kwa 0:
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
Baadhi ya code ya kernel itaita `priv_check_cred()` kutoka [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) kwa hati za KAuth za mchakato na moja ya misimbo ya privileges ambazo zitaaita `mac_priv_check` kuona kama sera yoyote **inakataza** (**denies**) kutoa privilege, na kisha itaita `mac_priv_grant` kuona kama sera yoyote inapatia `privilege`.

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
Ambayo itachunguza katika mchakato unaoitisha **bitmask** ikiwa syscall ya sasa inapaswa kuita `mac_proc_check_syscall_unix`. Hii ni kwa sababu syscalls zinaitishwa mara nyingi sana, hivyo inafaa kuepuka kuita `mac_proc_check_syscall_unix` kila mara.

Tambua kwamba function `proc_set_syscall_filter_mask()`, ambayo inaweka **bitmask** ya syscalls katika mchakato, inaitwa na Sandbox ili kuweka masks kwenye sandboxed processes.

## Syscalls za MACF zilizofichuliwa

Inawezekana kuingiliana na MACF kupitia baadhi ya syscalls zilizobainishwa katika [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Marejeo

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
