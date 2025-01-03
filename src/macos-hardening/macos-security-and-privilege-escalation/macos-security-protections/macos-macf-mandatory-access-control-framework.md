# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**MACF** inasimama kwa **Mandatory Access Control Framework**, ambayo ni mfumo wa usalama uliojengwa ndani ya mfumo wa uendeshaji kusaidia kulinda kompyuta yako. Inafanya kazi kwa kuweka **kanuni kali kuhusu nani au nini kinaweza kufikia sehemu fulani za mfumo**, kama vile faili, programu, na rasilimali za mfumo. Kwa kutekeleza kanuni hizi kiotomatiki, MACF inahakikisha kwamba ni watumiaji na michakato walioidhinishwa pekee wanaweza kufanya vitendo maalum, kupunguza hatari ya ufikiaji usioidhinishwa au shughuli mbaya.

Kumbuka kwamba MACF haifanyi maamuzi yoyote kwani inachukua tu **hatua**, inawaachia maamuzi **moduli za sera** (kernel extensions) inazopiga simu kama `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` na `mcxalr.kext`.

### Mchakato

1. Mchakato unafanya syscall/mach trap
2. Kazi husika inaitwa ndani ya kernel
3. Kazi inaita MACF
4. MACF inakagua moduli za sera ambazo zilitaka kuunganisha kazi hiyo katika sera zao
5. MACF inaita sera husika
6. Sera zinaonyesha kama zinaruhusu au kukataa hatua hiyo

> [!CAUTION]
> Apple ndiye pekee anayeweza kutumia KPI ya MAC Framework.

### Lebo

MACF inatumia **lebo** ambazo sera zitakazokagua ikiwa zinapaswa kutoa ufikiaji fulani au la. Kanuni ya tamko la lebo inaweza kupatikana [hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), ambayo kisha inatumika ndani ya **`struct ucred`** katika [**hapa**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) katika sehemu ya **`cr_label`**. Lebo ina bendera na nambari ya **slots** ambazo zinaweza kutumika na **sera za MACF kutoa viashiria**. Kwa mfano, Sanbox itakuwa na kiashiria kwa wasifu wa kontena.

## Sera za MACF

Sera ya MACF inafafanua **kanuni na masharti yanayopaswa kutumika katika operesheni fulani za kernel**.&#x20;

Kupanua kernel kunaweza kuunda tamko la `mac_policy_conf` na kisha kujiandikisha kwa kuita `mac_policy_register`. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Ni rahisi kubaini nyongeza za kernel zinazounda sera hizi kwa kuangalia simu za `mac_policy_register`. Zaidi ya hayo, kuangalia disassemble ya nyongeza pia inawezekana kupata muundo wa `mac_policy_conf` unaotumika.

Kumbuka kwamba sera za MACF zinaweza kuandikishwa na kufutwa pia **kikamilifu**.

Moja ya maeneo makuu ya `mac_policy_conf` ni **`mpc_ops`**. Huu ni uwanja unaoeleza ni shughuli zipi sera inavutiwa nazo. Kumbuka kwamba kuna mamia yao, hivyo inawezekana kuweka sifuri kwa zote na kisha kuchagua zile tu ambazo sera inavutiwa nazo. Kutoka [hapa](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Karibu karibu na MACF itaitwa wakati moja ya operesheni hizo inakamatwa. Hata hivyo, **`mpo_policy_*`** hooks ni tofauti kwa sababu `mpo_hook_policy_init()` ni callback inayoitwa wakati wa usajili (basi baada ya `mac_policy_register()`) na `mpo_hook_policy_initbsd()` inaitwa wakati wa usajili wa mwisho mara tu mfumo wa BSD umekamilika vizuri.

Zaidi ya hayo, **`mpo_policy_syscall`** hook inaweza kuandikishwa na kext yoyote ili kufichua wito wa kibinafsi wa mtindo wa **ioctl** **interface**. Kisha, mteja wa mtumiaji ataweza kuita `mac_syscall` (#381) akitaja kama vigezo jina la **policy** pamoja na **code** ya nambari na **arguments** za hiari.\
Kwa mfano, **`Sandbox.kext`** inatumia hii sana.

Kuangalia **`__DATA.__const*`** ya kext kunawezekana kubaini muundo wa `mac_policy_ops` unaotumika wakati wa kuandikisha sera. Inawezekana kuipata kwa sababu kiashiria chake kiko kwenye offset ndani ya `mpo_policy_conf` na pia kwa sababu idadi ya viashiria vya NULL vitakuwa katika eneo hilo.

Zaidi ya hayo, pia inawezekana kupata orodha ya kexts ambazo zimeweka sera kwa kutupa kutoka kwenye kumbukumbu muundo wa **`_mac_policy_list`** ambayo inasasishwa na kila sera inayosajiliwa.

## MACF Initialization

MACF inaanzishwa mapema sana. Inapangwa katika `bootstrap_thread` ya XNU: baada ya `ipc_bootstrap` wito wa `mac_policy_init()` ambayo inaanzisha `mac_policy_list` na muda mfupi baadaye `mac_policy_initmach()` inaitwa. Miongoni mwa mambo mengine, kazi hii itapata kext zote za Apple zenye ufunguo wa `AppleSecurityExtension` katika Info.plist yao kama vile `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` na `TMSafetyNet.kext` na kuzipakia.

## MACF Callouts

Ni kawaida kupata wito kwa MACF ulioainishwa katika msimbo kama: **`#if CONFIG_MAC`** vizuizi vya masharti. Zaidi ya hayo, ndani ya vizuizi hivi inawezekana kupata wito kwa `mac_proc_check*` ambayo inaita MACF ili **kuangalia ruhusa** za kutekeleza vitendo fulani. Zaidi ya hayo, muundo wa wito wa MACF ni: **`mac_<object>_<opType>_opName`**.

Kitu ni kimoja kati ya yafuatayo: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` kwa kawaida ni check ambayo itatumika kuruhusu au kukataa kitendo. Hata hivyo, pia inawezekana kupata `notify`, ambayo itaruhusu kext kujibu kitendo kilichotolewa.

Unaweza kupata mfano katika [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&#x26;maxprot);
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
Ambayo itapitia sera zote za mac zilizorekodiwa ikitaja kazi zao na kuhifadhi matokeo ndani ya mabadiliko ya makosa, ambayo yanaweza kubadilishwa tu na `mac_error_select` kwa nambari za mafanikio hivyo ikiwa ukaguzi wowote unashindwa ukaguzi kamili utashindwa na hatua haitaruhusiwa.

> [!TIP]
> Hata hivyo, kumbuka kwamba si kila kito cha MACF kinatumika tu kukataa hatua. Kwa mfano, `mac_priv_grant` inaita macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), ambayo itatoa kibali kilichohitajika ikiwa sera yoyote itajibu kwa 0:
>
> ```c
> /*
>  * MAC_GRANT inatekeleza ukaguzi ulioainishwa kwa kutembea kwenye orodha ya
>  * moduli za sera na kuangalia kila moja jinsi inavyohisi kuhusu
>  * ombi. Tofauti na MAC_CHECK, inatoa ikiwa sera yoyote inarudisha '0',
>  * na vinginevyo inarudisha EPERM. Kumbuka kwamba inarudisha thamani yake kupitia
>  * 'makosa' katika upeo wa mwitishaji.
>  */
> #define MAC_GRANT(check, args...) do {                              \
>     makosa = EPERM;                                                  \
>     MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, makosa, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                makosa = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
>	    }                                                           \
>     });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

Hizi callas zinakusudia kuangalia na kutoa (mifumo ya) **privileges** zilizofafanuliwa katika [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Baadhi ya msimbo wa kernel ungeita `priv_check_cred()` kutoka [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) kwa KAuth credentials za mchakato na moja ya nambari za kibali ambayo itaita `mac_priv_check` kuona ikiwa sera yoyote **inakataa** kutoa kibali na kisha inaita `mac_priv_grant` kuona ikiwa sera yoyote inatoa `privilege`.

### proc_check_syscall_unix

Kito hiki kinaruhusu kukamata wito wote wa mfumo. Katika `bsd/dev/[i386|arm]/systemcalls.c` inawezekana kuona kazi iliyoainishwa [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), ambayo ina msimbo huu:
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
Ambayo itakagua katika mchakato wa kuita **bitmask** ikiwa syscall ya sasa inapaswa kuita `mac_proc_check_syscall_unix`. Hii ni kwa sababu syscalls zinaitwa mara nyingi hivyo ni muhimu kuepuka kuita `mac_proc_check_syscall_unix` kila wakati.

Kumbuka kwamba kazi `proc_set_syscall_filter_mask()`, ambayo inaweka bitmask syscalls katika mchakato inaitwa na Sandbox kuweka masks kwenye mchakato zilizowekwa kwenye sandbox.

## Syscalls za MACF zilizofichuliwa

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
## Marejeleo

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
