# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

**MACF** staan vir **Verpligte Toegang Beheer Raamwerk**, wat 'n sekuriteitstelsel is wat in die bedryfstelsel ingebou is om jou rekenaar te help beskerm. Dit werk deur **strenge reëls op te stel oor wie of wat sekere dele van die stelsel kan toegang hê**, soos lêers, toepassings en stelselhulpbronne. Deur hierdie reëls outomaties af te dwing, verseker MACF dat slegs gemagtigde gebruikers en prosesse spesifieke aksies kan uitvoer, wat die risiko van ongemagtigde toegang of kwaadwillige aktiwiteite verminder.

Let daarop dat MACF nie werklik enige besluite neem nie, aangesien dit net **aksies onderskep**, dit laat die besluite aan die **beleidsmodules** (kernel uitbreidings) wat dit aanroep soos `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` en `mcxalr.kext`.

### Stroom

1. Proses voer 'n syscall/mach trap uit
2. Die relevante funksie word binne die kernel aangeroep
3. Funksie roep MACF aan
4. MACF kontroleer beleidsmodules wat versoek het om daardie funksie in hul beleid te haak
5. MACF roep die relevante beleids aan
6. Beleide dui aan of hulle die aksie toelaat of weier

> [!CAUTION]
> Apple is die enigste wat die MAC Framework KPI kan gebruik.

### Etikette

MACF gebruik **etikette** wat dan deur die beleide nagegaan word of hulle sekere toegang moet toestaan of nie. Die kode van die etikette struktuurdeklarasie kan [hier gevind word](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), wat dan binne die **`struct ucred`** in [**hier**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) in die **`cr_label`** deel gebruik word. Die etiket bevat vlae en 'n aantal **slots** wat deur **MACF beleide gebruik kan word om wysers toe te ken**. Byvoorbeeld, Sanbox sal na die houerprofiel wys.

## MACF Beleide

'n MACF Beleid definieer **reëls en voorwaardes wat in sekere kernel operasies toegepas moet word**.&#x20;

'n Kernel uitbreiding kan 'n `mac_policy_conf` struktuur konfigureer en dit dan registreer deur `mac_policy_register` aan te roep. Van [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Dit is maklik om die kernuitbreidings wat hierdie beleide konfigureer te identifiseer deur oproepe na `mac_policy_register` te kontroleer. Boonop, deur die disassemble van die uitbreiding te kontroleer, is dit ook moontlik om die gebruikte `mac_policy_conf` struktuur te vind.

Let daarop dat MACF-beleide ook **dynamies** geregistreer en ongeregistreer kan word.

Een van die hoofvelde van die `mac_policy_conf` is die **`mpc_ops`**. Hierdie veld spesifiseer watter operasies die beleid belangrik is. Let daarop dat daar honderde daarvan is, so dit is moontlik om al hulle op nul te stel en dan net diegene te kies waarin die beleid belangstel. Van [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Byna al die hooks sal deur MACF teruggeroep word wanneer een van daardie operasies geintercepteer word. egter, **`mpo_policy_*`** hooks is 'n uitsondering omdat `mpo_hook_policy_init()` 'n terugroep is wat tydens registrasie aangeroep word (so na `mac_policy_register()`) en `mpo_hook_policy_initbsd()` word tydens laat registrasie aangeroep sodra die BSD-substelsel behoorlik geinitialiseer is.

Boonop kan die **`mpo_policy_syscall`** hook deur enige kext geregistreer word om 'n private **ioctl** styl oproep **interface** bloot te stel. Dan sal 'n gebruikersklient in staat wees om `mac_syscall` (#381) aan te roep en die **beleidsnaam** met 'n heelgetal **kode** en opsionele **argumente** as parameters te spesifiseer.\
Byvoorbeeld, die **`Sandbox.kext`** gebruik dit baie.

Deur die kext se **`__DATA.__const*`** te kontroleer, is dit moontlik om die `mac_policy_ops` struktuur te identifiseer wat gebruik word wanneer die beleid geregistreer word. Dit is moontlik om dit te vind omdat sy pointer op 'n offset binne `mpo_policy_conf` is en ook omdat die hoeveelheid NULL pointers wat in daardie area sal wees.

Boonop is dit ook moontlik om die lys van kexts wat 'n beleid geconfigureer het, te verkry deur die struktuur **`_mac_policy_list`** uit geheue te dump wat met elke geregistreerde beleid opgedateer word.

## MACF Inisialiserings

MACF word baie vroeg geinitialiseer. Dit word opgestel in XNU se `bootstrap_thread`: na `ipc_bootstrap` 'n oproep na `mac_policy_init()` wat die `mac_policy_list` inisialiseer en 'n oomblik later word `mac_policy_initmach()` aangeroep. Onder andere dinge, sal hierdie funksie al die Apple kexts met die `AppleSecurityExtension` sleutel in hul Info.plist soos `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` en `TMSafetyNet.kext` verkry en laai.

## MACF Oproepe

Dit is algemeen om oproepe na MACF te vind wat in kode gedefinieer is soos: **`#if CONFIG_MAC`** voorwaardelike blokke. Boonop is dit binne hierdie blokke moontlik om oproepe na `mac_proc_check*` te vind wat MACF aanroep om **toestemmings te kontroleer** om sekere aksies uit te voer. Boonop is die formaat van die MACF oproepe: **`mac_<object>_<opType>_opName`**.

Die objek is een van die volgende: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Die `opType` is gewoonlik check wat gebruik sal word om die aksie toe te laat of te weier. Dit is egter ook moontlik om `notify` te vind, wat die kext sal toelaat om op die gegewe aksie te reageer.

Jy kan 'n voorbeeld vind in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Dan is dit moontlik om die kode van `mac_file_check_mmap` te vind in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Wat die `MAC_CHECK` makro aanroep, waarvan die kode in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) gevind kan word.
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
Wat al die geregistreerde mac-beleide sal deurgaan, hul funksies aanroep en die uitvoer binne die fout veranderlike stoor, wat slegs deur `mac_error_select` oorruilbaar sal wees deur sukses kodes, so as enige kontrole misluk, sal die volledige kontrole misluk en die aksie nie toegelaat word.

> [!TIP]
> Onthou egter dat nie alle MACF-aanroepings slegs gebruik word om aksies te weier nie. Byvoorbeeld, `mac_priv_grant` roep die makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) aan, wat die aangevraagde voorreg sal toeken as enige beleid met 'n 0 antwoord gee:
>
> ```c
> /*
>  * MAC_GRANT voer die aangewese kontrole uit deur die beleid
>  * module lys te loop en met elkeen te kontroleer hoe dit oor die
>  * versoek voel.  Anders as MAC_CHECK, grant dit as enige beleid '0' teruggee,
>  * en andersins terugkeer EPERM.  Let daarop dat dit sy waarde via
>  * 'error' in die omvang van die oproeper teruggee.
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

Hierdie aanroepings is bedoel om (tens of) **voorregte** te kontroleer en te verskaf wat gedefinieer is in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Sommige kernkode sal `priv_check_cred()` van [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) aanroep met die KAuth akrediteer van die proses en een van die voorregte kode wat `mac_priv_check` sal aanroep om te sien of enige beleid die voorreg **weier** en dan roep dit `mac_priv_grant` aan om te sien of enige beleid die `voorreg` toeken.

### proc_check_syscall_unix

Hierdie haak laat toe om alle stelsels aanroepe te onderskep. In `bsd/dev/[i386|arm]/systemcalls.c` is dit moontlik om die verklaarde funksie [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) te sien, wat hierdie kode bevat:
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
Wat die oproepende proses **bitmask** sal nagaan of die huidige syscall `mac_proc_check_syscall_unix` moet aanroep. Dit is omdat syscalls so gereeld aangeroep word dat dit interessant is om te vermy om `mac_proc_check_syscall_unix` elke keer aan te roep.

Let daarop dat die funksie `proc_set_syscall_filter_mask()`, wat die bitmask syscalls in 'n proses stel, deur Sandbox aangeroep word om masks op gesandboksde prosesse te stel.

## Blootgestelde MACF syscalls

Dit is moontlik om met MACF te kommunikeer deur sommige syscalls wat in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) gedefinieer is:
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
## Verwysings

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
