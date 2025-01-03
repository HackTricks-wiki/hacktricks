# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**MACF** označava **Okvir obaveznog pristupa**, što je bezbednosni sistem ugrađen u operativni sistem kako bi pomogao u zaštiti vašeg računara. Funkcioniše tako što postavlja **stroga pravila o tome ko ili šta može pristupiti određenim delovima sistema**, kao što su datoteke, aplikacije i sistemski resursi. Sprovodeći ova pravila automatski, MACF osigurava da samo ovlašćeni korisnici i procesi mogu izvršavati određene radnje, smanjujući rizik od neovlašćenog pristupa ili zlonamernih aktivnosti.

Napomena da MACF zapravo ne donosi nikakve odluke jer samo **presreće** radnje, ostavljajući odluke **modulima politike** (kernel ekstenzijama) koje poziva kao što su `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

### Tok

1. Proces izvršava syscall/mach trap
2. Relevantna funkcija se poziva unutar kernela
3. Funkcija poziva MACF
4. MACF proverava module politike koji su zatražili da se povežu sa tom funkcijom u svojoj politici
5. MACF poziva relevantne politike
6. Politike označavaju da li dozvoljavaju ili odbacuju radnju

> [!CAUTION]
> Apple je jedini koji može koristiti MAC Framework KPI.

### Oznake

MACF koristi **oznake** koje zatim politike koriste da provere da li treba da odobre neki pristup ili ne. Kod deklaracije strukture oznaka može se [pronaći ovde](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), koja se zatim koristi unutar **`struct ucred`** u [**ovde**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) u delu **`cr_label`**. Oznaka sadrži zastavice i broj **slotova** koji se mogu koristiti od strane **MACF politika za dodeljivanje pokazivača**. Na primer, Sanbox će ukazivati na profil kontejnera.

## MACF Politike

MACF politika definiše **pravila i uslove koji se primenjuju u određenim operacijama kernela**.&#x20;

Kernel ekstenzija može konfigurisati `mac_policy_conf` strukturu i zatim je registrovati pozivajući `mac_policy_register`. Od [ovde](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Lako je identifikovati kernel ekstenzije koje konfigurišu ove politike proverom poziva na `mac_policy_register`. Štaviše, proverom disasembla ekstenzije takođe je moguće pronaći korišćenu `mac_policy_conf` strukturu.

Napomena da se MACF politike mogu registrovati i deregistrovati takođe **dinamički**.

Jedno od glavnih polja `mac_policy_conf` je **`mpc_ops`**. Ovo polje specificira koje operacije politika zanima. Napomena da ih ima stotine, tako da je moguće postaviti sve na nulu, a zatim odabrati samo one koje politiku zanimaju. Od [ovde](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Skoro svi hook-ovi će biti pozvani od strane MACF kada se jedna od tih operacija presretne. Međutim, **`mpo_policy_*`** hook-ovi su izuzetak jer je `mpo_hook_policy_init()` callback koji se poziva prilikom registracije (dakle, nakon `mac_policy_register()`) i `mpo_hook_policy_initbsd()` se poziva tokom kasne registracije kada je BSD podsystem pravilno inicijalizovan.

Štaviše, **`mpo_policy_syscall`** hook može biti registrovan od strane bilo kog kext-a da izloži privatni **ioctl** stil poziva **interface**. Tada će korisnički klijent moći da pozove `mac_syscall` (#381) navodeći kao parametre **ime politike** sa celobrojnim **kodom** i opcionim **argumentima**.\
Na primer, **`Sandbox.kext`** to često koristi.

Proverom **`__DATA.__const*`** kext-a moguće je identifikovati `mac_policy_ops` strukturu koja se koristi prilikom registracije politike. Moguće je pronaći je jer je njen pokazivač na offset-u unutar `mpo_policy_conf` i takođe zbog broja NULL pokazivača koji će biti u toj oblasti.

Štaviše, takođe je moguće dobiti listu kext-ova koji su konfigurisali politiku dump-ovanjem iz memorije strukture **`_mac_policy_list`** koja se ažurira sa svakom registrovanom politikom.

## MACF Inicijalizacija

MACF se inicijalizuje vrlo brzo. Postavlja se u XNU-ovom `bootstrap_thread`: nakon `ipc_bootstrap` poziva na `mac_policy_init()` koji inicijalizuje `mac_policy_list`, a trenutak kasnije se poziva `mac_policy_initmach()`. Između ostalog, ova funkcija će dobiti sve Apple kext-ove sa `AppleSecurityExtension` ključem u njihovom Info.plist kao što su `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` i `TMSafetyNet.kext` i učitati ih.

## MACF Pozivi

Uobičajeno je pronaći pozive ka MACF definisane u kodu kao: **`#if CONFIG_MAC`** uslovni blokovi. Štaviše, unutar ovih blokova moguće je pronaći pozive na `mac_proc_check*` koji poziva MACF da **proveri dozvole** za izvršavanje određenih akcija. Takođe, format MACF poziva je: **`mac_<object>_<opType>_opName`**.

Objekat je jedan od sledećih: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` je obično check koji će se koristiti za dozvoljavanje ili odbijanje akcije. Međutim, takođe je moguće pronaći `notify`, koji će omogućiti kext-u da reaguje na datu akciju.

Možete pronaći primer u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Zatim, moguće je pronaći kod `mac_file_check_mmap` u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Koji poziva `MAC_CHECK` makro, čiji se kod može naći u [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Koji će proći kroz sve registrovane mac politike pozivajući njihove funkcije i čuvajući izlaz unutar promenljive error, koja će biti prepisiva samo od strane `mac_error_select` pomoću kodova uspeha, tako da ako bilo koja provera ne uspe, cela provera će propasti i akcija neće biti dozvoljena.

> [!TIP]
> Međutim, zapamtite da se ne koriste svi MACF pozivi samo za odbijanje akcija. Na primer, `mac_priv_grant` poziva makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), koji će odobriti traženu privilegiju ako bilo koja politika odgovori sa 0:
>
> ```c
> /*
>  * MAC_GRANT vrši određenu proveru prolazeći kroz listu politika
>  * i proveravajući svaku kako se oseća u vezi sa
>  * zahtevom. Za razliku od MAC_CHECK, odobrava ako bilo koja politika vrati '0',
>  * a inače vraća EPERM. Imajte na umu da vraća svoju vrednost putem
>  * 'error' u opsegu pozivaoca.
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

Ovi pozivi su namenjeni za proveru i pružanje (desetina) **privilegija** definisanih u [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Neki kernel kod bi pozvao `priv_check_cred()` iz [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) sa KAuth kredencijalima procesa i jednim od kodova privilegija koji će pozvati `mac_priv_check` da vidi da li neka politika **odbija** davanje privilegije, a zatim poziva `mac_priv_grant` da vidi da li neka politika odobrava `privilegiju`.

### proc_check_syscall_unix

Ova kuka omogućava presretanje svih sistemskih poziva. U `bsd/dev/[i386|arm]/systemcalls.c` moguće je videti deklarisanu funkciju [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), koja sadrži ovaj kod:
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
Koji će proveriti u pozivnom procesu **bitmasku** da li trenutni syscall treba da pozove `mac_proc_check_syscall_unix`. To je zato što se syscalls pozivaju tako često da je zanimljivo izbeći pozivanje `mac_proc_check_syscall_unix` svaki put.

Napomena da funkcija `proc_set_syscall_filter_mask()`, koja postavlja bitmasku syscalls u procesu, se poziva od strane Sandbox-a da postavi maske na sandboxed procesima.

## Izloženi MACF syscalls

Moguće je interagovati sa MACF kroz neke syscalls definisane u [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Reference

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
