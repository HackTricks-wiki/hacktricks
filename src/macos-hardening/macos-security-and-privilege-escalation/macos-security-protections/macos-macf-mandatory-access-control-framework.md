# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**MACF** sta per **Mandatory Access Control Framework**, che è un sistema di sicurezza integrato nel sistema operativo per aiutare a proteggere il computer. Funziona impostando **regole rigorose su chi o cosa può accedere a determinate parti del sistema**, come file, applicazioni e risorse di sistema. Applicando automaticamente queste regole, MACF garantisce che solo utenti e processi autorizzati possano eseguire azioni specifiche, riducendo il rischio di accesso non autorizzato o attività dannose.

Si noti che MACF non prende realmente decisioni, poiché **intercetta** solo le azioni, lasciando le decisioni ai **moduli di policy** (estensioni del kernel) che chiama come `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` e `mcxalr.kext`.

### Flusso

1. Il processo esegue una syscall/mach trap
2. La funzione pertinente viene chiamata all'interno del kernel
3. La funzione chiama MACF
4. MACF controlla i moduli di policy che hanno richiesto di agganciarsi a quella funzione nella loro policy
5. MACF chiama le policy pertinenti
6. Le policy indicano se consentono o negano l'azione

> [!CAUTION]
> Apple è l'unica che può utilizzare il KPI del MAC Framework.

### Etichette

MACF utilizza **etichette** che poi le policy controllano per decidere se concedere o meno l'accesso. Il codice della dichiarazione della struttura delle etichette può essere [trovato qui](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), che viene poi utilizzato all'interno della **`struct ucred`** in [**qui**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) nella parte **`cr_label`**. L'etichetta contiene flag e un numero di **slot** che possono essere utilizzati dalle **policy MACF per allocare puntatori**. Ad esempio, Sanbox punterà al profilo del contenitore.

## Policy MACF

Una policy MACF definisce **regole e condizioni da applicare in determinate operazioni del kernel**.&#x20;

Un'estensione del kernel potrebbe configurare una struttura `mac_policy_conf` e poi registrarla chiamando `mac_policy_register`. Da [qui](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
È facile identificare le estensioni del kernel che configurano queste politiche controllando le chiamate a `mac_policy_register`. Inoltre, controllando il disassemblaggio dell'estensione è anche possibile trovare la struct `mac_policy_conf` utilizzata.

Nota che le politiche MACF possono essere registrate e deregistrate anche **dinamicamente**.

Uno dei principali campi della `mac_policy_conf` è **`mpc_ops`**. Questo campo specifica quali operazioni interessano la politica. Nota che ce ne sono centinaia, quindi è possibile azzerarle tutte e poi selezionare solo quelle di interesse per la politica. Da [qui](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Quasi tutti i hook verranno richiamati da MACF quando una di queste operazioni viene intercettata. Tuttavia, i hook **`mpo_policy_*`** sono un'eccezione perché `mpo_hook_policy_init()` è un callback chiamato al momento della registrazione (quindi dopo `mac_policy_register()`) e `mpo_hook_policy_initbsd()` viene chiamato durante la registrazione tardiva una volta che il sottosistema BSD è stato inizializzato correttamente.

Inoltre, il hook **`mpo_policy_syscall`** può essere registrato da qualsiasi kext per esporre un'interfaccia di chiamata in stile **ioctl** privata. Quindi, un client utente sarà in grado di chiamare `mac_syscall` (#381) specificando come parametri il **nome della policy** con un **codice** intero e **argomenti** opzionali.\
Ad esempio, il **`Sandbox.kext`** utilizza molto questo.

Controllando il **`__DATA.__const*`** del kext è possibile identificare la struttura `mac_policy_ops` utilizzata durante la registrazione della policy. È possibile trovarla perché il suo puntatore si trova a un offset all'interno di `mpo_policy_conf` e anche a causa della quantità di puntatori NULL che saranno in quell'area.

Inoltre, è anche possibile ottenere l'elenco dei kext che hanno configurato una policy dumpando dalla memoria la struct **`_mac_policy_list`** che viene aggiornata con ogni policy registrata.

## Inizializzazione di MACF

MACF viene inizializzato molto presto. Viene impostato nel `bootstrap_thread` di XNU: dopo `ipc_bootstrap` viene effettuata una chiamata a `mac_policy_init()` che inizializza la `mac_policy_list` e momenti dopo viene chiamato `mac_policy_initmach()`. Tra le altre cose, questa funzione otterrà tutti i kext Apple con la chiave `AppleSecurityExtension` nel loro Info.plist come `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` e `TMSafetyNet.kext` e li carica.

## Chiamate a MACF

È comune trovare chiamate a MACF definite nel codice come: **`#if CONFIG_MAC`** blocchi condizionali. Inoltre, all'interno di questi blocchi è possibile trovare chiamate a `mac_proc_check*` che chiamano MACF per **controllare i permessi** per eseguire determinate azioni. Inoltre, il formato delle chiamate a MACF è: **`mac_<object>_<opType>_opName`**.

L'oggetto è uno dei seguenti: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
L'`opType` è solitamente check che verrà utilizzato per consentire o negare l'azione. Tuttavia, è anche possibile trovare `notify`, che consentirà al kext di reagire all'azione data.

Puoi trovare un esempio in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Poi, è possibile trovare il codice di `mac_file_check_mmap` in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Quale sta chiamando il macro `MAC_CHECK`, il cui codice può essere trovato in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Quale passerà in rassegna tutte le politiche mac registrate chiamando le loro funzioni e memorizzando l'output all'interno della variabile di errore, che sarà sovrascrivibile solo da `mac_error_select` tramite codici di successo, quindi se un controllo fallisce, il controllo completo fallirà e l'azione non sarà consentita.

> [!TIP]
> Tuttavia, ricorda che non tutte le chiamate MACF sono utilizzate solo per negare azioni. Ad esempio, `mac_priv_grant` chiama il macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), che concederà il privilegio richiesto se qualche politica risponde con un 0:
>
> ```c
> /*
>  * MAC_GRANT esegue il controllo designato attraversando l'elenco dei moduli
>  * di politica e controllando con ciascuno come si sente riguardo alla
>  * richiesta. A differenza di MAC_CHECK, concede se qualche politica restituisce '0',
>  * e altrimenti restituisce EPERM. Nota che restituisce il suo valore tramite
>  * 'error' nel contesto del chiamante.
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

Queste chiamate sono destinate a controllare e fornire (decine di) **privilegi** definiti in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Alcuni codici del kernel chiamerebbero `priv_check_cred()` da [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con le credenziali KAuth del processo e uno dei codici di privilegio che chiamerà `mac_priv_check` per vedere se qualche politica **nega** di concedere il privilegio e poi chiama `mac_priv_grant` per vedere se qualche politica concede il `privilegio`.

### proc_check_syscall_unix

Questo hook consente di intercettare tutte le chiamate di sistema. In `bsd/dev/[i386|arm]/systemcalls.c` è possibile vedere la funzione dichiarata [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), che contiene questo codice:
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
Quale controllerà nel processo chiamante **bitmask** se la syscall corrente dovrebbe chiamare `mac_proc_check_syscall_unix`. Questo perché le syscall vengono chiamate così frequentemente che è interessante evitare di chiamare `mac_proc_check_syscall_unix` ogni volta.

Nota che la funzione `proc_set_syscall_filter_mask()`, che imposta il bitmask delle syscall in un processo, è chiamata da Sandbox per impostare i filtri sui processi in sandbox.

## Syscall MACF esposte

È possibile interagire con MACF attraverso alcune syscall definite in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Riferimenti

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
