# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**MACF** sta per **Mandatory Access Control Framework**, che è un sistema di sicurezza integrato nel sistema operativo per aiutare a proteggere il computer. Funziona impostando **regole rigorose su chi o cosa può accedere a determinate parti del sistema**, come file, applicazioni e risorse di sistema. Applicando automaticamente queste regole, MACF garantisce che solo utenti e processi autorizzati possano eseguire azioni specifiche, riducendo il rischio di accessi non autorizzati o attività dannose.

Nota che MACF non prende veramente decisioni in quanto si limita a **intercettare** le azioni; lascia le decisioni ai **policy modules** (kernel extensions) che invoca, come `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` e `mcxalr.kext`.

- Una policy può essere enforcing (restituisce 0 o un valore non-zero su alcune operazioni)
- Una policy può essere monitoring (restituisce 0, quindi non si oppone ma sfrutta l'hook per fare qualcosa)
- Una policy MACF statica è installata al boot e NON sarà MAI rimossa
- Una policy MACF dinamica è installata da un KEXT (kextload) e ipoteticamente può essere kextunloaded
- In iOS sono permesse solo policy statiche, mentre in macOS sono presenti sia statiche che dinamiche.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flusso

1. Il processo esegue una syscall/mach trap
2. La funzione rilevante viene chiamata all'interno del kernel
3. La funzione chiama MACF
4. MACF verifica i policy modules che hanno richiesto di intercettare quella funzione nella loro policy
5. MACF invoca le policy rilevanti
6. Le policy indicano se consentono o negano l'azione

> [!CAUTION]
> Solo Apple può utilizzare il MAC Framework KPI.

Di solito le funzioni che verificano i permessi con MACF chiameranno la macro `MAC_CHECK`. Come nel caso della syscall per creare un socket, che chiamerà la funzione `mac_socket_check_create` che a sua volta invoca `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Inoltre, la macro `MAC_CHECK` è definita in security/mac_internal.h come:
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
Nota che trasformando `check` in `socket_check_create` e `args...` in `(cred, domain, type, protocol)` ottieni:
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
Espandendo le macro helper viene mostrato il flusso di controllo concreto:
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
In altre parole, `MAC_CHECK(socket_check_create, ...)` percorre prima le policy statiche, acquisisce condizionalmente il lock e itera sulle policy dinamiche, emette le DTrace probes attorno a ogni hook, e comprime il codice di ritorno di ogni hook nel singolo risultato `error` tramite `mac_error_select()`.


### Etichette

MACF usa delle **labels** che le policy utilizzeranno per verificare se concedere o meno un accesso. Il codice della dichiarazione della struct delle labels può essere [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), che viene poi usato all'interno della **`struct ucred`** in [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) nella parte **`cr_label`**. La label contiene flag e un numero di **slots** che possono essere utilizzati dalle **MACF policies** per allocare puntatori. Per esempio Sanbox punterà al profilo del container

## Politiche MACF

Una MACF Policy definisce delle **regole e condizioni da applicare in determinate operazioni del kernel**.

Un'estensione del kernel potrebbe configurare una struct `mac_policy_conf` e poi registrarla chiamando `mac_policy_register`. Da [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
È facile identificare le estensioni del kernel che configurano queste policy controllando le chiamate a `mac_policy_register`. Inoltre, esaminando il disassemblato dell'estensione è possibile trovare la struct `mac_policy_conf` utilizzata.

Nota che le policy MACF possono essere registrate e rimosse anche **dinamicamente**.

Uno dei campi principali di `mac_policy_conf` è **`mpc_ops`**. Questo campo specifica quali operazioni interessano alla policy. Nota che ce ne sono centinaia, quindi è possibile azzerarle tutte e poi selezionare solo quelle di interesse per la policy. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Quasi tutti gli hook verranno richiamati da MACF quando una di quelle operazioni viene intercettata. Tuttavia, gli hook **`mpo_policy_*`** sono un'eccezione perché `mpo_hook_policy_init()` è una callback chiamata al momento della registrazione (quindi dopo `mac_policy_register()`) e `mpo_hook_policy_initbsd()` viene chiamata durante una registrazione tardiva, una volta che il sottosistema BSD si è inizializzato correttamente.

Inoltre, l'hook **`mpo_policy_syscall`** può essere registrato da qualsiasi kext per esporre una interfaccia di chiamata privata in stile **ioctl**. Un user client potrà quindi chiamare `mac_syscall` (#381) specificando come parametri il **policy name** con un **integer code** e eventuali **arguments**.\

Ad esempio, il **`Sandbox.kext`** ne fa ampio uso.

Controllando la sezione del kext **`__DATA.__const*`** è possibile identificare la struttura `mac_policy_ops` usata quando si registra la policy. È possibile trovarla perché il suo puntatore è a un offset all'interno di `mpo_policy_conf` e anche a causa del numero di puntatori NULL che saranno in quell'area.

Inoltre, è anche possibile ottenere la lista dei kext che hanno configurato una policy eseguendo un dump dalla memoria della struct **`_mac_policy_list`**, che viene aggiornata con ogni policy registrata.

È anche possibile usare lo strumento `xnoop` per fare il dump di tutte le policy registrate nel sistema:
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
E poi esegui il dump di tutti i check della check policy con:
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
## Inizializzazione di MACF in XNU

### Bootstrap iniziale e mac_policy_init()

- MACF viene inizializzato molto presto. In `bootstrap_thread` (nel codice di avvio XNU), dopo `ipc_bootstrap`, XNU chiama `mac_policy_init()` (in `mac_base.c`).
- `mac_policy_init()` inizializza la `mac_policy_list` globale (un array o lista di slot di policy) e imposta l'infrastruttura per MAC (Mandatory Access Control) all'interno di XNU.
- Successivamente viene invocato `mac_policy_initmach()`, che gestisce il lato kernel della registrazione delle policy per le policy incorporate o incluse in una “policy injection” list.

### `mac_policy_initmach()` e il caricamento “estensioni di sicurezza”

- `mac_policy_initmach()` esamina le kernel extensions (kexts) che sono precaricate (o in una “policy injection” list) e ispeziona il loro Info.plist per la chiave `AppleSecurityExtension`.
- I kext che dichiarano `<key>AppleSecurityExtension</key>` (o `true`) nel loro Info.plist sono considerati “security extensions” — cioè quelli che implementano una MAC policy o agganciano l'infrastruttura MACF.
- Esempi di kext Apple con quella chiave includono **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, tra gli altri (come hai già elencato).
- Il kernel garantisce che quei kext vengano caricati presto, poi chiama le loro routine di registrazione (via `mac_policy_register`) durante il boot, inserendoli nella `mac_policy_list`.

- Ogni modulo di policy (kext) fornisce una struttura `mac_policy_conf`, con hook (`mpc_ops`) per varie operazioni MAC (controlli su vnode, controlli di exec, aggiornamenti di label, ecc.).
- I flag di load time possono includere `MPC_LOADTIME_FLAG_NOTLATE` che significa “deve essere caricato presto” (quindi i tentativi di registrazione tardiva vengono rifiutati).
- Una volta registrato, ogni modulo ottiene un handle e occupa uno slot nella `mac_policy_list`.
- Quando un hook MAC viene invocato successivamente (per esempio, accesso a vnode, exec, ecc.), MACF itera tutte le policy registrate per prendere decisioni collettive.

- In particolare, **AMFI** (Apple Mobile File Integrity) è una di queste security extension. Il suo Info.plist include `AppleSecurityExtension` che la marca come policy di sicurezza.
- Come parte del boot del kernel, la logica di caricamento del kernel assicura che la “security policy” (AMFI, ecc.) sia già attiva prima che molti sottosistemi dipendano da essa. Per esempio, il kernel “si prepara per i compiti futuri caricando … la security policy, inclusi AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Dipendenza KPI & com.apple.kpi.dsep nei kext di policy MAC

Quando si scrive un kext che usa il MAC framework (cioè chiamando `mac_policy_register()` ecc.), è necessario dichiarare dipendenze sulle KPI (Kernel Programming Interfaces) così che il linker del kext (kxld) possa risolvere quei simboli. Quindi, per dichiarare che un `kext` dipende da MACF bisogna indicarlo in `Info.plist` con `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); in questo modo il kext farà riferimento a simboli come `mac_policy_register`, `mac_policy_unregister` e ai puntatori alle funzioni hook del MAC. Per risolverli, devi elencare `com.apple.kpi.dsep` come dipendenza.

Esempio di frammento Info.plist (all'interno del tuo .kext):
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
## Richiami MACF

È comune trovare richiami a MACF definiti nel codice come: **`#if CONFIG_MAC`** blocchi condizionali. Inoltre, all'interno di questi blocchi è possibile trovare chiamate a `mac_proc_check*` che invocano MACF per **verificare i permessi** per eseguire certe azioni. Inoltre, il formato dei richiami MACF è: **`mac_<object>_<opType>_opName`**.

L'oggetto è uno dei seguenti: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Il `opType` è solitamente check, che sarà usato per consentire o negare l'azione. Tuttavia, è anche possibile trovare `notify`, che permette al kext di reagire all'azione specificata.

Puoi trovare un esempio in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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
Che chiama la macro `MAC_CHECK`, il cui codice può essere trovato in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Which will go over all the registered mac policies calling their functions and storing the output inside the error variable, which will only be overridable by `mac_error_select` by success codes so if any check fails the complete check will fail and the action won't be allowed.

> [!TIP]
> Tuttavia, ricorda che non tutte le callout MACF vengono usate solo per negare azioni. Ad esempio, `mac_priv_grant` richiama la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), che concederà il privilegio richiesto se qualche policy risponde con 0:
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

Questi callout sono destinati a verificare e fornire (decine di) **privilegi** definiti in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Parte del codice del kernel può chiamare `priv_check_cred()` da [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con le credenziali KAuth del processo e uno dei codici di privilegio, che chiamerà `mac_priv_check` per verificare se qualche policy **nega** la concessione del privilegio e poi chiamerà `mac_priv_grant` per vedere se qualche policy concede il `privilege`.

### proc_check_syscall_unix

Questo hook permette di intercettare tutte le system call. In `bsd/dev/[i386|arm]/systemcalls.c` è possibile vedere la funzione dichiarata [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), che contiene questo codice:
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
Che controllerà nel processo chiamante **bitmask** se la syscall corrente dovrebbe chiamare `mac_proc_check_syscall_unix`. Questo perché le syscalls vengono chiamate così frequentemente che è interessante evitare di chiamare `mac_proc_check_syscall_unix` ogni volta.

Nota che la funzione `proc_set_syscall_filter_mask()`, che imposta la bitmask delle syscalls in un processo, è chiamata dal Sandbox per impostare le maschere sui processi sandboxed.

## Exposed MACF syscalls

È possibile interagire con MACF attraverso alcune syscalls definite in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
