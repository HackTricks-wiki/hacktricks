# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**MACF** sta per **Mandatory Access Control Framework**, un sistema di sicurezza integrato nel sistema operativo per contribuire a proteggere il computer. Funziona impostando **regole rigide su chi o cosa può accedere a determinate parti del sistema**, come file, applicazioni e risorse di sistema. Applicando automaticamente queste regole, MACF garantisce che solo gli utenti e i processi autorizzati possano eseguire azioni specifiche, riducendo il rischio di accessi non autorizzati o attività dannose.

Si noti che MACF non prende realmente alcuna decisione, poiché si limita a **intercettare** le azioni e lascia le decisioni ai **policy modules** (estensioni del kernel) che richiama, come `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` e `mcxalr.kext`.

- Una policy può applicare restrizioni (restituire 0 o un valore diverso da zero per una determinata operazione)
- Una policy può eseguire attività di monitoraggio (restituire 0, per non opporsi, ma sfruttare l'hook per eseguire un'azione)
- Una static policy MACF viene installata durante il boot e non verrà MAI rimossa
- Una dynamic policy MACF viene installata da un KEXT (`kextload`) e, ipoteticamente, può essere rimossa con `kextunload`
- In iOS sono consentite solo static policies, mentre in macOS sono consentite static + dynamic policies.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flusso

1. Il processo esegue una syscall/mach trap
2. La funzione pertinente viene chiamata all'interno del kernel
3. La funzione chiama MACF
4. MACF verifica i policy modules che hanno richiesto di applicare un hook a quella funzione nella propria policy
5. MACF chiama le policy pertinenti
6. Le policy indicano se consentono o negano l'azione

> [!CAUTION]
> Apple è l'unica entità che può utilizzare il MAC Framework KPI.

Solitamente, le funzioni che verificano i permessi tramite MACF chiamano la macro `MAC_CHECK`. Ad esempio, nel caso della syscall per creare un socket, questa chiamerà la funzione `mac_socket_check_create`, che a sua volta chiama `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Inoltre, la macro `MAC_CHECK` è definita in security/mac_internal.h come:<sup>[3]</sup>
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
L'espansione delle macro helper mostra il flusso di controllo concreto:
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
In altre parole, `MAC_CHECK(socket_check_create, ...)` attraversa prima le policy statiche, blocca condizionalmente e itera sulle policy dinamiche, emette i probe DTrace attorno a ogni hook e combina il codice restituito da ogni hook nel singolo risultato `error` tramite `mac_error_select()`.


### Etichette

MACF usa **etichette** che le policy incaricate di verificare se concedere o meno un accesso utilizzeranno. Il codice della dichiarazione della struct delle etichette è [disponibile qui](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), e viene quindi utilizzato all'interno di **`struct ucred`** [qui](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), nella parte **`cr_label`**. L'etichetta contiene flag e un certo numero di **slot** che possono essere utilizzati dalle **policy MACF per allocare puntatori**. Per esempio, Sandbox punterà al profilo del container.

## Policy MACF

Una policy MACF definisce **regole e condizioni da applicare durante determinate operazioni del kernel**.

Un'estensione del kernel potrebbe configurare una struct `mac_policy_conf` e quindi registrarla chiamando `mac_policy_register`. Da [qui](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
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
È facile identificare le estensioni del kernel che configurano queste policy controllando le chiamate a `mac_policy_register`. Inoltre, esaminando il disassemblato dell'estensione, è anche possibile trovare la struct `mac_policy_conf` utilizzata.

Nota che le policy MACF possono essere registrate e annullate anche **dinamicamente**.

Uno dei campi principali di `mac_policy_conf` è **`mpc_ops`**. Questo campo specifica a quali operazioni è interessata la policy. Nota che ce ne sono centinaia, quindi è possibile azzerarle tutte e selezionare soltanto quelle a cui la policy è interessata. Da [qui](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
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
Quasi tutti gli hook verranno richiamati da MACF quando una di queste operazioni viene intercettata. Tuttavia, gli hook **`mpo_policy_*`** costituiscono un'eccezione, perché `mpo_hook_policy_init()` è una callback chiamata al momento della registrazione (quindi dopo `mac_policy_register()`), mentre `mpo_hook_policy_initbsd()` viene chiamata durante la registrazione tardiva, una volta che il sottosistema BSD è stato inizializzato correttamente.

Inoltre, l'hook **`mpo_policy_syscall`** può essere registrato da qualsiasi kext per esporre un'**interfaccia** di chiamata in stile **ioctl** privata. Un user client potrà quindi chiamare `mac_syscall` (#381), specificando come parametri il **nome della policy**, un **codice** intero e **argomenti** opzionali.\
Ad esempio, **`Sandbox.kext`** ne fa ampio uso.

Esaminando **`__DATA.__const*`** del kext è possibile identificare la struttura `mac_policy_ops` utilizzata durante la registrazione della policy. È possibile trovarla perché il suo puntatore si trova a un offset all'interno di `mpo_policy_conf`, nonché grazie alla quantità di puntatori NULL presenti in quell'area.

Inoltre, è possibile ottenere l'elenco dei kext che hanno configurato una policy effettuando il dump dalla memoria della struct **`_mac_policy_list`**, che viene aggiornata con ogni policy registrata.

È anche possibile usare lo strumento `xnoop` per effettuare il dump di tutte le policy registrate nel sistema:
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
E quindi esegui il dump di tutti i controlli della check policy con:
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

- MACF viene inizializzato molto presto. In `bootstrap_thread` (nel codice di startup di XNU), dopo `ipc_bootstrap`, XNU chiama `mac_policy_init()` (in `mac_base.c`).
- `mac_policy_init()` inizializza la `mac_policy_list` globale (un array o un elenco di slot per le policy) e configura l'infrastruttura per il MAC (Mandatory Access Control) all'interno di XNU.
- Successivamente viene invocata `mac_policy_initmach()`, che gestisce il lato kernel della registrazione delle policy integrate o incluse.

### `mac_policy_initmach()` e il caricamento delle “security extensions”

- `mac_policy_initmach()` esamina le kernel extensions (kext) precaricate (o presenti in un elenco di “policy injection”) e analizza il loro Info.plist alla ricerca della chiave `AppleSecurityExtension`.
- Le kext che dichiarano `<key>AppleSecurityExtension</key>` (o `true`) nel loro Info.plist sono considerate “security extensions”, ovvero implementano una MAC policy o si integrano con l'infrastruttura MACF.
- Esempi di kext Apple con questa chiave includono **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, tra le altre (come già elencato).
- Il kernel garantisce che queste kext vengano caricate in anticipo, quindi chiama le loro routine di registrazione (tramite `mac_policy_register`) durante il boot, inserendole nella `mac_policy_list`.

- Ogni modulo di policy (kext) fornisce una struttura `mac_policy_conf`, con hook (`mpc_ops`) per varie operazioni MAC (controlli sui vnode, controlli sull'exec, aggiornamenti delle label e così via).
- I flag del tempo di caricamento possono includere `MPC_LOADTIME_FLAG_NOTLATE`, che significa “deve essere caricato in anticipo” (pertanto i tentativi di registrazione tardiva vengono rifiutati).
- Dopo la registrazione, ogni modulo riceve un handle e occupa uno slot nella `mac_policy_list`.
- Quando un MAC hook viene invocato in seguito (ad esempio per l'accesso a un vnode, l'exec e così via), MACF itera su tutte le policy registrate per prendere decisioni collettive.

- In particolare, **AMFI** (Apple Mobile File Integrity) è una di queste security extensions. Il suo Info.plist include `AppleSecurityExtension`, contrassegnandolo come security policy.
- Durante il boot del kernel, la logica di caricamento del kernel garantisce che la “security policy” (AMFI e così via) sia già attiva prima che molti sottosistemi dipendano da essa. Ad esempio, il kernel “si prepara per le attività successive caricando … la security policy, inclusi AppleMobileFileIntegrity (AMFI), Sandbox e la Quarantine policy.”
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
## Dipendenza da KPI e com.apple.kpi.dsep nei kext delle MAC policy

Quando scrivi un kext che utilizza il framework MAC (ovvero chiama `mac_policy_register()` ecc.), devi dichiarare le dipendenze dai KPI (Kernel Programming Interfaces), in modo che il linker dei kext (kxld) possa risolvere quei simboli. Quindi, per dichiarare che un `kext` dipende da MACF, devi indicarlo in `Info.plist` con `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); il kext farà quindi riferimento a simboli come `mac_policy_register`, `mac_policy_unregister` e ai puntatori alle funzioni degli hook MAC. Per risolverli, devi elencare `com.apple.kpi.dsep` come dipendenza.

Esempio di snippet di Info.plist (all'interno del tuo `.kext`):
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
## MACF nelle versioni moderne di macOS

Nelle versioni moderne di macOS, le policy di sicurezza di Apple di solito non vengono gestite al meglio come bundle `.kext` standalone separati. A partire da **macOS 11**, le kernel extensions vengono collegate nelle **kernel collections**; su **Apple Silicon** non esiste un **SystemKC** separato e i kext di terze parti diventano caricabili solo dopo essere stati integrati nell’**Auxiliary Kernel Collection (AuxKC)** e dopo un reboot. Per la ricerca su MACF, ciò significa che le policy integrate come **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** o **Quarantine** sono solitamente più facili da enumerare con `kmutil` rispetto a strumenti deprecati come `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Su Apple Silicon, se un security kext non è nel BootKC, controlla poi l'AuxKC. Di solito è più utile che cercare un bundle standalone in `/System/Library/Extensions`.

## MACF Callouts

È comune trovare callout a MACF definiti nel codice all'interno di blocchi condizionali come: **`#if CONFIG_MAC`**. Inoltre, all'interno di questi blocchi è possibile trovare chiamate a `mac_proc_check*` che chiamano MACF per **verificare i permessi** necessari a eseguire determinate azioni. Inoltre, il formato dei callout MACF è: **`mac_<object>_<opType>_opName`**.

L'oggetto è uno dei seguenti: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
L'`opType` è solitamente check, che verrà utilizzato per consentire o negare l'azione. Tuttavia, è possibile trovare anche `notify`, che consentirà al kext di reagire all'azione indicata.

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

Successivamente, è possibile trovare il codice di `mac_file_check_mmap` in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Che chiama la macro `MAC_CHECK`, il cui codice è disponibile in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[3]</sup>.
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
Il che esaminerà tutte le mac policy registrate, chiamandone le funzioni e memorizzando l'output nella variabile `error`, che potrà essere sovrascritta da `mac_error_select` solo tramite codici di successo; pertanto, se un controllo fallisce, l'intero controllo fallirà e l'azione non sarà consentita.

> [!TIP]
> Tuttavia, ricorda che non tutti i callout MACF vengono utilizzati esclusivamente per negare le azioni. Ad esempio, `mac_priv_grant` chiama la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), che concederà il privilegio richiesto se una qualsiasi policy risponde con 0:
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

Queste chiamate servono a controllare e fornire decine di **privilegi** definiti in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Alcune parti del kernel chiamano `priv_check_cred()` da [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con le credenziali KAuth del processo e uno dei codici dei privilegi; questa funzione chiamerà `mac_priv_check` per verificare se una qualsiasi policy **nega** la concessione del privilegio, quindi chiamerà `mac_priv_grant` per verificare se una qualsiasi policy concede il `privilege`.<sup>[4]</sup>

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
Che controllerà nel processo chiamante la **bitmask** per verificare se la syscall corrente debba chiamare `mac_proc_check_syscall_unix`. Questo perché le syscall vengono chiamate molto frequentemente, quindi è utile evitare di chiamare `mac_proc_check_syscall_unix` ogni volta.

Si noti che la funzione `proc_set_syscall_filter_mask()`, che imposta la bitmask delle syscall in un processo, viene chiamata da Sandbox per impostare le mask sui processi sottoposti a sandbox.

## Syscall MACF esposte

È possibile interagire con MACF tramite alcune syscall definite in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Per il reversing offensivo, **`__mac_syscall`** è ancora uno dei migliori chokepoint in userland. Trasporta un **nome della policy** (ad esempio `"Sandbox"` o `"AMFI"`), un **selector/codice specifico della policy** e un puntatore al **blob di argomenti opaco** che verrà gestito da `mpo_policy_syscall`. È molto utile durante il reversing di operazioni non documentate, iniziando da userland e facendo solo in seguito il pivot verso l'implementazione nel kernel. Sandbox lo raggiunge comunemente tramite `__sandbox_ms`, mentre AMFI utilizza lo stesso meccanismo per le decisioni relative alle policy di dyld.<sup>[2][5]</sup>

## Note pratiche di ricerca offensiva

I bug recenti di macOS raramente "rompono MACF" direttamente. In genere sfruttano invece una **desincronizzazione tra una decisione di MACF / Sandbox / TCC e l'azione privilegiata che avviene successivamente**.

### Controlli dei path nel broker vs reale azione privilegiata

Un pattern ricorrente consiste in un daemon privilegiato che esegue un **pre-check in userland** (ad esempio `sandbox_check_by_audit_token()`) su una versione di un path e, in seguito, esegue il reale sink privilegiato con un **path controllato dall'attaccante diverso o non canonicalizzato**. Le recenti ricerche su `diskarbitrationd` / `storagekitd` ne sono un buon esempio: **directory traversal** più **symlink swaps** consentono all'attaccante di superare la validazione Sandbox del daemon e quindi eseguire il mount su posizioni sensibili come `~/Library/Application Support/com.apple.TCC`, trasformando il bug in un **sandbox escape**, una **local privilege escalation** o un **TCC bypass**, a seconda del mount point scelto.<sup>[6]</sup>

Durante l'audit dei root broker raggiungibili dal sandbox, cerca prima:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helper di canonicalizzazione dei path
- sink privilegiati come `mount`, `rename`, `copyfile`, i metodi XPC degli helper-tool o qualsiasi altra cosa che in seguito acceda a path controllati dall'attaccante come root

### Trusted deputies con entitlements privati

Un altro pattern pratico consiste nell'evitare di attaccare direttamente gli hook MACF e abusare invece di un **processo trusted** che possiede già i diritti necessari per attraversare il confine. Le recenti ricerche su Safari/TCC ne sono un buon esempio: la primitive interessante non era "disabilitare TCC nel kernel", ma modificare la policy/configurazione locale in modo che un processo firmato da Apple con **`com.apple.private.tcc.allow`** eseguisse l'azione sensibile al posto dell'attaccante. In pratica, gli obiettivi di audit di maggior valore sono daemon/app Apple che combinano:

- **private entitlements** o accesso simile a FDA
- una config / database / mount point / policy file scrivibile
- una successiva operazione sensibile mediata da **Sandbox**, **AMFI**, **TCC** o da un'altra policy MACF

Per un reversing più approfondito e specifico del prodotto, consulta le pagine dedicate a [macOS Sandbox](macos-sandbox/README.md) e [macOS TCC](macos-tcc/README.md).

## Riferimenti

- [1] [XNU — `security/mac_policy.h` (il vettore completo delle operazioni della policy MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macro `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (codici di privilegio utilizzati da `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
