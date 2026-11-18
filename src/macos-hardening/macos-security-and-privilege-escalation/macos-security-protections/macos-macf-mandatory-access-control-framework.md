# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**MACF** sta per **Mandatory Access Control Framework**: un sistema di sicurezza integrato nel sistema operativo per proteggere il computer. Funziona impostando **regole rigorose su chi o cosa può accedere a determinate parti del sistema**, come file, applicazioni e risorse di sistema. Applicando automaticamente queste regole, MACF garantisce che solo gli utenti e i processi autorizzati possano eseguire azioni specifiche, riducendo il rischio di accessi non autorizzati o attività dannose.

Nota che MACF non prende realmente decisioni: si limita a **intercettare** le azioni e lascia le decisioni ai **moduli di policy** (estensioni del kernel) che richiama, come `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` e `mcxalr.kext`.

- Una policy può applicare restrizioni (restituire 0 o un valore diverso da zero per alcune operazioni)
- Una policy può monitorare (restituire 0, così da non opporsi all'azione ma sfruttare l'hook per fare qualcosa)
- Una policy statica MACF viene installata all'avvio e non verrà MAI rimossa
- Una policy dinamica MACF viene installata da una KEXT (kextload) e, in teoria, può essere scaricata con kextunload
- In iOS sono consentite solo le policy statiche, mentre in macOS sono consentite quelle statiche e dinamiche.<sup>[[7]](#references)</sup>

### Flusso

1. Un processo esegue una syscall/un mach trap
2. La funzione pertinente viene chiamata all'interno del kernel
3. La funzione chiama MACF
4. MACF verifica i moduli di policy che hanno richiesto di inserire un hook per quella funzione nella propria policy
5. MACF chiama le policy pertinenti
6. Le policy indicano se consentono o negano l'azione

> [!CAUTION]
> Solo Apple può usare il MAC Framework KPI.

Di solito, le funzioni che verificano le autorizzazioni con MACF chiamano la macro `MAC_CHECK`. Per esempio, nel caso della syscall per creare un socket, viene chiamata la funzione `mac_socket_check_create`, che a sua volta chiama `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Inoltre, la macro `MAC_CHECK` è definita in security/mac_internal.h come segue:<sup>[[3]](#references)</sup>
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

Nota che trasformando `check` in `socket_check_create` e `args...` in `(cred, domain, type, protocol)` si ottiene:

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

Espandendo le macro helper, si ottiene il flusso di controllo concreto:

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

In altre parole, `MAC_CHECK(socket_check_create, ...)` scorre prima le policy statiche, blocca e itera condizionalmente sulle policy dinamiche, emette le probe DTrace attorno a ciascun hook e combina i codici di ritorno di tutti gli hook in un unico risultato `error` tramite `mac_error_select()`.


### Etichette

MACF usa **etichette**, che le policy utilizzano per decidere se concedere o meno determinati accessi. Il codice della dichiarazione della struct delle etichette si trova [qui](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h); viene poi usata all'interno di **`struct ucred`**, [qui](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), nella parte **`cr_label`**. L'etichetta contiene flag e un certo numero di **slot** che le **policy MACF possono usare per allocare puntatori**. Ad esempio, Sanbox punterà al profilo del container.

## Policy MACF

Una policy MACF definisce **regole e condizioni da applicare a determinate operazioni del kernel**.

Un'estensione del kernel può configurare una struct `mac_policy_conf` e quindi registrarla chiamando `mac_policy_register`. Da [qui](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

È facile identificare le estensioni del kernel che configurano queste policy controllando le chiamate a `mac_policy_register`. Inoltre, esaminando il disassemblato dell'estensione, è possibile trovare anche la struct `mac_policy_conf` utilizzata.

Tieni presente che le policy MACF possono essere registrate e annullate anche **dinamicamente**.

Uno dei campi principali di `mac_policy_conf` è **`mpc_ops`**. Questo campo specifica le operazioni che interessano alla policy. Ce ne sono centinaia, quindi è possibile azzerare tutte le voci e selezionare solo quelle necessarie alla policy. Da [qui](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Quasi tutti gli hook vengono richiamati da MACF quando una di queste operazioni viene intercettata. Tuttavia, gli hook **`mpo_policy_*`** fanno eccezione, perché `mpo_hook_policy_init()` è una callback chiamata al momento della registrazione (quindi dopo `mac_policy_register()`), mentre `mpo_hook_policy_initbsd()` viene chiamata durante la registrazione tardiva, una volta che il sottosistema BSD è stato inizializzato correttamente.

Inoltre, qualsiasi kext può registrare l'hook **`mpo_policy_syscall`** per esporre un'**interfaccia** di chiamata in stile **ioctl** privata. Un client utente potrà quindi chiamare `mac_syscall` (#381) specificando come parametri il **nome della policy**, un **codice** intero e **argomenti** facoltativi.\
Ad esempio, `Sandbox.kext` ne fa largo uso.

Esaminando **`__DATA.__const*`** del kext è possibile identificare la struttura `mac_policy_ops` usata al momento della registrazione della policy. È possibile trovarla perché il suo puntatore si trova a un offset all'interno di `mpo_policy_conf` e anche in base al numero di puntatori NULL presenti in quell'area.

Inoltre, è possibile ottenere l'elenco dei kext che hanno configurato una policy eseguendo un dump dalla memoria della struct **`_mac_policy_list`**, aggiornata ogni volta che viene registrata una policy.

Puoi anche usare lo strumento `xnoop` per eseguire un dump di tutte le policy registrate nel sistema:

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

E poi esegui il dump di tutti i controlli di check policy con:

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

### Avvio iniziale e mac_policy_init()

- MACF viene inizializzato molto presto. In `bootstrap_thread` (nel codice di avvio di XNU), dopo `ipc_bootstrap`, XNU chiama `mac_policy_init()` (in `mac_base.c`).  
- `mac_policy_init()` inizializza la `mac_policy_list` globale (un array o un elenco di slot per le policy) e configura l'infrastruttura per MAC (Mandatory Access Control) all'interno di XNU.  
- In seguito viene invocata `mac_policy_initmach()`, che gestisce la registrazione delle policy integrate o incluse nel kernel.

### `mac_policy_initmach()` e caricamento delle “estensioni di sicurezza”

- `mac_policy_initmach()` esamina le estensioni del kernel (kext) precaricate (o presenti in un elenco di “iniezione delle policy”) e controlla nei relativi Info.plist la chiave `AppleSecurityExtension`.  
- Le kext che dichiarano `<key>AppleSecurityExtension</key>` (o `true`) nel proprio Info.plist sono considerate “estensioni di sicurezza”, ovvero implementano una policy MAC o si collegano all'infrastruttura MACF.  
- Tra le kext Apple che includono questa chiave ci sono **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** e altre (come già elencato).  
- Il kernel si assicura che queste kext vengano caricate presto, quindi richiama le loro routine di registrazione (tramite `mac_policy_register`) durante l'avvio, inserendole nella `mac_policy_list`.

  - Ogni modulo di policy (kext) fornisce una struttura `mac_policy_conf`, con hook (`mpc_ops`) per varie operazioni MAC (controlli vnode, controlli di exec, aggiornamenti delle label e così via).  
  - I flag relativi al momento del caricamento possono includere `MPC_LOADTIME_FLAG_NOTLATE`, che significa “deve essere caricato presto” (quindi i tentativi di registrazione tardiva vengono rifiutati).  
  - Una volta registrato, ogni modulo riceve un handle e occupa uno slot nella `mac_policy_list`.  
  - Quando in seguito viene invocato un hook MAC (per esempio, per l'accesso a un vnode, l'esecuzione e così via), MACF esegue l'iterazione su tutte le policy registrate per prendere decisioni collettive.

- In particolare, **AMFI** (Apple Mobile File Integrity) è un'estensione di sicurezza di questo tipo. Il suo Info.plist include `AppleSecurityExtension`, che lo identifica come policy di sicurezza. 
- Durante l'avvio del kernel, la logica di caricamento si assicura che la “policy di sicurezza” (AMFI e altre) sia già attiva prima che molti sottosistemi dipendano da essa. Per esempio, il kernel “si prepara alle attività successive caricando … la policy di sicurezza, tra cui AppleMobileFileIntegrity (AMFI), Sandbox e la policy Quarantine.” 

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

## Dipendenza da KPI e com.apple.kpi.dsep nelle kext delle policy MAC

Quando scrivi una kext che usa il framework MAC (ad esempio, chiamando `mac_policy_register()` e così via), devi dichiarare le dipendenze dai KPI (Interfacce di programmazione del kernel), affinché il linker delle kext (kxld) possa risolvere quei simboli. Quindi, per dichiarare che una `kext` dipende da MACF, devi indicarlo in `Info.plist` con `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); la kext farà quindi riferimento a simboli come `mac_policy_register`, `mac_policy_unregister` e ai puntatori alle funzioni MAC hook. Per risolverli, devi elencare `com.apple.kpi.dsep` come dipendenza.

Esempio di frammento di Info.plist (all'interno della tua .kext):

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

Nelle versioni moderne di macOS, è generalmente preferibile non considerare le policy di sicurezza di Apple come bundle `.kext` autonomi e isolati. Da **macOS 11**, le estensioni del kernel vengono collegate in **kernel collection**; su **Apple Silicon** non esiste un **SystemKC** separato e i kext di terze parti possono essere caricati solo dopo essere stati integrati nell’**Auxiliary Kernel Collection (AuxKC)** e dopo un riavvio. Per la ricerca su MACF, questo significa che in genere è più semplice enumerare le policy integrate, come **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** o **Quarantine**, con `kmutil` anziché con strumenti deprecati come `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Su Apple Silicon, se un kext di sicurezza non è nel BootKC, controlla poi l'AuxKC. Di solito è più utile che cercare un bundle autonomo in `/System/Library/Extensions`.

## MACF Callouts

È comune trovare callout a MACF definiti in blocchi condizionali come **`#if CONFIG_MAC`**. Inoltre, all'interno di questi blocchi è possibile trovare chiamate a `mac_proc_check*`, che invocano MACF per **verificare i permessi** necessari a eseguire determinate azioni. Il formato dei callout MACF è: **`mac_<object>_<opType>_opName`**.

L'oggetto è uno dei seguenti: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` è solitamente check, che viene usato per consentire o negare l'azione. È tuttavia possibile trovare anche `notify`, che consente al kext di reagire all'azione specificata.

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

È poi possibile trovare il codice di `mac_file_check_mmap` in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Che richiama la macro `MAC_CHECK`, il cui codice è disponibile in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Questo percorre le policy registrate e combina i risultati con `mac_error_select()`. Un valore di ritorno pari a zero da un controllo successivo non può annullare un diniego precedente; se più policy negano l’azione, la funzione sceglie l’errore in base alla precedenza (ad esempio, `EACCES` prima di `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Tuttavia, ricorda che non tutte le callout MACF vengono usate solo per negare azioni. Ad esempio, `mac_priv_grant` chiama la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), che concede il privilegio richiesto se una qualsiasi policy risponde con 0:
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

Queste chiamate servono a verificare e concedere (decine di) **privilegi** definiti in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Alcuni componenti del kernel chiamano `priv_check_cred()` da [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con le credenziali KAuth del processo e il codice di uno dei privilegi. Questa funzione chiama `mac_priv_check` per verificare se una policy **nega** la concessione del privilegio, quindi chiama `mac_priv_grant` per verificare se una policy concede il `privilege`.<sup>[[4]](#references)</sup>

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

Che controllerà la **maschera di bit** nel processo chiamante per verificare se la syscall corrente deve chiamare `mac_proc_check_syscall_unix`. Questo perché le syscall vengono chiamate così frequentemente che è utile evitare di chiamare `mac_proc_check_syscall_unix` ogni volta.

Si noti che la funzione `proc_set_syscall_filter_mask()`, che imposta la maschera delle syscall in un processo, viene chiamata da Sandbox per impostare le maschere sui processi sandboxed.

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

Per il reversing offensivo, **`__mac_syscall`** è ancora uno dei migliori chokepoint in userland. Trasporta un **nome di policy** (per esempio `"Sandbox"` o `"AMFI"`), un **selector/codice specifico della policy** e un puntatore al **blob di argomenti opaco** che verrà gestito da `mpo_policy_syscall`. È molto utile quando si fa reversing di operazioni non documentate prima da userland e solo in seguito si passa all'implementazione nel kernel. Sandbox lo raggiunge comunemente tramite `__sandbox_ms`, mentre AMFI usa lo stesso meccanismo per le decisioni sulle policy di dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Note pratiche per la ricerca offensiva

I bug recenti di macOS raramente «aggirano MACF» direttamente. In genere sfruttano una **desincronizzazione tra una decisione MACF / Sandbox / TCC e l'azione privilegiata che avviene in seguito**.

### Attributi di spawn specifici della policy come input MACF

`posix_spawnattr_setmacpolicyinfo_np()` associa un nome di policy e byte opachi a una richiesta `posix_spawn()`. XNU cerca quei byte usando l'`mpc_name` di ciascuna policy registrata e li passa all'hook della policy per l'etichetta di esecuzione; anche l'hook dei vincoli di avvio legge i byte corrispondenti. Questo è un percorso di input MACF distinto da `__mac_syscall` e controllato dall'attaccante. Verifica se la policy tratta quei byte come una *restrizione aggiuntiva* oppure se consente loro di sostituire la policy già applicata al processo padre o all'eseguibile.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Per un test controllato, parti da un processo padre con restrizioni e avvia lo stesso processo figlio **senza** e **con** un attributo specifico della policy. Confronta l'accesso effettivo del processo figlio a una risorsa che il padre non può usare; il solo fatto che lo spawn riesca non dimostra che sia stato oltrepassato un confine.<sup>[[12]](#references)[[13]](#references)</sup>

Durante il reversing della policy, segui `mpo_cred_label_update_execve` e `mpo_proc_check_launch_constraints`, poi verifica se il chiamante può fornire l'attributo.<sup>[[10]](#references)[[11]](#references)</sup> Storicamente, AMFI accettava i vincoli di avvio forniti al posto di quelli integrati; Sandbox poteva applicare a un processo figlio un profilo integrato indicato per nome anziché mantenere le restrizioni del padre.<sup>[[13]](#references)[[12]](#references)</sup> Entrambi i comportamenti sono stati corretti, quindi non dare per scontato che siano presenti nei sistemi attuali.<sup>[[13]](#references)[[12]](#references)</sup>

Per il caso AMFI, consulta l'[analisi dei vincoli di avvio](macos-launch-environment-constraints.md); per testare la policy effettiva del processo figlio, consulta il [debugging di Sandbox](macos-sandbox/macos-sandbox-debug-and-bypass/).

### Controlli dei percorsi del broker vs azione privilegiata effettiva

Uno schema ricorrente consiste nel fatto che un daemon privilegiato esegue un **controllo preliminare in userland** (per esempio `sandbox_check_by_audit_token()`) su una versione di un percorso, per poi eseguire l'operazione privilegiata effettiva usando un percorso **diverso o non canonico, controllato dall'attaccante**. Le recenti ricerche su `diskarbitrationd` / `storagekitd` ne sono un buon esempio: **directory traversal** e **symlink swaps** consentono all'attaccante di superare la convalida sandbox del daemon e quindi montare un filesystem su percorsi sensibili come `~/Library/Application Support/com.apple.TCC`, trasformando il bug in un **sandbox escape**, **local privilege escalation** o **TCC bypass**, a seconda del punto di mount scelto.<sup>[[6]](#references)</sup>

Quando analizzi broker root raggiungibili dalla sandbox, cerca innanzitutto:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helper per la canonicalizzazione dei percorsi
- sink privilegiati come `mount`, `rename`, `copyfile`, metodi XPC di helper tool o qualsiasi altra cosa che in seguito acceda come root a percorsi controllati dall'attaccante

### Deputy fidati con entitlement privati

Un altro schema pratico consiste nell'evitare di attaccare direttamente gli hook MACF e abusare invece di un **processo fidato** che dispone già dei diritti necessari per oltrepassare il confine. Le recenti ricerche su Safari/TCC ne sono un buon esempio: la primitiva interessante non era «disabilitare TCC nel kernel», ma modificare policy/configurazioni locali affinché un processo firmato da Apple con **`com.apple.private.tcc.allow`** eseguisse l'operazione sensibile per conto dell'attaccante.<sup>[[8]](#references)</sup> In pratica, gli obiettivi di analisi più importanti sono daemon/app Apple che combinano:

- **entitlement privati** o accesso simile a FDA
- una configurazione / database / punto di mount / file di policy scrivibile
- un'operazione sensibile successiva mediata da **Sandbox**, **AMFI**, **TCC** o un'altra policy MACF

Per un reversing più approfondito, specifico per prodotto, consulta le pagine dedicate a [macOS Sandbox](macos-sandbox/README.md) e [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (il vettore completo delle operazioni delle policy MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macro `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (codici dei privilegi usati da `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [Syscall AMFI (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Alla scoperta delle vulnerabilità Apple: audit di diskarbitrationd e storagekitd, parte 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — strumento di cross-reference per XNU](https://newosxbook.com/xxr/index.php)
- [8] [Una nuova vulnerabilità di macOS, «HM Surf», potrebbe consentire l'accesso non autorizzato ai dati (blog sulla sicurezza di Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — setter dell'attributo di policy per posix_spawn](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — dispatch dell'attributo per l'etichetta di esecuzione specifica della policy](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — dispatch delle policy per i vincoli di avvio](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Evadere la Apple Sandbox avviando un eseguibile](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Aggirare i vincoli di avvio su macOS](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
