# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

**MACF** signifie **Mandatory Access Control Framework**, un système de sécurité intégré au système d'exploitation qui aide à protéger votre ordinateur. Il fonctionne en définissant des **règles strictes concernant les personnes ou les éléments pouvant accéder à certaines parties du système**, comme les fichiers, les applications et les ressources système. En appliquant automatiquement ces règles, MACF garantit que seuls les utilisateurs et processus autorisés peuvent effectuer certaines actions, ce qui réduit le risque d'accès non autorisés ou d'activités malveillantes.

Notez que MACF ne prend pas vraiment de décisions, puisqu'il **intercepte** simplement les actions et laisse les décisions aux **modules de policy** (extensions du kernel) qu'il appelle, comme `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` et `mcxalr.kext`.

- Une policy peut appliquer des restrictions (retourner 0 ou une valeur non nulle lors d'une opération)
- Une policy peut effectuer une surveillance (retourner 0, afin de ne pas s'opposer à l'action, mais de tirer parti du hook pour effectuer une opération)
- Une policy statique MACF est installée au démarrage et ne sera JAMAIS supprimée
- Une policy dynamique MACF est installée par un KEXT (`kextload`) et pourrait théoriquement être déchargée avec `kextunload`
- Sous iOS, seules les policies statiques sont autorisées, tandis que macOS autorise les policies statiques et dynamiques.<sup>[[7]](#references)</sup>

### Flux

1. Le processus effectue un syscall/mach trap
2. La fonction pertinente est appelée dans le kernel
3. La fonction appelle MACF
4. MACF vérifie les modules de policy qui ont demandé à hooker cette fonction dans leur policy
5. MACF appelle les policies pertinentes
6. Les policies indiquent si elles autorisent ou refusent l'action

> [!CAUTION]
> Apple est le seul acteur pouvant utiliser le KPI de MAC Framework.

En général, les fonctions qui vérifient les permissions avec MACF appellent la macro `MAC_CHECK`. C'est notamment le cas du syscall visant à créer un socket, qui appelle la fonction `mac_socket_check_create`, laquelle appelle `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. De plus, la macro `MAC_CHECK` est définie dans security/mac_internal.h comme suit :<sup>[[3]](#references)</sup>
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
Notez qu’en transformant `check` en `socket_check_create` et `args...` en `(cred, domain, type, protocol)`, vous obtenez :
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
L’expansion des macros auxiliaires révèle le flux de contrôle concret :
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
En d'autres termes, `MAC_CHECK(socket_check_create, ...)` parcourt d'abord les politiques statiques, verrouille et parcourt conditionnellement les politiques dynamiques, émet les probes DTrace autour de chaque hook, puis regroupe le code de retour de chaque hook en un seul résultat `error` via `mac_error_select()`.


### Labels

MACF utilise des **labels** que les politiques chargées de vérifier si elles doivent accorder ou non un accès utilisent ensuite. Le code de déclaration de la structure des labels peut être [consulté ici](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), puis il est utilisé à l'intérieur de la **struct ucred**, [ici](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), dans la partie **`cr_label`**. Le label contient des flags et un certain nombre de **slots** que les **policies MACF peuvent utiliser pour allouer des pointeurs**. Par exemple, Sanbox pointera vers le container profile.

## MACF Policies

Une MACF Policy définit des **règles et des conditions à appliquer lors de certaines opérations du kernel**.

Une kernel extension peut configurer une structure `mac_policy_conf`, puis l'enregistrer en appelant `mac_policy_register`. Depuis [ici](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Il est facile d’identifier les extensions du kernel qui configurent ces policies en recherchant les appels à `mac_policy_register`. De plus, en examinant le désassemblage de l’extension, il est également possible de trouver la struct `mac_policy_conf` utilisée.

Notez que les policies MACF peuvent également être enregistrées et désenregistrées **dynamiquement**.

L’un des principaux champs de `mac_policy_conf` est **`mpc_ops`**. Ce champ spécifie les opérations qui intéressent la policy. Il y en a des centaines ; il est donc possible de mettre toutes les entrées à zéro, puis de sélectionner uniquement celles dont la policy a besoin. Depuis [ici](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) :<sup>[[1]](#references)</sup>
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
Presque tous les hooks seront rappelés par MACF lorsque l’une de ces opérations est interceptée. Cependant, les hooks **`mpo_policy_*`** font exception, car **`mpo_hook_policy_init()`** est un callback appelé lors de l’enregistrement (donc après **`mac_policy_register()`**) et **`mpo_hook_policy_initbsd()`** est appelé lors de l’enregistrement tardif, une fois que le sous-système BSD a été correctement initialisé.

De plus, le hook **`mpo_policy_syscall`** peut être enregistré par n’importe quel kext afin d’exposer une **interface** d’appel privée de type **ioctl**. Un client utilisateur pourra alors appeler `mac_syscall` (#381) en spécifiant comme paramètres le **nom de la policy**, un **code** entier et des **arguments** facultatifs.\
Par exemple, **`Sandbox.kext`** l’utilise beaucoup.

L’inspection de **`__DATA.__const*`** du kext permet d’identifier la structure `mac_policy_ops` utilisée lors de l’enregistrement de la policy. Il est possible de la trouver, car son pointeur se situe à un offset dans `mpo_policy_conf`, et également grâce au nombre de pointeurs NULL présents dans cette zone.

De plus, il est aussi possible d’obtenir la liste des kexts ayant configuré une policy en extrayant de la mémoire la structure **`_mac_policy_list`**, qui est mise à jour avec chaque policy enregistrée.

Vous pouvez également utiliser l’outil `xnoop` pour extraire toutes les policies enregistrées dans le système :
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
Puis, afficher toutes les vérifications de check policy avec :
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
## Initialisation de MACF dans XNU

### Bootstrap précoce et mac_policy_init()

- MACF est initialisé très tôt. Dans `bootstrap_thread` (dans le code de démarrage de XNU), après `ipc_bootstrap`, XNU appelle `mac_policy_init()` (dans `mac_base.c`).
- `mac_policy_init()` initialise la `mac_policy_list` globale (un tableau ou une liste de slots de policy) et met en place l’infrastructure de MAC (Mandatory Access Control) au sein de XNU.
- Plus tard, `mac_policy_initmach()` est appelée ; elle gère l’enregistrement côté kernel des policies intégrées ou incluses.

### `mac_policy_initmach()` et le chargement des « security extensions »

- `mac_policy_initmach()` examine les kernel extensions (kexts) préchargées (ou présentes dans une liste de « policy injection ») et inspecte leur Info.plist à la recherche de la clé `AppleSecurityExtension`.
- Les kexts qui déclarent `<key>AppleSecurityExtension</key>` (ou `true`) dans leur Info.plist sont considérées comme des « security extensions », c’est-à-dire celles qui implémentent une MAC policy ou s’intègrent à l’infrastructure MACF.
- Parmi les kexts d’Apple possédant cette clé figurent **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre autres (comme déjà indiqué).
- Le kernel s’assure que ces kexts sont chargées tôt, puis appelle leurs routines d’enregistrement (via `mac_policy_register`) pendant le boot, en les insérant dans la `mac_policy_list`.

- Chaque module de policy (kext) fournit une structure `mac_policy_conf`, avec des hooks (`mpc_ops`) pour différentes opérations MAC (vérifications de vnode, vérifications d’exec, mises à jour de labels, etc.).
- Les flags de chargement peuvent inclure `MPC_LOADTIME_FLAG_NOTLATE`, ce qui signifie que la policy « doit être chargée tôt » (les tentatives d’enregistrement tardives sont donc rejetées).
- Une fois enregistré, chaque module reçoit un handle et occupe un slot dans la `mac_policy_list`.
- Lorsqu’un hook MAC est invoqué ultérieurement (par exemple pour un accès à un vnode, une exec, etc.), MACF parcourt toutes les policies enregistrées afin de prendre des décisions collectives.

- En particulier, **AMFI** (Apple Mobile File Integrity) est une telle security extension. Son Info.plist contient `AppleSecurityExtension`, ce qui l’identifie comme une security policy.
- Dans le cadre du boot du kernel, la logique de chargement du kernel s’assure que la « security policy » (AMFI, etc.) est déjà active avant que de nombreux sous-systèmes n’en dépendent. Par exemple, le kernel « se prépare aux tâches à venir en chargeant … la security policy, notamment AppleMobileFileIntegrity (AMFI), Sandbox et la Quarantine policy ».
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
## Dépendance aux KPI et com.apple.kpi.dsep dans les kexts de MAC policy

Lors de l’écriture d’un kext qui utilise le framework MAC (c’est-à-dire qui appelle `mac_policy_register()`, etc.), vous devez déclarer des dépendances envers les KPI (Kernel Programming Interfaces) afin que l’éditeur de liens du kext (kxld) puisse résoudre ces symboles. Ainsi, pour déclarer qu’un `kext` dépend de MACF, vous devez l’indiquer dans l’`Info.plist` avec `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`) ; le kext fera alors référence à des symboles tels que `mac_policy_register`, `mac_policy_unregister` et aux pointeurs de fonctions des hooks MAC. Pour les résoudre, vous devez répertorier `com.apple.kpi.dsep` comme dépendance.

Exemple d’extrait d’Info.plist (à l’intérieur de votre .kext) :
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
## MACF sur les versions modernes de macOS

Sur les versions modernes de macOS, il est généralement préférable de ne pas aborder les politiques de sécurité d’Apple comme de simples bundles `.kext` autonomes. Depuis **macOS 11**, les extensions du kernel sont liées dans des **kernel collections** ; sur **Apple Silicon**, il n’existe pas de **SystemKC** distinct, et les kexts tiers ne peuvent être chargés qu’après avoir été intégrés à l’**Auxiliary Kernel Collection (AuxKC)**, puis après un redémarrage. Pour la recherche sur MACF, cela signifie que les politiques intégrées telles que **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ou **Quarantine** sont généralement plus faciles à énumérer avec `kmutil` qu’avec des outils obsolètes tels que `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Sur Apple Silicon, si un security kext ne se trouve pas dans le BootKC, vérifiez ensuite l’AuxKC. Cela est généralement plus utile que de chercher un bundle standalone sous `/System/Library/Extensions`.

## MACF Callouts

Il est courant de trouver des callouts vers MACF définis dans du code, notamment dans des blocs conditionnels **`#if CONFIG_MAC`**. De plus, à l’intérieur de ces blocs, il est possible de trouver des appels à `mac_proc_check*`, qui appellent MACF pour **vérifier les permissions** nécessaires à l’exécution de certaines actions. Par ailleurs, le format des callouts MACF est le suivant : **`mac_<object>_<opType>_opName`**.

L’objet est l’un des suivants : `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
L’`opType` est généralement `check`, qui sera utilisé pour autoriser ou refuser l’action. Cependant, il est également possible de trouver `notify`, qui permettra au kext de réagir à l’action donnée.

Vous pouvez trouver un exemple dans [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) :

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

Ensuite, il est possible de trouver le code de `mac_file_check_mmap` dans [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174).
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
Qui appelle la macro `MAC_CHECK`, dont le code est disponible dans [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
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
Qui parcourra toutes les politiques mac enregistrées, appellera leurs fonctions et stockera le résultat dans la variable `error`, qui ne pourra être remplacée par `mac_error_select` que par des codes de succès. Ainsi, si une vérification échoue, la vérification complète échouera et l'action ne sera pas autorisée.

> [!TIP]
> Cependant, rappelez-vous que tous les callouts MACF ne sont pas utilisés uniquement pour refuser des actions. Par exemple, `mac_priv_grant` appelle la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), qui accordera le privilege demandé si une politique répond par 0 :
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

Ces callbacks sont destinés à vérifier et à fournir des **privileges** définis dans [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Du code du kernel appelle `priv_check_cred()` depuis [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) avec les identifiants KAuth du processus et l'un des codes de privileges, ce qui appelle `mac_priv_check` pour vérifier si une politique **refuse** d'accorder le privilege, puis appelle `mac_priv_grant` pour vérifier si une politique accorde le `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Ce hook permet d'intercepter tous les appels système. Dans `bsd/dev/[i386|arm]/systemcalls.c`, il est possible de voir la fonction déclarée [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), qui contient ce code :
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
Qui vérifiera dans le **bitmask** du processus appelant si le syscall actuel doit appeler `mac_proc_check_syscall_unix`. Cela s'explique par le fait que les syscalls sont appelés très fréquemment, et qu'il est donc intéressant d'éviter d'appeler `mac_proc_check_syscall_unix` à chaque fois.

Notez que la fonction `proc_set_syscall_filter_mask()`, qui définit le bitmask des syscalls dans un processus, est appelée par Sandbox pour définir des masques sur les processus sandboxés.

## Syscalls MACF exposés

Il est possible d'interagir avec MACF via certains syscalls définis dans [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Pour le reversing offensif, **`__mac_syscall`** reste l’un des meilleurs chokepoints en userland. Il transporte un **nom de policy** (par exemple `"Sandbox"` ou `"AMFI"`), un **selector/code spécifique à la policy**, ainsi qu’un pointeur vers l’**opaque argument blob** qui sera traité par `mpo_policy_syscall`. C’est très utile pour reverser d’abord les opérations non documentées depuis le userland, puis pivoter vers l’implémentation kernel. Sandbox l’atteint couramment via `__sandbox_ms`, et AMFI utilise le même mécanisme pour les décisions de policy de dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Notes pratiques de recherche offensive

Les bugs macOS récents ne « cassent » que rarement MACF directement. Ils exploitent généralement une **désynchronisation entre une décision MACF / Sandbox / TCC et l’action privilégiée qui se produit ensuite**.

### Vérifications de chemins du broker vs action privilégiée réelle

Un schéma récurrent consiste, pour un daemon privilégié, à effectuer une **pré-vérification en userland** (par exemple `sandbox_check_by_audit_token()`) sur une version d’un chemin, puis à exécuter ultérieurement le véritable sink privilégié avec un **chemin contrôlé par l’attaquant, différent ou non canonique**. Les recherches récentes sur `diskarbitrationd` / `storagekitd` en sont un bon exemple : la **traversée de répertoires** ainsi que les **échanges de symlinks** permettent à l’attaquant de passer la validation Sandbox du daemon, puis de monter un système de fichiers sur des emplacements sensibles tels que `~/Library/Application Support/com.apple.TCC`, transformant le bug en **sandbox escape**, **local privilege escalation** ou **TCC bypass** selon le point de montage choisi.<sup>[[6]](#references)</sup>

Lors de l’audit de root brokers accessibles depuis le sandbox, recherchez d’abord :

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers de canonicalisation de chemins
- des sinks privilégiés tels que `mount`, `rename`, `copyfile`, les méthodes XPC de helper tools, ou tout élément qui touche ensuite des chemins contrôlés par l’attaquant en tant que root

### Trusted deputies avec des entitlements privés

Un autre schéma pratique consiste à éviter d’attaquer directement les hooks MACF et à abuser à la place d’un **processus de confiance** qui possède déjà les droits nécessaires pour franchir la frontière. Les recherches récentes sur Safari/TCC en sont un bon exemple : la primitive intéressante n’était pas de « désactiver TCC dans le kernel », mais de modifier la policy/configuration locale afin qu’un processus signé par Apple et disposant de **`com.apple.private.tcc.allow`** effectue l’action sensible à votre place.<sup>[[8]](#references)</sup> En pratique, les cibles d’audit à forte valeur sont les daemons/apps Apple qui combinent :

- des **entitlements privés** ou un accès de type FDA
- une configuration / base de données / point de montage / policy file inscriptible
- une opération sensible ultérieure médiée par **Sandbox**, **AMFI**, **TCC** ou une autre policy MACF

Pour un reversing plus approfondi spécifique à un produit, consultez les pages dédiées à [macOS Sandbox](macos-sandbox/README.md) et [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (le vecteur complet des opérations de policy MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macros `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (codes de privilèges utilisés par `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Découverte de vulnérabilités Apple : audit de diskarbitrationd et storagekitd, partie 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — outil Cross Reference de XNU](https://newosxbook.com/xxr/index.php)
- [8] [Nouvelle vulnérabilité macOS, « HM Surf », pouvant entraîner un accès non autorisé aux données (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
