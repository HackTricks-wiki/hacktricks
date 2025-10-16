# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

**MACF** signifie **Mandatory Access Control Framework**, qui est un système de sécurité intégré au système d'exploitation pour aider à protéger votre ordinateur. Il fonctionne en définissant des **règles strictes sur qui ou quoi peut accéder à certaines parties du système**, telles que les fichiers, les applications et les ressources système. En appliquant ces règles automatiquement, MACF garantit que seuls les utilisateurs et processus autorisés peuvent effectuer des actions spécifiques, réduisant ainsi le risque d'accès non autorisé ou d'activités malveillantes.

Notez que MACF ne prend pas réellement de décisions car il se contente d'**intercepter** les actions ; il laisse les décisions aux **modules de politique** (extensions du noyau) qu'il appelle comme `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` et `mcxalr.kext`.

- Une politique peut être en mode application (enforcing) (return 0 non-zero sur une opération)
- Une politique peut être en mode surveillance (monitoring) (return 0, pour ne pas s'opposer mais profiter du hook pour faire quelque chose)
- Une politique MACF statique est installée au démarrage et ne sera JAMAIS supprimée
- Une politique MACF dynamique est installée par une KEXT (kextload) et peut hypothétiquement être kextunloaded
- Sur iOS seules les politiques statiques sont autorisées et sur macOS statiques + dynamiques.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flux

1. Le processus effectue un syscall/mach trap
2. La fonction pertinente est appelée à l'intérieur du noyau
3. La fonction appelle MACF
4. MACF vérifie les modules de politique qui ont demandé à hooker cette fonction dans leur politique
5. MACF appelle les politiques pertinentes
6. Les politiques indiquent si elles autorisent ou refusent l'action

> [!CAUTION]
> Apple est le seul à pouvoir utiliser le MAC Framework KPI.

Généralement, les fonctions vérifiant les permissions avec MACF appellent la macro `MAC_CHECK`. Comme dans le cas d'un syscall pour créer un socket qui appelera la fonction `mac_socket_check_create` qui appelle `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. De plus, la macro `MAC_CHECK` est définie dans security/mac_internal.h comme :
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
Notez que, en transformant `check` en `socket_check_create` et `args...` en `(cred, domain, type, protocol)`, vous obtenez :
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
L'expansion des macros d'aide montre le flux de contrôle concret :
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
En d'autres termes, `MAC_CHECK(socket_check_create, ...)` parcourt d'abord les politiques statiques, verrouille et itère conditionnellement sur les politiques dynamiques, émet les probes DTrace autour de chaque hook, et réduit le code de retour de chaque hook en un unique résultat `error` via `mac_error_select()`.


### Labels

MACF utilise des **étiquettes** que les politiques consultent pour déterminer si elles doivent accorder un accès ou non. La déclaration de la structure des labels peut être [trouvée ici](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), qui est ensuite utilisée à l'intérieur de la **`struct ucred`** [**ici**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) dans la partie **`cr_label`**. Le label contient des flags et un certain nombre de **slots** qui peuvent être utilisés par les **politiques MACF pour allouer des pointeurs**. Par exemple, Sandbox pointera vers le profil du conteneur.

## MACF Policies

Une politique MACF définit des **règles et conditions à appliquer lors de certaines opérations du noyau**.

Une extension du noyau peut configurer une structure `mac_policy_conf` puis l'enregistrer en appelant `mac_policy_register`. D'après [ici](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Il est facile d'identifier les extensions du noyau qui configurent ces politiques en vérifiant les appels à `mac_policy_register`. De plus, en vérifiant le désassemblage de l'extension, il est aussi possible de trouver la struct `mac_policy_conf` utilisée.

Notez que les politiques MACF peuvent être enregistrées et désenregistrées également de façon **dynamique**.

L'un des champs principaux de la `mac_policy_conf` est le **`mpc_ops`**. Ce champ spécifie quelles opérations la politique prend en charge. Notez qu'il y en a des centaines, donc il est possible de mettre tous ces champs à zéro puis de ne sélectionner que ceux qui intéressent la politique. Voir [ici](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Presque tous les hooks seront rappelés par MACF lorsqu'une de ces opérations est interceptée. Cependant, les hooks **`mpo_policy_*`** font exception car `mpo_hook_policy_init()` est un callback appelé lors de l'enregistrement (donc après `mac_policy_register()`) et `mpo_hook_policy_initbsd()` est appelé lors d'un enregistrement tardif une fois que le sous-système BSD s'est correctement initialisé.

De plus, le hook **`mpo_policy_syscall`** peut être enregistré par n'importe quel kext pour exposer une interface de type **ioctl** privée. Ensuite, un user client pourra appeler `mac_syscall` (#381) en spécifiant comme paramètres le **policy name** avec un **code** entier et des **arguments** optionnels.\
Par exemple, le **`Sandbox.kext`** utilise cela très souvent.

Vérifier la section **`__DATA.__const*`** du kext permet d'identifier la structure `mac_policy_ops` utilisée lors de l'enregistrement de la policy. On peut la trouver car son pointeur est à un offset à l'intérieur de `mpo_policy_conf` et aussi à cause du nombre de pointeurs NULL présents dans cette zone.

De plus, il est également possible d'obtenir la liste des kexts qui ont configuré une policy en dumpant depuis la mémoire la struct **`_mac_policy_list`** qui est mise à jour à chaque policy enregistrée.

Vous pouvez aussi utiliser l'outil `xnoop` pour dumper toutes les policies enregistrées dans le système :
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
Et ensuite dumpez tous les checks de check policy avec :
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
## MACF initialization in XNU

### Early bootstrap and mac_policy_init()

- MACF est initialisé très tôt. Dans `bootstrap_thread` (dans le code de démarrage XNU), après `ipc_bootstrap`, XNU appelle `mac_policy_init()` (dans `mac_base.c`).
- `mac_policy_init()` initialise la `mac_policy_list` globale (un tableau ou une liste de slots de policy) et met en place l'infrastructure pour MAC (contrôle d'accès obligatoire) au sein de XNU.
- Plus tard, `mac_policy_initmach()` est invoqué, ce qui gère le côté noyau de l'enregistrement des policies pour les policies intégrées ou empaquetées.

### `mac_policy_initmach()` and loading “security extensions”

- `mac_policy_initmach()` examine les kernel extensions (kexts) qui sont préchargées (ou dans une liste de « policy injection ») et inspecte leur Info.plist pour la clé `AppleSecurityExtension`.
- Les kexts qui déclarent `<key>AppleSecurityExtension</key>` (ou `true`) dans leur Info.plist sont considérés comme des « security extensions » — c.-à-d. ceux qui implémentent une MAC policy ou qui s'accrochent à l'infrastructure MACF.
- Des exemples de kexts Apple avec cette clé incluent **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre autres (comme vous l'avez déjà listé).
- Le noyau s'assure que ces kexts sont chargés tôt, puis appelle leurs routines d'enregistrement (via `mac_policy_register`) durant le boot, en les insérant dans la `mac_policy_list`.

- Chaque module de policy (kext) fournit une structure `mac_policy_conf`, avec des hooks (`mpc_ops`) pour diverses opérations MAC (vérifications vnode, vérifications exec, mises à jour de label, etc.).
- Les flags au moment du chargement peuvent inclure `MPC_LOADTIME_FLAG_NOTLATE` signifiant « doit être chargé tôt » (donc les tentatives d'enregistrement tardives sont rejetées).
- Une fois enregistrés, chaque module obtient un handle et occupe un slot dans `mac_policy_list`.
- Lorsqu'un hook MAC est invoqué plus tard (par exemple, accès vnode, exec, etc.), MACF itère sur toutes les policies enregistrées pour prendre des décisions collectives.

- En particulier, **AMFI** (Apple Mobile File Integrity) est une telle security extension. Son Info.plist inclut `AppleSecurityExtension` la marquant comme une policy de sécurité.
- Dans le cadre du démarrage du noyau, la logique de chargement du noyau s'assure que la « security policy » (AMFI, etc.) est déjà active avant que de nombreux sous-systèmes en dépendent. Par exemple, le noyau « prépare les tâches à venir en chargeant … la security policy, y compris AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy. »
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
## Dépendance KPI & com.apple.kpi.dsep dans les kexts de politique MAC

Lorsque vous écrivez un kext qui utilise le MAC framework (c.-à-d. en appelant `mac_policy_register()` etc.), vous devez déclarer des dépendances sur les KPIs (Kernel Programming Interfaces) afin que le kext linker (kxld) puisse résoudre ces symboles. Ainsi, pour déclarer qu'un `kext` dépend de MACF, vous devez l'indiquer dans le `Info.plist` avec `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), puis le kext fera référence à des symboles tels que `mac_policy_register`, `mac_policy_unregister` et des pointeurs de fonctions hook MAC. Pour les résoudre, vous devez lister `com.apple.kpi.dsep` comme dépendance.

Exemple d'extrait Info.plist (à l'intérieur de votre .kext) :
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
## Appels MACF

Il est courant de trouver des appels à MACF définis dans le code comme : **`#if CONFIG_MAC`** blocs conditionnels. De plus, à l'intérieur de ces blocs il est possible de trouver des appels à `mac_proc_check*` qui font appel à MACF pour **vérifier les permissions** afin d'exécuter certaines actions. En outre, le format des appels MACF est : **`mac_<object>_<opType>_opName`**.

L'objet est l'un des suivants : `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.  
Le `opType` est généralement `check`, qui sera utilisé pour autoriser ou refuser l'action. Cependant, il est aussi possible de trouver `notify`, qui permettra au kext de réagir à l'action donnée.

Vous pouvez trouver un exemple dans https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621 :

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

Ensuite, il est possible de trouver le code de `mac_file_check_mmap` dans https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174
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
Qui appelle la macro `MAC_CHECK`, dont le code peut être trouvé dans [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Ce mécanisme parcourt toutes les politiques mac enregistrées, appelle leurs fonctions et stocke la sortie dans la variable error, qui ne peut être remplacée que par `mac_error_select` via des codes de succès : si un contrôle échoue, l'ensemble du contrôle échoue et l'action ne sera pas autorisée.

> [!TIP]
> Cependant, gardez à l'esprit que tous les callouts MACF ne servent pas uniquement à refuser des actions. Par exemple, `mac_priv_grant` appelle la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), qui accordera le privilège demandé si au moins une politique répond par 0 :
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

Ces appels sont destinés à vérifier et fournir (des dizaines de) **privilèges** définis dans [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Du code du kernel appellerait `priv_check_cred()` depuis [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) avec les credentials KAuth du processus et l'un des codes de privilèges, ce qui appellera `mac_priv_check` pour vérifier si une politique **refuse** d'accorder le privilège et ensuite appellera `mac_priv_grant` pour voir si une politique accorde le `privilege`.

### proc_check_syscall_unix

Ce hook permet d'intercepter tous les appels système. Dans `bsd/dev/[i386|arm]/systemcalls.c` on peut voir la fonction déclarée [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), qui contient ce code:
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
Qui vérifiera dans le processus appelant le **bitmask** si le syscall courant doit appeler `mac_proc_check_syscall_unix`. Ceci parce que les syscalls sont appelés si fréquemment qu'il est intéressant d'éviter d'appeler `mac_proc_check_syscall_unix` à chaque fois.

Notez que la fonction `proc_set_syscall_filter_mask()`, qui définit le bitmask des syscalls dans un processus, est appelée par Sandbox pour définir des masques sur les processus sandboxés.

## MACF syscalls exposés

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
## Références

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
