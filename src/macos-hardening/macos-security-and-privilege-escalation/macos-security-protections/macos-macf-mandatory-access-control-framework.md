# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

**MACF** signifie **Mandatory Access Control Framework**. Il s’agit d’un système de sécurité intégré au système d’exploitation pour protéger votre ordinateur. Il fonctionne en définissant des **règles strictes concernant les personnes ou les éléments pouvant accéder à certaines parties du système**, comme les fichiers, les applications et les ressources système. En appliquant automatiquement ces règles, MACF garantit que seuls les utilisateurs et les processus autorisés peuvent effectuer certaines actions, réduisant ainsi le risque d’accès non autorisé ou d’activités malveillantes.

Notez que MACF ne prend pas vraiment de décisions : il **intercepte** simplement les actions et laisse les **modules de politique** (extensions du kernel) qu’il appelle prendre les décisions, par exemple `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` et `mcxalr.kext`.

- Une politique peut appliquer des restrictions (renvoyer une valeur non nulle pour certaines opérations)
- Une politique peut effectuer une surveillance (renvoyer 0, pour ne pas s’opposer à l’action, mais profiter du hook pour faire quelque chose)
- Une politique MACF statique est installée au démarrage et ne sera JAMAIS supprimée
- Une politique MACF dynamique est installée par un KEXT (kextload) et pourrait théoriquement être déchargée avec kextunload
- Dans iOS, seules les politiques statiques sont autorisées ; dans macOS, les politiques statiques et dynamiques le sont.<sup>[[7]](#references)</sup>

### Flux d’exécution

1. Le processus effectue un syscall/mach trap
2. La fonction pertinente est appelée dans le kernel
3. La fonction appelle MACF
4. MACF vérifie les modules de politique qui ont demandé à effectuer un hook sur cette fonction dans leur politique
5. MACF appelle les politiques pertinentes
6. Les politiques indiquent si elles autorisent ou refusent l’action

> [!CAUTION]
> Seul Apple peut utiliser le KPI du MAC Framework.

En général, les fonctions qui vérifient les autorisations avec MACF appellent la macro `MAC_CHECK`. Par exemple, dans le cas d’un syscall visant à créer un socket, celui-ci appelle la fonction `mac_socket_check_create`, qui appelle `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. De plus, la macro `MAC_CHECK` est définie dans security/mac_internal.h comme suit :<sup>[[3]](#references)</sup>
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

L’expansion des macros auxiliaires montre le flux de contrôle concret :

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

En d’autres termes, `MAC_CHECK(socket_check_create, ...)` parcourt d’abord les politiques statiques, verrouille conditionnellement et parcourt les politiques dynamiques, émet les sondes DTrace autour de chaque hook et regroupe le code de retour de chaque hook dans le résultat unique `error` via `mac_error_select()`.


### Labels

MACF utilise des **labels** que les politiques consultent ensuite pour déterminer si elles doivent accorder ou non un accès. Le code de déclaration de la structure des labels se trouve [ici](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), et celle-ci est ensuite utilisée dans la **`struct ucred`**, [ici](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), dans la partie **`cr_label`**. Le label contient des flags et un certain nombre de **slots** que les **politiques MACF peuvent utiliser pour allouer des pointeurs**. Par exemple, Sandbox pointe vers le profil du conteneur.

## Politiques MACF

Une politique MACF définit des **règles et des conditions à appliquer lors de certaines opérations du noyau**.

Une extension du noyau peut configurer une structure `mac_policy_conf`, puis l’enregistrer en appelant `mac_policy_register`. D’après [cette source](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html) :<sup>[[1]](#references)</sup>

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

Il est facile d’identifier les extensions du noyau qui configurent ces politiques en recherchant les appels à `mac_policy_register`. De plus, en désassemblant l’extension, il est également possible de trouver la structure `mac_policy_conf` utilisée.

Notez que les politiques MACF peuvent également être enregistrées et désenregistrées **dynamiquement**.

L’un des principaux champs de `mac_policy_conf` est **`mpc_ops`**. Ce champ indique les opérations qui intéressent la politique. Il y en a des centaines ; il est donc possible de mettre toutes les entrées à zéro, puis de ne sélectionner que celles dont la politique a besoin. À partir de [ici](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Presque tous les hooks sont rappelés par MACF lorsque l’une de ces opérations est interceptée. Toutefois, les hooks **`mpo_policy_*`** font exception, car `mpo_hook_policy_init()` est un callback appelé lors de l’enregistrement (donc après `mac_policy_register()`), tandis que `mpo_hook_policy_initbsd()` est appelé pendant l’enregistrement tardif, une fois que le sous-système BSD est correctement initialisé.

De plus, le hook **`mpo_policy_syscall`** peut être enregistré par n’importe quel kext pour exposer une interface de type **ioctl** privée. Un client utilisateur pourra alors appeler `mac_syscall` (#381) en spécifiant en paramètres le **nom de la policy**, un **code** entier et des **arguments** facultatifs.\
Par exemple, `Sandbox.kext` l’utilise beaucoup.

Il est possible d’examiner le **`__DATA.__const*`** du kext pour identifier la structure `mac_policy_ops` utilisée lors de l’enregistrement de la policy. On peut la trouver parce que son pointeur se trouve à un décalage donné dans `mpo_policy_conf`, et aussi grâce au nombre de pointeurs NULL présents dans cette zone.

Il est également possible d’obtenir la liste des kexts qui ont configuré une policy en dumpant depuis la mémoire la structure **`_mac_policy_list`**, qui est mise à jour à chaque enregistrement d’une policy.

Vous pouvez aussi utiliser l’outil `xnoop` pour dumper toutes les policies enregistrées dans le système :

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

Puis afficher tous les contrôles de la stratégie de vérification avec :

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

### Démarrage précoce et `mac_policy_init()`

- MACF est initialisé très tôt. Dans `bootstrap_thread` (dans le code de démarrage de XNU), après `ipc_bootstrap`, XNU appelle `mac_policy_init()` (dans `mac_base.c`).
- `mac_policy_init()` initialise la variable globale `mac_policy_list` (un tableau ou une liste d’emplacements de stratégies) et met en place l’infrastructure de MAC (Mandatory Access Control, ou contrôle d’accès obligatoire) dans XNU.
- Plus tard, `mac_policy_initmach()` est appelée pour gérer l’enregistrement des stratégies côté noyau, notamment celles intégrées ou regroupées.

### `mac_policy_initmach()` et le chargement des « extensions de sécurité »

- `mac_policy_initmach()` examine les extensions du noyau (kexts) préchargées (ou présentes dans une liste d’« injection de stratégies ») et vérifie si leur Info.plist contient la clé `AppleSecurityExtension`.
- Les kexts qui déclarent `<key>AppleSecurityExtension</key>` (ou `true`) dans leur Info.plist sont considérées comme des « extensions de sécurité », c’est-à-dire qu’elles implémentent une stratégie MAC ou s’intègrent à l’infrastructure MACF.
- Parmi les kexts d’Apple qui contiennent cette clé, on trouve **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre autres (comme indiqué précédemment).
- Le noyau veille à ce que ces kexts soient chargées tôt, puis appelle leurs routines d’enregistrement (via `mac_policy_register`) pendant le démarrage, pour les ajouter à `mac_policy_list`.

  - Chaque module de stratégie (kext) fournit une structure `mac_policy_conf` contenant des hooks (`mpc_ops`) pour diverses opérations MAC (vérifications vnode, vérifications exec, mises à jour d’étiquettes, etc.).
  - Les indicateurs de chargement peuvent inclure `MPC_LOADTIME_FLAG_NOTLATE`, qui signifie que le module « doit être chargé tôt » (les tentatives d’enregistrement tardif sont donc rejetées).
  - Une fois enregistré, chaque module reçoit un handle et occupe un emplacement dans `mac_policy_list`.
  - Lorsqu’un hook MAC est appelé par la suite (par exemple, pour un accès vnode, exec, etc.), MACF parcourt toutes les stratégies enregistrées afin de prendre des décisions collectives.

- En particulier, **AMFI** (Apple Mobile File Integrity) est une extension de sécurité de ce type. Son Info.plist contient `AppleSecurityExtension`, ce qui la désigne comme une stratégie de sécurité.
- Pendant le démarrage du noyau, la logique de chargement veille à ce que la « stratégie de sécurité » (AMFI, etc.) soit déjà active avant que de nombreux sous-systèmes n’en dépendent. Par exemple, le noyau « se prépare aux tâches à venir en chargeant […] la stratégie de sécurité, notamment AppleMobileFileIntegrity (AMFI), Sandbox et la stratégie Quarantine ». 

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

## Dépendance aux KPI et com.apple.kpi.dsep dans les kexts de politique MAC

Lors de l’écriture d’un kext qui utilise le framework MAC (c.-à-d. qui appelle `mac_policy_register()`, etc.), vous devez déclarer des dépendances aux KPI (Kernel Programming Interfaces) afin que l’éditeur de liens du kext (kxld) puisse résoudre ces symboles. Donc, pour déclarer qu’un `kext` dépend de MACF, vous devez l’indiquer dans `Info.plist` avec `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Le kext fera alors référence à des symboles tels que `mac_policy_register`, `mac_policy_unregister` et aux pointeurs de fonction des hooks MAC. Pour les résoudre, vous devez lister `com.apple.kpi.dsep` comme dépendance.

Extrait d’exemple de Info.plist (dans votre .kext) :

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

Sur les versions modernes de macOS, les politiques de sécurité d’Apple sont généralement plus faciles à étudier autrement qu’en examinant des bundles `.kext` autonomes et isolés. Depuis **macOS 11**, les extensions du noyau sont liées dans des **collections du noyau** ; sur **Apple Silicon**, il n’existe pas de **SystemKC** distincte, et les kexts tiers ne peuvent être chargés qu’après avoir été intégrés à l’**Auxiliary Kernel Collection (AuxKC)** et après un redémarrage. Pour les recherches sur MACF, cela signifie que les politiques intégrées telles que **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ou **Quarantine** sont généralement plus faciles à inventorier avec `kmutil` qu’avec des outils obsolètes comme `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Sur Apple Silicon, si une extension kext de sécurité n'est pas dans le BootKC, vérifiez ensuite l'AuxKC. C'est généralement plus utile que de chercher un bundle autonome dans `/System/Library/Extensions`.

## Appels MACF

Il est courant de trouver des appels à MACF définis dans des blocs conditionnels comme **`#if CONFIG_MAC`**. De plus, il est possible de trouver dans ces blocs des appels à `mac_proc_check*`, qui appellent MACF pour **vérifier les autorisations** nécessaires à certaines actions. Par ailleurs, le format des appels MACF est : **`mac_<object>_<opType>_opName`**.

L'objet est l'un des suivants : `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
L'`opType` est généralement `check`, qui sera utilisé pour autoriser ou refuser l'action. Toutefois, il est également possible de trouver `notify`, qui permettra à l'extension kext de réagir à l'action donnée.

Vous trouverez un exemple dans [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) :

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

Il est ensuite possible de trouver le code de `mac_file_check_mmap` dans [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Ce qui appelle la macro `MAC_CHECK`, dont le code se trouve dans [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Cela parcourt les policies enregistrées et combine leurs résultats avec `mac_error_select()`. Un retour à zéro d’une vérification ultérieure ne peut pas annuler un refus antérieur ; si plusieurs policies refusent, la fonction choisit l’erreur selon leur ordre de priorité (par exemple, `EACCES` avant `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Cependant, n’oubliez pas que les callouts MACF ne servent pas tous uniquement à refuser des actions. Par exemple, `mac_priv_grant` appelle la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), qui accorde le privilège demandé si une policy répond par 0 :
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

Ces appels servent à vérifier et à fournir des **privilèges** (dizaines) définis dans [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Certains codes du kernel appellent `priv_check_cred()` depuis [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) avec les identifiants KAuth du processus et l’un des codes de privilège. Cette fonction appelle `mac_priv_check` pour vérifier si une policy **refuse** d’accorder le privilège, puis appelle `mac_priv_grant` pour vérifier si une policy accorde le `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Ce hook permet d’intercepter tous les appels système. Dans `bsd/dev/[i386|arm]/systemcalls.c`, on peut voir la fonction déclarée [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), qui contient ce code :

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

Cela vérifiera le **masque de bits** du processus appelant pour déterminer si l’appel système actuel doit appeler `mac_proc_check_syscall_unix`. En effet, les appels système sont si fréquents qu’il est préférable d’éviter d’appeler `mac_proc_check_syscall_unix` à chaque fois.

Notez que la fonction `proc_set_syscall_filter_mask()`, qui définit le masque des appels système d’un processus, est appelée par Sandbox pour définir les masques des processus sandboxés.

## Appels système MACF exposés

Il est possible d’interagir avec MACF via certains appels système définis dans [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):

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

Pour le reversing offensif, **`__mac_syscall`** reste l’un des meilleurs points de passage côté userland. Il transporte un **nom de policy** (par exemple `"Sandbox"` ou `"AMFI"`), un **sélecteur/code propre à la policy** et un pointeur vers le **bloc d’arguments opaque** qui sera traité par `mpo_policy_syscall`. C’est très utile pour analyser d’abord depuis le userland des opérations non documentées, puis passer à leur implémentation dans le kernel. Sandbox y accède généralement via `__sandbox_ms`, et AMFI utilise le même mécanisme pour les décisions de policy de dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Notes pratiques de recherche offensive

Les bugs macOS récents ne « cassent » que rarement MACF directement. Ils exploitent plutôt une **désynchronisation entre une décision de MACF / Sandbox / TCC et l’action privilégiée qui survient ensuite**.

### Attributs de spawn propres à une policy en entrée de MACF

`posix_spawnattr_setmacpolicyinfo_np()` associe un nom de policy et des octets opaques à une requête `posix_spawn()`. XNU recherche ces octets à partir du `mpc_name` de chaque policy enregistrée, puis les transmet au hook de label d’exécution de cette policy ; le hook de contraintes de lancement lit également les octets correspondants. Il s’agit d’un chemin d’entrée MACF distinct de `__mac_syscall` et contrôlé par l’attaquant. Vérifiez si la policy traite ces octets comme une *restriction supplémentaire* ou s’ils remplacent les restrictions existantes du parent ou de l’exécutable.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Pour effectuer un test contrôlé, partez d’un parent soumis à des restrictions et lancez le même enfant **sans**, puis **avec**, un attribut propre à la policy. Comparez l’accès effectif de l’enfant à une ressource que le parent ne peut pas utiliser ; la réussite du lancement ne prouve pas à elle seule qu’une frontière a été franchie.<sup>[[12]](#references)[[13]](#references)</sup>

Lors du reversing de la policy, suivez `mpo_cred_label_update_execve` et `mpo_proc_check_launch_constraints`, puis vérifiez si l’appelant peut fournir l’attribut.<sup>[[10]](#references)[[11]](#references)</sup> Historiquement, AMFI acceptait les contraintes de lancement fournies au lieu des contraintes intégrées ; Sandbox pouvait appliquer à un enfant un profil intégré désigné par son nom au lieu de conserver les restrictions du parent.<sup>[[13]](#references)[[12]](#references)</sup> Ces deux comportements ont été corrigés : ne les supposez donc pas présents sur les systèmes actuels.<sup>[[13]](#references)[[12]](#references)</sup>

Consultez l’[analyse des contraintes de lancement](macos-launch-environment-constraints.md) pour le cas d’AMFI et la page [débogage de Sandbox](macos-sandbox/macos-sandbox-debug-and-bypass/) pour tester la policy effective de l’enfant.

### Vérifications de chemin du broker vs action privilégiée réelle

Un schéma récurrent consiste en un daemon privilégié qui effectue une **vérification préalable côté userland** (par exemple `sandbox_check_by_audit_token()`) sur une version du chemin, puis exécute ensuite la véritable opération privilégiée avec un chemin **différent ou non canonique contrôlé par l’attaquant**. Les recherches récentes sur `diskarbitrationd` / `storagekitd` en sont un bon exemple : la **traversée de répertoires** et les **échanges de symlinks** permettent à l’attaquant de passer la validation Sandbox du daemon, puis de monter un volume sur des emplacements sensibles tels que `~/Library/Application Support/com.apple.TCC`. Selon le point de montage choisi, le bug peut ainsi devenir une **sandbox escape**, une **élévation de privilèges locale** ou un **contournement de TCC**.<sup>[[6]](#references)</sup>

Lors de l’audit de brokers root accessibles depuis le sandbox, recherchez d’abord :

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers de canonicalisation des chemins
- des opérations privilégiées telles que `mount`, `rename`, `copyfile`, des méthodes XPC de helper-tool, ou tout élément qui accède ensuite en tant que root à des chemins contrôlés par l’attaquant

### Deputies de confiance avec des entitlements privés

Un autre schéma pratique consiste à éviter d’attaquer directement les hooks MACF et à abuser plutôt d’un **processus de confiance** qui possède déjà les droits nécessaires pour franchir la frontière. Les recherches récentes sur Safari/TCC en sont un bon exemple : la primitive intéressante ne consistait pas à « désactiver TCC dans le kernel », mais à modifier une policy ou une configuration locale afin qu’un processus signé par Apple disposant de **`com.apple.private.tcc.allow`** effectue l’action sensible à votre place.<sup>[[8]](#references)</sup> En pratique, les cibles d’audit à forte valeur sont les daemons/apps Apple qui combinent :

- des **entitlements privés** ou un accès de type FDA
- une configuration / base de données / point de montage / fichier de policy modifiable en écriture
- une opération sensible ultérieure régie par **Sandbox**, **AMFI**, **TCC** ou une autre policy MACF

Pour approfondir le reversing propre à chaque produit, consultez les pages dédiées à [macOS Sandbox](macos-sandbox/README.md) et à [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (le vecteur complet des opérations de policy MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macros `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (codes de privilège utilisés par `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [Appel système AMFI (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Découverte de vulnérabilités Apple : audit de diskarbitrationd et storagekitd, partie 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — outil de référence croisée XNU](https://newosxbook.com/xxr/index.php)
- [8] [Nouvelle vulnérabilité macOS, « HM Surf », susceptible d’entraîner un accès non autorisé aux données (blog Microsoft Security)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — setter d’attribut de policy `posix_spawn`](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — dispatch des attributs de label d’exécution propres à une policy](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — dispatch des policies de contraintes de lancement](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Échapper au Sandbox d’Apple en lançant un exécutable](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Contourner les contraintes de lancement sur macOS](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
