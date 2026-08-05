# Extensions du noyau macOS & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les extensions du noyau (Kexts) sont des **packages** portant l’extension **`.kext`**, qui sont **chargés directement dans l’espace du noyau macOS** afin de fournir des fonctionnalités supplémentaires au système d’exploitation principal.

### Statut de dépréciation & DriverKit / System Extensions
À partir de **macOS Catalina (10.15)**, Apple a marqué la plupart des KPI legacy comme étant *deprecated* et a introduit les frameworks **System Extensions & DriverKit**, qui s’exécutent dans l’**espace utilisateur**. Depuis **macOS Big Sur (11)**, le système d’exploitation *refuse de charger* les kexts tiers qui dépendent de KPI deprecated, sauf si la machine est démarrée en mode **Reduced Security**. Sur Apple Silicon, l’activation des kexts exige en outre que l’utilisateur :

1. Redémarre en **Recovery** → *Startup Security Utility*.
2. Sélectionne **Reduced Security** et coche **“Allow user management of kernel extensions from identified developers”**.
3. Redémarre et approuve le kext depuis **System Settings → Privacy & Security**.

Les drivers en espace utilisateur écrits avec DriverKit/System Extensions **réduisent considérablement la surface d’attaque**, car les crashes ou corruptions mémoire restent confinés à un processus sandboxé plutôt que dans l’espace du noyau.<sup>[[1]](#references)</sup>

> 📝 Depuis macOS Sequoia (15), Apple a supprimé plusieurs KPI legacy liés aux réseaux et à l’USB – la seule solution compatible avec les futures versions pour les fournisseurs consiste à migrer vers les System Extensions.

### Exigences

Évidemment, cette fonctionnalité est si puissante qu’il est **compliqué de charger une extension du noyau**. Voici les **exigences** qu’une extension du noyau doit respecter pour être chargée :

- Lors du **passage en mode Recovery**, les **extensions du noyau doivent être autorisées** à être chargées :

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- L’extension du noyau doit être **signée avec un certificat de signature de code du noyau**, qui ne peut être **accordé que par Apple**. Apple examinera en détail l’entreprise ainsi que les raisons pour lesquelles ce certificat est nécessaire.
- L’extension du noyau doit également être **notarized** ; Apple pourra ainsi vérifier qu’elle ne contient pas de malware.
- Ensuite, l’utilisateur **root** est celui qui peut **charger l’extension du noyau**, et les fichiers à l’intérieur du package doivent **appartenir à root**.
- Pendant le processus d’upload, le package doit être préparé dans un **emplacement protégé non-root** : `/Library/StagedExtensions` (nécessite le grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Enfin, lors de la tentative de chargement, l’utilisateur [**recevra une demande de confirmation**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) et, si elle est acceptée, l’ordinateur devra être **redémarré** pour charger l’extension.

### Processus de chargement

Dans Catalina, le processus était le suivant : il est intéressant de noter que le processus de **vérification** se déroule en **userland**. Toutefois, seules les applications disposant du grant **`com.apple.private.security.kext-management`** peuvent **demander au noyau de charger une extension** : `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`**, le cli, **démarre** le processus de **vérification** nécessaire au chargement d’une extension
- Il communiquera avec **`kextd`** en envoyant une requête via un **service Mach**.
2. **`kextd`** vérifiera plusieurs éléments, notamment la **signature**
- Il communiquera avec **`syspolicyd`** afin de **vérifier** si l’extension peut être **chargée**.
3. **`syspolicyd`** demandera confirmation à l’**utilisateur** si l’extension n’a jamais été chargée auparavant.
- **`syspolicyd`** communiquera le résultat à **`kextd`**
4. **`kextd`** pourra finalement **demander au noyau de charger** l’extension

Si **`kextd`** n’est pas disponible, **`kextutil`** peut effectuer les mêmes vérifications.

### Énumération & gestion (kexts chargés)

`kextstat` était l’outil historique, mais il est **deprecated** dans les versions récentes de macOS. L’interface moderne est **`kmutil`** :
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
L’ancienne syntaxe est toujours disponible à titre de référence :
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` peut également être utilisé pour **extraire le contenu d'une Kernel Collection (KC)** ou vérifier qu'un kext résout toutes les dépendances de symboles :
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Même si les kernel extensions sont censées se trouver dans `/System/Library/Extensions/`, si vous accédez à ce dossier, vous **ne trouverez aucun binaire**. Cela est dû au **kernelcache** et, pour reverse un `.kext`, vous devez trouver un moyen de l'obtenir.

Le **kernelcache** est une **version précompilée et préliée du kernel XNU**, accompagnée des **drivers** de périphériques essentiels et des **kernel extensions**. Il est stocké dans un format **compressé** et décompressé en mémoire pendant le processus de démarrage. Le kernelcache permet un **démarrage plus rapide** en fournissant une version du kernel et des drivers essentiels prête à être exécutée, réduisant ainsi le temps et les ressources qui seraient autrement nécessaires pour charger et lier dynamiquement ces composants au démarrage.

Les principaux avantages du kernelcache sont la **rapidité de chargement** et le fait que tous les modules sont prelinked (aucun ralentissement au chargement). De plus, une fois que tous les modules ont été prelinked, KXLD peut être supprimé de la mémoire, de sorte que **XNU ne peut pas charger de nouveaux KEXTs.**

> [!TIP]
> L'outil [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) déchiffre les conteneurs AEA (Apple Encrypted Archive / AEA asset) d'Apple — le format de conteneur chiffré utilisé par Apple pour les assets OTA et certaines parties des IPSW — et peut produire l'archive .dmg/asset sous-jacente que vous pouvez ensuite extraire avec les outils aastuff fournis.


### Kerlnelcache local

Dans iOS, il se trouve dans **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. Dans macOS, vous pouvez le trouver avec : **`find / -name "kernelcache" 2>/dev/null`** \
Dans mon cas, je l'ai trouvé dans macOS à l'emplacement suivant :

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Vous trouverez également ici le [**kernelcache de la version 14 avec les symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Le format de fichier IMG4 est un format de conteneur utilisé par Apple sur ses appareils iOS et macOS pour **stocker et vérifier de manière sécurisée les composants du firmware** (comme le **kernelcache**). Le format IMG4 comprend un en-tête et plusieurs tags qui encapsulent différentes parties des données, notamment le payload réel (comme un kernel ou un bootloader), une signature et un ensemble de propriétés manifest. Le format prend en charge la vérification cryptographique, permettant à l'appareil de confirmer l'authenticité et l'intégrité du composant du firmware avant de l'exécuter.

Il est généralement composé des éléments suivants :

- **Payload (IM4P)** :
- Souvent compressé (LZFSE4, LZSS, …)
- Éventuellement chiffré
- **Manifest (IM4M)** :
- Contient une signature
- Dictionnaire Key/Value supplémentaire
- **Restore Info (IM4R)** :
- Également appelé APNonce
- Empêche la relecture de certaines updates
- OPTIONAL : Généralement, cet élément n'est pas présent

Décompressez le Kernelcache :
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Symboles Disarm pour le kernel

**`Disarm`** permet de symboliquer les fonctions du kernelcache à l'aide de matchers. Ces matchers sont simplement des règles de pattern (lignes de texte) qui indiquent à disarm comment reconnaître et auto-symboliquer les fonctions, les arguments et les chaînes panic/log à l'intérieur d'un binaire.

En résumé, vous indiquez la chaîne qu'une fonction utilise et disarm la trouvera et la **symboliquera**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Aller à /tmp/extracted où disarm a extrait les filesets
disarm -e filesets kernelcache.release.d23 # Toujours extraire vers /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Notez que xnu.matchers est en réalité un fichier contenant les matchers
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# Installer l'outil ipsw
brew install blacktop/tap/ipsw

# Extraire uniquement le kernelcache depuis l'IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Vous devriez obtenir quelque chose comme :
#   out/Firmware/kernelcache.release.iPhoneXX
#   ou un payload IMG4 : out/Firmware/kernelcache.release.iPhoneXX.im4p

# Si vous obtenez un payload IMG4 :
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# Lister toutes les extensions
kextex -l kernelcache.release.iphone14.e
## Extraire com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Tout extraire
kextex_all kernelcache.release.iphone14.e

# Vérifier les symboles de l'extension
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Créer un bundle de symbolication pour le dernier panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # obtenir la trace de la pile dans le contexte du kernel
```

### Attaching LLDB to a specific loaded kext

```bash
# Identifier l’adresse de chargement du kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attacher
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
