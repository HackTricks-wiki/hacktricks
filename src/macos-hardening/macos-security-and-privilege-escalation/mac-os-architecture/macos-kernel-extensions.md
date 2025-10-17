# Extensions du noyau macOS & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Kernel extensions (Kexts) sont des **packages** avec une **`.kext`** extension qui sont **chargés directement dans l'espace kernel de macOS**, fournissant des fonctionnalités supplémentaires au système d'exploitation principal.

### Statut de dépréciation & DriverKit / System Extensions
À partir de **macOS Catalina (10.15)** Apple a marqué la plupart des KPI hérités comme *dépréciés* et a introduit les frameworks **System Extensions & DriverKit** qui s'exécutent en **user-space**. Depuis **macOS Big Sur (11)** le système refusera de *charger* des kexts tiers qui dépendent de KPI dépréciés à moins que la machine ne soit démarrée en mode **Reduced Security**. Sur Apple Silicon, l'activation des kexts nécessite également que l'utilisateur :

1. Redémarre en **Recovery** → *Startup Security Utility*.
2. Sélectionne **Reduced Security** et coche **“Allow user management of kernel extensions from identified developers”**.
3. Redémarre et approuve le kext depuis **System Settings → Privacy & Security**.

Les drivers user-land écrits avec DriverKit/System Extensions réduisent dramatiquement la surface d'attaque parce que les crashes ou corruptions mémoire sont confinés à un processus sandboxé plutôt qu'au kernel space.

> 📝 Depuis macOS Sequoia (15) Apple a supprimé plusieurs KPI réseau et USB hérités – la seule solution compatible à long terme pour les fournisseurs est de migrer vers System Extensions.

### Exigences

Évidemment, c'est si puissant qu'il est **complexe de charger une kernel extension**. Voici les **exigences** qu'une kernel extension doit remplir pour être chargée :

- Lors de l'**entrée en recovery mode**, les kernel **extensions doivent être autorisées** à être chargées :

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- La kernel extension doit être **signée avec un certificat de signature de code kernel**, qui ne peut être **accordé que par Apple**. Apple examinera en détail l'entreprise et les raisons de la demande.
- La kernel extension doit aussi être **notarisée**, Apple pourra la vérifier pour malware.
- Ensuite, l'utilisateur **root** est celui qui peut **charger la kernel extension** et les fichiers à l'intérieur du package doivent **appartenir à root**.
- Pendant le processus d'upload, le package doit être préparé dans un emplacement **protégé non-root** : `/Library/StagedExtensions` (requiert la permission `com.apple.rootless.storage.KernelExtensionManagement`).
- Enfin, lors de la tentative de chargement, l'utilisateur [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) et, si accepté, l'ordinateur doit être **redémarré** pour la charger.

### Processus de chargement

Dans Catalina c'était comme suit : Il est intéressant de noter que le processus de **vérification** a lieu en **userland**. Cependant, seules les applications disposant de la permission **`com.apple.private.security.kext-management`** peuvent **demander au kernel de charger une extension** : `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **démarre** le processus de **vérification** pour le chargement d'une extension
- Il communiquera avec **`kextd`** en envoyant via un **Mach service**.
2. **`kextd`** vérifiera plusieurs éléments, comme la **signature**
- Il communiquera avec **`syspolicyd`** pour **vérifier** si l'extension peut être **chargée**.
3. **`syspolicyd`** affichera une **invite** à l'**utilisateur** si l'extension n'a pas été précédemment chargée.
- **`syspolicyd`** rapportera le résultat à **`kextd`**
4. **`kextd`** pourra finalement **dire au kernel de charger** l'extension

Si **`kextd`** n'est pas disponible, **`kextutil`** peut effectuer les mêmes vérifications.

### Énumération & gestion (kexts chargés)

`kextstat` était l'outil historique mais il est **déprécié** dans les récentes versions de macOS. L'interface moderne est **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
L'ancienne syntaxe est toujours disponible à titre de référence :
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
> Even though the kernel extensions are expected to be in `/System/Library/Extensions/`, if you go to this folder you **won't find any binary**. This is because of the **kernelcache** and in order to reverse one `.kext` you need to find a way to obtain it.

La **kernelcache** est une **version précompilée et préliée du kernel XNU**, avec les **drivers** essentiels et les **kernel extensions**. Elle est stockée dans un format **compressé** et est décompressée en mémoire lors du démarrage. La kernelcache permet un **démarrage plus rapide** en fournissant une version prête à l'exécution du kernel et des drivers cruciaux, réduisant le temps et les ressources qui seraient autrement nécessaires pour charger et lier dynamiquement ces composants au démarrage.

Les principaux avantages de la kernelcache sont la **vitesse de chargement** et le fait que tous les modules sont préliés (pas d'impact au moment du chargement). Et une fois que tous les modules ont été préliés — KXLD peut être retiré de la mémoire de sorte que **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.


### Kernelcache local

Sur iOS il se trouve dans **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** ; sur macOS vous pouvez le trouver avec : **`find / -name "kernelcache" 2>/dev/null`** \
Dans mon cas sur macOS je l'ai trouvé ici :

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Le format IMG4 est un format conteneur utilisé par Apple sur ses appareils iOS et macOS pour **stocker et vérifier de manière sécurisée des composants de firmware** (comme la **kernelcache**). Le format IMG4 inclut un en-tête et plusieurs tags qui encapsulent différentes données, y compris la charge utile réelle (par exemple un kernel ou un bootloader), une signature, et un ensemble de propriétés de manifeste. Le format supporte la vérification cryptographique, permettant à l'appareil de confirmer l'authenticité et l'intégrité du composant de firmware avant de l'exécuter.

Il est généralement composé des éléments suivants :

- **Payload (IM4P)** :
- Souvent compressé (LZFSE4, LZSS, …)
- Optionnellement chiffré
- **Manifest (IM4M)** :
- Contient la Signature
- Dictionnaire supplémentaire de clés/valeurs
- **Restore Info (IM4R)** :
- Aussi connu sous le nom d'APNonce
- Empêche la réutilisation de certaines mises à jour
- OPTIONAL: Usually this isn't found

Décompresser la kernelcache :
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
#### Disarm symboles du kernel

**`Disarm`** permet de symbolicate des fonctions du kernelcache en utilisant des matchers. Ces matchers sont juste des règles de motifs simples (lignes de texte) qui indiquent à disarm comment reconnaître & auto-symbolicate les fonctions, les arguments et les panic/log strings à l'intérieur d'un binary.

En gros, vous indiquez la chaîne qu'utilise une fonction et disarm la trouvera et **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Aller dans /tmp/extracted où disarm a extrait les filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
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

# Vous devriez obtenir quelque chose comme:
#   out/Firmware/kernelcache.release.iPhoneXX
#   ou un payload IMG4: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Si vous obtenez un payload IMG4:
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

# Extraire tout
kextex_all kernelcache.release.iphone14.e

# Vérifier l'extension pour les symboles
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
# Créer un bundle de symbolication pour le dernier kernel panic
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
(lldb) bt  # obtenir backtrace dans le contexte du kernel
```

### Attaching LLDB to a specific loaded kext

```bash
# Identifier l'adresse de chargement du kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attacher
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
