# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) are **packages** with a **`.kext`** extension that are **loaded directly into the macOS kernel space**, providing additional functionality to the main operating system.

### Deprecation status & DriverKit / System Extensions
Starting with **macOS Catalina (10.15)** Apple marked most legacy KPIs as *deprecated* and introduced the **System Extensions & DriverKit** frameworks that run in **user-space**. From **macOS Big Sur (11)** the operating system will *refuse to load* third-party kexts that rely on deprecated KPIs unless the machine is booted in **Reduced Security** mode. On Apple Silicon, enabling kexts additionally requires the user to:

1. Reboot into **Recovery** → *Startup Security Utility*.
2. Select **Reduced Security** and tick **“Allow user management of kernel extensions from identified developers”**.
3. Reboot and approve the kext from **System Settings → Privacy & Security**.

User-land drivers written with DriverKit/System Extensions dramatically **reduce attack surface** because crashes or memory corruption are confined to a sandboxed process rather than kernel space.

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### Requirements

Obviously, this is so powerful that it is **complicated to load a kernel extension**. These are the **requirements** that a kernel extension must meet to be loaded:

- When **entering recovery mode**, kernel **extensions must be allowed** to be loaded:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- The kernel extension must be **signed with a kernel code signing certificate**, which can only be **granted by Apple**. Who will review in detail the company and the reasons why it is needed.
- The kernel extension must also be **notarized**, Apple will be able to check it for malware.
- Then, the **root** user is the one who can **load the kernel extension** and the files inside the package must **belong to root**.
- During the upload process, the package must be prepared in a **protected non-root location**: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Finally, when attempting to load it, the user will [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) and, if accepted, the computer must be **restarted** to load it.

### Loading process

In Catalina it was like this: It is interesting to note that the **verification** process occurs in **userland**. However, only applications with the **`com.apple.private.security.kext-management`** grant can **request the kernel to load an extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **starts** the **verification** process for loading an extension
- It will talk to **`kextd`** by sending using a **Mach service**.
2. **`kextd`** will check several things, such as the **signature**
- It will talk to **`syspolicyd`** to **check** if the extension can be **loaded**.
3. **`syspolicyd`** will **prompt** the **user** if the extension has not been previously loaded.
- **`syspolicyd`** will report the result to **`kextd`**
4. **`kextd`** will finally be able to **tell the kernel to load** the extension

If **`kextd`** is not available, **`kextutil`** can perform the same checks.

### Enumeration & management (loaded kexts)

`kextstat` was the historical tool but it is **deprecated** in recent macOS releases. The modern interface is **`kmutil`**:
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
`kmutil inspect` peut également être utilisé pour **dump le contenu d'une Kernel Collection (KC)** ou vérifier qu'un kext résout toutes les dépendances de symboles :
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Même si les kernel extensions sont censées se trouver dans `/System/Library/Extensions/`, si vous ouvrez ce dossier vous **n'y trouverez aucun binaire**. C'est à cause du **kernelcache** et pour renverser un `.kext` vous devez trouver un moyen de l'obtenir.

Le **kernelcache** est une **version pré-compilée et pré-liée du noyau XNU**, avec les **drivers** essentiels et les **kernel extensions**. Il est stocké dans un format **compressé** et est décompressé en mémoire pendant le processus de démarrage. Le kernelcache permet un **démarrage plus rapide** en disposant d'une version prête à l'exécution du noyau et des drivers cruciaux, réduisant le temps et les ressources qui seraient autrement nécessaires pour charger et lier dynamiquement ces composants au démarrage.

Les principaux avantages du kernelcache sont la **vitesse de chargement** et le fait que tous les modules sont préliés (pas d'impédiment au temps de chargement). Et une fois tous les modules préliés, KXLD peut être retiré de la mémoire de sorte que **XNU ne peut pas charger de nouveaux KEXTs.**

> [!TIP]
> L'outil https://github.com/dhinakg/aeota décrypte les conteneurs AEA (Apple Encrypted Archive / AEA asset) d'Apple — le format de conteneur chiffré qu'Apple utilise pour les assets OTA et certaines pièces d'IPSW — et peut produire l'archive sous-jacente .dmg/asset que vous pouvez ensuite extraire avec les outils aastuff fournis.


### Kernelcache local

Sur iOS il est situé dans **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** ; sur macOS vous pouvez le trouver avec : **`find / -name "kernelcache" 2>/dev/null`** \
Dans mon cas sur macOS je l'ai trouvé dans :

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Le format de fichier IMG4 est un format conteneur utilisé par Apple sur ses appareils iOS et macOS pour **stocker et vérifier de manière sécurisée des composants de firmware** (comme le **kernelcache**). Le format IMG4 inclut un en-tête et plusieurs tags qui encapsulent différentes pièces de données incluant la payload réelle (comme un kernel ou un bootloader), une signature, et un ensemble de propriétés de manifeste. Le format supporte la vérification cryptographique, permettant à l'appareil de confirmer l'authenticité et l'intégrité du composant firmware avant de l'exécuter.

Il est généralement composé des composants suivants :

- **Payload (IM4P)**:
- Souvent compressé (LZFSE4, LZSS, …)
- Optionnellement chiffré
- **Manifest (IM4M)**:
- Contient la Signature
- Dictionnaire additionnel Key/Value
- **Restore Info (IM4R)**:
- Aussi connu sous le nom APNonce
- Empêche la réexécution (replay) de certaines mises à jour
- OPTIONAL : On le trouve généralement pas

Décompresser le Kernelcache:
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
#### Disarm : symboles pour le kernel

**`Disarm`** permet de symbolicate des fonctions du kernelcache en utilisant des matchers. Ces matchers sont juste de simples règles de pattern (lignes de texte) qui indiquent à disarm comment reconnaître & auto-symbolicate les fonctions, les arguments et les chaînes panic/log à l'intérieur d'un binaire.

Concrètement, vous indiquez la chaîne qu’utilise une fonction et disarm la trouvera et la **symbolicate**.
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

# Extraire uniquement le kernelcache de l'IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Vous devriez obtenir quelque chose comme :
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Si vous obtenez un IMG4 payload :
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
(lldb) bt  # obtenir la pile d'appels dans le contexte du noyau
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
