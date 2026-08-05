# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Kernel extensions (Kexts) são **packages** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidades adicionais ao sistema operacional principal.

### Status de descontinuação & DriverKit / System Extensions
A partir do **macOS Catalina (10.15)**, a Apple marcou a maioria dos KPIs legados como *deprecated* e introduziu os frameworks **System Extensions & DriverKit**, que executam em **user-space**. A partir do **macOS Big Sur (11)**, o sistema operacional irá *recusar-se a carregar* kexts de terceiros que dependam de KPIs deprecated, a menos que a máquina seja inicializada no modo **Reduced Security**. No Apple Silicon, habilitar kexts também exige que o usuário:

1. Reinicie no **Recovery** → *Startup Security Utility*.
2. Selecione **Reduced Security** e marque **“Allow user management of kernel extensions from identified developers”**.
3. Reinicie e aprove a kext em **System Settings → Privacy & Security**.

Drivers em user-land escritos com DriverKit/System Extensions **reduzem significativamente a superfície de ataque**, pois crashes ou corrupção de memória ficam confinados a um processo em sandbox, em vez do espaço do kernel.<sup>[1]</sup>

> 📝 A partir do macOS Sequoia (15), a Apple removeu completamente vários KPIs legados de networking e USB – a única solução compatível com versões futuras para vendors é migrar para System Extensions.

### Requisitos

Obviamente, isso é tão poderoso que **carregar uma kernel extension é complicado**. Estes são os **requisitos** que uma kernel extension deve atender para ser carregada:

- Ao **entrar no modo de recuperação**, as kernel **extensions devem ter permissão** para serem carregadas:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- A kernel extension deve ser **assinada com um certificado de assinatura de código do kernel**, que só pode ser **concedido pela Apple**. A Apple analisará detalhadamente a empresa e os motivos pelos quais ele é necessário.
- A kernel extension também deve ser **notarized**; a Apple poderá verificá-la em busca de malware.
- Em seguida, o usuário **root** é quem pode **carregar a kernel extension**, e os arquivos dentro do package devem **pertencer a root**.
- Durante o processo de upload, o package deve ser preparado em uma **localização protegida que não seja root**: `/Library/StagedExtensions` (requer o grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Finalmente, ao tentar carregá-lo, o usuário [**receberá uma solicitação de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se aceitar, o computador deverá ser **reiniciado** para carregá-lo.

### Processo de carregamento

No Catalina, era assim: é interessante observar que o processo de **verificação** ocorre em userland. No entanto, somente aplicações com o grant **`com.apple.private.security.kext-management`** podem **solicitar ao kernel o carregamento de uma extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** o processo de **verificação** para carregar uma extension
- Ele se comunicará com o **`kextd`** enviando dados por meio de um **Mach service**.
2. O **`kextd`** verificará várias coisas, como a **assinatura**
- Ele se comunicará com o **`syspolicyd`** para **verificar** se a extension pode ser **carregada**.
3. O **`syspolicyd`** solicitará a ação do **usuário** se a extension ainda não tiver sido carregada.
- O **`syspolicyd`** informará o resultado ao **`kextd`**
4. O **`kextd`** finalmente poderá **informar ao kernel para carregar** a extension

Se o **`kextd`** não estiver disponível, o **`kextutil`** poderá realizar as mesmas verificações.

### Enumeração & gerenciamento (kexts carregadas)

`kextstat` era a ferramenta histórica, mas está **deprecated** nas versões recentes do macOS. A interface moderna é o **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
A sintaxe mais antiga ainda está disponível para referência:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` também pode ser utilizado para **fazer dump do conteúdo de uma Kernel Collection (KC)** ou verificar se uma kext resolve todas as dependências de símbolos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Embora seja esperado que as extensões do kernel estejam em `/System/Library/Extensions/`, se você acessar essa pasta, **não encontrará nenhum binário**. Isso acontece por causa do **kernelcache** e, para fazer reverse engineering de um `.kext`, você precisa encontrar uma forma de obtê-lo.

O **kernelcache** é uma **versão pré-compilada e pré-vinculada do kernel XNU**, juntamente com **drivers** de dispositivos essenciais e **extensões do kernel**. Ele é armazenado em um formato **comprimido** e descomprimido na memória durante o processo de inicialização. O kernelcache proporciona um **tempo de boot mais rápido**, disponibilizando uma versão do kernel e dos drivers essenciais pronta para execução, reduzindo o tempo e os recursos que seriam gastos carregando e vinculando dinamicamente esses componentes durante o boot.

Os principais benefícios do kernelcache são a **velocidade de carregamento** e o fato de todos os módulos serem pré-vinculados (sem impedimento durante o carregamento). Além disso, depois que todos os módulos são pré-vinculados, o KXLD pode ser removido da memória, de modo que o **XNU não possa carregar novos KEXTs.**

> [!TIP]
> A ferramenta [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) descriptografa contêineres AEA (Apple Encrypted Archive / AEA asset) da Apple — o formato de contêiner criptografado que a Apple usa para assets OTA e algumas partes de IPSW — e pode produzir o arquivo .dmg/asset subjacente, que você pode extrair com as ferramentas aastuff fornecidas.


### Kernelcache local

No iOS, ele está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. No macOS, você pode encontrá-lo com: **`find / -name "kernelcache" 2>/dev/null`** \
No meu caso, no macOS, eu o encontrei em:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Encontre também aqui o [**kernelcache da versão 14 com símbolos**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para **armazenar e verificar com segurança componentes de firmware** (como o **kernelcache**). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes partes dos dados, incluindo o payload propriamente dito (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades do manifesto. O formato oferece suporte à verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e a integridade do componente de firmware antes de executá-lo.

Ele geralmente é composto pelos seguintes componentes:

- **Payload (IM4P)**:
- Frequentemente comprimido (LZFSE4, LZSS, …)
- Opcionalmente criptografado
- **Manifest (IM4M)**:
- Contém a assinatura
- Dicionário adicional de chave/valor
- **Restore Info (IM4R)**:
- Também conhecido como APNonce
- Impede o replay de algumas atualizações
- OPCIONAL: geralmente não é encontrado

Descomprima o Kernelcache:
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
#### Desarmar símbolos para o kernel

**`Disarm`** permite simbolizar funções do kernelcache usando matchers. Esses matchers são apenas regras de padrão simples (linhas de texto) que informam ao disarm como reconhecer e simbolizar automaticamente funções, argumentos e strings de panic/log dentro de um binário.

Basicamente, você indica a string usada por uma função, e o disarm a encontrará e **a simbolizará**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Go to /tmp/extracted where disarm extracted the filesets
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
# Instalar a ferramenta ipsw
brew install blacktop/tap/ipsw

# Extrair apenas o kernelcache do IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Você deverá obter algo como:
#   out/Firmware/kernelcache.release.iPhoneXX
#   ou um payload IMG4: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Se você obtiver um payload IMG4:
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
# Listar todas as extensões
kextex -l kernelcache.release.iphone14.e
## Extrair com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extrair todas
kextex_all kernelcache.release.iphone14.e

# Verificar a extensão em busca de símbolos
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
# Crie um bundle de symbolication para o panic mais recente
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
(lldb) bt  # get backtrace in kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# Identificar o endereço de carregamento do kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Anexar
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
