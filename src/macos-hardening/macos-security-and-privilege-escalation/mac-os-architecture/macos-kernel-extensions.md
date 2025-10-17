# Extensões de Kernel do macOS & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

Kernel extensions (Kexts) são **packages** com a extensão **`.kext`** que são **carregadas diretamente no espaço do kernel do macOS**, fornecendo funcionalidade adicional ao sistema operacional principal.

### Status de depreciação & DriverKit / System Extensions
A partir do **macOS Catalina (10.15)** a Apple marcou a maioria das KPIs legadas como *deprecated* e introduziu os frameworks **DriverKit & System Extensions** que rodam em **user-space**. A partir do **macOS Big Sur (11)** o sistema operacional irá *recusar carregar* kexts de terceiros que dependam de KPIs obsoletas, a menos que a máquina seja inicializada em modo **Reduced Security**. Em Apple Silicon, habilitar kexts adicionalmente requer que o usuário:

1. Reinicie em **Recovery** → *Startup Security Utility*.
2. Selecione **Reduced Security** e marque **“Allow user management of kernel extensions from identified developers”**.
3. Reinicie e aprove o kext em **System Settings → Privacy & Security**.

Drivers em user-land escritos com DriverKit/System Extensions reduzem dramaticamente a superfície de ataque porque falhas ou corrupção de memória ficam confinadas a um processo sandboxed em vez do espaço do kernel.

> 📝 A partir do macOS Sequoia (15) a Apple removeu vários KPIs legadas de rede e USB inteiramente – a única solução compatível para fornecedores é migrar para System Extensions.

### Requisitos

Obviamente, isso é tão poderoso que é **complicado carregar uma kernel extension**. Estes são os **requisitos** que uma kernel extension deve cumprir para ser carregada:

- Ao **entrar no modo recovery**, as kernel **extensions devem ser permitidas** para serem carregadas:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- A kernel extension deve ser **assinada com um certificado de assinatura de código para kernel**, que só pode ser **concedido pela Apple** — que irá revisar em detalhe a empresa e os motivos pelos quais é necessário.
- A kernel extension também deve ser **notarizada**, a Apple poderá verificá-la quanto a malware.
- Além disso, o usuário **root** é quem pode **carregar a kernel extension** e os arquivos dentro do package devem **pertencer ao root**.
- Durante o processo de upload, o package deve ser preparado em um local protegido e não-root: `/Library/StagedExtensions` (requer a permissão `com.apple.rootless.storage.KernelExtensionManagement`).
- Finalmente, ao tentar carregá-la, o usuário irá [**receber uma solicitação de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se aceita, o computador deve ser **reiniciado** para carregá-la.

### Processo de carregamento

Em Catalina era assim: É interessante notar que o processo de **verificação** ocorre em **userland**. Contudo, apenas aplicações com a permissão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel o carregamento de uma extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **inicia** o processo de **verificação** para carregar uma extension
- Ele irá comunicar-se com **`kextd`** enviando usando um **Mach service**.
2. **`kextd`** verificará várias coisas, como a **assinatura**
- Ele falará com **`syspolicyd`** para **checar** se a extension pode ser **carregada**.
3. **`syspolicyd`** irá **solicitar** a **confirmação do usuário** se a extension não tiver sido carregada previamente.
- **`syspolicyd`** reportará o resultado para **`kextd`**
4. **`kextd`** finalmente poderá **dizer ao kernel para carregar** a extension

Se **`kextd`** não estiver disponível, **`kextutil`** pode realizar as mesmas verificações.

### Enumeração & gerenciamento (kexts carregados)

`kextstat` foi a ferramenta histórica, mas está **deprecated** nas versões mais recentes do macOS. A interface moderna é **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
A sintaxe antiga ainda está disponível para referência:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` também pode ser usado para **dump o conteúdo de uma Kernel Collection (KC)** ou verificar se um kext resolve todas as dependências de símbolos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Mesmo que as kernel extensions sejam esperadas em `/System/Library/Extensions/`, se você for para essa pasta você **não encontrará nenhum binário**. Isso se deve ao **kernelcache** e, para reverter um `.kext`, você precisa encontrar uma maneira de obtê‑lo.

O **kernelcache** é uma **versão pré-compilada e pré-linkada do kernel XNU**, junto com os **drivers** essenciais do dispositivo e **kernel extensions**. Ele é armazenado em um formato **comprimido** e é descomprimido na memória durante o processo de boot. O kernelcache facilita um **tempo de boot mais rápido** ao ter uma versão pronta para execução do kernel e dos drivers cruciais, reduzindo o tempo e os recursos que seriam gastos carregando e linkando dinamicamente esses componentes no boot.

Os principais benefícios do kernelcache são a **velocidade de carregamento** e o fato de que todos os módulos estão pré-linkados (sem impedimento de tempo de carregamento). E, uma vez que todos os módulos foram pré-linkados, o KXLD pode ser removido da memória, de modo que **XNU não pode carregar novos KEXTs.**

> [!TIP]
> A ferramenta [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) decripta os contêineres AEA (Apple Encrypted Archive / AEA asset) da Apple — o formato de contêiner criptografado que a Apple usa para assets OTA e algumas partes de IPSW — e pode produzir o arquivo .dmg/asset subjacente que você pode então extrair com as ferramentas aastuff fornecidas.


### Local Kerlnelcache

No iOS ele está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; no macOS você pode encontrá‑lo com: **`find / -name "kernelcache" 2>/dev/null`** \
No meu caso, no macOS, eu o encontrei em:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Encontre também aqui o [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para **armazenar e verificar com segurança componentes de firmware** (como **kernelcache**). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes pedaços de dados, incluindo o payload real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades de manifest. O formato suporta verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e a integridade do componente de firmware antes de executá‑lo.

Normalmente é composto pelos seguintes componentes:

- **Payload (IM4P)**:
  - Frequentemente comprimido (LZFSE4, LZSS, …)
  - Opcionalmente encriptado
- **Manifest (IM4M)**:
  - Contém Signature
  - Dicionário adicional de Key/Value
- **Restore Info (IM4R)**:
  - Também conhecido como APNonce
  - Previne o replay de algumas atualizações
  - OPTIONAL: Normalmente isto não é encontrado

Decompress the Kernelcache:
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
#### Disarm símbolos do kernel

**`Disarm`** permite symbolicate funções do kernelcache usando matchers. Esses matchers são apenas regras simples de padrão (linhas de texto) que dizem ao disarm como reconhecer & auto-symbolicate funções, argumentos e panic/log strings dentro de um binário.

Basicamente, você indica a string que uma função usa e o disarm a encontrará e **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Vá para /tmp/extracted onde disarm extraiu os filesets
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

# Você deve obter algo como:
#   out/Firmware/kernelcache.release.iPhoneXX
#   ou um IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Se você receber um IMG4 payload:
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

# Extrair tudo
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
# Criar um pacote de simbolicação para o kernel panic mais recente
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

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
