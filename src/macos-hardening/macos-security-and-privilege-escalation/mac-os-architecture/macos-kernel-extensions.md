# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Kernel extensions (Kexts) são **packages** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidades adicionais ao sistema operacional principal.

### Status de depreciação & DriverKit / System Extensions
A partir do **macOS Catalina (10.15)**, a Apple marcou a maioria das KPIs legadas como *deprecated* e introduziu os frameworks **System Extensions & DriverKit**, que são executados no **user-space**. A partir do **macOS Big Sur (11)**, o sistema operacional irá *recusar-se a carregar* kexts de terceiros que dependam de KPIs deprecated, a menos que a máquina seja inicializada no modo **Reduced Security**. No Apple Silicon, habilitar kexts também exige que o usuário:

1. Reinicie no **Recovery** → *Startup Security Utility*.
2. Selecione **Reduced Security** e marque **“Allow user management of kernel extensions from identified developers”**.
3. Reinicie e aprove a kext em **System Settings → Privacy & Security**.

Drivers de user-land escritos com DriverKit/System Extensions **reduzem drasticamente a attack surface**, pois crashes ou corrupção de memória ficam confinados a um processo em sandbox, em vez do espaço do kernel.<sup>[[1]](#references)</sup>

> 📝 A partir do macOS Sequoia (15), a Apple removeu completamente várias KPIs legadas de networking e USB – a única solução compatível com versões futuras para vendors é migrar para System Extensions.

### Requisitos

Obviamente, isso é tão poderoso que **carregar uma kernel extension é complicado**. Estes são os **requisitos** que uma kernel extension deve cumprir para ser carregada:

- Ao **entrar no recovery mode**, as kernel **extensions devem ter permissão para ser carregadas**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- A kernel extension deve ser **assinada com um certificado de kernel code signing**, que só pode ser **concedido pela Apple**, que analisará detalhadamente a empresa e os motivos pelos quais ele é necessário.
- A kernel extension também deve ser **notarized**; a Apple poderá verificá-la quanto à presença de malware.
- Em seguida, o usuário **root** é quem pode **carregar a kernel extension**, e os arquivos dentro do package devem **pertencer ao root**.
- Durante o processo de upload, o package deve ser preparado em uma **protected non-root location**: `/Library/StagedExtensions` (requer o grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Por fim, ao tentar carregá-lo, o usuário [**receberá uma solicitação de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se aceitar, o computador deverá ser **reiniciado** para carregá-lo.

### Processo de carregamento

No Catalina, era assim: é interessante observar que o processo de **verification** ocorre em **userland**. No entanto, apenas applications com o grant **`com.apple.private.security.kext-management`** podem **solicitar ao kernel o carregamento de uma extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** o processo de **verification** para carregar uma extension
- Ele falará com o **`kextd`** enviando dados por meio de um **Mach service**.
2. O **`kextd`** verificará várias coisas, como a **signature**
- Ele falará com o **`syspolicyd`** para **verificar** se a extension pode ser **carregada**.
3. O **`syspolicyd`** irá **solicitar** uma ação ao **usuário** se a extension não tiver sido carregada anteriormente.
- O **`syspolicyd`** informará o resultado ao **`kextd`**
4. O **`kextd`** finalmente poderá **informar ao kernel para carregar** a extension

Se o **`kextd`** não estiver disponível, o **`kextutil`** poderá executar as mesmas verificações.

### Enumeração e gerenciamento (kexts carregadas)

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
`kmutil inspect` também pode ser usado para **despejar o conteúdo de uma Kernel Collection (KC)** ou verificar se uma kext resolve todas as dependências de símbolos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Mesmo que seja esperado que as kernel extensions estejam em `/System/Library/Extensions/`, se você acessar essa pasta, **não encontrará nenhum binário**. Isso acontece por causa do **kernelcache** e, para fazer reverse engineering de uma `.kext`, é necessário encontrar uma forma de obtê-la.

O **kernelcache** é uma **versão pré-compilada e pré-vinculada do kernel XNU**, juntamente com **drivers** de dispositivos essenciais e **kernel extensions**. Ele é armazenado em um formato **comprimido** e descomprimido na memória durante o processo de inicialização. O kernelcache permite um **tempo de boot mais rápido**, disponibilizando uma versão pronta para execução do kernel e dos drivers essenciais, reduzindo o tempo e os recursos que seriam gastos carregando e vinculando dinamicamente esses componentes durante o boot.

Os principais benefícios do kernelcache são a **velocidade de carregamento** e o fato de que todos os módulos são prelinked (sem impedimento no tempo de carregamento). Além disso, depois que todos os módulos são prelinked, o KXLD pode ser removido da memória, de modo que o **XNU não pode carregar novas KEXTs.**

> [!TIP]
> A ferramenta [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) descriptografa containers AEA (Apple Encrypted Archive / AEA asset) da Apple — o formato de container criptografado usado pela Apple para assets OTA e algumas partes de IPSW — e pode produzir o arquivo .dmg/asset subjacente, que você pode extrair com as ferramentas aastuff fornecidas.


### Kernelcache local

No iOS, ele está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; no macOS, você pode encontrá-lo com: **`find / -name "kernelcache" 2>/dev/null`** \
No meu caso, no macOS, encontrei-o em:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Encontre também aqui o [**kernelcache da versão 14 com symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

O formato de arquivo IMG4 é um formato de container usado pela Apple em seus dispositivos iOS e macOS para **armazenar e verificar com segurança** componentes de **firmware** (como o **kernelcache**). O formato IMG4 inclui um header e várias tags que encapsulam diferentes partes dos dados, incluindo o payload real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades de manifesto. O formato oferece suporte à verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e a integridade do componente de firmware antes de executá-lo.

Geralmente, ele é composto pelos seguintes componentes:

- **Payload (IM4P)**:
- Frequentemente comprimido (LZFSE4, LZSS, …)
- Opcionalmente criptografado
- **Manifest (IM4M)**:
- Contém a assinatura
- Dicionário adicional de chave/valor
- **Restore Info (IM4R)**:
- Também conhecido como APNonce
- Impede o replay de algumas atualizações
- OPTIONAL: Geralmente, isso não é encontrado

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
#### Símbolos do kernel com Disarm

**`Disarm`** permite simbolizar funções do kernelcache usando matchers. Esses matchers são apenas regras de padrão simples (linhas de texto) que informam ao disarm como reconhecer e simbolizar automaticamente funções, argumentos e strings de panic/log dentro de um binário.

Basicamente, você indica a string usada por uma função, e o disarm a encontrará e **a simbolizará**.

Você pode encontrar alguns `xnu.matchers` em [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), na seção **`Matchers`**. Você também pode criar seus próprios matchers.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Download

Um **IPSW (iPhone/iPad Software)** é o formato de pacote de firmware da Apple usado para restaurações de dispositivos, atualizações e pacotes completos de firmware. Entre outras coisas, ele contém o **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Em [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases), é possível encontrar todos os kits de depuração do kernel. Você pode baixá-lo, montá-lo, abri-lo com a ferramenta [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), acessar a pasta **`.kext`** e **extraí-la**.

Verifique se há símbolos com:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Às vezes, a Apple disponibiliza **kernelcache** com **symbols**. Você pode baixar alguns firmwares com symbols seguindo os links nessas páginas. Os firmwares conterão o **kernelcache**, entre outros arquivos.

Para **extract** o kernel cache, você pode fazer:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Outra opção para **extrair** os arquivos é começar alterando a extensão de `.ipsw` para `.zip` e **descompactá-lo**.

Após extrair o firmware, você obterá um arquivo como: **`kernelcache.release.iphone14`**. Ele está no formato **IMG4**; você pode extrair as informações interessantes com:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecionando o kernelcache

Verifique se o kernelcache possui símbolos com
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Com isso, agora podemos **extrair todas as extensões** ou **aquela na qual você está interessado:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Vulnerabilidades recentes & técnicas de exploitation

| Ano | CVE | Resumo |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Falha lógica no **`storagekitd`** permitia que um atacante *root* registrasse um bundle de sistema de arquivos malicioso que, por fim, carregava um **kext não assinado**, **bypassando o System Integrity Protection (SIP)** e permitindo rootkits persistentes. Corrigido no macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Um daemon de instalação com o entitlement `com.apple.rootless.install` podia ser abusado para executar scripts arbitrários de pós-instalação, desabilitar o SIP e carregar kexts arbitrários. <sup>[[3]](#references)</sup> |

**Principais conclusões para red-teamers**

1. **Procure daemons com entitlements (`codesign -dvv /path/bin | grep entitlements`) que interajam com Disk Arbitration, Installer ou Kext Management.**
2. **Abusar de SIP bypasses quase sempre concede a capacidade de carregar um kext → execução de código no kernel**.

**Dicas defensivas**

*Mantenha o SIP habilitado*, monitore invocações de `kmutil load`/`kmutil create -n aux` originadas de binários que não sejam da Apple e gere alertas para qualquer gravação em `/Library/Extensions`. Os eventos do Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` oferecem visibilidade quase em tempo real.

## Debugging do kernel e dos kexts do macOS

O workflow recomendado pela Apple consiste em compilar um **Kernel Debug Kit (KDK)** compatível com a build em execução e, em seguida, anexar o **LLDB** por meio de uma sessão de rede **KDP (Kernel Debugging Protocol)**.

### Debug local de uma única execução para um panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Depuração remota em tempo real a partir de outro Mac

1. Baixe e instale a versão exata do **KDK** para a máquina alvo.
2. Conecte o Mac alvo e o Mac host com um **cabo USB-C ou Thunderbolt**.
3. No **alvo**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. No **host**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Anexando o LLDB a uma kext carregada específica
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️ O KDP expõe apenas uma interface **somente leitura**. Para instrumentação dinâmica, será necessário aplicar um patch no binário em disco, utilizar **kernel function hooking** (por exemplo, `mach_override`) ou migrar o driver para um **hypervisor** para obter acesso completo de leitura/escrita.

## Referências

- [1] [Segurança do DriverKit para macOS - Guia de Segurança das Plataformas Apple](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analisando a CVE-2024-44243, um bypass do System Integrity Protection do macOS por meio de extensões do kernel - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft encontra uma nova vulnerabilidade do macOS, Shrootless, que poderia realizar bypass do System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
