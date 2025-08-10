# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

As extensões do kernel (Kexts) são **pacotes** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidade adicional ao sistema operacional principal.

### Status de descontinuação & DriverKit / Extensões do Sistema
A partir do **macOS Catalina (10.15)**, a Apple marcou a maioria dos KPIs legados como *obsoletos* e introduziu os frameworks **Extensões do Sistema & DriverKit** que rodam em **espaço do usuário**. A partir do **macOS Big Sur (11)**, o sistema operacional *se recusará a carregar* kexts de terceiros que dependem de KPIs obsoletos, a menos que a máquina seja inicializada no modo **Segurança Reduzida**. No Apple Silicon, habilitar kexts também requer que o usuário:

1. Reinicie em **Recuperação** → *Utilitário de Segurança de Inicialização*.
2. Selecione **Segurança Reduzida** e marque **“Permitir gerenciamento de extensões do kernel por desenvolvedores identificados”**.
3. Reinicie e aprove o kext em **Configurações do Sistema → Privacidade & Segurança**.

Drivers em espaço do usuário escritos com DriverKit/Extensões do Sistema **reduzem drasticamente a superfície de ataque** porque falhas ou corrupção de memória são confinadas a um processo isolado em vez do espaço do kernel.

> 📝 A partir do macOS Sequoia (15), a Apple removeu completamente vários KPIs legados de rede e USB – a única solução compatível para os fornecedores é migrar para Extensões do Sistema.

### Requisitos

Obviamente, isso é tão poderoso que é **complicado carregar uma extensão do kernel**. Estes são os **requisitos** que uma extensão do kernel deve atender para ser carregada:

- Ao **entrar no modo de recuperação**, as **extensões do kernel devem ser permitidas** para serem carregadas:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- A extensão do kernel deve ser **assinada com um certificado de assinatura de código do kernel**, que só pode ser **concedido pela Apple**. Quem irá revisar em detalhes a empresa e os motivos pelos quais é necessário.
- A extensão do kernel também deve ser **notarizada**, a Apple poderá verificá-la em busca de malware.
- Então, o usuário **root** é quem pode **carregar a extensão do kernel** e os arquivos dentro do pacote devem **pertencer ao root**.
- Durante o processo de upload, o pacote deve ser preparado em um **local protegido não-root**: `/Library/StagedExtensions` (requer a concessão `com.apple.rootless.storage.KernelExtensionManagement`).
- Finalmente, ao tentar carregá-la, o usuário [**receberá um pedido de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se aceito, o computador deve ser **reiniciado** para carregá-la.

### Processo de Carregamento

Em Catalina era assim: É interessante notar que o processo de **verificação** ocorre em **espaço do usuário**. No entanto, apenas aplicativos com a concessão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel que carregue uma extensão**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. O cli **`kextutil`** **inicia** o processo de **verificação** para carregar uma extensão
- Ele se comunicará com **`kextd`** enviando usando um **serviço Mach**.
2. **`kextd`** verificará várias coisas, como a **assinatura**
- Ele se comunicará com **`syspolicyd`** para **verificar** se a extensão pode ser **carregada**.
3. **`syspolicyd`** **pedirá** ao **usuário** se a extensão não foi carregada anteriormente.
- **`syspolicyd`** relatará o resultado para **`kextd`**
4. **`kextd`** finalmente poderá **dizer ao kernel para carregar** a extensão

Se **`kextd`** não estiver disponível, **`kextutil`** pode realizar as mesmas verificações.

### Enumeração & gerenciamento (kexts carregados)

`kextstat` era a ferramenta histórica, mas está **obsoleta** nas versões recentes do macOS. A interface moderna é **`kmutil`**:
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
`kmutil inspect` também pode ser utilizado para **extrair o conteúdo de uma Kernel Collection (KC)** ou verificar se um kext resolve todas as dependências de símbolo:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Mesmo que as extensões do kernel sejam esperadas em `/System/Library/Extensions/`, se você for para esta pasta, **não encontrará nenhum binário**. Isso se deve ao **kernelcache** e, para reverter um `.kext`, você precisa encontrar uma maneira de obtê-lo.

O **kernelcache** é uma **versão pré-compilada e pré-linkada do kernel XNU**, juntamente com **drivers** e **extensões de kernel** essenciais. Ele é armazenado em um formato **compactado** e é descompactado na memória durante o processo de inicialização. O kernelcache facilita um **tempo de inicialização mais rápido** ao ter uma versão pronta para execução do kernel e drivers cruciais disponíveis, reduzindo o tempo e os recursos que seriam gastos carregando e vinculando dinamicamente esses componentes no momento da inicialização.

### Kernelcache Local

No iOS, ele está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** no macOS você pode encontrá-lo com: **`find / -name "kernelcache" 2>/dev/null`** \
No meu caso, no macOS, eu o encontrei em:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para **armazenar e verificar com segurança** componentes de firmware (como **kernelcache**). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes partes de dados, incluindo a carga útil real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades de manifesto. O formato suporta verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e integridade do componente de firmware antes de executá-lo.

Ele é geralmente composto pelos seguintes componentes:

- **Carga útil (IM4P)**:
- Frequentemente compactada (LZFSE4, LZSS, …)
- Opcionalmente criptografada
- **Manifesto (IM4M)**:
- Contém Assinatura
- Dicionário adicional de Chave/Valor
- **Informações de Restauração (IM4R)**:
- Também conhecido como APNonce
- Impede a repetição de algumas atualizações
- OPCIONAL: Geralmente isso não é encontrado

Descompacte o Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

No [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) é possível encontrar todos os kits de depuração do kernel. Você pode baixá-lo, montá-lo, abri-lo com a ferramenta [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), acessar a pasta **`.kext`** e **extrair**.

Verifique os símbolos com:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Às vezes, a Apple libera **kernelcache** com **símbolos**. Você pode baixar alguns firmwares com símbolos seguindo os links nessas páginas. Os firmwares conterão o **kernelcache** entre outros arquivos.

Para **extrair** os arquivos, comece mudando a extensão de `.ipsw` para `.zip` e **descompacte**.

Após extrair o firmware, você obterá um arquivo como: **`kernelcache.release.iphone14`**. Está no formato **IMG4**, você pode extrair as informações interessantes com:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecionando kernelcache

Verifique se o kernelcache possui símbolos com
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Com isso, agora podemos **extrair todas as extensões** ou a **que você está interessado:**
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
## Vulnerabilidades recentes & técnicas de exploração

| Ano | CVE | Resumo |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Falha lógica em **`storagekitd`** permitiu que um atacante *root* registrasse um pacote de sistema de arquivos malicioso que, em última análise, carregou um **kext não assinado**, **contornando a Proteção de Integridade do Sistema (SIP)** e permitindo rootkits persistentes. Corrigido no macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | O daemon de instalação com a autorização `com.apple.rootless.install` poderia ser abusado para executar scripts pós-instalação arbitrários, desativar o SIP e carregar kexts arbitrários.  |

**Principais aprendizados para red-teamers**

1. **Procure por daemons autorizados (`codesign -dvv /path/bin | grep entitlements`) que interagem com Disk Arbitration, Installer ou Kext Management.**
2. **O abuso de contornos do SIP quase sempre concede a capacidade de carregar um kext → execução de código no kernel**.

**Dicas defensivas**

*Mantenha o SIP habilitado*, monitore invocações de `kmutil load`/`kmutil create -n aux` provenientes de binários não-Apple e alerta sobre qualquer gravação em `/Library/Extensions`. Eventos de Segurança de Endpoint `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` fornecem visibilidade quase em tempo real.

## Depuração do kernel macOS & kexts

O fluxo de trabalho recomendado pela Apple é construir um **Kernel Debug Kit (KDK)** que corresponda à versão em execução e, em seguida, anexar **LLDB** por meio de uma sessão de rede **KDP (Kernel Debugging Protocol)**.

### Depuração local de um pânico em uma única execução
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Depuração remota ao vivo de outro Mac

1. Baixe + instale a versão exata do **KDK** para a máquina alvo.
2. Conecte o Mac alvo e o Mac host com um cabo **USB-C ou Thunderbolt**.
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
### Anexando LLDB a um kext carregado específico
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP expõe apenas uma interface **somente leitura**. Para instrumentação dinâmica, você precisará modificar o binário em disco, aproveitar o **hooking de função do kernel** (por exemplo, `mach_override`) ou migrar o driver para um **hipervisor** para leitura/gravação completa.

## Referências

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analisando a CVE-2024-44243 bypass do SIP*

{{#include ../../../banners/hacktricks-training.md}}
