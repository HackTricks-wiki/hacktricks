# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

As extensões de kernel (Kexts) são **pacotes** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidade adicional ao sistema operacional principal.

### Requisitos

Obviamente, isso é tão poderoso que é **complicado carregar uma extensão de kernel**. Estes são os **requisitos** que uma extensão de kernel deve atender para ser carregada:

- Ao **entrar no modo de recuperação**, as **extensões de kernel devem ser permitidas** para serem carregadas:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- A extensão de kernel deve ser **assinada com um certificado de assinatura de código de kernel**, que só pode ser **concedido pela Apple**. Quem irá revisar em detalhes a empresa e os motivos pelos quais é necessário.
- A extensão de kernel também deve ser **notarizada**, a Apple poderá verificá-la em busca de malware.
- Então, o usuário **root** é quem pode **carregar a extensão de kernel** e os arquivos dentro do pacote devem **pertencer ao root**.
- Durante o processo de upload, o pacote deve ser preparado em um **local protegido não-root**: `/Library/StagedExtensions` (requer a concessão `com.apple.rootless.storage.KernelExtensionManagement`).
- Finalmente, ao tentar carregá-la, o usuário [**receberá uma solicitação de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se aceita, o computador deve ser **reiniciado** para carregá-la.

### Processo de Carregamento

Em Catalina era assim: É interessante notar que o processo de **verificação** ocorre no **userland**. No entanto, apenas aplicativos com a concessão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel que carregue uma extensão**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** o processo de **verificação** para carregar uma extensão
- Ele se comunicará com **`kextd`** enviando usando um **serviço Mach**.
2. **`kextd`** verificará várias coisas, como a **assinatura**
- Ele se comunicará com **`syspolicyd`** para **verificar** se a extensão pode ser **carregada**.
3. **`syspolicyd`** **pedirá** ao **usuário** se a extensão não foi carregada anteriormente.
- **`syspolicyd`** relatará o resultado para **`kextd`**
4. **`kextd`** finalmente poderá **dizer ao kernel para carregar** a extensão

Se **`kextd`** não estiver disponível, **`kextutil`** pode realizar as mesmas verificações.

### Enumeração (kexts carregados)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> Mesmo que as extensões do kernel sejam esperadas em `/System/Library/Extensions/`, se você for para esta pasta, **não encontrará nenhum binário**. Isso se deve ao **kernelcache** e, para reverter um `.kext`, você precisa encontrar uma maneira de obtê-lo.

O **kernelcache** é uma **versão pré-compilada e pré-linkada do kernel XNU**, juntamente com **drivers** e **extensões de kernel** essenciais. Ele é armazenado em um formato **compactado** e é descompactado na memória durante o processo de inicialização. O kernelcache facilita um **tempo de inicialização mais rápido** ao ter uma versão pronta para execução do kernel e drivers cruciais disponíveis, reduzindo o tempo e os recursos que seriam gastos carregando e vinculando dinamicamente esses componentes no momento da inicialização.

### Kernelcache Local

No iOS, está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** no macOS você pode encontrá-lo com: **`find / -name "kernelcache" 2>/dev/null`** \
No meu caso, no macOS, eu o encontrei em:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para **armazenar e verificar com segurança** componentes de firmware (como **kernelcache**). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes partes de dados, incluindo a carga útil real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades de manifesto. O formato suporta verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e integridade do componente de firmware antes de executá-lo.

Geralmente, é composto pelos seguintes componentes:

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
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download&#x20;

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
## Depuração

## Referências

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
