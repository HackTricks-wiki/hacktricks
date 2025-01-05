# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Informações Básicas**

**System Integrity Protection (SIP)** no macOS é um mecanismo projetado para impedir que até mesmo os usuários mais privilegiados façam alterações não autorizadas em pastas-chave do sistema. Este recurso desempenha um papel crucial na manutenção da integridade do sistema, restringindo ações como adicionar, modificar ou excluir arquivos em áreas protegidas. As pastas principais protegidas pelo SIP incluem:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

As regras que governam o comportamento do SIP são definidas no arquivo de configuração localizado em **`/System/Library/Sandbox/rootless.conf`**. Dentro deste arquivo, os caminhos que são precedidos por um asterisco (\*) são denotados como exceções às restrições rigorosas do SIP. 

Considere o exemplo abaixo:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Este trecho implica que, embora o SIP geralmente proteja o **`/usr`** diretório, existem subdiretórios específicos (`/usr/libexec/cups`, `/usr/local` e `/usr/share/man`) onde modificações são permitidas, conforme indicado pelo asterisco (\*) que precede seus caminhos.

Para verificar se um diretório ou arquivo está protegido pelo SIP, você pode usar o comando **`ls -lOd`** para verificar a presença da flag **`restricted`** ou **`sunlnk`**. Por exemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Neste caso, a flag **`sunlnk`** significa que o diretório `/usr/libexec/cups` em si **não pode ser deletado**, embora arquivos dentro dele possam ser criados, modificados ou deletados.

Por outro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aqui, a flag **`restricted`** indica que o diretório `/usr/libexec` é protegido pelo SIP. Em um diretório protegido pelo SIP, arquivos não podem ser criados, modificados ou excluídos.

Além disso, se um arquivo contém o atributo **`com.apple.rootless`** como **atributo** estendido, esse arquivo também será **protegido pelo SIP**.

> [!TIP]
> Note que o hook **Sandbox** **`hook_vnode_check_setextattr`** impede qualquer tentativa de modificar o atributo estendido **`com.apple.rootless`.**

**O SIP também limita outras ações de root** como:

- Carregar extensões de kernel não confiáveis
- Obter task-ports para processos assinados pela Apple
- Modificar variáveis NVRAM
- Permitir depuração de kernel

As opções são mantidas na variável nvram como um bitflag (`csr-active-config` em Intel e `lp-sip0` é lido da Device Tree inicializada para ARM). Você pode encontrar as flags no código-fonte do XNU em `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status do SIP

Você pode verificar se o SIP está habilitado em seu sistema com o seguinte comando:
```bash
csrutil status
```
Se você precisar desativar o SIP, deve reiniciar seu computador em modo de recuperação (pressionando Command+R durante a inicialização), em seguida, execute o seguinte comando:
```bash
csrutil disable
```
Se você deseja manter o SIP ativado, mas remover as proteções de depuração, pode fazê-lo com:
```bash
csrutil enable --without debug
```
### Outras Restrições

- **Desabilita o carregamento de extensões de kernel não assinadas** (kexts), garantindo que apenas extensões verificadas interajam com o kernel do sistema.
- **Previne a depuração** de processos do sistema macOS, protegendo componentes centrais do sistema contra acesso e modificação não autorizados.
- **Inibe ferramentas** como dtrace de inspecionar processos do sistema, protegendo ainda mais a integridade da operação do sistema.

[**Saiba mais sobre informações do SIP nesta palestra**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **Direitos Relacionados ao SIP**

- `com.apple.rootless.xpc.bootstrap`: Controlar launchd
- `com.apple.rootless.install[.heritable]`: Acessar o sistema de arquivos
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Gerenciar UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Capacidades de configuração do XPC
- `com.apple.rootless.xpc.effective-root`: Root via launchd XPC
- `com.apple.rootless.restricted-block-devices`: Acesso a dispositivos de bloco brutos
- `com.apple.rootless.internal.installer-equivalent`: Acesso irrestrito ao sistema de arquivos
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Acesso total ao NVRAM
- `com.apple.rootless.storage.label`: Modificar arquivos restritos pelo com.apple.rootless xattr com o rótulo correspondente
- `com.apple.rootless.volume.VM.label`: Manter a troca de VM no volume

## Bypasses do SIP

Contornar o SIP permite que um atacante:

- **Acesse Dados do Usuário**: Leia dados sensíveis do usuário, como e-mails, mensagens e histórico do Safari de todas as contas de usuário.
- **Bypass do TCC**: Manipule diretamente o banco de dados do TCC (Transparência, Consentimento e Controle) para conceder acesso não autorizado à webcam, microfone e outros recursos.
- **Estabeleça Persistência**: Coloque malware em locais protegidos pelo SIP, tornando-o resistente à remoção, mesmo por privilégios de root. Isso também inclui a possibilidade de adulterar a Ferramenta de Remoção de Malware (MRT).
- **Carregue Extensões de Kernel**: Embora existam salvaguardas adicionais, contornar o SIP simplifica o processo de carregamento de extensões de kernel não assinadas.

### Pacotes de Instalador

**Pacotes de instalador assinados com o certificado da Apple** podem contornar suas proteções. Isso significa que mesmo pacotes assinados por desenvolvedores padrão serão bloqueados se tentarem modificar diretórios protegidos pelo SIP.

### Arquivo SIP Inexistente

Uma possível brecha é que se um arquivo for especificado em **`rootless.conf` mas não existir atualmente**, ele pode ser criado. Malware poderia explorar isso para **estabelecer persistência** no sistema. Por exemplo, um programa malicioso poderia criar um arquivo .plist em `/System/Library/LaunchDaemons` se estiver listado em `rootless.conf` mas não presente.

### com.apple.rootless.install.heritable

> [!CAUTION]
> O direito **`com.apple.rootless.install.heritable`** permite contornar o SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Foi descoberto que era possível **trocar o pacote de instalador após o sistema verificar sua assinatura** de código e então, o sistema instalaria o pacote malicioso em vez do original. Como essas ações eram realizadas por **`system_installd`**, isso permitiria contornar o SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Se um pacote fosse instalado a partir de uma imagem montada ou unidade externa, o **instalador** **executaria** o binário daquele **sistema de arquivos** (em vez de um local protegido pelo SIP), fazendo **`system_installd`** executar um binário arbitrário.

#### CVE-2021-30892 - Shrootless

[**Pesquisadores deste post de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descobriram uma vulnerabilidade no mecanismo de Proteção de Integridade do Sistema (SIP) do macOS, chamada de vulnerabilidade 'Shrootless'. Essa vulnerabilidade gira em torno do daemon **`system_installd`**, que possui um direito, **`com.apple.rootless.install.heritable`**, que permite que qualquer um de seus processos filhos contorne as restrições do sistema de arquivos do SIP.

O daemon **`system_installd`** instalará pacotes que foram assinados pela **Apple**.

Os pesquisadores descobriram que durante a instalação de um pacote assinado pela Apple (.pkg), **`system_installd`** **executa** quaisquer scripts **pós-instalação** incluídos no pacote. Esses scripts são executados pelo shell padrão, **`zsh`**, que automaticamente **executa** comandos do arquivo **`/etc/zshenv`**, se existir, mesmo em modo não interativo. Esse comportamento poderia ser explorado por atacantes: criando um arquivo `/etc/zshenv` malicioso e esperando que **`system_installd` invocasse `zsh`**, eles poderiam realizar operações arbitrárias no dispositivo.

Além disso, foi descoberto que **`/etc/zshenv` poderia ser usado como uma técnica de ataque geral**, não apenas para um bypass do SIP. Cada perfil de usuário tem um arquivo `~/.zshenv`, que se comporta da mesma forma que `/etc/zshenv`, mas não requer permissões de root. Este arquivo poderia ser usado como um mecanismo de persistência, sendo acionado toda vez que `zsh` inicia, ou como um mecanismo de elevação de privilégios. Se um usuário administrador elevar para root usando `sudo -s` ou `sudo <comando>`, o arquivo `~/.zshenv` seria acionado, efetivamente elevando para root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Em [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) foi descoberto que o mesmo processo **`system_installd`** ainda poderia ser abusado porque estava colocando o **script pós-instalação dentro de uma pasta nomeada aleatoriamente protegida pelo SIP dentro de `/tmp`**. O fato é que **`/tmp` em si não é protegido pelo SIP**, então era possível **montar** uma **imagem virtual sobre ele**, então o **instalador** colocaria lá o **script pós-instalação**, **desmontaria** a imagem virtual, **recriaria** todas as **pastas** e **adicionaria** o **script de pós-instalação** com o **payload** a ser executado.

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Uma vulnerabilidade foi identificada onde **`fsck_cs`** foi enganado a corromper um arquivo crucial, devido à sua capacidade de seguir **links simbólicos**. Especificamente, atacantes criaram um link de _`/dev/diskX`_ para o arquivo `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Executar **`fsck_cs`** em _`/dev/diskX`_ levou à corrupção de `Info.plist`. A integridade deste arquivo é vital para o SIP (Proteção de Integridade do Sistema) do sistema operacional, que controla o carregamento de extensões de kernel. Uma vez corrompido, a capacidade do SIP de gerenciar exclusões de kernel é comprometida.

Os comandos para explorar essa vulnerabilidade são:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
A exploração dessa vulnerabilidade tem implicações severas. O arquivo `Info.plist`, normalmente responsável por gerenciar permissões para extensões do kernel, torna-se ineficaz. Isso inclui a incapacidade de colocar certas extensões na lista negra, como `AppleHWAccess.kext`. Consequentemente, com o mecanismo de controle do SIP fora de ordem, essa extensão pode ser carregada, concedendo acesso não autorizado de leitura e gravação à RAM do sistema.

#### [Montar sobre pastas protegidas pelo SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Foi possível montar um novo sistema de arquivos sobre **pastas protegidas pelo SIP para contornar a proteção**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

O sistema está configurado para inicializar a partir de uma imagem de disco do instalador incorporada dentro do `Install macOS Sierra.app` para atualizar o SO, utilizando a ferramenta `bless`. O comando utilizado é o seguinte:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
A segurança deste processo pode ser comprometida se um atacante alterar a imagem de atualização (`InstallESD.dmg`) antes da inicialização. A estratégia envolve substituir um carregador dinâmico (dyld) por uma versão maliciosa (`libBaseIA.dylib`). Essa substituição resulta na execução do código do atacante quando o instalador é iniciado.

O código do atacante ganha controle durante o processo de atualização, explorando a confiança do sistema no instalador. O ataque prossegue alterando a imagem `InstallESD.dmg` via method swizzling, visando particularmente o método `extractBootBits`. Isso permite a injeção de código malicioso antes que a imagem do disco seja utilizada.

Além disso, dentro do `InstallESD.dmg`, há um `BaseSystem.dmg`, que serve como o sistema de arquivos raiz do código de atualização. Injetar uma biblioteca dinâmica nisso permite que o código malicioso opere dentro de um processo capaz de alterar arquivos em nível de OS, aumentando significativamente o potencial de comprometimento do sistema.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Nesta palestra do [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), é mostrado como **`systemmigrationd`** (que pode contornar o SIP) executa um **bash** e um **perl** script, que podem ser abusados via variáveis de ambiente **`BASH_ENV`** e **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Como [**detalhado neste post do blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), um script `postinstall` de pacotes `InstallAssistant.pkg` permitia a execução:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
e foi possível criar um symlink em `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` que permitiria a um usuário **remover restrições de qualquer arquivo, contornando a proteção SIP**.

### **com.apple.rootless.install**

> [!CAUTION]
> A permissão **`com.apple.rootless.install`** permite contornar o SIP

A permissão `com.apple.rootless.install` é conhecida por contornar a Proteção de Integridade do Sistema (SIP) no macOS. Isso foi notavelmente mencionado em relação a [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

Neste caso específico, o serviço XPC do sistema localizado em `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possui essa permissão. Isso permite que o processo relacionado contorne as restrições do SIP. Além disso, este serviço apresenta notavelmente um método que permite a movimentação de arquivos sem impor quaisquer medidas de segurança.

## Instantâneas do Sistema Seladas

As Instantâneas do Sistema Seladas são um recurso introduzido pela Apple no **macOS Big Sur (macOS 11)** como parte de seu mecanismo de **Proteção de Integridade do Sistema (SIP)** para fornecer uma camada adicional de segurança e estabilidade do sistema. Elas são essencialmente versões somente leitura do volume do sistema.

Aqui está uma visão mais detalhada:

1. **Sistema Imutável**: As Instantâneas do Sistema Seladas tornam o volume do sistema macOS "imutável", o que significa que não pode ser modificado. Isso impede quaisquer alterações não autorizadas ou acidentais no sistema que poderiam comprometer a segurança ou a estabilidade do sistema.
2. **Atualizações de Software do Sistema**: Quando você instala atualizações ou upgrades do macOS, o macOS cria uma nova instantânea do sistema. O volume de inicialização do macOS então usa **APFS (Apple File System)** para alternar para essa nova instantânea. Todo o processo de aplicação de atualizações se torna mais seguro e confiável, pois o sistema pode sempre reverter para a instantânea anterior se algo der errado durante a atualização.
3. **Separação de Dados**: Em conjunto com o conceito de separação de Dados e Volume do Sistema introduzido no macOS Catalina, o recurso de Instantânea do Sistema Selada garante que todos os seus dados e configurações sejam armazenados em um volume separado "**Data**". Essa separação torna seus dados independentes do sistema, o que simplifica o processo de atualizações do sistema e melhora a segurança do sistema.

Lembre-se de que essas instantâneas são gerenciadas automaticamente pelo macOS e não ocupam espaço adicional no seu disco, graças às capacidades de compartilhamento de espaço do APFS. Também é importante notar que essas instantâneas são diferentes das **instantâneas do Time Machine**, que são backups acessíveis ao usuário de todo o sistema.

### Verificar Instantâneas

O comando **`diskutil apfs list`** lista os **detalhes dos volumes APFS** e seu layout:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

Na saída anterior, é possível ver que **locais acessíveis ao usuário** estão montados em `/System/Volumes/Data`.

Além disso, a **instantânea do volume do sistema macOS** está montada em `/` e está **selada** (assinada criptograficamente pelo OS). Portanto, se o SIP for contornado e modificado, o **OS não inicializará mais**.

Também é possível **verificar se o selo está habilitado** executando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Além disso, o disco de snapshot também é montado como **somente leitura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{{#include ../../../banners/hacktricks-training.md}}
