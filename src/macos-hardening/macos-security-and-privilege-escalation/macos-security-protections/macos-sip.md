# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Informações básicas**

A **System Integrity Protection (SIP)** no macOS é um mecanismo criado para impedir que até mesmo os usuários mais privilegiados façam alterações não autorizadas em pastas importantes do sistema. Esse recurso desempenha um papel fundamental na manutenção da integridade do sistema, restringindo ações como adicionar, modificar ou excluir arquivos em áreas protegidas. As principais pastas protegidas pelo SIP incluem:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

As regras que controlam o comportamento do SIP são definidas no arquivo de configuração localizado em **`/System/Library/Sandbox/rootless.conf`**. Nesse arquivo, os caminhos precedidos por um asterisco (\*) são identificados como exceções às rigorosas restrições do SIP.

Considere o exemplo abaixo:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Este trecho indica que, embora o SIP geralmente proteja o diretório **`/usr`**, existem subdiretórios específicos (`/usr/libexec/cups`, `/usr/local` e `/usr/share/man`) nos quais modificações são permitidas, conforme indicado pelo asterisco (\*) antes de seus caminhos.

Para verificar se um diretório ou arquivo está protegido pelo SIP, você pode usar o comando **`ls -lOd`** para verificar a presença da flag **`restricted`** ou **`sunlnk`**. Por exemplo:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Nesse caso, a flag **`sunlnk`** indica que o diretório `/usr/libexec/cups` em si **não pode ser excluído**, embora arquivos dentro dele possam ser criados, modificados ou excluídos.

Por outro lado:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Aqui, a flag **`restricted`** indica que o diretório `/usr/libexec` é protegido pelo SIP. Em um diretório protegido pelo SIP, não é possível criar, modificar ou excluir arquivos.

Além disso, se um arquivo contiver o **atributo** estendido **`com.apple.rootless`**, esse arquivo também será **protegido pelo SIP**.

> [!TIP]
> Observe que o hook do **Sandbox** **`hook_vnode_check_setextattr`** impede qualquer tentativa de modificar o atributo estendido **`com.apple.rootless`.**

O **SIP também limita outras ações de root**, como:

- Carregar extensões de kernel não confiáveis
- Obter task-ports de processos assinados pela Apple
- Modificar variáveis NVRAM
- Permitir debugging do kernel

As opções são mantidas na variável nvram como uma bitflag (`csr-active-config` no Intel e `lp-sip0` é lida da Device Tree inicializada no ARM). Você pode encontrar as flags no código-fonte do XNU em `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status do SIP

Você pode verificar se o SIP está habilitado no seu sistema com o seguinte comando:
```bash
csrutil status
```
Se precisar desabilitar o SIP, reinicie o computador no modo de recuperação (pressionando Command+R durante a inicialização) e execute o seguinte comando:
```bash
csrutil disable
```
Se quiser manter o SIP ativado, mas remover as proteções de debugging, você pode fazer isso com:
```bash
csrutil enable --without debug
```
### Outras restrições

- **Impede o carregamento de extensões de kernel não assinadas** (kexts), garantindo que apenas extensões verificadas interajam com o kernel do sistema.
- **Impede a depuração** de processos do sistema macOS, protegendo os componentes essenciais do sistema contra acesso e modificação não autorizados.
- **Inibe ferramentas** como dtrace de inspecionar processos do sistema, protegendo ainda mais a integridade da operação do sistema.

[**Saiba mais sobre as informações do SIP nesta palestra**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **Entitlements relacionados ao SIP**

- `com.apple.rootless.xpc.bootstrap`: Controlar o launchd
- `com.apple.rootless.install[.heritable]`: Acessar o sistema de arquivos
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Gerenciar UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Capacidades de configuração do XPC
- `com.apple.rootless.xpc.effective-root`: Root via XPC do launchd
- `com.apple.rootless.restricted-block-devices`: Acesso a dispositivos de bloco brutos
- `com.apple.rootless.internal.installer-equivalent`: Acesso irrestrito ao sistema de arquivos
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Acesso total à NVRAM
- `com.apple.rootless.storage.label`: Modificar arquivos restritos pelo xattr com o rótulo correspondente de com.apple.rootless
- `com.apple.rootless.volume.VM.label`: Manter o swap da VM no volume

## Bypasses do SIP

BYPASS do SIP permite que um atacante:

- **Acesse dados do usuário**: Leia dados sensíveis do usuário, como e-mails, mensagens e histórico do Safari, de todas as contas de usuário.
- **Bypass do TCC**: Manipule diretamente o banco de dados do TCC (Transparency, Consent, and Control) para conceder acesso não autorizado à webcam, ao microfone e a outros recursos.
- **Estabeleça persistência**: Coloque malware em locais protegidos pelo SIP, tornando-o resistente à remoção, mesmo com privilégios de root. Isso também inclui a possibilidade de adulterar o Malware Removal Tool (MRT).
- **Carregue extensões de kernel**: Embora existam proteções adicionais, ignorar o SIP simplifica o processo de carregamento de extensões de kernel não assinadas.

### Pacotes do Installer

**Pacotes do Installer assinados com o certificado da Apple** podem ignorar suas proteções. Isso significa que até mesmo pacotes assinados por desenvolvedores comuns serão bloqueados se tentarem modificar diretórios protegidos pelo SIP.

### Arquivo inexistente do SIP

Uma possível brecha é que, se um arquivo for especificado em **`rootless.conf`, mas não existir atualmente**, ele poderá ser criado. O malware poderia explorar isso para **estabelecer persistência** no sistema. Por exemplo, um programa malicioso poderia criar um arquivo .plist em `/System/Library/LaunchDaemons` se ele estiver listado em `rootless.conf`, mas não estiver presente.

### com.apple.rootless.install.heritable

> [!CAUTION]
> O entitlement **`com.apple.rootless.install.heritable`** permite ignorar o SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Foi descoberto que era possível **trocar o pacote do Installer depois que o sistema verificasse sua assinatura de código** e, então, o sistema instalaria o pacote malicioso em vez do original. Como essas ações eram realizadas pelo **`system_installd`**, isso permitiria ignorar o SIP.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Se um pacote fosse instalado a partir de uma imagem montada ou de uma unidade externa, o **Installer** **executaria** o binário a partir **desse sistema de arquivos** (em vez de um local protegido pelo SIP), fazendo com que o **`system_installd`** executasse um binário arbitrário.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Pesquisadores desta publicação**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) descobriram uma vulnerabilidade no mecanismo System Integrity Protection (SIP) do macOS, denominada vulnerabilidade 'Shrootless'. Essa vulnerabilidade está centrada no daemon **`system_installd`**, que possui um entitlement, **`com.apple.rootless.install.heritable`**, permitindo que qualquer um de seus processos filhos ignore as restrições do sistema de arquivos do SIP.<sup>[4]</sup>

O daemon **`system_installd`** instalará pacotes assinados pela **Apple**.

Os pesquisadores descobriram que, durante a instalação de um pacote assinado pela Apple (arquivo .pkg), o **`system_installd`** **executa** quaisquer scripts de **pós-instalação** incluídos no pacote. Esses scripts são executados pelo shell padrão, **`zsh`**, que automaticamente **executa** comandos do arquivo **`/etc/zshenv`**, se ele existir, mesmo no modo não interativo. Esse comportamento poderia ser explorado por atacantes: criando um arquivo `/etc/zshenv` malicioso e aguardando o **`system_installd` invocar o `zsh`**, eles poderiam realizar operações arbitrárias no dispositivo.<sup>[4]</sup>

Além disso, descobriu-se que **`/etc/zshenv` poderia ser usado como uma técnica geral de ataque**, não apenas para um bypass do SIP. Cada perfil de usuário possui um arquivo `~/.zshenv`, que se comporta da mesma forma que `/etc/zshenv`, mas não exige permissões de root. Esse arquivo poderia ser usado como mecanismo de persistência, sendo acionado sempre que o `zsh` fosse iniciado, ou como mecanismo de elevação de privilégios. Se um usuário administrador elevasse seus privilégios para root usando `sudo -s` ou `sudo <command>`, o arquivo `~/.zshenv` seria acionado, efetivamente elevando os privilégios para root.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Em [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) descobriu-se que o mesmo processo **`system_installd`** ainda poderia ser abusado porque ele colocava o **script de pós-instalação dentro de uma pasta com nome aleatório protegida pelo SIP dentro de `/tmp`**. O problema é que o próprio **`/tmp` não é protegido pelo SIP**, portanto era possível **montar** uma **imagem virtual nele**; então o **Installer** colocaria ali o **script de pós-instalação**, **desmontaria** a imagem virtual, **recriaria** todas as **pastas** e **adicionaria** o script de **pós-instalação** com o **payload** a ser executado.<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Foi identificada uma vulnerabilidade na qual o **`fsck_cs`** era induzido a corromper um arquivo crucial devido à sua capacidade de seguir **symbolic links**. Especificamente, os atacantes criavam um link de _`/dev/diskX`_ para o arquivo `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Executar o **`fsck_cs`** em _`/dev/diskX`_ causava a corrupção de `Info.plist`. A integridade desse arquivo é vital para o SIP (System Integrity Protection) do sistema operacional, que controla o carregamento de extensões de kernel. Depois de corrompido, o recurso do SIP de gerenciar exclusões do kernel fica comprometido.<sup>[6]</sup>

Os comandos para explorar essa vulnerabilidade são:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
A exploração dessa vulnerabilidade tem implicações graves. O arquivo `Info.plist`, normalmente responsável por gerenciar as permissões das extensões do kernel, torna-se ineficaz. Isso inclui a impossibilidade de colocar certas extensões na blacklist, como `AppleHWAccess.kext`. Consequentemente, com o mecanismo de controle do SIP fora de operação, essa extensão pode ser carregada, concedendo acesso não autorizado de leitura e escrita à RAM do sistema.<sup>[6]</sup>

#### [Montar sobre pastas protegidas pelo SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Era possível montar um novo sistema de arquivos sobre **pastas protegidas pelo SIP para contornar a proteção**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

O sistema é configurado para inicializar a partir de uma imagem de disco do instalador incorporada no `Install macOS Sierra.app` para atualizar o sistema operacional, utilizando o utilitário `bless`. O comando utilizado é o seguinte:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
A segurança desse processo pode ser comprometida se um invasor alterar a imagem de upgrade (`InstallESD.dmg`) antes da inicialização. A estratégia envolve substituir um dynamic loader (dyld) por uma versão maliciosa (`libBaseIA.dylib`). Essa substituição resulta na execução do código do invasor quando o instalador é iniciado.<sup>[7]</sup>

O código do invasor obtém controle durante o processo de upgrade, explorando a confiança do sistema no instalador. O ataque prossegue alterando a imagem `InstallESD.dmg` por meio de method swizzling, visando especificamente o método `extractBootBits`. Isso permite a injeção de código malicioso antes que a disk image seja utilizada.<sup>[7]</sup>

Além disso, dentro da `InstallESD.dmg`, há uma `BaseSystem.dmg`, que funciona como o sistema de arquivos raiz do código de upgrade. A injeção de uma dynamic library nela permite que o código malicioso opere dentro de um processo capaz de alterar arquivos no nível do sistema operacional, aumentando significativamente o potencial de comprometimento do sistema.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Nesta palestra da [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), é mostrado como o **`systemmigrationd`** (que pode bypassar o SIP) executa um script **bash** e um script **perl**, que podem ser abusados por meio das variáveis de ambiente **`BASH_ENV`** e **`PERL5OPT`**.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Conforme [**detalhado nesta publicação de blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), um script `postinstall` dos pacotes `InstallAssistant.pkg` permitia a execução de:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
e era possível criar um symlink em `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` que permitiria a um usuário **desrestringir qualquer arquivo, contornando a proteção do SIP**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> O entitlement **`com.apple.rootless.install`** permite contornar o SIP

O entitlement `com.apple.rootless.install` é conhecido por contornar o System Integrity Protection (SIP) no macOS. Isso foi mencionado especificamente em relação à [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[10]</sup>

Nesse caso específico, o serviço XPC do sistema localizado em `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possui esse entitlement. Isso permite que o processo relacionado contorne as restrições do SIP. Além disso, esse serviço apresenta notavelmente um método que permite a movimentação de arquivos sem aplicar quaisquer medidas de segurança.<sup>[10]</sup>

## Snapshots Selados do Sistema

Os Snapshots Selados do Sistema são um recurso introduzido pela Apple no **macOS Big Sur (macOS 11)** como parte do mecanismo de **System Integrity Protection (SIP)**, com o objetivo de fornecer uma camada adicional de segurança e estabilidade ao sistema. Eles são essencialmente versões somente leitura do volume do sistema.

Veja uma explicação mais detalhada:

1. **Sistema Imutável**: os Snapshots Selados do Sistema tornam o volume do sistema do macOS "imutável", o que significa que ele não pode ser modificado. Isso impede alterações não autorizadas ou acidentais no sistema que poderiam comprometer a segurança ou a estabilidade do sistema.
2. **Atualizações do Software do Sistema**: quando você instala atualizações ou upgrades do macOS, o macOS cria um novo snapshot do sistema. O volume de inicialização do macOS usa então o **APFS (Apple File System)** para alternar para esse novo snapshot. Todo o processo de aplicação das atualizações se torna mais seguro e confiável, pois o sistema pode sempre reverter para o snapshot anterior caso algo dê errado durante a atualização.
3. **Separação de Dados**: em conjunto com o conceito de separação dos volumes Data e System introduzido no macOS Catalina, o recurso de Snapshot Selado do Sistema garante que todos os seus dados e configurações sejam armazenados em um volume "**Data**" separado. Essa separação torna seus dados independentes do sistema, o que simplifica o processo de atualizações do sistema e aumenta a segurança do sistema.

Lembre-se de que esses snapshots são gerenciados automaticamente pelo macOS e não ocupam espaço adicional no disco, graças aos recursos de compartilhamento de espaço do APFS. Também é importante observar que esses snapshots são diferentes dos **snapshots do Time Machine**, que são backups acessíveis ao usuário de todo o sistema.

### Verificar Snapshots

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
|   Encrypted:                 No
</code></pre>

Na saída anterior, é possível ver que os **locais acessíveis ao usuário** estão montados em `/System/Volumes/Data`.

Além disso, o **snapshot do volume System do macOS** está montado em `/` e está **selado** (assinado criptograficamente pelo sistema operacional). Portanto, se o SIP for contornado e o snapshot for modificado, o **sistema operacional não será mais inicializado**.

Também é possível **verificar se o selo está habilitado** executando:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Além disso, o disco do snapshot também é montado como **somente leitura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Referências

- [1] [SyScan360 - Stefan Esser - OS X El Capitan afundando o S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Blog do Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: bugs de lógica do "Unauthd" (três) ftw! - Blog do Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft encontra uma nova vulnerabilidade no macOS, Shrootless, que poderia contornar o System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Análise técnica: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [A segurança rootless da Apple, sem frutos, quebrada por código que cabe em um tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Contornando o System Integrity Protection da Apple - Blog do Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Tendo uma enxaqueca - Unique SIP Bypass no MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [A Apple mitiga vulnerabilidades em Installer Scripts - Blog da Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: o POC para SIP-Bypass também pode ser publicado em um tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
