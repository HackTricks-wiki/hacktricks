# Sandbox do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações básicas

O Sandbox do macOS (inicialmente chamado de Seatbelt) **limita as aplicações** em execução dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual a aplicação está sendo executada. Isso ajuda a garantir que **a aplicação esteja acessando apenas os recursos esperados**.

Qualquer aplicativo com a **permissão** **`com.apple.security.app-sandbox`** será executado dentro do sandbox. **Binários da Apple** geralmente são executados dentro de um Sandbox e, para publicar na **App Store**, **essa permissão é obrigatória**. Portanto, a maioria das aplicações será executada dentro do sandbox.

Para controlar o que um processo pode ou não fazer, o **Sandbox tem hooks** em todas as **syscalls** em todo o kernel. **Dependendo** das **permissões** do aplicativo, o Sandbox permitirá **determinadas ações**.

Alguns componentes importantes do Sandbox são:

* A **extensão do kernel** `/System/Library/Extensions/Sandbox.kext`
* O **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Um **daemon** em execução no userland `/usr/libexec/sandboxd`
* Os **containers** `~/Library/Containers`

Dentro da pasta containers, você pode encontrar **uma pasta para cada aplicativo executado no sandbox** com o nome do bundle id:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Dentro de cada pasta de identificação de pacote, você pode encontrar o arquivo **plist** e o diretório **Data** do aplicativo:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Note que mesmo que os links simbólicos estejam lá para "escapar" do Sandbox e acessar outras pastas, o aplicativo ainda precisa **ter permissões** para acessá-las. Essas permissões estão dentro do **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# In this file you can find the entitlements:
<key>Entitlements</key>
	<dict>
		<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
		<true/>
		<key>com.apple.accounts.appleaccount.fullaccess</key>
		<true/>
		<key>com.apple.appattest.spi</key>
		<true/>
[...]

# Some parameters
<key>Parameters</key>
	<dict>
		<key>_HOME</key>
		<string>/Users/username</string>
		<key>_UID</key>
		<string>501</string>
		<key>_USER</key>
		<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
	<array>
		<string>/Users/username/Downloads</string>
		<string>/Users/username/Documents</string>
		<string>/Users/username/Library/Calendars</string>
		<string>/Users/username/Desktop</string>
[...]
```
### Perfis de Sandbox

Os perfis de Sandbox são arquivos de configuração que indicam o que será **permitido/proibido** nessa **Sandbox**. Eles usam a **Linguagem de Perfil de Sandbox (SBPL)**, que utiliza a linguagem de programação [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Aqui você pode encontrar um exemplo:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
    (subpath "/Users/username/")
    (literal "/tmp/afile")
    (regex #"^/private/etc/.*")
)

(allow mach-lookup
    (global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Confira esta [**pesquisa**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para verificar mais ações que podem ser permitidas ou negadas.**
{% endhint %}

Serviços importantes do **sistema** também são executados dentro de seus próprios **perfis de sandbox personalizados**, como o serviço `mdnsresponder`. Você pode visualizar esses **perfis de sandbox personalizados** em:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Outros perfis de sandbox podem ser verificados em [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Os aplicativos da **App Store** usam o **perfil** **`/System/Library/Sandbox/Profiles/application.sb`**. Você pode verificar neste perfil como as permissões, como **`com.apple.security.network.server`**, permitem que um processo use a rede.

O SIP é um perfil de sandbox chamado platform\_profile em /System/Library/Sandbox/rootless.conf

### Exemplos de Perfil de Sandbox

Para iniciar um aplicativo com um **perfil de sandbox específico**, você pode usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}
;; touch.sb - Sandbox profile for the touch command

(version 1)

(deny default)

(allow file-write-data
    (literal "/dev/null")
    (regex #"^/tmp/.*"))

(allow file-read-data
    (regex #"^/usr/share/locale/.*"))

(allow process-exec
    (regex #"^/bin/.*"))

(allow sysctl-write
    (regex #"^kern\.securelevel$"))

(allow signal
    (target self))

(allow mach-lookup
    (global-name "com.apple.system.notification_center"))

(allow network-outbound
    (regex #"^https?://.*"))

(allow network-inbound
    (local tcp))
{% endcode %}
{% endtab %}
{% endtabs %}

## macOS Sandbox

O macOS Sandbox é um mecanismo de segurança que restringe o acesso de um processo a recursos do sistema, como arquivos, diretórios, rede e outros processos. Ele é usado para limitar o impacto de vulnerabilidades de segurança em aplicativos e para proteger o sistema contra malware.

O arquivo `touch.sb` é um exemplo de um perfil de sandbox para o comando `touch`. Ele permite que o comando `touch` escreva em `/dev/null` e em qualquer arquivo que comece com `/tmp/`. Ele também permite que o comando leia arquivos em `/usr/share/locale/` e execute processos em `/bin/`. Além disso, ele permite que o comando escreva em `kern.securelevel`, envie sinais para si mesmo, acesse o centro de notificação do sistema e faça conexões de rede HTTPS e TCP local.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %} (This is not a text to be translated, it is a markdown tag)
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```
(version 1)
(deny default)
(allow file-write*
    (regex #"^/Users/[^/]+/Desktop/[^/]+$")
    (regex #"^/Users/[^/]+/Documents/[^/]+$")
    (regex #"^/Users/[^/]+/Downloads/[^/]+$")
    (regex #"^/Users/[^/]+/Movies/[^/]+$")
    (regex #"^/Users/[^/]+/Music/[^/]+$")
    (regex #"^/Users/[^/]+/Pictures/[^/]+$")
    (regex #"^/Users/[^/]+/Public/[^/]+$")
    (regex #"^/Users/[^/]+/Sites/[^/]+$")
)
```
{% endcode %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```
(version 1)
(deny default)
(import "bsd.sb")
(import "mach.sb")
(import "iokit.sb")

;; Allow reading of system files
(allow file-read* (regex #"^/usr/share/"))
(allow file-read* (regex #"^/usr/lib/"))
(allow file-read* (regex #"^/usr/lib/dtrace/"))
(allow file-read* (regex #"^/usr/lib/system/"))
(allow file-read* (regex #"^/usr/libexec/"))
(allow file-read* (regex #"^/usr/bin/"))
(allow file-read* (regex #"^/bin/"))
(allow file-read* (regex #"^/private/var/db/dyld/"))

;; Allow writing to user's home directory
(allow file-write* (subpath (user-home-dir) ))

;; Allow network access
(allow network*)

;; Allow access to system services
(allow mach*)
(allow iokit*)

;; Allow execution of touch command
(allow process-exec (regex #"^/usr/bin/touch$"))

;; Allow access to standard input/output/error
(allow file-read-data file-write-data
    (literal "/dev/null")
    (regex #"^/dev/fd/[0-9]+$")
    (regex #"^/dev/tty[0-9]*$"))

;; Allow access to temporary files
(allow file-read* file-write*
    (regex #"^/private/var/tmp/"))
(allow file-read* file-write*
    (regex #"^/private/tmp/"))
(allow file-read* file-write*
    (regex #"^/tmp/"))
```
{% endcode %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Observe que o **software** **desenvolvido pela Apple** que roda no **Windows** **não possui precauções de segurança adicionais**, como o sandboxing de aplicativos.
{% endhint %}

Exemplos de bypass:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (eles conseguem escrever arquivos fora do sandbox cujo nome começa com `~$`).

### Depurar e Bypass Sandbox

**Os processos não nascem sandboxed no macOS: ao contrário do iOS**, onde o sandbox é aplicado pelo kernel antes da primeira instrução de um programa ser executada, no macOS **um processo deve optar por se colocar no sandbox.**

Os processos são automaticamente sandboxed a partir do userland quando iniciam se tiverem a entitlement: `com.apple.security.app-sandbox`. Para uma explicação detalhada desse processo, verifique:

{% content-ref url="macos-sandbox-debug-and-bypass.md" %}
[macos-sandbox-debug-and-bypass.md](macos-sandbox-debug-and-bypass.md)
{% endcontent-ref %}

### **Verificar Privilégios PID**

[De acordo com isso](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), o **`sandbox_check`** (é um `__mac_syscall`), pode verificar **se uma operação é permitida ou não** pelo sandbox em um determinado PID.

A [**ferramenta sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) pode verificar se um PID pode executar uma determinada ação:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### SBPL personalizado em aplicativos da App Store

É possível para empresas fazerem seus aplicativos rodarem com **perfis de Sandbox personalizados** (em vez do padrão). Eles precisam usar a permissão **`com.apple.security.temporary-exception.sbpl`** que precisa ser autorizada pela Apple.

É possível verificar a definição dessa permissão em **`/System/Library/Sandbox/Profiles/application.sb:`**.
```scheme
(sandbox-array-entitlement
  "com.apple.security.temporary-exception.sbpl"
  (lambda (string)
    (let* ((port (open-input-string string)) (sbpl (read port)))
      (with-transparent-redirection (eval sbpl)))))
```
Isso **avaliará a string após essa permissão** como um perfil de Sandbox.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
