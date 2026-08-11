# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

다음은 **역사적인 Microsoft Office for Mac sandbox escape** 사례입니다. 재사용 가능한 trust boundary 오류를 기록한 것이지만, 정확한 버전과 정책을 재현하지 않고서는 patch된 Office/macOS 조합이 취약하다고 간주해서는 안 됩니다.

### LaunchAgents를 통한 Word sandbox bypass

영향받은 애플리케이션은 `com.apple.security.temporary-exception.sbpl`을 통해 custom sandbox rule을 사용했습니다. 이 rule은 basename이 `~$`로 시작하는 regular file을 허용했습니다: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

따라서 `~/Library/LaunchAgents/~$escape.plist`에 **`plist` LaunchAgent를 작성**하는 것만으로 쉽게 escape할 수 있었습니다.

[**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)를 확인하세요.<sup>[[1]](#references)</sup>

### Login Items 및 zip을 통한 Word Sandbox bypass

첫 번째 escape에서 Word는 이름이 `~$`로 시작하는 임의의 파일을 작성할 수 있었지만, 이전 vulnerability가 patch된 후에는 `/Library/Application Scripts` 또는 `/Library/LaunchAgents`에 파일을 작성할 수 없었습니다.

영향받은 sandbox는 사용자가 로그인할 때 실행되는 **Login Item**을 생성할 수 있도록 허용했습니다. 시연된 경로에는 허용되는 서명/공증된 애플리케이션이 필요했고 arbitrary arguments는 허용하지 않았으므로, reverse-shell argument와 함께 `bash`를 추가하는 것만으로는 충분하지 않았습니다.<sup>[[2]](#references)</sup>

이전 Sandbox bypass 이후 Microsoft는 `~/Library/LaunchAgents`에 파일을 작성하는 옵션을 비활성화했습니다. 그러나 **zip file을 Login Item으로 지정하면** `Archive Utility`가 해당 파일을 현재 위치에 그대로 **unzip**한다는 사실이 발견되었습니다. 기본적으로 `~/Library` 아래의 `LaunchAgents` folder는 생성되어 있지 않으므로, **`LaunchAgents/~$escape.plist`에 plist를 zip으로 압축**한 뒤 zip file을 **`~/Library`에 배치**하면 압축 해제 시 persistence destination에 도달하게 할 수 있었습니다.

[**original report here**](https://objective-see.org/blog/blog_0x4B.html)를 확인하세요.<sup>[[2]](#references)</sup>

### Login Items 및 .zshenv를 통한 Word Sandbox bypass

(첫 번째 escape에서 Word는 이름이 `~$`로 시작하는 임의의 파일을 작성할 수 있었습니다.)

그러나 이전 technique에는 limitation이 있었습니다. 다른 software가 **`~/Library/LaunchAgents`** folder를 생성한 경우 실패했습니다. 이에 대한 다른 Login Items chain이 발견되었습니다.

공격자는 payload를 포함하는 **`.bash_profile`** 및 **`.zshenv`**를 생성하고 이를 archive한 다음, ZIP을 **victim의** home directory에 **`~/~$escape.zip`**으로 작성할 수 있었습니다.

그런 다음 ZIP과 **Terminal**을 Login Items로 추가합니다. 다음 login 시 Archive Utility가 dotfiles를 사용자의 home directory에 extract하고, Terminal의 shell이 해당 startup file을 평가합니다(시연된 Bash 경로에서는 `.bash_profile`, Zsh에서는 `.zshenv`).<sup>[[3]](#references)</sup>

[**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)를 확인하세요.<sup>[[3]](#references)</sup>

### Open 및 env variables를 사용한 Word Sandbox Bypass

Sandboxed process는 여전히 **`open`**을 통해 application launch를 요청할 수 있었습니다. 실행된 application은 Word의 정확히 동일한 sandbox profile을 상속하는 대신 자체 security context에서 실행되었습니다.<sup>[[4]](#references)</sup>

영향받은 `open` utility에는 environment variables를 제공하는 **`--env`** option이 있었습니다. exploit은 sandbox 내부에 `.zshenv`를 생성하고 `HOME`을 해당 directory로 설정한 뒤 Terminal을 실행하여 Zsh가 이를 평가하도록 했습니다. 보고된 chain은 철자가 잘못된 private variable `__OSINSTALL_ENVIROMENT`도 설정했으므로, historical PoC를 재현할 때는 이 정확한 철자를 유지해야 합니다.<sup>[[4]](#references)</sup>

[**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)를 확인하세요.<sup>[[4]](#references)</sup>

### Open 및 stdin을 사용한 Word Sandbox Bypass

**`open`** utility는 **`--stdin`** param도 지원했습니다(이전 bypass 이후에는 더 이상 `--env`를 사용할 수 없었습니다).

Apple의 Python application은 quarantined script file을 거부했지만, vulnerable workflow에서는 동일한 script를 standard input을 통해 전달하여 file-based quarantine check를 우회할 수 있었습니다:<sup>[[5]](#references)</sup>

1. 임의의 Python commands가 포함된 **`~$exploit.py`** file을 drop합니다.
2. `open --stdin='~$exploit.py' -a Python`을 실행합니다. 실행된 Python application은 drop된 code를 standard input으로 받고, vulnerable version에서는 LaunchServices가 이를 `launchd` 아래에서 생성하기 때문에 Word의 sandbox 외부에서 실행합니다.<sup>[[5]](#references)</sup>

## References

- [1] [Sandbox 탈출 – macOS의 Microsoft Office](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [macOS에서의 Office Drama](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [CVE-2021-30864의 Technical Analysis](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [macOS App Sandbox escape vulnerability 분석: CVE-2022-26706 심층 분석 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
