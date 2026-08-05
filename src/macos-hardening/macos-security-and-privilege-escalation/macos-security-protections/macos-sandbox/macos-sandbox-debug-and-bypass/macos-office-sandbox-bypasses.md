# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Launch Agents를 통한 Word Sandbox bypass

애플리케이션은 **`com.apple.security.temporary-exception.sbpl`** entitlement를 사용하는 **custom Sandbox**를 사용하며, 이 custom sandbox에서는 파일명이 `~$`로 시작하기만 하면 어디에든 파일을 쓸 수 있습니다: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

따라서 `~/Library/LaunchAgents/~$escape.plist`에 **`plist`** LaunchAgent를 **작성**하는 것만으로 쉽게 escape할 수 있었습니다.

[**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)를 확인하세요.<sup>[[1]](#references)</sup>

### Login Items 및 zip을 통한 Word Sandbox bypass

첫 번째 escape를 통해 Word는 파일명이 `~$`로 시작하는 임의의 파일을 작성할 수 있었습니다. 하지만 이전 vuln의 patch 이후에는 `/Library/Application Scripts` 또는 `/Library/LaunchAgents`에 파일을 작성할 수 없었습니다.

Sandbox 내부에서 **Login Item**(사용자가 로그인할 때 실행되는 앱)을 생성할 수 있다는 사실이 발견되었습니다. 그러나 이러한 앱은 **notarized**되지 않으면 **실행되지 않으며**, **args를 추가할 수도 없습니다**(따라서 **`bash`**를 사용해 reverse shell을 실행할 수 없습니다).

이전 Sandbox bypass 이후 Microsoft는 `~/Library/LaunchAgents`에 파일을 작성하는 옵션을 비활성화했습니다. 그러나 **zip file을 Login Item으로 설정하면** `Archive Utility`가 해당 파일을 현재 위치에 그대로 **unzip**한다는 사실이 발견되었습니다. 기본적으로 `~/Library`의 `LaunchAgents` folder는 생성되어 있지 않으므로, **`LaunchAgents/~$escape.plist`에 plist를 zip으로 압축**한 뒤 zip file을 **`~/Library`에 배치**할 수 있었습니다. 그러면 압축이 해제될 때 persistence destination에 도달합니다.

[**original report here**](https://objective-see.org/blog/blog_0x4B.html)를 확인하세요.<sup>[[2]](#references)</sup>

### Login Items 및 .zshenv를 통한 Word Sandbox bypass

(첫 번째 escape를 통해 Word는 파일명이 `~$`로 시작하는 임의의 파일을 작성할 수 있습니다.)

그러나 이전 technique에는 제한이 있었습니다. 다른 software가 `**`~/Library/LaunchAgents`**` folder를 이미 생성한 경우 실패했습니다. 따라서 이를 위한 다른 Login Items chain이 발견되었습니다.

공격자는 실행할 payload가 포함된 **`.bash_profile`** 및 **`.zshenv`** 파일을 생성한 다음 이를 zip으로 압축하고 **victim의** user folder인 **`~/~$escape.zip`**에 **작성**할 수 있었습니다.

그런 다음 zip file과 **`Terminal`** app을 **Login Items**에 추가합니다. 사용자가 다시 로그인하면 zip file이 사용자의 file에 압축 해제되어 **`.bash_profile`**과 **`.zshenv`**를 덮어쓰고, 그 결과 terminal은 두 파일 중 하나를 실행합니다(bash 또는 zsh 사용 여부에 따라 다름).

[**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)를 확인하세요.<sup>[[3]](#references)</sup>

### Open 및 env variables를 사용한 Word Sandbox Bypass

Sandbox된 process에서는 여전히 **`open`** utility를 사용해 다른 process를 invoke할 수 있습니다. 또한 이러한 process는 **자체 sandbox 내에서** 실행됩니다.

open utility에 **specific env** variables를 사용해 app을 실행하는 **`--env`** option이 있다는 사실이 발견되었습니다. 따라서 **sandbox 내부의 folder**에 **`.zshenv file`**을 생성한 뒤, **`HOME` variable**이 해당 folder를 가리키도록 `--env`를 설정한 **`open`**으로 `Terminal` app을 열 수 있었습니다. 그러면 `.zshenv` file이 실행됩니다(어떤 이유에서인지 `__OSINSTALL_ENVIROMENT` variable도 설정해야 했습니다).

[**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)를 확인하세요.<sup>[[4]](#references)</sup>

### Open 및 stdin을 사용한 Word Sandbox Bypass

**`open`** utility는 **`--stdin`** param도 지원했습니다(이전 bypass 이후에는 더 이상 `--env`를 사용할 수 없었습니다).

문제는 **`python`**이 Apple에 의해 signed되어 있더라도 **`quarantine`** attribute가 있는 script는 **실행하지 않는다는** 점입니다. 그러나 stdin으로 script를 전달하면 해당 script가 quarantine되었는지 확인하지 않도록 할 수 있었습니다.

1. 임의의 Python commands가 포함된 **`~$exploit.py`** file을 drop합니다.
2. _open_ **`–stdin='~$exploit.py' -a Python`**을 실행합니다. 이는 drop한 file을 standard input으로 사용하여 Python app을 실행합니다. Python은 우리의 code를 문제없이 실행하며, _launchd_의 child process이므로 Word의 sandbox rules에 bound되지 않습니다.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
