# Evasiones del Sandbox de Office en macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Evasión del Sandbox de Word mediante Launch Agents

La aplicación utiliza un **Sandbox personalizado** mediante el entitlement **`com.apple.security.temporary-exception.sbpl`**, y este Sandbox personalizado permite escribir archivos en cualquier ubicación siempre que el nombre del archivo comience con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Por lo tanto, escapar era tan sencillo como **escribir un `plist`** de LaunchAgent en `~/Library/LaunchAgents/~$escape.plist`.

Consulta el [**informe original aquí**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Evasión del Sandbox de Word mediante Login Items y zip

Recuerda que, desde el primer escape, Word puede escribir archivos cuyo nombre comience con `~$`, aunque después del parche de la vulnerabilidad anterior ya no era posible escribir en `/Library/Application Scripts` ni en `/Library/LaunchAgents`.

Se descubrió que desde dentro del Sandbox es posible crear un **Login Item** (aplicaciones que se ejecutan cuando el usuario inicia sesión). Sin embargo, estas aplicaciones **no se ejecutarán a menos que** estén **notarized** y **no es posible añadir argumentos** (por lo que no se puede ejecutar directamente un reverse shell usando **`bash`**).

A partir del bypass anterior del Sandbox, Microsoft deshabilitó la opción de escribir archivos en `~/Library/LaunchAgents`. Sin embargo, se descubrió que, si colocas un **archivo zip como Login Item**, `Archive Utility` simplemente lo **descomprimirá** en su ubicación actual. Por lo tanto, como la carpeta `LaunchAgents` de `~/Library` no se crea de forma predeterminada, era posible **comprimir un plist en `LaunchAgents/~$escape.plist`** y **colocar** el archivo zip en **`~/Library`**, de modo que al descomprimirlo alcanzara el destino de persistencia.

Consulta el [**informe original aquí**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Evasión del Sandbox de Word mediante Login Items y .zshenv

(Recuerda que, desde el primer escape, Word puede escribir archivos cuyo nombre comience con `~$`).

Sin embargo, la técnica anterior tenía una limitación: si la carpeta **`~/Library/LaunchAgents`** existía porque algún otro software la había creado, fallaría. Por ello, se descubrió otra cadena de Login Items.

Un atacante podía crear los archivos **`.bash_profile`** y **`.zshenv`** con el payload que se debía ejecutar, comprimirlos y después **escribir el zip en la carpeta del usuario víctima**: **`~/~$escape.zip`**.

A continuación, se añade el archivo zip a los **Login Items** y después la aplicación **`Terminal`**. Cuando el usuario volviera a iniciar sesión, el archivo zip se descomprimiría en la carpeta del usuario, sobrescribiendo **`.bash_profile`** y **`.zshenv`** y, por lo tanto, el terminal ejecutaría uno de estos archivos (dependiendo de si se utiliza bash o zsh).

Consulta el [**informe original aquí**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Evasión del Sandbox de Word con Open y variables de entorno

Desde los procesos sandboxed todavía es posible invocar otros procesos mediante la utilidad `open`. Además, estos procesos se ejecutarán **dentro de su propio Sandbox**.

Se descubrió que la utilidad open tiene la opción **`--env`** para ejecutar una aplicación con variables de entorno **específicas**. Por lo tanto, era posible crear el archivo **`.zshenv`** dentro de una carpeta **situada dentro del** **sandbox** y utilizar `open` con `--env`, estableciendo la variable **`HOME`** en esa carpeta y abriendo la aplicación `Terminal`, que ejecutará el archivo `.zshenv` (por algún motivo, también era necesario establecer la variable `__OSINSTALL_ENVIROMENT`).

Consulta el [**informe original aquí**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Evasión del Sandbox de Word con Open y stdin

La utilidad **`open`** también admitía el parámetro **`--stdin`** (y, después del bypass anterior, ya no era posible utilizar `--env`).

El caso es que, aunque **`python`** estuviera firmado por Apple, **no ejecutaría** un script con el atributo **`quarantine`**. Sin embargo, era posible pasarle un script desde stdin, de modo que no comprobara si estaba en cuarentena:

1. Crear un archivo **`~$exploit.py`** con comandos Python arbitrarios.
2. Ejecutar _open_ **`–stdin='~$exploit.py' -a Python`**, lo que ejecuta la aplicación Python utilizando el archivo creado como entrada estándar. Python ejecuta nuestro código sin problemas y, como es un proceso hijo de **`launchd`**, no está sujeto a las reglas del Sandbox de Word.<sup>[[5]](#references)</sup>

## Referencias

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
