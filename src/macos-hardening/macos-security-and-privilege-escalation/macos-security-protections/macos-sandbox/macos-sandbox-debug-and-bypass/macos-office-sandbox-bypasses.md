# Bypasses del Sandbox de Office en macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Los siguientes son **escapes históricos del sandbox de Microsoft Office para Mac**. Documentan errores reutilizables en los límites de confianza, pero no debe asumirse que las combinaciones de Office/macOS parcheadas sean vulnerables sin reproducir la versión y la política exactas.

### Bypass del sandbox de Word mediante LaunchAgents

La aplicación afectada utilizaba una regla de sandbox personalizada mediante `com.apple.security.temporary-exception.sbpl`. Permitía archivos normales cuyo basename comenzara con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Por lo tanto, escapar era tan sencillo como **escribir un `plist`** de LaunchAgent en `~/Library/LaunchAgents/~$escape.plist`.

Consulta el [**informe original aquí**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Bypass del sandbox de Word mediante Login Items y zip

Recuerda que, desde el primer escape, Word puede escribir archivos arbitrarios cuyo nombre comienza con `~$`, aunque después del parche de la vulnerabilidad anterior ya no era posible escribir en `/Library/Application Scripts` ni en `/Library/LaunchAgents`.

El sandbox afectado permitía crear un **Login Item**, que se ejecuta cuando el usuario inicia sesión. El método demostrado requería una aplicación aceptablemente firmada/notarizada y no permitía argumentos arbitrarios, por lo que añadir `bash` con un argumento de reverse-shell no era suficiente.<sup>[[2]](#references)</sup>

A partir del bypass anterior del Sandbox, Microsoft deshabilitó la opción de escribir archivos en `~/Library/LaunchAgents`. Sin embargo, se descubrió que, si colocabas un **archivo zip como Login Item**, `Archive Utility` simplemente lo **descomprimía** en su ubicación actual. Por lo tanto, como la carpeta `LaunchAgents` de `~/Library` no se crea de forma predeterminada, era posible **comprimir un plist en `LaunchAgents/~$escape.plist`** y **colocar** el archivo zip en **`~/Library`**, de modo que al descomprimirse alcanzara el destino de persistencia.

Consulta el [**informe original aquí**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Bypass del sandbox de Word mediante Login Items y .zshenv

(Recuerda que, desde el primer escape, Word puede escribir archivos arbitrarios cuyo nombre comienza con `~$`).

Sin embargo, la técnica anterior tenía una limitación: si la carpeta **`~/Library/LaunchAgents`** existía porque otro software la había creado, fallaba. Por ello, se descubrió otra cadena de Login Items.

Un atacante podía crear **`.bash_profile`** y **`.zshenv`** con el payload, archivarlos y escribir el ZIP en el directorio principal del **víctima** como **`~/~$escape.zip`**.

Después, debía añadir el ZIP y **Terminal** como Login Items. En el siguiente inicio de sesión, Archive Utility extrae los dotfiles en el directorio principal del usuario y el shell de Terminal evalúa el archivo de inicio aplicable (`.bash_profile` para la ruta demostrada con Bash o `.zshenv` para Zsh).<sup>[[3]](#references)</sup>

Consulta el [**informe original aquí**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Bypass del Sandbox de Word con Open y variables de entorno

Los procesos en sandbox todavía podían solicitar el lanzamiento de aplicaciones mediante **`open`**. La aplicación lanzada se ejecutaba en su propio contexto de seguridad, en lugar de heredar exactamente el perfil de sandbox de Word.<sup>[[4]](#references)</sup>

La utilidad `open` afectada tenía una opción **`--env`** para proporcionar variables de entorno. El exploit creaba `.zshenv` dentro del sandbox, establecía `HOME` en ese directorio y lanzaba Terminal para que Zsh lo evaluara. La cadena descrita también establecía la variable privada mal escrita `__OSINSTALL_ENVIROMENT`; conserva esa ortografía exacta al reproducir el PoC histórico.<sup>[[4]](#references)</sup>

Consulta el [**informe original aquí**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Bypass del Sandbox de Word con Open y stdin

La utilidad **`open`** también admitía el parámetro **`--stdin`** (y, después del bypass anterior, ya no era posible utilizar `--env`).

Aunque la aplicación Python de Apple rechazaba un archivo de script en cuarentena, el flujo de trabajo vulnerable podía introducir el mismo script mediante la entrada estándar, evitando la comprobación de cuarentena basada en archivos:<sup>[[5]](#references)</sup>

1. Deposita un archivo **`~$exploit.py`** con comandos Python arbitrarios.
2. Ejecuta `open --stdin='~$exploit.py' -a Python`. La aplicación Python lanzada recibe el código depositado mediante la entrada estándar y, en las versiones vulnerables, se ejecuta fuera del sandbox de Word porque LaunchServices la crea bajo `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office en macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Drama de Office en macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Escape del Sandbox de Office365 en MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Análisis técnico de CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Descubriendo una vulnerabilidad de escape del App Sandbox de macOS: análisis detallado de CVE-2022-26706 - Blog de Microsoft Security](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
