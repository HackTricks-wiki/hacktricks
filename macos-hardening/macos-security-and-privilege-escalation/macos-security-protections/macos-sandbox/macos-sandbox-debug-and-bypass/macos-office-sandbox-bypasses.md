# Saltos de la caja de arena de macOS Office

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Saltar la caja de arena de Word a través de Launch Agents

La aplicación utiliza una **caja de arena personalizada** utilizando el permiso **`com.apple.security.temporary-exception.sbpl`** y esta caja de arena personalizada permite escribir archivos en cualquier lugar siempre que el nombre del archivo comience con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Por lo tanto, escapar fue tan fácil como **escribir un archivo `plist`** LaunchAgent en `~/Library/LaunchAgents/~$escape.plist`.

Consulte el [**informe original aquí**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Saltar la caja de arena de Word a través de elementos de inicio de sesión y zip

(Recuerde que desde el primer escape, Word puede escribir archivos arbitrarios cuyo nombre comienza con `~$`).

Se descubrió que desde dentro de la caja de arena es posible crear un **elemento de inicio de sesión** (aplicaciones que se ejecutarán cuando el usuario inicie sesión). Sin embargo, estas aplicaciones **no se ejecutarán a menos que** estén **notarizadas** y no es posible agregar argumentos (por lo que no se puede ejecutar una shell inversa usando **`bash`**).

Desde el escape anterior de la caja de arena, Microsoft deshabilitó la opción de escribir archivos en `~/Library/LaunchAgents`. Sin embargo, se descubrió que si se coloca un **archivo zip como elemento de inicio de sesión**, el `Archive Utility` simplemente lo **descomprimirá** en su ubicación actual. Entonces, como por defecto la carpeta `LaunchAgents` de `~/Library` no se crea, fue posible **comprimir un archivo plist en `LaunchAgents/~$escape.plist`** y **colocar** el archivo zip en **`~/Library`** para que cuando se descomprima llegue al destino de persistencia.

Consulte el [**informe original aquí**](https://objective-see.org/blog/blog\_0x4B.html).

### Saltar la caja de arena de Word a través de elementos de inicio de sesión y .zshenv

(Recuerde que desde el primer escape, Word puede escribir archivos arbitrarios cuyo nombre comienza con `~$`).

Sin embargo, la técnica anterior tenía una limitación, si la carpeta **`~/Library/LaunchAgents`** existe porque otro software la creó, fallaría. Entonces se descubrió una cadena de elementos de inicio de sesión diferente para esto.

Un atacante podría crear los archivos **`.bash_profile`** y **`.zshenv`** con la carga útil para ejecutar y luego comprimirlos y **escribir el archivo zip en la carpeta** del usuario víctima: \~/\~$escape.zip.

Luego, agregue el archivo zip a los **elementos de inicio de sesión** y luego la aplicación **`Terminal`**. Cuando el usuario vuelva a iniciar sesión, el archivo zip se descomprimirá en los archivos del usuario, sobrescribiendo **`.bash_profile`** y **`.zshenv`** y, por lo tanto, la terminal ejecutará uno de estos archivos (dependiendo de si se usa bash o zsh).

Consulte el [**informe original aquí**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Saltar la caja de arena de Word con Open y variables de entorno

Desde procesos en la caja de arena, todavía es posible invocar otros procesos utilizando la utilidad **`open`**. Además, estos procesos se ejecutarán **dentro de su propia caja de arena**.

Se descubrió que la utilidad open tiene la opción **`--env`** para ejecutar una aplicación con **variables de entorno específicas**. Por lo tanto, fue posible crear el archivo **`.zshenv`** dentro de una carpeta **dentro** de la **caja de arena** y usar `open` con `--env` estableciendo la variable **`HOME`** en esa carpeta abriendo esa aplicación `Terminal`, que ejecutará el archivo `.zshenv` (por alguna razón también fue necesario establecer la variable `__OSINSTALL_ENVIROMENT`).

Consulte el [**informe original aquí**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Saltar la caja de arena de Word con Open y stdin

La utilidad **`open`** también admitía el parámetro **`--stdin`** (y después del escape anterior ya no era posible usar `--env`).

La cosa es que incluso si **`python`** estaba firmado por Apple, **no ejecutará** un script con el atributo **`quarantine`**. Sin embargo, fue posible pasarle un script desde stdin para que no verifique si estaba en cuarentena o no:&#x20;

1. Deje caer un archivo **`~$exploit.py`** con comandos Python arbitrarios.
2. Ejecute _open_ **`–stdin='~$exploit.py' -a Python`**, que ejecuta la aplicación Python con nuestro archivo eliminado como su entrada estándar. Python ejecuta felizmente nuestro código y, como es un proceso secundario de _launchd_, no está sujeto a las reglas de la caja de arena de Word.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a
