# Evasiones del Sandbox de Office en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Evasión del Sandbox de Word mediante Launch Agents

La aplicación utiliza un **Sandbox personalizado** con el derecho **`com.apple.security.temporary-exception.sbpl`** y este sandbox personalizado permite escribir archivos en cualquier lugar siempre que el nombre del archivo comience con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Por lo tanto, la evasión fue tan fácil como **escribir un `plist`** LaunchAgent en `~/Library/LaunchAgents/~$escape.plist`.

Consulta el [**informe original aquí**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Evasión del Sandbox de Word mediante Login Items y zip

Recuerda que desde la primera evasión, Word puede escribir archivos arbitrarios cuyo nombre comience con `~$`, aunque después del parche de la vulnerabilidad anterior no era posible escribir en `/Library/Application Scripts` o en `/Library/LaunchAgents`.

Se descubrió que desde dentro del sandbox es posible crear un **Login Item** (aplicaciones que se ejecutarán cuando el usuario inicie sesión). Sin embargo, estas aplicaciones **no se ejecutarán a menos** de que estén **notarizadas** y **no es posible añadir argumentos** (por lo que no puedes simplemente ejecutar un shell inverso usando **`bash`**).

Desde la evasión anterior del Sandbox, Microsoft deshabilitó la opción de escribir archivos en `~/Library/LaunchAgents`. Sin embargo, se descubrió que si pones un **archivo zip como Login Item**, la `Archive Utility` simplemente lo **descomprimirá** en su ubicación actual. Entonces, porque por defecto la carpeta `LaunchAgents` de `~/Library` no está creada, fue posible **comprimir un plist en `LaunchAgents/~$escape.plist`** y **colocar** el archivo zip en **`~/Library`** para que al descomprimirlo alcance el destino de persistencia.

Consulta el [**informe original aquí**](https://objective-see.org/blog/blog\_0x4B.html).

### Evasión del Sandbox de Word mediante Login Items y .zshenv

(Recuerda que desde la primera evasión, Word puede escribir archivos arbitrarios cuyo nombre comience con `~$`).

Sin embargo, la técnica anterior tenía una limitación, si la carpeta **`~/Library/LaunchAgents`** existe porque otro software la creó, fallaría. Por lo tanto, se descubrió una cadena diferente de Login Items para esto.

Un atacante podría crear los archivos **`.bash_profile`** y **`.zshenv`** con la carga útil a ejecutar y luego comprimirlos y **escribir el zip en la carpeta del usuario víctima**: **`~/~$escape.zip`**.

Luego, añadir el archivo zip a los **Login Items** y luego la aplicación **`Terminal`**. Cuando el usuario vuelva a iniciar sesión, el archivo zip se descomprimirá en la carpeta del usuario, sobrescribiendo **`.bash_profile`** y **`.zshenv`** y por lo tanto, la terminal ejecutará uno de estos archivos (dependiendo si se usa bash o zsh).

Consulta el [**informe original aquí**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Evasión del Sandbox de Word con Open y variables de entorno

Desde procesos en sandbox todavía es posible invocar otros procesos utilizando la utilidad **`open`**. Además, estos procesos se ejecutarán **dentro de su propio sandbox**.

Se descubrió que la utilidad open tiene la opción **`--env`** para ejecutar una aplicación con variables de entorno **específicas**. Por lo tanto, fue posible crear el archivo **`.zshenv`** dentro de una carpeta **dentro** del **sandbox** y luego usar `open` con `--env` estableciendo la variable **`HOME`** a esa carpeta abriendo la aplicación `Terminal`, la cual ejecutará el archivo `.zshenv` (por alguna razón también fue necesario establecer la variable `__OSINSTALL_ENVIROMENT`).

Consulta el [**informe original aquí**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Evasión del Sandbox de Word con Open y stdin

La utilidad **`open`** también soportaba el parámetro **`--stdin`** (y después de la evasión anterior ya no era posible usar `--env`).

El caso es que incluso si **`python`** estaba firmado por Apple, **no ejecutará** un script con el atributo **`quarantine`**. Sin embargo, era posible pasarle un script desde stdin para que no comprobara si estaba en cuarentena o no:

1. Suelta un archivo **`~$exploit.py`** con comandos de Python arbitrarios.
2. Ejecuta _open_ **`–stdin='~$exploit.py' -a Python`**, lo que ejecuta la aplicación Python con nuestro archivo soltado sirviendo como su entrada estándar. Python ejecuta felizmente nuestro código, y dado que es un proceso hijo de _launchd_, no está sujeto a las reglas del sandbox de Word.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
