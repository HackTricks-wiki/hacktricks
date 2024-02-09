# Saltos de la caja de arena de Word en macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Salto de la caja de arena de Word a través de Agentes de Inicio

La aplicación utiliza una **Caja de Arena personalizada** utilizando el permiso **`com.apple.security.temporary-exception.sbpl`** y esta caja de arena personalizada permite escribir archivos en cualquier lugar siempre que el nombre del archivo comience con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Por lo tanto, el escape fue tan fácil como **escribir un `plist`** de LaunchAgent en `~/Library/LaunchAgents/~$escape.plist`.

Consulta el [**informe original aquí**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Salto de la caja de arena de Word a través de Elementos de Inicio y zip

Recuerda que a partir del primer escape, Word puede escribir archivos arbitrarios cuyo nombre comienza con `~$`, aunque después del parche de la vulnerabilidad anterior no era posible escribir en `/Library/Application Scripts` o en `/Library/LaunchAgents`.

Se descubrió que desde dentro de la caja de arena es posible crear un **Elemento de Inicio** (aplicaciones que se ejecutarán cuando el usuario inicie sesión). Sin embargo, estas aplicaciones **no se ejecutarán a menos que** estén **notarizadas** y no es **posible agregar argumentos** (por lo que no se puede simplemente ejecutar un shell inverso usando **`bash`**).

A partir del escape anterior de la caja de arena, Microsoft deshabilitó la opción de escribir archivos en `~/Library/LaunchAgents`. Sin embargo, se descubrió que si se coloca un **archivo zip como Elemento de Inicio**, el `Utilidad de Archivo` simplemente lo **descomprimirá** en su ubicación actual. Entonces, como por defecto la carpeta `LaunchAgents` de `~/Library` no se crea, fue posible **comprimir un plist en `LaunchAgents/~$escape.plist`** y **colocar** el archivo zip en **`~/Library`** para que al descomprimirlo alcance el destino de persistencia.

Consulta el [**informe original aquí**](https://objective-see.org/blog/blog\_0x4B.html).

### Salto de la caja de arena de Word a través de Elementos de Inicio y .zshenv

(Recuerda que a partir del primer escape, Word puede escribir archivos arbitrarios cuyo nombre comienza con `~$`).

Sin embargo, la técnica anterior tenía una limitación, si la carpeta **`~/Library/LaunchAgents`** existe porque otro software la creó, fallaría. Por lo tanto, se descubrió una cadena de Elementos de Inicio diferente para esto.

Un atacante podría crear los archivos **`.bash_profile`** y **`.zshenv`** con el payload para ejecutar y luego comprimirlos y **escribir el zip en la carpeta del usuario** de la víctima: **`~/~$escape.zip`**.

Luego, agregar el archivo zip a los **Elementos de Inicio** y luego la aplicación **`Terminal`**. Cuando el usuario vuelva a iniciar sesión, el archivo zip se descomprimirá en los archivos del usuario, sobrescribiendo **`.bash_profile`** y **`.zshenv`** y por lo tanto, el terminal ejecutará uno de estos archivos (dependiendo de si se usa bash o zsh).

Consulta el [**informe original aquí**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Salto de la caja de arena de Word con Open y variables de entorno

Desde procesos en la caja de arena, todavía es posible invocar otros procesos utilizando la utilidad **`open`**. Además, estos procesos se ejecutarán **dentro de su propia caja de arena**.

Se descubrió que la utilidad open tiene la opción **`--env`** para ejecutar una aplicación con **variables de entorno específicas**. Por lo tanto, fue posible crear el archivo **`.zshenv` dentro** de una carpeta **dentro** de la **caja de arena** y luego usar `open` con `--env` configurando la variable **`HOME`** a esa carpeta abriendo la aplicación `Terminal`, que ejecutará el archivo `.zshenv` (por alguna razón también fue necesario establecer la variable `__OSINSTALL_ENVIROMENT`).

Consulta el [**informe original aquí**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Salto de la caja de arena de Word con Open y stdin

La utilidad **`open`** también admitía el parámetro **`--stdin`** (y después del escape anterior ya no era posible usar `--env`).

La cuestión es que incluso si **`python`** estaba firmado por Apple, **no ejecutará** un script con el atributo **`quarantine`**. Sin embargo, era posible pasarle un script desde stdin para que no verifique si estaba en cuarentena o no:&#x20;

1. Dejar un archivo **`~$exploit.py`** con comandos arbitrarios de Python.
2. Ejecutar _open_ **`–stdin='~$exploit.py' -a Python`**, que ejecuta la aplicación Python con nuestro archivo dejado sirviendo como su entrada estándar. Python ejecuta nuestro código felizmente y, como es un proceso secundario de _launchd_, no está sujeto a las reglas de la caja de arena de Word.

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
