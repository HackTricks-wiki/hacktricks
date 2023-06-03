# Espacio de nombres UTS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

Un espacio de nombres UTS (UNIX Time-Sharing System) es una característica del kernel de Linux que proporciona **aislamiento de dos identificadores del sistema**: el **nombre de host** y el **dominio NIS** (Servicio de Información de Red). Este aislamiento permite que cada espacio de nombres UTS tenga su **propio nombre de host y dominio NIS independiente**, lo que es particularmente útil en escenarios de contenerización donde cada contenedor debe aparecer como un sistema separado con su propio nombre de host.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres UTS, comienza con una **copia del nombre de host y del dominio NIS de su espacio de nombres padre**. Esto significa que, en la creación, el nuevo espacio de nombres **comparte los mismos identificadores que su padre**. Sin embargo, cualquier cambio posterior en el nombre de host o en el dominio NIS dentro del espacio de nombres no afectará a otros espacios de nombres.
2. Los procesos dentro de un espacio de nombres UTS **pueden cambiar el nombre de host y el dominio NIS** utilizando las llamadas al sistema `sethostname()` y `setdomainname()`, respectivamente. Estos cambios son locales al espacio de nombres y no afectan a otros espacios de nombres ni al sistema host.
3. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()` o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUTS`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a utilizar el nombre de host y el dominio NIS asociados con ese espacio de nombres.

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` utilizando el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Si ejecutas la línea anterior sin `-f`, obtendrás ese error.\
El error es causado por el proceso PID 1 que sale en el nuevo espacio de nombres.

Después de que bash comience a ejecutarse, bifurcará varios nuevos subprocesos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo PID que el proceso "unshare" actual. El proceso "unshare" actual llama al sistema de llamadas unshare, crea un nuevo espacio de nombres de PID, pero el proceso "unshare" actual no está en el nuevo espacio de nombres de PID. Es el comportamiento deseado del kernel de Linux: el proceso A crea un nuevo espacio de nombres, el proceso A en sí mismo no se colocará en el nuevo espacio de nombres, solo los subprocesos del proceso A se colocarán en el nuevo espacio de nombres. Entonces, cuando ejecutas:
```
unshare -p /bin/bash
```
El proceso unshare ejecutará /bin/bash, y /bin/bash bifurcará varios subprocesos, el primer subproceso de bash se convertirá en PID 1 del nuevo espacio de nombres, y el subproceso saldrá después de completar su trabajo. Por lo tanto, el PID 1 del nuevo espacio de nombres sale.

El proceso PID 1 tiene una función especial: debe convertirse en el proceso padre de todos los procesos huérfanos. Si el proceso PID 1 en el espacio de nombres raíz sale, el kernel entrará en pánico. Si el proceso PID 1 en un subespacio de nombres sale, el kernel de Linux llamará a la función disable\_pid\_allocation, que limpiará la bandera PIDNS\_HASH\_ADDING en ese espacio de nombres. Cuando el kernel de Linux crea un nuevo proceso, llama a la función alloc\_pid para asignar un PID en un espacio de nombres, y si la bandera PIDNS\_HASH\_ADDING no está establecida, la función alloc\_pid devolverá un error -ENOMEM. Es por eso que se produce el error "Cannot allocate memory".

Puede resolver este problema utilizando la opción '-f':
```
unshare -fp /bin/bash
```
Si ejecutas unshare con la opción '-f', unshare bifurcará un nuevo proceso después de crear el nuevo espacio de nombres pid. Y ejecutará /bin/bash en el nuevo proceso. El nuevo proceso será el pid 1 del nuevo espacio de nombres pid. Luego, bash también bifurcará varios subprocesos para realizar algunas tareas. Como bash en sí mismo es el pid 1 del nuevo espacio de nombres pid, sus subprocesos pueden salir sin ningún problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verificar en qué espacio de nombres está su proceso
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Encontrar todos los espacios de nombres UTS

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un namespace UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro namespace de proceso si eres root**. Y no puedes **entrar** en otro namespace **sin un descriptor** que apunte a él (como `/proc/self/ns/uts`).

### Cambiar el nombre del host
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
