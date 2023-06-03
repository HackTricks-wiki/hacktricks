# Espacio de nombres de red

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

Un espacio de nombres de red es una característica del kernel de Linux que proporciona el aislamiento de la pila de red, permitiendo que **cada espacio de nombres de red tenga su propia configuración de red independiente**, interfaces, direcciones IP, tablas de enrutamiento y reglas de firewall. Este aislamiento es útil en varios escenarios, como la contenerización, donde cada contenedor debe tener su propia configuración de red, independiente de otros contenedores y del sistema host.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de red, comienza con una **pila de red completamente aislada**, sin **interfaces de red** excepto la interfaz de bucle local (lo). Esto significa que los procesos que se ejecutan en el nuevo espacio de nombres de red no pueden comunicarse con procesos en otros espacios de nombres o en el sistema host de forma predeterminada.
2. Se pueden crear **interfaces de red virtuales**, como pares veth, y moverlas entre espacios de nombres de red. Esto permite establecer conectividad de red entre espacios de nombres o entre un espacio de nombres y el sistema host. Por ejemplo, un extremo de un par veth se puede colocar en el espacio de nombres de red de un contenedor, y el otro extremo se puede conectar a un **puente** u otra interfaz de red en el espacio de nombres del host, proporcionando conectividad de red al contenedor.
3. Las interfaces de red dentro de un espacio de nombres pueden tener sus **propias direcciones IP, tablas de enrutamiento y reglas de firewall**, independientes de otros espacios de nombres. Esto permite que los procesos en diferentes espacios de nombres de red tengan diferentes configuraciones de red y operen como si estuvieran ejecutándose en sistemas de red separados.
4. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()`, o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWNET`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a usar la configuración de red e interfaces asociadas con ese espacio de nombres. 

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
# Run ifconfig or ip -a
```
### &#x20;Verificar en qué espacio de nombres está tu proceso
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Encontrar todos los espacios de nombres de red

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un namespace de red
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro namespace de proceso si eres root**. Y no puedes **entrar** en otro namespace **sin un descriptor** que apunte a él (como `/proc/self/ns/net`).
