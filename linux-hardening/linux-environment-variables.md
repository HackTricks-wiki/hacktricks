# Variables de entorno de Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Variables globales

Las variables globales **serán** heredadas por los **procesos hijos**.

Puedes crear una variable global para tu sesión actual haciendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variable será accesible por las sesiones actuales y sus procesos hijos.

Puedes **eliminar** una variable haciendo:
```bash
unset MYGLOBAL
```
## Variables locales

Las **variables locales** solo pueden ser **accedidas** por la **shell/script actual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Listar las variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variables de entorno persistentes

#### **Archivos que afectan el comportamiento de todos los usuarios:**

* _**/etc/bash.bashrc**_: Este archivo se lee cada vez que se inicia una shell interactiva (terminal normal) y todos los comandos especificados aquí se ejecutan.
* _**/etc/profile y /etc/profile.d/\***_**:** Este archivo se lee cada vez que un usuario inicia sesión. Por lo tanto, todos los comandos ejecutados aquí se ejecutarán solo una vez en el momento del inicio de sesión del usuario.
  *   \*\*Ejemplo: \*\*

      `/etc/profile.d/somescript.sh`

      ```bash
      #!/bin/bash
      TEST=$(cat /var/somefile)
      export $TEST
      ```

#### **Archivos que afectan el comportamiento de un usuario específico:**

* _**\~/.bashrc**_: Este archivo funciona de la misma manera que el archivo _/etc/bash.bashrc_, pero se ejecuta solo para un usuario específico. Si desea crear un entorno para usted, modifique o cree este archivo en su directorio de inicio.
* _**\~/.profile, \~/.bash\_profile, \~/.bash\_login**_**:** Estos archivos son iguales a _/etc/profile_. La diferencia radica en la forma en que se ejecuta. Este archivo se ejecuta solo cuando un usuario en cuyo directorio de inicio existe este archivo inicia sesión.

**Extraído de:** [**aquí**](https://codeburst.io/linux-environment-variables-53cea0245dc9) **y** [**aquí**](https://www.gnu.org/software/bash/manual/html\_node/Bash-Startup-Files.html)

## Variables comunes

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – la pantalla utilizada por **X**. Esta variable suele establecerse en **:0.0**, lo que significa la primera pantalla en la computadora actual.
* **EDITOR** – el editor de texto preferido del usuario.
* **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de historial.
* \*\*HISTSIZE - \*\*Número de líneas agregadas al archivo de historial cuando el usuario finaliza su sesión.
* **HOME** – su directorio de inicio.
* **HOSTNAME** – el nombre de host de la computadora.
* **LANG** – su idioma actual.
* **MAIL** – la ubicación del buzón de correo del usuario. Por lo general, **/var/spool/mail/USER**.
* **MANPATH** – la lista de directorios para buscar páginas del manual.
* **OSTYPE** – el tipo de sistema operativo.
* **PS1** – el indicador predeterminado en bash.
* \*\*PATH - \*\*almacena la ruta de todos los directorios que contienen archivos binarios que desea ejecutar solo especificando el nombre del archivo y no por ruta relativa o absoluta.
* **PWD** – el directorio de trabajo actual.
* **SHELL** – la ruta a la shell de comando actual (por ejemplo, **/bin/bash**).
* **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
* **TZ** – su zona horaria.
* **USER** – su nombre de usuario actual.

## Variables interesantes para hacking

### **HISTFILESIZE**

Cambie el **valor de esta variable a 0**, para que cuando **finalice su sesión**, el **archivo de historial** (\~/.bash\_history) **se elimine**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, de esta manera cuando **finalices tu sesión** cualquier comando no será añadido al **archivo de historial** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Los procesos utilizarán el **proxy** declarado aquí para conectarse a internet a través de **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Cambia cómo se ve tu prompt.

He creado [**este**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808) (basado en otro, lee el código).

Root:

![](<../.gitbook/assets/image (87).png>)

Usuario regular:

![](<../.gitbook/assets/image (88).png>)

Uno, dos y tres trabajos en segundo plano:

![](<../.gitbook/assets/image (89).png>)

Un trabajo en segundo plano, uno detenido y el último comando no finalizó correctamente:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
