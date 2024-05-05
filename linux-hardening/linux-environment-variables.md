# Variables de entorno de Linux

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

**Grupo de Seguridad Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Variables globales

Las variables globales **serán** heredadas por los **procesos secundarios**.

Puedes crear una variable global para tu sesión actual haciendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variable será accesible por tus sesiones actuales y sus procesos hijos.

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
## Listar variables actuales

```bash
printenv
```
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variables comunes

Desde: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – la pantalla utilizada por **X**. Esta variable suele establecerse en **:0.0**, lo que significa la primera pantalla en la computadora actual.
* **EDITOR** – el editor de texto preferido del usuario.
* **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de historial.
* **HISTSIZE** – Número de líneas añadidas al archivo de historial cuando el usuario finaliza su sesión.
* **HOME** – tu directorio de inicio.
* **HOSTNAME** – el nombre de host de la computadora.
* **LANG** – tu idioma actual.
* **MAIL** – la ubicación del buzón de correo del usuario. Normalmente **/var/spool/mail/USUARIO**.
* **MANPATH** – la lista de directorios donde buscar páginas de manual.
* **OSTYPE** – el tipo de sistema operativo.
* **PS1** – el indicador predeterminado en bash.
* **PATH** – almacena la ruta de todos los directorios que contienen archivos binarios que deseas ejecutar solo especificando el nombre del archivo y no la ruta relativa o absoluta.
* **PWD** – el directorio de trabajo actual.
* **SHELL** – la ruta del shell de comandos actual (por ejemplo, **/bin/bash**).
* **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
* **TZ** – tu zona horaria.
* **USER** – tu nombre de usuario actual.

## Variables interesantes para hacking

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0**, de modo que cuando **finalices tu sesión** el **archivo de historial** (\~/.bash\_history) **se eliminará**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambie el **valor de esta variable a 0**, de modo que cuando **finalice su sesión** ningún comando se agregará al **archivo de historial** (\~/.bash\_history).
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

Cambia cómo se ve tu indicador.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Usuario regular:

![](<../.gitbook/assets/image (740).png>)

Uno, dos y tres trabajos en segundo plano:

![](<../.gitbook/assets/image (145).png>)

Un trabajo en segundo plano, uno detenido y el último comando no finalizó correctamente:

![](<../.gitbook/assets/image (715).png>)

**Grupo de Seguridad Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
