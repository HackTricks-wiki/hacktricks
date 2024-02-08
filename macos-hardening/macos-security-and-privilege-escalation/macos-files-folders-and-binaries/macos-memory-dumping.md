# Volcado de memoria de macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Artefactos de memoria

### Archivos de intercambio

Los archivos de intercambio, como `/private/var/vm/swapfile0`, sirven como **cachés cuando la memoria física está llena**. Cuando ya no hay espacio en la memoria física, sus datos se transfieren a un archivo de intercambio y luego se devuelven a la memoria física según sea necesario. Pueden estar presentes varios archivos de intercambio, con nombres como swapfile0, swapfile1, y así sucesivamente.

### Imagen de hibernación

El archivo ubicado en `/private/var/vm/sleepimage` es crucial durante el **modo de hibernación**. **Los datos de la memoria se almacenan en este archivo cuando macOS hiberna**. Al despertar la computadora, el sistema recupera los datos de la memoria de este archivo, lo que permite al usuario continuar donde lo dejó.

Cabe destacar que en los sistemas macOS modernos, este archivo suele estar encriptado por razones de seguridad, lo que dificulta la recuperación.

* Para verificar si la encriptación está habilitada para sleepimage, se puede ejecutar el comando `sysctl vm.swapusage`. Esto mostrará si el archivo está encriptado.

### Registros de presión de memoria

Otro archivo importante relacionado con la memoria en los sistemas macOS son los **registros de presión de memoria**. Estos registros se encuentran en `/var/log` y contienen información detallada sobre el uso de memoria del sistema y eventos de presión. Pueden ser particularmente útiles para diagnosticar problemas relacionados con la memoria o comprender cómo el sistema gestiona la memoria con el tiempo.

## Volcado de memoria con osxpmem

Para volcar la memoria en una máquina macOS, puedes utilizar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Las siguientes instrucciones solo funcionarán para Macs con arquitectura Intel. Esta herramienta está ahora archivada y la última versión fue en 2017. El binario descargado utilizando las instrucciones a continuación apunta a chips Intel ya que Apple Silicon no existía en 2017. Puede ser posible compilar el binario para la arquitectura arm64, pero tendrás que intentarlo por ti mismo.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si encuentras este error: `osxpmem.app/MacPmem.kext no se pudo cargar - (libkern/kext) fallo de autenticación (propietario/permisos de archivo); verifica los registros del sistema/núcleo en busca de errores o intenta con kextutil(8)` Puedes solucionarlo haciendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Otros errores** podrían ser solucionados al **permitir la carga del kext** en "Seguridad y privacidad --> General", simplemente **permítelo**.

También puedes usar este **oneliner** para descargar la aplicación, cargar el kext y volcar la memoria:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
