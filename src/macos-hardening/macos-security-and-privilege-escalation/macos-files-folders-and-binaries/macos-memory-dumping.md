# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Los archivos de intercambio, como `/private/var/vm/swapfile0`, sirven como **cachés cuando la memoria física está llena**. Cuando no hay más espacio en la memoria física, sus datos se transfieren a un archivo de intercambio y luego se traen de vuelta a la memoria física según sea necesario. Pueden estar presentes múltiples archivos de intercambio, con nombres como swapfile0, swapfile1, y así sucesivamente.

### Hibernate Image

El archivo ubicado en `/private/var/vm/sleepimage` es crucial durante **el modo de hibernación**. **Los datos de la memoria se almacenan en este archivo cuando OS X hiberna**. Al despertar la computadora, el sistema recupera los datos de la memoria de este archivo, permitiendo al usuario continuar donde lo dejó.

Vale la pena señalar que en los sistemas MacOS modernos, este archivo está típicamente cifrado por razones de seguridad, lo que dificulta la recuperación.

- Para verificar si el cifrado está habilitado para el sleepimage, se puede ejecutar el comando `sysctl vm.swapusage`. Esto mostrará si el archivo está cifrado.

### Memory Pressure Logs

Otro archivo importante relacionado con la memoria en los sistemas MacOS es el **registro de presión de memoria**. Estos registros se encuentran en `/var/log` y contienen información detallada sobre el uso de memoria del sistema y eventos de presión. Pueden ser particularmente útiles para diagnosticar problemas relacionados con la memoria o entender cómo el sistema gestiona la memoria a lo largo del tiempo.

## Dumping memory with osxpmem

Para volcar la memoria en una máquina MacOS, puedes usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Las siguientes instrucciones solo funcionarán para Macs con arquitectura Intel. Esta herramienta ahora está archivada y la última versión fue en 2017. El binario descargado utilizando las instrucciones a continuación está dirigido a chips Intel, ya que Apple Silicon no existía en 2017. Puede ser posible compilar el binario para arquitectura arm64, pero tendrás que intentarlo por ti mismo.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si encuentras este error: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Puedes solucionarlo haciendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Otros errores** pueden ser corregidos **permitiendo la carga del kext** en "Seguridad y Privacidad --> General", solo **permítelo**.

También puedes usar este **oneliner** para descargar la aplicación, cargar el kext y volcar la memoria:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
