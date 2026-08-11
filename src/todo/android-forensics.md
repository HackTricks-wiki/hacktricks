# Análisis forense de Android

{{#include ../banners/hacktricks-training.md}}

## Dispositivo bloqueado

Prioriza los métodos de adquisición que preserven el estado del dispositivo y documenta cada acción. Si el dispositivo está bloqueado, las opciones disponibles dependen del modelo, la versión de Android, el nivel de parche y de si el acceso se configuró antes de la incautación. NIST recomienda elegir un método de acuerdo con el dispositivo y la autoridad para el examen.<sup>[[1]](#references)</sup>

- Comprueba si la depuración USB estaba habilitada y si la estación de trabajo de adquisición ya estaba autorizada. El acceso mediante ADB normalmente requiere que el usuario desbloquee el dispositivo y confirme la clave RSA de la estación de trabajo.<sup>[[3]](#references)</sup>
- Considera si el acceso biométrico sigue disponible conforme a las normas legales y procedimentales aplicables.
- Un **smudge attack** puede revelar un patrón gráfico de desbloqueo a partir de los residuos en la pantalla, aunque los toques posteriores y la limpieza reducen su fiabilidad.<sup>[[2]](#references)</sup>
- Utiliza herramientas comerciales o de investigación para el bypass del bloqueo únicamente cuando indiquen explícitamente que son compatibles con el dispositivo y la compilación de software exactos.

## Adquisición de datos

En dispositivos antiguos, un [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) heredado puede producir un archivo `.backup` que Android Backup Extractor puede desempaquetar:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
No asumas que esto captura todas las aplicaciones. ADB etiqueta el comando como obsoleto, y Android 12 excluye los datos de las aplicaciones destinadas al nivel de API 31 o posterior, a menos que la aplicación sea depurable.<sup>[[4]](#references)</sup>

### Acceso root o de depuración física

Con acceso root a un dispositivo en funcionamiento, primero haz un inventario de las particiones y los montajes; los comandos siguientes no se aplican directamente a una adquisición física mediante JTAG. El dispositivo de bloques correcto depende del hardware, así que no asumas que siempre es `mmcblk0`. Crea una imagen únicamente de la fuente verificada en un almacenamiento separado:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Hashea el resultado y registra el comando exacto, los identificadores del dispositivo, la hora y cualquier cambio realizado durante la adquisición.<sup>[[1]](#references)</sup>

### Memoria

LiME puede adquirir memoria física de Linux y algunos dispositivos Android, pero su kernel module debe compilarse para el kernel objetivo y cargarse con privilegios suficientes. La firma de módulos, el kernel lockdown y las medidas de hardening modernas de Android pueden impedir su carga.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Directrices sobre análisis forense de dispositivos móviles](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Ataques Smudge en pantallas táctiles de smartphones](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restricción de copias de seguridad ADB de Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
