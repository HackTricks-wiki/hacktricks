# Android Forensics

{{#include ../../banners/hacktricks-training.md}}

## Dispositivo bloqueado

Prefiere métodos de adquisición que preserven el estado del dispositivo y documenta cada acción. Si el dispositivo está bloqueado, las opciones disponibles dependen del modelo, la versión de Android, el nivel de parche y si se configuró el acceso antes de la incautación. NIST recomienda elegir un método según el dispositivo y la autoridad para el examen.<sup>[[1]](#references)</sup>

- Comprueba si la depuración USB estaba habilitada y si la estación de trabajo de adquisición ya estaba autorizada. El acceso ADB normalmente requiere que el usuario desbloquee el dispositivo y confirme la clave RSA de la estación de trabajo.<sup>[[3]](#references)</sup>
- Considera si el acceso biométrico sigue disponible según las normas legales y procesales aplicables.
- Un **smudge attack** puede revelar un patrón gráfico de desbloqueo a partir de los residuos en la pantalla, aunque los toques posteriores y la limpieza reducen su fiabilidad.<sup>[[2]](#references)</sup>
- Cuando las herramientas autorizadas sean compatibles con el dispositivo y la versión exactos del software, pueden intentar recuperar o aplicar fuerza bruta a un PIN, contraseña o patrón. La verificación de credenciales respaldada por hardware, los retrasos entre intentos y las políticas de borrado hacen que esto dependa mucho del dispositivo; por tanto, no sustituyas una técnica o un resultado de iPhone por pruebas de que un dispositivo Android es compatible.<sup>[[1]](#references)</sup>

## Adquisición de datos

En dispositivos antiguos, un [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) heredado puede generar un archivo `.backup` que Android Backup Extractor puede desempaquetar:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

No asumas que esto captura todas las aplicaciones. ADB etiqueta el comando como obsoleto, y Android 12 excluye los datos de las aplicaciones que tienen como objetivo el nivel de API 31 o posterior, a menos que la aplicación sea depurable.<sup>[[4]](#references)</sup>

### Acceso root o depuración física

Con acceso root a un dispositivo en ejecución, primero inventaría las particiones y los puntos de montaje; los comandos de abajo no se aplican directamente a una adquisición física por JTAG. El dispositivo de bloques correcto depende del hardware, así que no asumas que siempre es `mmcblk0`. Crea una imagen únicamente de la fuente verificada y guárdala en un almacenamiento separado:<sup>[[1]](#references)</sup>

En cambio, una adquisición por JTAG utiliza la interfaz de acceso de prueba de hardware del dispositivo y equipo de adquisición compatible para leer la memoria accesible. La distribución de pines, la compatibilidad con el chipset, el estado del dispositivo y la distinción entre objetivos volátiles y no volátiles dependen del dispositivo; documenta la ruta de hardware y utiliza un procedimiento validado para ese modelo.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Por ejemplo, si el inventario de particiones confirma que `/dev/block/mmcblk0` es todo el dispositivo flash y el destino tiene espacio suficiente, el comando de adquisición original queda así:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Aquí, `df /data` ayuda a asociar `/data` con su sistema de archivos montado; no debe considerarse una prueba de que `mmcblk0` sea la fuente correcta del dispositivo completo ni de que `4096` sea el único tamaño de bloque válido para `dd`.

Calcula el hash del resultado y registra el comando exacto, los identificadores del dispositivo, la hora y cualquier cambio realizado durante la adquisición.<sup>[[1]](#references)</sup>

### Memoria

LiME puede adquirir memoria física de Linux y de algunos dispositivos Android, pero su módulo del kernel debe compilarse para el kernel de destino y cargarse con privilegios suficientes. La firma de módulos, el bloqueo del kernel y las medidas de protección modernas de Android pueden impedir que se cargue.<sup>[[5]](#references)</sup>

El flujo de trabajo de Android del proyecto envía el módulo correspondiente mediante ADB, redirige un puerto TCP, carga el módulo desde una shell root y captura el flujo en el host de análisis:<sup>[[5]](#references)</sup>

```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```

LiME también puede escribir en el almacenamiento del dispositivo con `path=/sdcard/ram.lime`, pero esto modifica el almacenamiento del dispositivo y requiere suficiente espacio libre. Registra ese efecto secundario y calcula el hash de la imagen adquirida.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Directrices para el análisis forense de dispositivos móviles](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Ataques Smudge en pantallas táctiles de smartphones](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restricción de las copias de seguridad de ADB en Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
