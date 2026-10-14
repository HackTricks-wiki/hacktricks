# Metodología básica de análisis forense

{{#include ../../banners/hacktricks-training.md}}

## Crear y montar una imagen


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Análisis de malware

**No es necesariamente el primer paso que hay que realizar una vez que tienes la imagen**. Pero puedes aplicar estas técnicas de análisis de malware de forma independiente si tienes un archivo, una imagen del sistema de archivos, una imagen de memoria, un pcap... así que es bueno **tener presentes estas acciones**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspeccionar una imagen

Si te proporcionan una **imagen forense** de un dispositivo, puedes empezar **analizando las particiones y el sistema de archivos** utilizados, y **recuperando** posibles **archivos interesantes** (incluso los eliminados). Aprende cómo hacerlo en:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Según los sistemas operativos y las plataformas utilizados, puede ser interesante buscar distintos artefactos:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

Para obtener información sobre la adquisición de datos de un dispositivo Android bloqueado, las rutas de adquisición y la creación de imágenes de memoria, consulta [análisis forense de Android](android-forensics.md).

## Inspección detallada de tipos de archivo y software específicos

Si tienes un **archivo** muy **sospechoso**, puede que te resulten útiles varios **trucos**, **según el tipo de archivo y el software** que lo haya creado.\
Lee la siguiente página para aprender algunos trucos interesantes:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Quiero hacer una mención especial a la página:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspección de volcados de memoria


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspección de Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Técnicas antiforenses**

Ten en cuenta el posible uso de técnicas antiforenses:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Caza de amenazas


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
