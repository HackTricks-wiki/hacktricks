# Metodología Forense Básica

{{#include ../../banners/hacktricks-training.md}}

## Creación y Montaje de una Imagen


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Análisis de Malware

Esto **no es necesariamente el primer paso que se debe realizar una vez que se tiene la imagen**. Pero puedes utilizar estas técnicas de análisis de malware de forma independiente si tienes un archivo, una imagen del sistema de archivos, una imagen de memoria, un pcap... por lo que es bueno **tener presentes estas acciones**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspección de una Imagen

si se te proporciona una **imagen forense** de un dispositivo, puedes comenzar a **analizar las particiones y el sistema de archivos** utilizado, así como a **recuperar** posibles **archivos interesantes** (incluso los eliminados). Aprende cómo hacerlo en:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Dependiendo de los sistemas operativos utilizados e incluso de la plataforma, se deben buscar diferentes artefactos interesantes:


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

## Inspección profunda de tipos de archivo y Software específicos

Si tienes un **archivo** muy **sospechoso**, entonces **dependiendo del tipo de archivo y del software** que lo creó, varios **trucos** pueden ser útiles.\
Lee la siguiente página para aprender algunos trucos interesantes:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Quiero hacer una mención especial a la página:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspección de Volcados de Memoria


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspección de Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Técnicas Anti-Forenses**

Ten en cuenta el posible uso de técnicas anti-forenses:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
