# Metodología Forense Básica

## Creación y Montaje de una Imagen


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Análisis de Malware

Esto **no es necesariamente el primer paso que se debe realizar una vez que tienes la imagen**. Pero puedes utilizar estas técnicas de análisis de malware de forma independiente si tienes un archivo, una imagen del sistema de archivos, una imagen de memoria, un pcap... por lo que es bueno **tener presentes estas acciones**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspección de una Imagen

si se te proporciona una **imagen forense** de un dispositivo, puedes comenzar a **analizar las particiones y el sistema de archivos** utilizado y **recuperar** potencialmente **archivos interesantes** (incluso archivos eliminados). Aprende cómo hacerlo en:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Dependiendo de los OS utilizados e incluso de la plataforma, se deben buscar diferentes artefactos interesantes:


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

## Inspección Profunda de Tipos de Archivo y Software Específicos

Si tienes un **archivo** muy **sospechoso**, entonces, **dependiendo del tipo de archivo y del software** que lo creó, varios **trucos** pueden resultar útiles.\
Lee la siguiente página para aprender algunos trucos interesantes:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Quiero hacer una mención especial a la página:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspección de Volcado de Memoria


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
