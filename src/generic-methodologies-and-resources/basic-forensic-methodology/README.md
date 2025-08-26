# Metodología Forense Básica

{{#include ../../banners/hacktricks-training.md}}

## Creación y Montaje de una Imagen


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Esto **no es necesariamente el primer paso a realizar una vez que tienes la imagen**. Pero puedes usar estas técnicas de malware analysis de forma independiente si tienes un archivo, una imagen de sistema de archivos, imagen de memoria, pcap... así que es bueno **tener estas acciones en mente**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspección de una Imagen

si te entregan una **imagen forense** de un dispositivo puedes empezar **a analizar las particiones, el sistema de archivos** usado y **recuperar** potencialmente **archivos interesantes** (incluso borrados). Aprende cómo en:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Metodología Forense Básica



## Creación y Montaje de una Imagen


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Esto **no es necesariamente el primer paso a realizar una vez que tienes la imagen**. Pero puedes usar estas técnicas de malware analysis de forma independiente si tienes un archivo, una imagen de sistema de archivos, imagen de memoria, pcap... así que es bueno **tener estas acciones en mente**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspección de una Imagen

si te entregan una **imagen forense** de un dispositivo puedes empezar **a analizar las particiones, el sistema de archivos** usado y **recuperar** potencialmente **archivos interesantes** (incluso borrados). Aprende cómo en:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Dependiendo de los OSs utilizados e incluso la plataforma, deberían buscarse diferentes artefactos interesantes:


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

Si tienes un archivo muy **sospechoso**, entonces **dependiendo del tipo de archivo y del software** que lo creó, varios **trucos** pueden ser útiles.\
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

## **Técnicas Anti-Forense**

Ten en cuenta el posible uso de técnicas anti-forense:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## Inspección profunda de tipos de archivo y Software específicos

Si tienes un archivo muy **sospechoso**, entonces **dependiendo del tipo de archivo y del software** que lo creó, varios **trucos** pueden ser útiles.\
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

## **Técnicas Anti-Forense**

Ten en cuenta el posible uso de técnicas anti-forense:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
