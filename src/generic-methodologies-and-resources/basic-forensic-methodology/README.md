# Metodología forense básica

{{#include ../../banners/hacktricks-training.md}}

## Creación y montaje de una imagen


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Análisis de Malware

Esto **no es necesariamente el primer paso que se debe realizar una vez que se tiene la imagen**. Pero puedes utilizar estas técnicas de análisis de Malware de forma independiente si tienes un archivo, una imagen del sistema de archivos, una imagen de memoria, un pcap... por lo que es recomendable **tener estas acciones en cuenta**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspección de una imagen

si se te proporciona una **imagen forense** de un dispositivo, puedes empezar a **analizar las particiones y el sistema de archivos** utilizado, así como a **recuperar** posibles **archivos interesantes** (incluso archivos eliminados). Aprende cómo hacerlo en:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Según los sistemas operativos utilizados e incluso la plataforma, se deben buscar diferentes artefactos interesantes:


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

## Inspección profunda de tipos de archivos y Software específicos

Si tienes un **archivo** muy **sospechoso**, entonces, **dependiendo del tipo de archivo y del software** que lo creó, pueden ser útiles varios **trucos**.\
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

## **Técnicas anti-forenses**

Ten en cuenta el posible uso de técnicas anti-forenses:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
