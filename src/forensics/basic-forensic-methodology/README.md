# Metodologia Básica de Análise Forense

{{#include ../../banners/hacktricks-training.md}}

## Criando e Montando uma Imagem

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Análise de Malware

Isso **não é necessariamente o primeiro passo a ser realizado uma vez que você tenha a imagem**. Mas você pode usar essas técnicas de análise de malware de forma independente se tiver um arquivo, uma imagem de sistema de arquivos, imagem de memória, pcap... então é bom **manter essas ações em mente**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Inspecionando uma Imagem

Se você receber uma **imagem forense** de um dispositivo, pode começar **a analisar as partições, o sistema de arquivos** utilizado e **recuperar** potencialmente **arquivos interessantes** (mesmo os deletados). Aprenda como em:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Dependendo dos sistemas operacionais utilizados e até mesmo da plataforma, diferentes artefatos interessantes devem ser pesquisados:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Inspeção Profunda de Tipos de Arquivo e Software Específicos

Se você tiver um **arquivo** muito **suspeito**, então **dependendo do tipo de arquivo e do software** que o criou, vários **truques** podem ser úteis.\
Leia a página a seguir para aprender alguns truques interessantes:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Quero fazer uma menção especial à página:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspeção de Dump de Memória

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspeção de Pcap

{{#ref}}
pcap-inspection/
{{#endref}}

## **Técnicas Anti-Forenses**

Tenha em mente o possível uso de técnicas anti-forenses:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Caça a Ameaças

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
