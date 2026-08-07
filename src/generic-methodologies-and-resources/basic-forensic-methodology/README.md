# Metodologia Básica de Forense

{{#include ../../banners/hacktricks-training.md}}

## Criando e Montando uma Imagem


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Análise de Malware

Isso **não é necessariamente o primeiro passo a ser executado depois que você tiver a imagem**. Porém, você pode usar estas técnicas de análise de malware de forma independente se tiver um arquivo, uma imagem de sistema de arquivos, uma imagem de memória, um pcap... portanto, é bom **manter estas ações em mente**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspecionando uma Imagem

se receber uma **imagem forense** de um dispositivo, você pode começar **analisando as partições e o sistema de arquivos** utilizado e **recuperando** possíveis **arquivos interessantes** (inclusive arquivos excluídos). Saiba como em:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Dependendo dos sistemas operacionais utilizados e até mesmo da plataforma, diferentes artefatos interessantes devem ser procurados:


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

## Inspeção detalhada de tipos de arquivo e Software específicos

Se você tiver um **arquivo** muito **suspeito**, então, **dependendo do tipo de arquivo e do software** que o criou, vários **truques** podem ser úteis.\
Leia a página a seguir para conhecer alguns truques interessantes:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Gostaria de fazer uma menção especial à página:


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

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
