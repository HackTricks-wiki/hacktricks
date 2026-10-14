# Metodologia Básica de Forense

{{#include ../../banners/hacktricks-training.md}}

## Criar e Montar uma Imagem


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Análise de Malware

Isso **não é necessariamente a primeira etapa a ser realizada depois que você obtém a imagem**. Mas você pode usar estas técnicas de análise de malware de forma independente se tiver um arquivo, uma imagem de sistema de arquivos, uma imagem de memória, um pcap... então é bom **ter estas ações em mente**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspecionar uma Imagem

se você receber uma **imagem forense** de um dispositivo, poderá começar **analisando as partições e o sistema de arquivos** utilizado e **recuperando** arquivos potencialmente **interessantes** (inclusive os excluídos). Saiba como em:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Dependendo dos sistemas operacionais e até mesmo da plataforma utilizados, devem ser procurados diferentes artefatos interessantes:


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

Para um dispositivo Android bloqueado, métodos de aquisição e criação de imagens de memória, consulte [forense Android](android-forensics.md).

## Inspeção aprofundada de tipos de arquivo e softwares específicos

Se você tiver um **arquivo** muito **suspeito**, dependendo do **tipo de arquivo e do software** que o criou, vários **truques** podem ser úteis.\
Leia a página a seguir para conhecer alguns truques interessantes:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Quero dar destaque especial à página:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspeção de Dumps de Memória


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspeção de Pcaps


{{#ref}}
pcap-inspection/
{{#endref}}

## **Técnicas Antiforenses**

Tenha em mente a possibilidade de uso de técnicas antiforenses:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Caça a Ameaças


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
