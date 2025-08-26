# Metodologia Forense di Base

{{#include ../../banners/hacktricks-training.md}}

## Creazione e Montaggio di un'Immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi Malware

Questo **non è necessariamente il primo passo da eseguire una volta che hai l'immagine**. Però puoi usare queste tecniche di malware analysis in modo indipendente se hai un file, un file-system image, memory image, pcap... quindi è bene **tenere a mente queste azioni**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'Immagine

Se ti viene fornita un'**immagine forense** di un dispositivo puoi iniziare a **analizzare le partizioni, il file-system** usato e **recuperare** potenzialmente **file interessanti** (anche eliminati). Scopri come in:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Metodologia Forense di Base



## Creazione e Montaggio di un'Immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi Malware

Questo **non è necessariamente il primo passo da eseguire una volta che hai l'immagine**. Però puoi usare queste tecniche di malware analysis in modo indipendente se hai un file, un file-system image, memory image, pcap... quindi è bene **tenere a mente queste azioni**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'Immagine

Se ti viene fornita un'**immagine forense** di un dispositivo puoi iniziare a **analizzare le partizioni, il file-system** usato e **recuperare** potenzialmente **file interessanti** (anche eliminati). Scopri come in:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

A seconda dei sistemi operativi e della piattaforma usati, dovrebbero essere ricercati diversi artefatti interessanti:


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

## Ispezione approfondita di tipi di file e Software specifici

Se hai un file molto **sospetto**, allora **a seconda del file-type e del software** che lo ha creato, possono essere utili diversi **trucchi**.\
Leggi la pagina seguente per apprendere alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}

Voglio fare una menzione speciale alla pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione del memory dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione di pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Tecniche anti-forensi**

Tieni presente il possibile uso di tecniche anti-forensi:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## Ispezione approfondita di tipi di file e Software specifici

Se hai un file molto **sospetto**, allora **a seconda del file-type e del software** che lo ha creato, possono essere utili diversi **trucchi**.\
Leggi la pagina seguente per apprendere alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Voglio fare una menzione speciale alla pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione del memory dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione di pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Tecniche anti-forensi**

Tieni presente il possibile uso di tecniche anti-forensi:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
