# Metodologia Forense di Base

{{#include ../../banners/hacktricks-training.md}}

## Creazione e Montaggio di un'Immagine

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi del Malware

Questo **non è necessariamente il primo passo da eseguire una volta ottenuta l'immagine**. Ma puoi utilizzare queste tecniche di analisi del malware in modo indipendente se hai un file, un'immagine del file system, un'immagine della memoria, pcap... quindi è bene **tenere a mente queste azioni**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'Immagine

Se ti viene fornita un'**immagine forense** di un dispositivo, puoi iniziare **ad analizzare le partizioni, il file-system** utilizzato e **recuperare** potenzialmente **file interessanti** (anche quelli eliminati). Scopri come in:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

A seconda dei sistemi operativi utilizzati e persino della piattaforma, dovrebbero essere cercati diversi artefatti interessanti:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Ispezione Approfondita di Tipi di File e Software Specifici

Se hai un **file** molto **sospetto**, allora **a seconda del tipo di file e del software** che lo ha creato, potrebbero essere utili diversi **trucchi**.\
Leggi la pagina seguente per scoprire alcuni trucchi interessanti:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Voglio fare una menzione speciale alla pagina:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione del Dump di Memoria

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione Pcap

{{#ref}}
pcap-inspection/
{{#endref}}

## **Tecniche Anti-Forensi**

Tieni a mente il possibile uso di tecniche anti-forensi:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Ricerca di Minacce

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
