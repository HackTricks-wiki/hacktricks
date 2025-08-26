# Metodologia Forense di Base

{{#include ../../banners/hacktricks-training.md}}

## Creazione e Montaggio di un'Immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi del Malware

Questo **non è necessariamente il primo passo da eseguire una volta ottenuta l'immagine**. Ma puoi usare queste tecniche di analisi del malware in modo indipendente se hai un file, un'immagine del file-system, un'immagine di memoria, pcap... quindi è utile **tenere queste azioni a mente**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'Immagine

Se ti viene fornita un'**immagine forense** di un dispositivo puoi iniziare a **analizzare le partizioni, il file-system** usato e **recuperare** potenzialmente **file interessanti** (anche cancellati). Impara come in:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Metodologia Forense di Base



## Creazione e Montaggio di un'Immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi del Malware

Questo **non è necessariamente il primo passo da eseguire una volta ottenuta l'immagine**. Ma puoi usare queste tecniche di analisi del malware in modo indipendente se hai un file, un'immagine del file-system, un'immagine di memoria, pcap... quindi è utile **tenere queste azioni a mente**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'Immagine

Se ti viene fornita un'**immagine forense** di un dispositivo puoi iniziare a **analizzare le partizioni, il file-system** usato e **recuperare** potenzialmente **file interessanti** (anche cancellati). Impara come in:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

A seconda degli OS e della piattaforma utilizzata, vanno cercati diversi artefatti interessanti:


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

Se hai un file molto **sospetto**, allora **a seconda del tipo di file e del software** che lo ha creato diversi **trucchi** possono essere utili.\
Leggi la pagina seguente per imparare alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Faccio una menzione speciale alla pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione del Memory Dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione del Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Tecniche Anti-Forensi**

Tieni presente l'eventuale uso di tecniche anti-forensi:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## Ispezione approfondita di tipi di file e Software specifici

Se hai un file molto **sospetto**, allora **a seconda del tipo di file e del software** che lo ha creato diversi **trucchi** possono essere utili.\
Leggi la pagina seguente per imparare alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Faccio una menzione speciale alla pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione del Memory Dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione del Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Tecniche Anti-Forensi**

Tieni presente l'eventuale uso di tecniche anti-forensi:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
