# Metodologia di base per l'analisi forense

{{#include ../../banners/hacktricks-training.md}}

## Creazione e montaggio di un'immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi del malware

Questa **non è necessariamente la prima operazione da eseguire una volta ottenuta l'immagine**. Tuttavia, puoi usare queste tecniche di analisi del malware in modo indipendente se hai a disposizione un file, un'immagine del file system, un'immagine della memoria, un pcap... quindi è utile **tenere a mente queste attività**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'immagine

se ti viene fornita un'**immagine forense** di un dispositivo, puoi iniziare ad **analizzare le partizioni e il file system** utilizzato e a **recuperare** potenzialmente **file interessanti** (anche quelli eliminati). Scopri come fare qui:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

A seconda dei sistemi operativi e persino della piattaforma utilizzata, è necessario cercare artefatti interessanti diversi:


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

Se hai un **file** molto **sospetto**, allora, **a seconda del tipo di file e del software** che lo ha creato, possono essere utili diversi **trucchi**.\
Leggi la pagina seguente per scoprire alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Vorrei fare una menzione speciale alla pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione di un dump della memoria


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione di un Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Tecniche anti-forensi**

Tieni a mente il possibile utilizzo di tecniche anti-forensi:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
