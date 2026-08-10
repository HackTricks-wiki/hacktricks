# Metodologia di base dell'analisi forense

## Creazione e montaggio di un'immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi del malware

Questo **non è necessariamente il primo passaggio da eseguire una volta ottenuta l'immagine**. Tuttavia, puoi utilizzare queste tecniche di analisi del malware in modo indipendente se disponi di un file, di un'immagine del file-system, di un'immagine della memoria, di un pcap... quindi è utile **tenere a mente queste azioni**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'immagine

se ti viene fornita un'**immagine forense** di un dispositivo, puoi iniziare ad **analizzare le partizioni e il file-system** utilizzati e a **recuperare** potenzialmente **file interessanti** (anche quelli eliminati). Scopri come:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

A seconda degli OS utilizzati e persino della piattaforma, è necessario cercare diversi artefatti interessanti:


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

Se disponi di un **file** molto **sospetto**, allora, **a seconda del tipo di file e del software** che lo ha creato, possono essere utili diversi **trucchi**.\
Leggi la pagina seguente per scoprire alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Voglio fare una menzione speciale alla pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione del dump della memoria


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione di Pcap


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

## References

{{#include ../../banners/hacktricks-training.md}}
