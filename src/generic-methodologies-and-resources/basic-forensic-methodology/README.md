# Metodologia di base della computer forensics

{{#include ../../banners/hacktricks-training.md}}

## Creazione e montaggio di un'immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi del malware

Questo **non è necessariamente il primo passaggio da eseguire dopo aver ottenuto l'immagine**. Tuttavia, puoi utilizzare queste tecniche di analisi del malware indipendentemente se hai un file, un'immagine del file system, un'immagine della memoria, un pcap... quindi è utile **tenere a mente queste azioni**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ispezione di un'immagine

se ti viene fornita un'**immagine forense** di un dispositivo, puoi iniziare ad **analizzare le partizioni e il file system** utilizzato e a **recuperare** potenzialmente **file interessanti** (anche quelli eliminati). Scopri come fare in:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

A seconda dei sistemi operativi utilizzati e persino della piattaforma, è necessario cercare artefatti interessanti diversi:


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

Se hai un **file** molto **sospetto**, allora, **a seconda del tipo di file e del software** che lo ha creato, diversi **trucchi** possono essere utili.\
Leggi la pagina seguente per scoprire alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Vorrei fare una menzione speciale alla pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ispezione dei dump della memoria


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ispezione dei Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Tecniche anti-forensi**

Tieni presente il possibile utilizzo di tecniche anti-forensi:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
