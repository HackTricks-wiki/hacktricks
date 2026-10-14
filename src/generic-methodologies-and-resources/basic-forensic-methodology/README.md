# Metodologia di base per l'analisi forense

{{#include ../../banners/hacktricks-training.md}}

## Creazione e montaggio di un'immagine


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analisi del malware

**Non è necessariamente il primo passaggio da eseguire dopo aver ottenuto l'immagine**. Tuttavia, puoi usare queste tecniche di analisi del malware anche indipendentemente, se hai a disposizione un file, un'immagine del file system, un'immagine della memoria, un pcap... quindi è utile **tenerle a mente**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Esame di un'immagine

se ti viene fornita un'**immagine forense** di un dispositivo, puoi iniziare ad **analizzare le partizioni e il file system** utilizzato e a **recuperare** eventuali **file interessanti** (anche quelli eliminati). Scopri come qui:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

A seconda dei sistemi operativi utilizzati e persino della piattaforma, è opportuno cercare diversi artefatti interessanti:


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

Per un dispositivo Android bloccato, i metodi di acquisizione e l'acquisizione di immagini della memoria, consulta [Android forensics](android-forensics.md).

## Esame approfondito di tipi di file e software specifici

Se hai un **file** molto **sospetto**, possono essere utili diversi **trucchi**, a seconda del **tipo di file e del software** che lo ha creato.\
Leggi la pagina seguente per scoprire alcuni trucchi interessanti:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Vorrei menzionare in particolare la pagina:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Esame del dump della memoria


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Esame del pcap


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
