# Analisi del dump di memoria

{{#include ../../../banners/hacktricks-training.md}}

## Inizio

Inizia a **cercare** **malware** all'interno del pcap. Usa gli **strumenti** menzionati in [**Analisi del Malware**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility è il principale framework open-source per l'analisi dei dump di memoria**. Questo strumento Python analizza i dump provenienti da fonti esterne o VM VMware, identificando dati come processi e password in base al profilo OS del dump. È estensibile con plugin, rendendolo altamente versatile per le indagini forensi.

**[Trova qui un cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Rapporto di crash mini dump

Quando il dump è piccolo (solo alcuni KB, forse qualche MB) allora probabilmente si tratta di un rapporto di crash mini dump e non di un dump di memoria.

![](<../../../images/image (216).png>)

Se hai Visual Studio installato, puoi aprire questo file e legare alcune informazioni di base come nome del processo, architettura, informazioni sull'eccezione e moduli in esecuzione:

![](<../../../images/image (217).png>)

Puoi anche caricare l'eccezione e vedere le istruzioni decompilate

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

Comunque, Visual Studio non è il miglior strumento per eseguire un'analisi approfondita del dump.

Dovresti **aprirlo** usando **IDA** o **Radare** per ispezionarlo in **profondità**.

​

{{#include ../../../banners/hacktricks-training.md}}
