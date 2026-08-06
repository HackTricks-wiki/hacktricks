# Analisi del memory dump

{{#include ../../../banners/hacktricks-training.md}}

## Inizio

Inizia a **cercare** **malware** all'interno del pcap. Usa gli **strumenti** menzionati in [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility è il principale framework open-source per l'analisi dei memory dump**. Questo tool Python analizza i dump provenienti da fonti esterne o da VM VMware, identificando dati come processi e password in base al profilo del sistema operativo del dump. È estensibile tramite plugin, il che lo rende molto versatile per le indagini forensi.

[**Trova qui una cheatsheet**](volatility-cheatsheet.md)

## Report di crash di un mini dump

Quando il dump è di piccole dimensioni (solo alcuni KB, forse pochi MB), probabilmente si tratta di un report di crash di un mini dump e non di un memory dump.

![Volatility - Report di crash di un mini dump: quando il dump è di piccole dimensioni (solo alcuni KB, forse pochi MB), probabilmente si tratta di un report di crash di un mini dump e non di un memory dump](<../../../images/image (532).png>)

Se hai Visual Studio installato, puoi aprire questo file e visualizzare alcune informazioni di base come il nome del processo, l'architettura, le informazioni sull'eccezione e i moduli in esecuzione:

![Volatility - Report di crash di un mini dump: se hai Visual Studio installato, puoi aprire questo file e visualizzare alcune informazioni di base come il nome del processo, l'architettura, le informazioni sull'eccezione e...](<../../../images/image (263).png>)

Puoi anche caricare l'eccezione e visualizzare le istruzioni decompilate

![Volatility - Report di crash di un mini dump: puoi anche caricare l'eccezione e visualizzare le istruzioni decompilate](<../../../images/image (142).png>)

![Volatility - Report di crash di un mini dump: puoi anche caricare l'eccezione e visualizzare le istruzioni decompilate](<../../../images/image (610).png>)

In ogni caso, Visual Studio non è il tool migliore per eseguire un'analisi approfondita del dump.

Dovresti **aprirlo** usando **IDA** o **Radare** per ispezionarlo **in profondità**.

{{#include ../../../banners/hacktricks-training.md}}
