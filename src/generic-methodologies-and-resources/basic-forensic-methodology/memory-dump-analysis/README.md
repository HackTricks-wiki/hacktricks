# Analisi del memory dump

{{#include ../../../banners/hacktricks-training.md}}

## Inizio

Inizia a **cercare** **malware** all'interno del pcap. Usa gli **strumenti** menzionati in [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility è un framework open source per l'analisi dei memory dump**. Questo strumento Python analizza i dump provenienti da fonti esterne o da VM VMware, identificando dati come processi e password in base al profilo del sistema operativo del dump. È estensibile tramite plugin, il che lo rende estremamente versatile per le analisi forensi.<sup>[[1]](#references)[[2]](#references)</sup>

[**Trova qui una cheatsheet**](volatility-cheatsheet.md)

## Report di crash del minidump

Quando il dump è di piccole dimensioni (solo alcuni KB, magari pochi MB), potrebbe trattarsi di un report di crash del minidump anziché di un memory dump completo.<sup>[[3]](#references)</sup>

![Volatility - Report di crash del minidump: un piccolo file di dump identificato come report di crash Mini DuMP](<../../../images/image (532).png>)

Se hai Visual Studio installato, puoi aprire questo file per visualizzare informazioni di base come il nome del processo, l'architettura, i dettagli dell'eccezione e i moduli caricati:<sup>[[4]](#references)</sup>

![Volatility - Report di crash del minidump: se hai Visual Studio installato, puoi aprire questo file e visualizzare alcune informazioni di base come il nome del processo, l'architettura, le informazioni sull'eccezione e...](<../../../images/image (263).png>)

Puoi anche esaminare l'eccezione e visualizzare il disassembly del modulo.<sup>[[4]](#references)</sup>

![Pannello Azioni di Visual Studio per il minidump, con opzioni per eseguire il debug nativo e impostare i percorsi dei simboli](<../../../images/image (142).png>)

![Disassembly di Visual Studio delle istruzioni relative all'eccezione del minidump](<../../../images/image (610).png>)

In ogni caso, Visual Studio non è lo strumento migliore per eseguire un'analisi approfondita del dump.

Dovresti **aprirlo** usando **IDA** o **Radare** per ispezionarlo in **profondità**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Utilizzo di Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [File Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Utilizzare i file di dump nel debugger di Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
