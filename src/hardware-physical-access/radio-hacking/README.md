# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

I test di sicurezza radio esaminano come un dispositivo trasmette, riceve e interpreta i segnali wireless. Una radio definita via software (SDR) può aiutare a individuare un segnale, registrare campioni in fase/quadratura (I/Q) e testare demodulazione e decodifica senza dover ricorrere a hardware specifico per un protocollo.<sup>[[1]](#references)</sup>

Un flusso di lavoro pratico consiste nell'identificare la banda di frequenza e la larghezza del canale, acquisire diverse azioni note del dispositivo, confrontare i segnali risultanti e determinare quindi la modulazione e la struttura dei pacchetti. Testa la riproduzione o la trasmissione solo in un ambiente isolato e su frequenze e apparecchiature per cui hai l'autorizzazione. Le pagine di questa sezione trattano RFID, NFC, radio sub-GHz, infrarossi, BLE e strumenti correlati.<sup>[[1]](#references)</sup>

## Individua l'interfaccia pertinente

- Per un badge di accesso o una chiave contactless, inizia da [tipi di tag RFID/NFC e attacchi](pentesting-rfid.md), [flussi di lavoro con Proxmark3](proxmark-3.md) o [chiavi iButton e 1-Wire](ibutton.md). La [guida a Flipper Zero](flipper-zero/README.md) rimanda alle azioni specifiche per la sua interfaccia.
- Per un segnale di telecomando, usa [RF sub-GHz e rolling code](sub-ghz-rf.md) o [protocolli e attacchi a infrarossi](infrared.md).
- Per dispositivi e sensori nelle vicinanze, usa [test di advertising BLE, GATT e mesh](pentesting-ble-bluetooth-low-energy.md) o [sicurezza LPWAN/LoRaWAN](low-power-wide-area-network.md).
- Per segnali RF acquisiti o sconosciuti, usa [l'analisi dei segnali con SigDigger](../hardware-hacking/radio.md#sigdigger) o il [framework FISSURE](fissure-the-rf-framework.md).
- Per i downlink dei terminali satellitari, consulta [l'iniezione di segnali sul forward link VSAT](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Radio definita via software con HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
