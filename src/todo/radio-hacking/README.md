# Hacking radio

{{#include ../../banners/hacktricks-training.md}}

I test di sicurezza radio esaminano il modo in cui un dispositivo trasmette, riceve e interpreta i segnali wireless. Una software-defined radio (SDR) può aiutare a individuare un segnale, registrare campioni in fase/quadratura (I/Q) e testare demodulazione e decodifica senza dover utilizzare hardware specifico per il protocollo.<sup>[[1]](#references)</sup>

Un flusso di lavoro pratico consiste nell'identificare la banda di frequenza e l'ampiezza del canale, acquisire diverse azioni note del dispositivo, confrontare i segnali risultanti e determinare quindi la modulazione e la struttura dei pacchetti. Esegui test di replay o trasmissione solo in un ambiente isolato e su frequenze e apparecchiature per le quali disponi dell'autorizzazione. Le pagine di questa sezione trattano RFID, NFC, radio sub-GHz, infrarossi, BLE e strumenti correlati.<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - Radio definita via software con HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
