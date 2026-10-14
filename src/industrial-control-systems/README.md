# Hacking dei sistemi di controllo industriale

{{#include ../banners/hacktricks-training.md}}

## Informazioni su questa sezione

Questa sezione presenta i componenti, le architetture, i protocolli e i metodi di valutazione della sicurezza dei sistemi di controllo industriale (ICS). Gli ICS fanno parte del più ampio ambito della tecnologia operativa (OT): sistemi e dispositivi programmabili che monitorano o modificano i processi fisici. Tra gli esempi più comuni vi sono i sistemi di controllo di supervisione e acquisizione dati (SCADA), i sistemi di controllo distribuito (DCS) e i controllori logici programmabili (PLC).<sup>[[1]](#references)</sup>

Le attività di sicurezza in questi ambienti devono tenere conto di requisiti diversi da quelli dell'IT tradizionale, tra cui la sicurezza dei processi, l'affidabilità, la disponibilità, il funzionamento deterministico e il ciclo di vita delle apparecchiature. Un controllo di sicurezza tecnicamente valido può comunque risultare inadatto se interrompe il processo fisico; pertanto, i test e le correzioni dovrebbero essere coordinati con il proprietario del sistema e il personale operativo.<sup>[[1]](#references)</sup>

Una compromissione o un'interruzione accidentale possono bloccare la produzione, danneggiare le apparecchiature, causare la fuoriuscita di materiali pericolosi, danneggiare l'ambiente o provocare lesioni e perdita di vite umane. Questo potenziale impatto fisico rende essenziale comprendere il processo controllato e i suoi limiti operativi di sicurezza prima di avviare qualsiasi test attivo.<sup>[[1]](#references)</sup>

Molte installazioni OT continuano a usare sistemi operativi, applicazioni e protocolli legacy, poiché le apparecchiature hanno una lunga vita utile e le modifiche richiedono test operativi e di sicurezza. Alcuni protocolli sono stati progettati senza autenticazione o cifratura moderne, e l'applicazione delle patch può essere limitata dal supporto del fornitore o dalle finestre di manutenzione; quando gli aggiornamenti diretti non sono praticabili, si può compensare con segmentazione, controllo degli accessi e monitoraggio.<sup>[[1]](#references)</sup>

## Priorità di valutazione

Inizia comprendendo il processo controllato, i confini del sistema, la topologia di rete, gli asset, i flussi di dati, le relazioni di fiducia e le connessioni esterne. Dispositivi simili possono svolgere funzioni diverse nei vari siti, quindi evita di presumere che l'architettura o il modello d'impatto di un'installazione siano validi anche per un'altra.<sup>[[1]](#references)</sup>

Quando possibile, prediligi l'individuazione passiva e la documentazione ingegneristica esistente. Qualsiasi scansione attiva o exploit dovrebbe attenersi a un piano di test approvato che definisca i vincoli di sicurezza, le finestre di manutenzione, le procedure di ripristino e le condizioni di interruzione. I risultati dovrebbero essere valutati sia per il loro impatto sulla cybersecurity sia per i potenziali effetti sul processo fisico.<sup>[[1]](#references)</sup>

Le stesse conoscenze architetturali supportano attività difensive come l'inventario degli asset, la segmentazione di rete, il monitoraggio, la risposta agli incidenti e la gestione delle vulnerabilità basata sul rischio.<sup>[[1]](#references)</sup>

## Punti di accesso ai protocolli

- [Test di Modbus](../network-services-pentesting/pentesting-modbus.md) tratta Modbus TCP, le varianti seriali, i codici funzione e l'accesso ai registri.
- [Test di OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) tratta il servizio di scambio dati industriale.
- [Test di BACnet](../network-services-pentesting/47808-udp-bacnet.md) tratta le reti di controllo dell'automazione degli edifici.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guida alla sicurezza della tecnologia operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
