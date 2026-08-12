# Hacking dei sistemi di controllo industriale

{{#include ../../banners/hacktricks-training.md}}

## Informazioni su questa sezione

Questa sezione introduce i componenti, le architetture, i protocolli e i metodi di valutazione della sicurezza dei sistemi di controllo industriale (ICS). Gli ICS fanno parte del più ampio dominio della tecnologia operativa (OT): sistemi e dispositivi programmabili che monitorano o causano cambiamenti nei processi fisici. Esempi comuni includono i sistemi di supervisione, controllo e acquisizione dati (SCADA), i sistemi di controllo distribuito (DCS) e i controllori logici programmabili (PLC).<sup>[[1]](#references)</sup>

Il lavoro sulla sicurezza in questi ambienti deve tenere conto di requisiti diversi da quelli dell'IT convenzionale, tra cui sicurezza del processo, affidabilità, disponibilità, funzionamento deterministico e cicli di vita delle apparecchiature. Un controllo di sicurezza tecnicamente valido può comunque risultare inadatto se interrompe il processo fisico; pertanto, i test e la remediation devono essere coordinati con il proprietario del sistema e con il personale operativo.<sup>[[1]](#references)</sup>

Una compromissione o un'interruzione accidentale possono fermare la produzione, danneggiare le apparecchiature, causare il rilascio di materiali pericolosi, danneggiare l'ambiente o provocare lesioni e perdite di vite umane. Questo potenziale impatto fisico spiega perché la comprensione del processo controllato e dei suoi limiti operativi sicuri debba precedere qualsiasi active testing.<sup>[[1]](#references)</sup>

Molte implementazioni OT mantengono sistemi operativi, applicazioni e protocolli legacy perché le apparecchiature hanno una lunga vita utile e le modifiche richiedono test operativi e di sicurezza. Alcuni protocolli sono stati progettati senza autenticazione o crittografia moderne, mentre il patching può essere limitato dal supporto del vendor o dalle finestre di manutenzione; ove gli upgrade diretti non siano fattibili, è necessario compensare con segmentazione, controllo degli accessi e monitoring.<sup>[[1]](#references)</sup>

## Priorità della valutazione

Iniziare comprendendo il processo controllato, i confini del sistema, la topologia di rete, gli asset, i flussi di dati, le relazioni di trust e le connessioni esterne. Tipi di dispositivi simili possono svolgere funzioni diverse in siti differenti; evitare quindi di presumere che l'architettura o il modello di impatto di un'implementazione si applichino a un'altra.<sup>[[1]](#references)</sup>

Preferire, ove possibile, la discovery passiva e la documentazione di engineering esistente. Qualsiasi active scanning o exploitation deve seguire un test plan approvato che definisca i vincoli di sicurezza, le finestre di manutenzione, le procedure di recovery e le condizioni di arresto. I finding devono essere valutati sia per l'impatto sulla cybersecurity sia per i potenziali effetti sul processo fisico.<sup>[[1]](#references)</sup>

Le stesse conoscenze architetturali supportano attività difensive quali l'inventario degli asset, la segmentazione di rete, il monitoring, l'incident response e la gestione delle vulnerabilità basata sul rischio.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Guida alla sicurezza della tecnologia operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
