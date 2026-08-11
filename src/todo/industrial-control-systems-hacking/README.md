# Hacking dei sistemi di controllo industriale

{{#include ../../banners/hacktricks-training.md}}

## Informazioni su questa sezione

Questa sezione presenta i componenti, le architetture, i protocolli e i metodi di valutazione della sicurezza dei sistemi di controllo industriale (ICS). Gli ICS fanno parte del più ampio dominio della tecnologia operativa (OT): sistemi e dispositivi programmabili che monitorano o provocano modifiche nei processi fisici. Esempi comuni includono i sistemi di controllo e acquisizione dati (SCADA), i sistemi di controllo distribuito (DCS) e i controllori logici programmabili (PLC).<sup>[[1]](#references)</sup>

Il lavoro sulla sicurezza in questi ambienti deve tenere conto di requisiti diversi da quelli dell'IT convenzionale, tra cui la sicurezza del processo, l'affidabilità, la disponibilità, il funzionamento deterministico e i cicli di vita delle apparecchiature. Un controllo di sicurezza tecnicamente valido potrebbe comunque non essere adatto se interrompe il processo fisico; pertanto, i test e la remediation dovrebbero essere coordinati con il responsabile del sistema e con il personale operativo.<sup>[[1]](#references)</sup>

## Priorità della valutazione

Iniziare comprendendo il processo controllato, i confini del sistema, la topologia di rete, gli asset, i flussi di dati, le relazioni di trust e le connessioni esterne. Tipi di dispositivi simili possono svolgere funzioni diverse in siti differenti; pertanto, evitare di presumere che l'architettura o il modello d'impatto di un deployment si applichi a un altro.<sup>[[1]](#references)</sup>

Preferire, ove possibile, la discovery passiva e la documentazione ingegneristica esistente. Qualsiasi scansione attiva o exploitation dovrebbe seguire un test plan approvato che definisca i vincoli di sicurezza, le finestre di manutenzione, le procedure di recovery e le condizioni di arresto. I finding dovrebbero essere valutati sia in base all'impatto sulla cybersecurity sia ai potenziali effetti sul processo fisico.<sup>[[1]](#references)</sup>

Le stesse conoscenze architetturali supportano attività difensive come l'inventario degli asset, la segmentazione di rete, il monitoring, l'incident response e la gestione delle vulnerabilità basata sul rischio.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Guida alla sicurezza della tecnologia operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
