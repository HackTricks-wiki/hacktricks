# Hacking dei sistemi di controllo industriale

{{#include ../banners/hacktricks-training.md}}

## Informazioni su questa sezione

Questa sezione introduce i componenti, le architetture, i protocolli e i metodi di valutazione della sicurezza dei sistemi di controllo industriale (ICS). Gli ICS fanno parte del più ampio dominio della tecnologia operativa (OT): sistemi e dispositivi programmabili che monitorano o provocano cambiamenti nei processi fisici. Esempi comuni includono i sistemi di supervisione, controllo e acquisizione dati (SCADA), i sistemi di controllo distribuito (DCS) e i controllori logici programmabili (PLC).<sup>[[1]](#references)</sup>

Le attività di sicurezza in questi ambienti devono considerare requisiti diversi da quelli dei tradizionali sistemi IT, tra cui la sicurezza dei processi, l'affidabilità, la disponibilità, il funzionamento deterministico e i cicli di vita delle apparecchiature. Una misura di sicurezza tecnicamente valida potrebbe comunque non essere adatta se interrompe il processo fisico: i test e la correzione dei problemi dovrebbero quindi essere coordinati con il proprietario del sistema e il personale operativo.<sup>[[1]](#references)</sup>

Una compromissione o un'interruzione accidentale può bloccare la produzione, danneggiare le apparecchiature, causare il rilascio di materiali pericolosi, nuocere all'ambiente o provocare lesioni e perdite di vite umane. Questo potenziale impatto fisico rende necessario comprendere il processo controllato e i suoi limiti operativi di sicurezza prima di iniziare qualsiasi test attivo.<sup>[[1]](#references)</sup>

Molte infrastrutture OT mantengono sistemi operativi, applicazioni e protocolli legacy perché le apparecchiature hanno una lunga vita utile e ogni modifica richiede test operativi e di sicurezza. Alcuni protocolli sono stati progettati senza autenticazione o crittografia moderne; inoltre, l'applicazione di patch può essere limitata dal supporto del vendor o dalle finestre di manutenzione. Quando gli aggiornamenti diretti non sono fattibili, è possibile compensare con segmentazione, controllo degli accessi e monitoraggio.<sup>[[1]](#references)</sup>

## Priorità di valutazione

Iniziate comprendendo il processo controllato, i confini del sistema, la topologia di rete, gli asset, i flussi di dati, le relazioni di fiducia e le connessioni esterne. Dispositivi simili possono svolgere funzioni diverse a seconda del sito: non date per scontato che l'architettura o il modello d'impatto di un'infrastruttura siano applicabili a un'altra.<sup>[[1]](#references)</sup>

Quando possibile, preferite la discovery passiva e la documentazione ingegneristica esistente. Qualsiasi scansione attiva o exploitation dovrebbe seguire un piano di test approvato, che definisca i vincoli di sicurezza, le finestre di manutenzione, le procedure di ripristino e le condizioni di arresto. I risultati dovrebbero essere valutati sia per il loro impatto sulla cybersecurity sia per i potenziali effetti sul processo fisico.<sup>[[1]](#references)</sup>

Le stesse conoscenze architetturali supportano attività difensive come l'inventario degli asset, la segmentazione di rete, il monitoraggio, la risposta agli incidenti e la gestione delle vulnerabilità basata sul rischio.<sup>[[1]](#references)</sup>

## Abuso del controllore di refrigerazione con supervisione

Un gestore di sistemi di refrigerazione coordina i controllori di compressori e banchi frigoriferi, ma non raffredda direttamente i banchi. L'accesso alla sua interfaccia di gestione può quindi consentire di controllare molti dispositivi subordinati tramite la normale distribuzione della configurazione. Questo è diverso dal modificare un singolo termostato o dal comandare direttamente un compressore.<sup>[[3]](#references)[[4]](#references)</sup>

### Login con codice di manutenzione derivato dalla data

Nei gestori di sistema Danfoss interessati, un login XML alternativo accetta un codice derivato dalla data del controllore anziché la password di un account.<sup>[[2]](#references)[[3]](#references)</sup> Su SM800 e SC255, Synacktiv ha seguito gli attributi `eds_only` e `quantum_only` attraverso `xml_load_file` e `check_authorize` fino a `check_code_of_day`. Il suo advisory mostra inoltre che `read_date_time` su `xml.cgi` divulga senza autenticazione la data del controllore.<sup>[[2]](#references)</sup> Claroty ha individuato un percorso `getauth` corrispondente sull'AK-SM 800A, ma ne ha oscurato gli attributi di attivazione; non si dovrebbe presumere che i nomi degli attributi dei modelli precedenti funzionino su quella piattaforma.<sup>[[3]](#references)</sup>

Synacktiv documenta come segue la richiesta della data senza autenticazione:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Il codice non contiene segreti specifici del dispositivo: recuperare l'algoritmo dal [firmware](../hardware-physical-access/firmware-analysis/) può consentire di ottenere una credenziale valida in base alla data per i dispositivi con la stessa implementazione vulnerabile.<sup>[[2]](#references)[[3]](#references)</sup> Verifica prima il modello e il firmware. Una risposta basata sulla data, da sola, non dimostra che sia disponibile il login alternativo né che sia stata ottenuta una sessione.

### Abuso della configurazione in blocco e delle resistenze di sbrinamento

Dopo aver ottenuto l'accesso amministrativo, individua i controller dei banchi frigoriferi associati al system manager e verifica se la sua funzione di distribuzione della configurazione può aggiornarli tutti insieme. Una modifica del setpoint del banco normalmente riscalda il mobile solo fino alla temperatura ambiente. Per riscaldarlo oltre la temperatura ambiente, il controllo pertinente è la resistenza elettrica di sbrinamento dell'evaporatore del controller del banco: lo sbrinamento interrompe il raffreddamento e attiva la resistenza finché un sensore o un timer non termina il ciclo. Modificare il metodo di sbrinamento, la pianificazione, la temperatura di fine ciclo e il limite di tempo può invece mantenere attiva la resistenza. Il manager può distribuire queste modifiche a molti banchi e sopprimere i relativi allarmi, trasformando la compromissione di un singolo sistema di supervisione in una modifica dei processi a livello dell'intero negozio.<sup>[[4]](#references)</sup>

Si tratta di un pericolo per il processo fisico, non di una prova di concetto sicura da eseguire su un sistema in produzione. Se presenti, gli interruttori termici possono limitare il funzionamento della resistenza, ma il funzionamento continuo può comunque surriscaldare un collegamento elettrico già deteriorato. Convalida la configurazione e l'impatto solo in un laboratorio autorizzato o seguendo il piano di sicurezza dei processi dell'operatore.<sup>[[4]](#references)</sup>

## Punti di accesso ai protocolli

- [Test di Modbus](../network-services-pentesting/pentesting-modbus.md) tratta Modbus TCP, le varianti seriali, i codici funzione e l'accesso ai registri.
- [Test di OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) tratta il servizio di scambio dati industriale.
- [Test di BACnet](../network-services-pentesting/47808-udp-bacnet.md) tratta le reti di controllo dell'automazione degli edifici.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guida alla sicurezza della tecnologia operativa (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Bypass dell'autenticazione nei System-Manager SM800 e SC255 di Danfoss](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Congelare il controller, scongelare gli alimenti](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Non serve uno stato-nazione per riscaldare un frigorifero](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
