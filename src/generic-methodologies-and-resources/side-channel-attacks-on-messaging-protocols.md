# Attacchi Side-Channel delle Ricevute di Consegna nei Messenger E2EE

Le ricevute di consegna sono obbligatorie nei moderni messenger end-to-end encrypted (E2EE), perché i client devono sapere quando un ciphertext è stato decrittato, così da poter eliminare lo stato del ratchet e le chiavi effimere. Il server inoltra blob opachi, quindi gli acknowledgement dei dispositivi (doppie spunte) vengono emessi dal destinatario dopo una decrittazione riuscita. Misurare il round-trip time (RTT) tra un'azione attivata dall'attaccante e la relativa ricevuta di consegna espone un canale temporale ad alta risoluzione che fa leak dello stato del dispositivo e della presenza online, e può essere abusato per un DoS covert. Le implementazioni multi-device con "client-fanout" amplificano il leak, perché ogni dispositivo registrato decritta la probe e restituisce la propria ricevuta.<sup>[[1]](#references)</sup>

## Sorgenti delle ricevute di consegna vs. segnali visibili all'utente

Scegli tipi di messaggi che emettono sempre una ricevuta di consegna, ma non mostrano elementi nella UI della vittima. La tabella seguente riassume il comportamento confermato empiricamente:<sup>[[1]](#references)</sup>

| Messenger | Azione | Ricevuta di consegna | Notifica alla vittima | Note |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Messaggio di testo | ● | ● | Sempre rumoroso → utile solo per inizializzare lo stato. |
| | Reazione | ● | ◐ (solo reagendo al messaggio della vittima) | Le autoreazioni e le rimozioni rimangono silenziose. |
| | Modifica | ● | Push silenziosa dipendente dalla piattaforma | Finestra di modifica ≈20 min; riceve comunque l'ack dopo la scadenza. |
| | Elimina per tutti | ● | ○ | La UI consente ~60 h, ma i pacchetti successivi ricevono comunque l'ack. |
| **Signal** | Messaggio di testo | ● | ● | Stesse limitazioni di WhatsApp. |
| | Reazione | ● | ◐ | Le autoreazioni sono invisibili alla vittima. |
| | Modifica/Eliminazione | ● | ○ | Il server applica una finestra di ~48 h, consente fino a 10 modifiche, ma i pacchetti tardivi ricevono comunque l'ack. |
| **Threema** | Messaggio di testo | ● | ● | Le ricevute multi-device sono aggregate, quindi per ogni probe diventa visibile un solo RTT. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. Il comportamento della UI dipendente dalla piattaforma è indicato nelle note. Disabilita le read receipts se necessario, ma le delivery receipts non possono essere disattivate in WhatsApp o Signal.<sup>[[1]](#references)</sup>

## Obiettivi e modelli dell'attaccante

* **G1 – Fingerprinting dei dispositivi:** Conta quante ricevute arrivano per ogni probe, raggruppa gli RTT per dedurre il sistema operativo/client (Android vs iOS vs desktop) e osserva le transizioni online/offline.
* **G2 – Monitoraggio comportamentale:** Tratta la serie di RTT ad alta frequenza (≈1 Hz è stabile) come una serie temporale e deduci schermo acceso/spento, app in foreground/background, orari di spostamento rispetto agli orari di lavoro, ecc.
* **G3 – Esaurimento delle risorse:** Mantieni attive radio/CPU di ogni dispositivo della vittima inviando probe silenziose senza fine, consumando batteria/dati e degradando la qualità delle videochiamate.<sup>[[1]](#references)</sup>

Due threat actor sono sufficienti per descrivere la superficie di abuso:<sup>[[1]](#references)</sup>

1. **Compagno inquietante:** Condivide già una chat con la vittima e abusa di autoreazioni, rimozioni di reazioni o modifiche/eliminazioni ripetute associate a ID di messaggi esistenti.
2. **Sconosciuto inquietante:** Registra un burner account e invia reazioni che fanno riferimento a ID di messaggi mai esistiti nella conversazione locale; WhatsApp e Signal li decrittano e inviano comunque l'ack, anche se la UI scarta il cambiamento di stato, quindi non è necessaria una conversazione precedente.

## Tooling per l'accesso al protocollo raw

Usa client che espongano una quantità sufficiente del protocollo E2EE sottostante per creare pacchetti supportati al di fuori dei vincoli della UI e registrare timestamp precisi; per gli ID di messaggi arbitrari è necessario verificare ogni implementazione:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API WhatsApp Web multi-device) documenta l'invio e la ricezione delle delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (API non ufficiale Java/Kotlin Web e mobile) documenta operazioni sui messaggi come reagire, modificare ed eliminare. Usa le API documentate invece di supporre che ogni frame interno sia esposto.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) espone interfacce CLI, JSON-RPC e D-Bus, mentre [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) è una libreria Java per comunicare con Signal.<sup>[[5]](#references)[[7]](#references)</sup> La sintassi attuale di `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantieni in esecuzione `receive` o `daemon` affinché gli aggiornamenti del protocollo continuino a essere elaborati.<sup>[[6]](#references)</sup> Esempio di toggle di un'autoreazione:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Le misurazioni nel paper Careless Whisper hanno rilevato che le delivery receipts sono sincronizzate tra i dispositivi, quindi viene esposta una sola ricevuta per messaggio anche in una configurazione multi-device.<sup>[[1]](#references)</sup>
* **PoC turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) include backend WhatsApp/Signal, usa per impostazione predefinita probe di eliminazione silenziose e contrassegna `active` e `standby` con una soglia di rolling median (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) è una CLI più leggera, orientata prima di tutto a WhatsApp, con `--delay`, `--concurrent`, exporter CSV/Prometheus e output adatto a Grafana.<sup>[[9]](#references)</sup> Considerali entrambi helper di reconnaissance, non riferimenti del protocollo; l'aspetto importante è quanto poco codice serva una volta ottenuto l'accesso al client raw.

Quando il tooling personalizzato non è disponibile, i client ufficiali o i browser developer tools possono comunque attivare azioni silenziose ed esporre la temporizzazione del traffico cifrato; le API raw eliminano i ritardi della UI e consentono operazioni non valide.<sup>[[1]](#references)</sup>

## Compagno inquietante: ciclo di campionamento silenzioso

1. Scegli un messaggio storico qualsiasi che hai scritto nella chat, così la vittima non vedrà cambiare i balloon delle "reazioni".
2. Alterna tra un'emoji visibile e un payload di reazione vuoto (codificato come `""` nei protobuf di WhatsApp o come `--remove` in signal-cli). Ogni trasmissione produce un ack del dispositivo nonostante l'assenza di variazioni nella UI della vittima.
3. Registra il momento dell'invio e l'arrivo di ogni delivery receipt. Un ciclo a 1 Hz come il seguente fornisce indefinitamente tracce RTT per dispositivo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Poiché WhatsApp/Signal accettano aggiornamenti illimitati delle reazioni, l'attaccante non deve mai pubblicare nuovi contenuti nella chat né preoccuparsi delle finestre di modifica.<sup>[[1]](#references)</sup>

## Sconosciuto inquietante: probing di numeri di telefono arbitrari

1. Registra un nuovo account WhatsApp/Signal e recupera le chiavi di identità pubbliche del numero target (operazione eseguita automaticamente durante il setup della sessione).
2. Crea un pacchetto di reazione che faccia riferimento a un `message_id` casuale mai visto da nessuna delle due parti; il paper riporta che sia WhatsApp sia Signal accettano tali reazioni e generano comunque delivery receipts.<sup>[[1]](#references)</sup>
3. Invia il pacchetto anche se non esiste alcun thread. I dispositivi della vittima lo decrittano, non riescono a trovare il messaggio di base, scartano il cambiamento di stato, ma riconoscono comunque il ciphertext in ingresso, inviando le ricevute del dispositivo all'attaccante.
4. Ripeti continuamente per creare serie RTT senza una conversazione precedente o notifiche visibili.<sup>[[1]](#references)</sup>

Se prima devi scoprire quali numeri sono registrati o vuoi pre-popolare inventari dei dispositivi su larga scala, concatena questa attività con gli [oracoli di contact-discovery / registrazione](../pentesting-web/registration-vulnerabilities.md) invece di indovinare manualmente intervalli casuali E.164.

I lavori pubblicati sul contact-discovery hanno mostrato perché questo è importante sul piano operativo: usando tabelle accurate dei prefissi telefonici e risorse moderate, i ricercatori hanno potuto interrogare circa il `10%` dei numeri mobili statunitensi su WhatsApp e il `100%` su Signal prima di passare al probing mirato.<sup>[[11]](#references)</sup> In pratica, pre-filtrare prima gli account attivi mantiene il budget delle probe silenziose concentrato sui numeri che decritteranno effettivamente i pacchetti.

Le build recenti di WhatsApp espongono inoltre `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Consideralo un limitatore di throughput: la documentazione del tracker afferma che WhatsApp blocca i messaggi ad alto volume provenienti da account sconosciuti, ma non comunica la soglia, quindi non impedisce completamente le reaction probe.<sup>[[8]](#references)</sup>

## Riutilizzo di modifiche ed eliminazioni come trigger covert

* **Eliminazioni ripetute:** Dopo che un messaggio è stato eliminato per tutti una volta, ulteriori pacchetti di eliminazione che fanno riferimento allo stesso `message_id` non hanno alcun effetto sulla UI, ma ogni dispositivo li decritta e invia comunque l'ack.
* **Operazioni fuori finestra:** WhatsApp applica nella UI finestre di ~60 h per l'eliminazione e ~20 min per la modifica; Signal applica ~48 h. I messaggi di protocollo creati al di fuori di queste finestre vengono ignorati silenziosamente sul dispositivo della vittima, ma le ricevute vengono trasmesse, consentendo agli attaccanti di effettuare probe indefinitamente anche molto tempo dopo la fine della conversazione.
* **Payload non validi:** Il paper riporta che i messaggi non validi possono comunque ricevere un ack; il comportamento preciso per body malformati o ID eliminati dipende dall'implementazione, quindi esegui test prima di farci affidamento.<sup>[[1]](#references)</sup>

## Amplificazione multi-device e fingerprinting

* Su WhatsApp e Signal, ogni dispositivo associato (telefono, app desktop, browser companion) decritta la probe autonomamente e restituisce il proprio ack. Contare le ricevute per probe rivela il numero esatto di dispositivi.<sup>[[1]](#references)</sup>
* Se un dispositivo è offline, la sua ricevuta viene accodata ed emessa alla riconnessione. Le lacune fanno quindi leak dei cicli online/offline e persino degli orari degli spostamenti (ad esempio, le ricevute desktop si interrompono durante i viaggi).
* Le distribuzioni degli RTT differiscono in base alla piattaforma e all'ambiente, perché sistema operativo, modello, client e condizioni di rete influenzano la temporizzazione. Raggruppa gli RTT (ad esempio con k-means sulle feature di mediana/varianza) per classificare “telefono Android", “telefono iOS", “desktop Electron", ecc.
* Poiché il mittente deve recuperare l'inventario delle chiavi del destinatario prima di cifrare, l'attaccante può anche osservare quando vengono associati nuovi dispositivi; un improvviso aumento del numero di dispositivi o un nuovo cluster RTT è un forte indicatore.<sup>[[1]](#references)</sup>

## Frequenza di campionamento, accodamento e ricevute accumulate

* **Tolleranza ai burst di WhatsApp:** Le misurazioni pubblicate hanno riportato che WhatsApp accettava burst di reazioni silenziose fino a una probe ogni `50 ms` senza un evidente accodamento lato server. Questo è utile per brevi burst di calibrazione, per contare rapidamente i dispositivi o per aumentare rapidamente un drain attack.
* **Accodamento a lungo termine di Signal:** Signal tollerava brevi burst, ma iniziava ad accodare traffico sostenuto di più probe al secondo. Per il monitoraggio a lungo termine, mantieni la frequenza intorno a `1 Hz` (o inferiore), così ogni ricevuta riflette ancora lo stato corrente del dispositivo invece di svuotare una coda arretrata.
* **Artefatti di riconnessione:** Quando un dispositivo torna online, alcuni client raggruppano o scaricano rapidamente più ricevute ritardate. Considera questi burst di ricevute come indicatori di transizione di stato e non come campioni RTT indipendenti, altrimenti il tuo clustering/classificatore `active` vs `idle` farà overfit sul rumore della riconnessione.<sup>[[1]](#references)</sup>

## Inferenza del comportamento dalle tracce RTT

1. Campiona a ≥1 Hz per catturare gli effetti dello scheduling del sistema operativo. Con WhatsApp su iOS, RTT <1 s correlano fortemente con schermo acceso/foreground, mentre RTT >1 s correlano con throttling a schermo spento/background.
2. Crea classificatori semplici (thresholding o k-means a due cluster) che etichettino ogni RTT come "active" o "idle". Aggrega le etichette in sequenze per ricavare orari di sonno, spostamenti, ore di lavoro o i momenti in cui il companion desktop è attivo.
3. Metti in correlazione le probe simultanee verso ogni dispositivo per osservare quando gli utenti passano dal mobile al desktop, quando i companion vanno offline e se l'app è rate limited da push o socket persistente.
4. Nelle reti reali, evita una singola soglia rigida di `1 s`. Inizializza ogni dispositivo con una breve finestra di warm-up e mantieni una baseline mobile (ad esempio, la PoC device-activity-tracker usa `threshold = 0.9 * median RTT`) così che la variazione Wi-Fi/cellulare non renda inutilizzabile il classificatore.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferenza della posizione dall'RTT di consegna

Lo stesso primitivo temporale può essere riutilizzato per dedurre dove si trova il destinatario, non solo se è attivo. Il lavoro `Hope of Delivery` ha mostrato che l'addestramento su distribuzioni RTT relative a posizioni note del ricevitore consente successivamente a un attaccante di classificare la posizione della vittima basandosi esclusivamente sulle conferme di consegna:<sup>[[2]](#references)</sup>

* Crea una baseline per lo stesso target mentre si trova in diversi luoghi noti (casa, ufficio, campus, paese A rispetto al paese B, ecc.).
* Per ogni posizione, raccogli molti RTT di messaggi normali ed estrai feature semplici come mediana, varianza o bucket di percentile.
* Durante l'attacco reale, confronta la nuova serie di probe con i cluster addestrati. Il paper riporta che spesso è possibile distinguere anche posizioni nella stessa città, con accuratezza `>80%` in una configurazione a 3 posizioni.
* Funziona meglio quando l'attaccante controlla l'ambiente del mittente ed esegue le probe in condizioni di rete simili, perché il percorso misurato include la rete di accesso del destinatario, la latenza di risveglio e l'infrastruttura del messenger.<sup>[[2]](#references)</sup>

A differenza degli attacchi silenziosi tramite reazioni/modifiche/eliminazioni descritti sopra, l'inferenza della posizione non richiede ID di messaggi non validi o pacchetti stealth che modificano lo stato. Sono sufficienti messaggi normali con normali conferme di consegna, quindi il compromesso consiste in una stealth inferiore, ma in un'applicabilità più ampia tra i messenger.

## Resource exhaustion stealth

Poiché ogni probe silenziosa deve essere decrittata e riconosciuta, l'invio continuo di toggle delle reazioni, modifiche non valide o pacchetti di eliminazione per tutti crea un DoS a livello applicativo:<sup>[[1]](#references)</sup>

* Forza la radio/modem a trasmettere/ricevere ogni secondo → consumo evidente della batteria, soprattutto sui telefoni inattivi.
* Genera traffico upstream/downstream che consuma i piani dati mobili e può competere con funzionalità sensibili alla latenza come le videochiamate.<sup>[[1]](#references)</sup>
* I payload non validi di grandi dimensioni aggiungono lavoro di elaborazione, ma il paper riporta che la crittografia costituisce una parte trascurabile del costo energetico.<sup>[[1]](#references)</sup>
* Su WhatsApp, le reazioni non valide accettano molti più dati di quanto suggerirebbe una normale emoji: le misurazioni pubblicate hanno rilevato un'accettazione lato server fino a circa `1 MB` per reazione.
* Le reazioni sovradimensionate smettono di produrre delivery receipts affidabili quando il body supera circa `30 bytes`, ma vengono comunque inoltrate ed elaborate prima di essere scartate. Mantieni i body delle reazioni piccoli quando ti servono gli ACK; aumentali solo quando l'obiettivo è il puro drain o un trasporto unidirezionale covert.
* Le misurazioni pubbliche hanno raggiunto circa `3.7 MB/s` (`~13.3 GB/h`) di traffico verso la vittima in questa modalità.

## References

- [1] [Careless Whisper: Sfruttare le ricevute di consegna silenziose per monitorare gli utenti sui Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Estrarre le posizioni degli utenti dai Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Pagina man di signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Come bloccare grandi volumi di messaggi sconosciuti | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [Tutti i numeri sono statunitensi: abuso su larga scala del Contact Discovery nei Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
