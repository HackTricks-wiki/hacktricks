# Iniezione di segnale sul forward link VSAT

{{#include ../../banners/hacktricks-training.md}}

Un terminale VSAT normalmente considera il downlink satellitare come traffico proveniente dall'hub dell'operatore. In un sistema DVB-RCS, questo forward link può trasportare sia pacchetti IP utente sia messaggi di controllo del modem. Se il ricevitore non autentica un messaggio prima di elaborarlo, un segnale iniettato localmente può attraversare il confine di fiducia tra radio e control plane. Si tratta di **iniezione del downlink sul terminale**, non di un uplink verso il satellite o di intercettazione passiva del downlink. L'esito dimostrato dipende dall'implementazione del protocollo e dall'autenticazione dei messaggi del modem, non dal solo DVB-RCS.<sup>[[1]](#references)[[2]](#references)</sup>

## Test in un laboratorio contenuto in RF

Usa un terminale di tua proprietà, il relativo firmware e un SDR collegato all'ingresso di ricezione del modem tramite un'attenuazione appropriata, oppure usa una configurazione RF schermata. Non trasmettere su un canale satellitare attivo. Per prima cosa, registra la portante di avvio configurata nel terminale, il symbol rate e il population ID: questi parametri guidano l'acquisizione del forward link.<sup>[[1]](#references)[[3]](#references)</sup> La catena di acquisizione DVB-RCS usa la Network Information Table (NIT) per individuare la RCS Map Table (RMT), quindi la Program Association Table (PAT) e la Program Map Table (PMT) per individuare gli stream di segnalazione del forward link. Prima di raggiungere lo stream dati, il terminale potrebbe sintonizzarsi su più portanti del transport stream.<sup>[[3]](#references)</sup>

1. Decodifica o ricostruisci il transport stream di avvio del target e analizzane la NIT, la RMT, gli ID di servizio, i packet ID (PID) e la gestione dei riferimenti di clock. Confronta lo standard con il parser e i log del target; un ordinamento o descrittori specifici del vendor possono impedire che uno stream altrimenti valido venga accettato.
2. Nel trasmettitore di laboratorio, incapsula una sonda UDP innocua come `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` e inviala tramite un SDR sink al percorso di ricezione isolato. Mantieni il Program Clock Reference (PCR) del transport stream coerente con il byte rate, altrimenti il modem potrebbe perdere la sincronizzazione prima di elaborare la sonda.
3. Verifica sia il **lock del demodulatore** sia la ricezione della sonda su un endpoint interno di tua proprietà. Il solo lock dimostra soltanto che il livello fisico ha accettato la forma d'onda. Verifica poi se la *segnalazione* di gestione o aggiornamento non autenticata è esposta, senza installare un'immagine o modificare la configurazione del servizio.

Il caso MDM2200 pubblicato ha usato un modulo sorgente GNU Radio per DVB-RCS/MPE/MPEG-TS e `gr-dtv` per la modulazione DVB-S2. Il modem richiedeva dettagli di inizializzazione specifici per il target: una SDT prima della PAT/PMT, un descrittore di contenuto RCS con table ID `0x3E` e un byte privato RMT pari a `0x01` per la modalità GSE/4CPM. Non presumere che questi valori funzionino su un altro terminale.<sup>[[1]](#references)</sup> I ricercatori hanno inoltre osservato che, nella loro configurazione, i pacchetti MPE multicast raggiungevano i modem riceventi, quindi non era necessario conoscere l'indirizzo MAC unicast per individuare i target.<sup>[[1]](#references)</sup> Un'analisi separata ha rilevato segnalazione di controllo e di aggiornamento software non protetta nel sistema studiato, ma questo risultato va verificato per ciascuna implementazione.<sup>[[2]](#references)</sup>

Un tunnel IPsec o VPN per il traffico utente non autentica la segnalazione DVB-RCS che lo precede né il parser di aggiornamento del modem. In una valutazione autorizzata, distingui la protezione crittografica del traffico **IP utente**, del **controllo del forward link** e del traffico di **manutenzione/ripristino**, invece di considerare un tunnel utente sicuro come prova che l'iniezione radio sia bloccata.<sup>[[1]](#references)[[2]](#references)</sup>

Per un'analisi iniziale I/Q, consulta [analisi del segnale radio](../hardware-hacking/radio.md). Per l'analisi del firmware e del parser lato scheda, consulta [analisi del firmware](../firmware-analysis/). Torna alla [panoramica del Radio Hacking](./) per altre interfacce.

## References

- [1] [Bisping et al. - Attacchi di iniezione di segnali wireless ai modem satellitari VSAT (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: alla scoperta di problemi di sicurezza intrinseci nelle pratiche dei sistemi VSAT attuali (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - Canale di interazione DVB per sistemi di distribuzione satellitare](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
