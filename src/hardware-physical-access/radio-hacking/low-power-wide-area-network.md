# Rete geografica a basso consumo

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

**Low-Power Wide Area Network** (LPWAN) è un gruppo di tecnologie di rete wireless a basso consumo e ad ampia copertura, progettate per le **comunicazioni a lunga distanza** con un basso bit rate.
A seconda dei parametri radio, dell’antenna, della regione normativa, del terreno e del duty cycle, le implementazioni LPWAN possono sacrificare il throughput per ottenere copertura di diversi chilometri e una durata della batteria di diversi anni. Considera i valori di portata e autonomia della batteria dichiarati dai vendor come obiettivi di progettazione, non come garanzie.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) è attualmente il livello fisico LPWAN più diffuso e la sua specifica aperta a livello MAC è **LoRaWAN**.

---

## LPWAN, LoRa e LoRaWAN

* LoRa – Livello fisico Chirp Spread Spectrum (CSS) sviluppato da Semtech (proprietario, ma documentato).
* LoRaWAN – Livello MAC/Network aperto, gestito dalla LoRa-Alliance. Le versioni 1.0.x e 1.1 sono comuni sul campo.
* Architettura tipica: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> In LoRaWAN 1.1, il **modello di sicurezza** utilizza chiavi root AES-128 distinte per applicazione e rete per derivare chiavi di sessione specifiche per ruolo durante OTAA. Le implementazioni precedenti, basate su 1.0.x, usano normalmente una sola AppKey per derivare le chiavi di sessione di rete e applicazione, mentre ABP configura direttamente le chiavi di sessione. Le capacità ottenibili da una chiave trapelata dipendono quindi dalla versione di LoRaWAN e dalla chiave esposta.<sup>[[3]](#references)</sup>

---

## Riepilogo della superficie di attacco

| Livello | Debolezza | Impatto pratico |
|-------|----------|------------------|
| PHY | Jamming reattivo / selettivo | Perdita localizzata di pacchetti; l’efficacia dipende dal link budget, dalla temporizzazione, dalla larghezza di banda e dai vincoli normativi |
| MAC | Replay di frame di join e dati quando lo stato di nonce/contatore viene riutilizzato | Desincronizzazione del dispositivo, spoofing o injection se il server/dispositivo non applica le protezioni anti-replay |
| Network-Server | Packet-forwarder non sicuro, filtri MQTT/UDP deboli, firmware del gateway non aggiornato | RCE sui gateway → pivot nella rete OT/IT |
| Applicazione | AppKey hard-coded o prevedibili | Brute-force/decrittazione del traffico, impersonificazione dei sensori |

---

## Vulnerabilità rappresentative delle implementazioni

* **CVE-2024-29862** – Le versioni di ChirpStack Gateway Bridge precedenti alla 4.0.11 e le versioni di MQTT Forwarder precedenti alla 4.2.1 potevano connettersi a un broker MQTT controllato da un attacker perché la convalida del certificato TLS del server era disabilitata. Questo poteva esporre credenziali e traffico del gateway; aggiorna alle versioni corrette.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 descrive un elenco non autenticato della directory `/lib/` che include un file di backup scaricabile; CVE-2022-45228 è una CSRF a bassa gravità nella pagina di logout. Questi record non confermano l’impatto dichiarato su LG308, la sovrascrittura della configurazione, le dimensioni della popolazione o lo stato delle patch nel 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Una versione precedente di questa pagina descriveva un presunto problema nel packet-forwarder UDP di Semtech come **un uplink appositamente creato, di dimensioni superiori a 255 byte, che causava uno stack smash e RCE sui gateway di riferimento SX130x**, attribuito a una presentazione “LoRa Exploitation Reloaded” al Black Hat Europe 2023 e a una patch privata dell’ottobre 2023. Questi dettagli specifici vengono mantenuti qui come pista di ricerca, ma non è stato possibile corroborare alcun advisory pubblico, presentazione o patch corrispondente. Non considerare il problema una vulnerabilità nota senza ottenere il prodotto/la versione interessati e una fonte primaria verificabile.

---

## Tecniche di attacco pratiche

### 1. Sniff & Decrypt traffic

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Questi comandi mantengono il workflow originale come **sintassi illustrativa**; la struttura del repository e i flag variano a seconda dei progetti e delle release. La cattura passiva non rivela una AppKey robusta. Il guessing offline è utile solo se la root key è abbastanza debole da poter essere trovata e uno scambio di join catturato fornisce un valore con cui verificare i candidati.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testare la protezione da replay OTAA e lo stato dei nonce

1. In una rete di test autorizzata, catturare un **JoinRequest** legittimo.
2. Riprodurre la stessa richiesta e confermare che il network server rifiuti il `DevNonce` riutilizzato.
3. Riavviare o ripristinare il dispositivo di test e ripetere il controllo per rilevare un’eventuale perdita dello stato dei nonce. Un server conforme deve tenere traccia dei nonce utilizzati; riprodurre un JoinRequest, da solo, non rivela le nuove session key derivate né consente a chi lo riproduce di controllare una sessione.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Downgrade dell’Adaptive Data-Rate (ADR)

Un attacker in grado di autenticare i comandi MAC a livello di rete, per esempio dopo aver compromesso la session key di rete pertinente o il network server, può tentare di forzare parametri di data rate inefficienti e aumentare il tempo di trasmissione. Un transmitter non autenticato nelle vicinanze non può inviare legittimamente comandi ADR solo conoscendo l’indirizzo di un dispositivo.<sup>[[3]](#references)</sup>

### 4. Jamming reattivo

Un jammer reattivo può trasmettere dopo aver rilevato un preambolo LoRa e disturbare selettivamente i frame. La pagina precedente affermava che una configurazione HackRF/GNU Radio causava un’interruzione totale a **2 km con non più di 200 mW**, ma non forniva fonti a supporto delle misurazioni; mantenere questi valori solo come obiettivo di riproduzione, non come risultato atteso. La potenza di trasmissione necessaria, la temporizzazione, la larghezza di banda, i fattori di spreading interessati e la portata dipendono dall’ambiente. Eseguire i test solo in un ambiente autorizzato e schermato dalle RF e rispettare le normative locali sullo spettro.

---

## Strumenti offensivi (2025)

| Tool | Scopo | Note |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Creare e analizzare frame LoRaWAN, attaccarli, usare analyzer basati su DB e strumenti brute-forcer | Immagine Docker; supporta input UDP Semtech<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utility Python di Trend Micro per brute-force OTAA, generare downlink e decrittare payload | Utility di ricerca pubblica; verificare l’hardware e le versioni del protocollo supportati<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework di ricerca per la cattura LoRaWAN multicanale, l’analisi delle sessioni, la derivazione delle chiavi e i test di replay | Descritto in una tesi magistrale del 2024; ottenere e verificare l’implementazione esatta prima di fare affidamento sui flag di esempio<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Blocchi out-of-tree GNU Radio per la ricezione della banda base LoRa o la ricerca sui transceiver | I progetti differiscono per compatibilità con GNU Radio e funzionalità disponibili<sup>[[9]](#references)</sup> |

---

## Raccomandazioni difensive (checklist per pentester)

1. Preferire **OTAA** e verificare che dispositivi e server memorizzino in modo persistente lo stato dei nonce richiesto; monitorare i join duplicati rifiutati.
2. Preferire **LoRaWAN 1.1** dove supportato, affinché le funzioni di rete utilizzino session key distinte e una gestione aggiornata dei nonce.<sup>[[3]](#references)</sup>
3. Memorizzare il frame-counter in memoria non volatile (**ABP**) oppure migrare a OTAA.
4. Integrare un **secure element** adeguato (per esempio, ATECC608A in una configurazione supportata) per ridurre l’esposizione delle root key nell’archiviazione ordinaria del firmware.
5. Non esporre a reti non attendibili i listener UDP configurati del packet-forwarder (comunemente sulla porta 1700); autenticare e cifrare il backhaul dei gateway oppure limitarlo con una VPN.
6. Mantenere i gateway su firmware supportati dal vendor e verificare il modello/la versione esatti rispetto agli advisory pertinenti.
7. Implementare il **rilevamento delle anomalie del traffico** (ad esempio, l’analyzer LAF) e segnalare reset dei contatori, join duplicati e variazioni improvvise di ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Panoramica di Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Specifica LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Parametri regionali LoRaWAN 1.1 e sincronizzazione del join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catalogo tesi CTU - Analisi della sicurezza dei protocolli LPWAN con tecnologia SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceiver GNU Radio `gr-lora_sdr` di EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
