# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

**Low-Power Wide Area Network** (LPWAN) è un gruppo di tecnologie di rete wireless, a bassa potenza e ad ampia area, progettate per le **comunicazioni a lunga distanza** a una velocità di trasmissione ridotta.
A seconda dei parametri radio, dell'antenna, della regione normativa, del terreno e del duty cycle, le implementazioni LPWAN possono sacrificare il throughput per ottenere una copertura di diversi chilometri e una durata della batteria di diversi anni. Considerare i valori di portata e durata della batteria dichiarati dai vendor come obiettivi di progettazione, non come garanzie.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) è attualmente il physical layer LPWAN più diffuso e la sua specifica MAC-layer open è **LoRaWAN**.

---

## LPWAN, LoRa e LoRaWAN

* LoRa – physical layer Chirp Spread Spectrum (CSS) sviluppato da Semtech (proprietario ma documentato).
* LoRaWAN – layer MAC/Network open mantenuto dalla LoRa-Alliance. Le versioni 1.0.x e 1.1 sono comuni sul campo.
* Architettura tipica: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> In LoRaWAN 1.1, il **modello di sicurezza** utilizza chiavi root AES-128 separate per l'applicazione e la rete, dalle quali vengono derivate chiavi di sessione specifiche per il ruolo durante OTAA. Le implementazioni precedenti della versione 1.0.x normalmente utilizzano una sola AppKey per derivare le chiavi di sessione della rete e dell'applicazione, mentre ABP esegue direttamente il provisioning delle chiavi di sessione. La capacità ottenuta da una chiave leaked dipende quindi dalla versione di LoRaWAN e dalla chiave che è stata esposta.<sup>[[3]](#references)</sup>

---

## Riepilogo della attack surface

| Layer | Vulnerabilità | Impatto pratico |
|-------|----------|------------------|
| PHY | Jamming reattivo / selettivo | Perdita localizzata di pacchetti; l'efficacia dipende dal link budget, dal timing, dalla larghezza di banda e dai vincoli normativi |
| MAC | Replay di join e data-frame quando lo stato di nonce/counter viene riutilizzato | Desincronizzazione del dispositivo, spoofing o injection se il server/dispositivo viola le protezioni contro il replay |
| Network-Server | Packet-forwarder insicuro, filtri MQTT/UDP deboli, firmware del gateway obsoleto | RCE sui gateway → pivot nella rete OT/IT |
| Application | AppKey hard-coded o prevedibili | Brute-force/decrittazione del traffico, impersonificazione dei sensori |

---

## Vulnerabilità rappresentative delle implementazioni

* **CVE-2024-29862** – Le versioni di ChirpStack Gateway Bridge precedenti alla 4.0.11 e le versioni di MQTT Forwarder precedenti alla 4.2.1 potevano connettersi a un broker MQTT controllato dall'attaccante perché la convalida del certificato server TLS era disabilitata. Ciò poteva esporre le credenziali e il traffico del gateway; eseguire l'upgrade alle release corrette.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 descrive un directory listing non autenticato di `/lib/` contenente un file di backup scaricabile; CVE-2022-45228 è una vulnerabilità CSRF a bassa gravità nella pagina di logout. Questi record non dimostrano l'impatto dichiarato su LG308, la sovrascrittura della configurazione, le dimensioni della popolazione o lo stato delle patch nel 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Una versione precedente di questa pagina descriveva un presunto problema del packet-forwarder UDP di Semtech come uno **stack smash e RCE sui gateway di riferimento SX130x causati da un uplink costruito di oltre 255 byte**, attribuito a una presentazione “LoRa Exploitation Reloaded” del Black Hat Europe 2023 e a una patch privata di ottobre 2023. Questi dettagli precisi vengono mantenuti qui come spunto di ricerca, ma non è stato possibile corroborarli con alcun advisory, presentazione o patch pubblici corrispondenti. Non considerare il problema una vulnerabilità nota senza ottenere il prodotto/la versione interessati e una fonte primaria verificabile.

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
Questi comandi preservano il workflow originale come **sintassi illustrativa**; la struttura dei repository e i flag differiscono tra progetti/release. La cattura passiva non rivela una AppKey robusta. Il guessing offline è utile solo quando la root key è sufficientemente debole da poter essere trovata e uno scambio di join catturato fornisce un valore in grado di validare i candidati.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testare la protezione dal replay OTAA e lo stato dei nonce

1. In una rete di test autorizzata, catturare un **JoinRequest** legittimo.
2. Riprodurre la stessa richiesta e verificare che il network server rifiuti il `DevNonce` riutilizzato.
3. Riavviare o resettare il dispositivo di test e ripetere il controllo per rilevare la perdita dello stato dei nonce. Un server conforme deve tenere traccia dei nonce utilizzati; riprodurre un JoinRequest da solo non divulga le session key appena derivate né dà al replayer il controllo di una sessione.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Downgrade dell'Adaptive Data-Rate (ADR)

Un attaccante in grado di autenticare i comandi MAC del network layer, ad esempio dopo aver compromesso la network session key applicabile o il network server, può tentare di forzare parametri di data rate inefficienti e aumentare l'airtime. Un trasmettitore vicino non autenticato non può emettere legittimamente comandi ADR semplicemente conoscendo l'indirizzo di un dispositivo.<sup>[[3]](#references)</sup>

### 4. Jamming reattivo

Un jammer reattivo può trasmettere dopo aver rilevato un preambolo LoRa e interrompere selettivamente i frame. La pagina precedente affermava che una configurazione HackRF/GNU Radio causava un'interruzione completa a **2 km con non più di 200 mW**, ma non era stata fornita alcuna fonte di misurazione a supporto; conservare questi numeri solo come obiettivo di riproduzione, non come risultato atteso. La potenza di trasmissione, la temporizzazione, la larghezza di banda, gli spreading factor interessati e la portata necessarie dipendono dall'ambiente. Eseguire i test solo all'interno di una configurazione autorizzata e contenuta dal punto di vista RF, rispettando le normative locali sullo spettro.

---

## Strumenti offensivi (2025)

| Strumento | Scopo | Note |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Creare/analizzare/attaccare frame LoRaWAN, analyzer basati su DB, brute-forcer | Immagine Docker; supporta input Semtech UDP<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utility Python di Trend Micro per eseguire brute OTAA, generare downlink e decrittografare payload | Utility di ricerca pubblica; verificare l'hardware supportato e le versioni del protocollo<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework di ricerca per la cattura LoRaWAN multi-canale, l'analisi delle sessioni, la derivazione delle chiavi e i test di replay | Descritto in una tesi magistrale del 2024; ottenere e verificare l'implementazione esatta prima di affidarsi ai flag dell'esempio<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Blocchi out-of-tree GNU Radio per la ricezione della baseband LoRa o la ricerca sui transceiver | I progetti differiscono per compatibilità con GNU Radio e set di funzionalità<sup>[[9]](#references)</sup> |

---

## Raccomandazioni difensive (checklist per pentester)

1. Preferire **OTAA** e verificare che dispositivi e server persistano lo stato dei nonce richiesto; monitorare i join duplicati rifiutati.
2. Preferire **LoRaWAN 1.1** quando supportato, in modo che le funzioni di rete utilizzino session key distinte e una gestione aggiornata dei nonce.<sup>[[3]](#references)</sup>
3. Memorizzare il frame-counter nella memoria non volatile (**ABP**) o migrare a OTAA.
4. Installare un **secure element** appropriato, ad esempio ATECC608A in un design supportato, per ridurre l'esposizione delle root key nella normale memoria del firmware.
5. Non esporre listener UDP configurati dei packet-forwarder, comunemente sulla porta 1700, a reti non attendibili; autenticare/cifrare il backhaul del gateway o limitarlo con una VPN.
6. Mantenere i gateway sul firmware supportato dal vendor e verificare il modello/la versione esatti rispetto agli advisory applicabili.
7. Implementare il **rilevamento delle anomalie del traffico** (ad esempio, analyzer LAF) e segnalare reset dei contatori, join duplicati e modifiche ADR improvvise.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Panoramica di Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - specifica LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - parametri regionali LoRaWAN 1.1 e sincronizzazione dei join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catalogo delle tesi CTU - Analisi della sicurezza dei protocolli LPWAN con tecnologia SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceiver GNU Radio `gr-lora_sdr` di EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
