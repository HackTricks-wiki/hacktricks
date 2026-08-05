# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

**Low-Power Wide Area Network** (LPWAN) è un gruppo di tecnologie di rete wireless, a bassa potenza e ad ampia copertura, progettate per le **comunicazioni a lunga distanza** a bassa velocità di trasmissione.
Possono raggiungere più di **sei miglia** e le loro **batterie** possono durare fino a **20 anni**.

Long Range (**LoRa**) è attualmente il physical layer LPWAN più utilizzato e la sua specifica open del livello MAC è **LoRaWAN**.

---

## LPWAN, LoRa e LoRaWAN

* LoRa – physical layer Chirp Spread Spectrum (CSS) sviluppato da Semtech (proprietario ma documentato).
* LoRaWAN – livello MAC/Network open gestito dalla LoRa-Alliance. Le versioni 1.0.x e 1.1 sono comuni sul campo.
* Architettura tipica: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> Il **modello di sicurezza** si basa su due root key AES-128 (AppKey/NwkKey) che derivano le session key durante la procedura di *join* (OTAA) oppure sono hard-coded (ABP). Se una chiave viene sottoposta a leak, l’attaccante ottiene capacità completa di lettura/scrittura sul traffico corrispondente.

---

## Riepilogo della attack surface

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Jamming reattivo / selettivo | Perdita del 100 % dei pacchetti dimostrata con un singolo SDR e un’uscita inferiore a 1 W |
| MAC | Replay di Join-Accept e data-frame (riutilizzo del nonce, rollover del contatore ABP) | Spoofing del dispositivo, message injection, DoS |
| Network-Server | packet-forwarder insicuro, filtri MQTT/UDP deboli, firmware obsoleto del gateway | RCE sui gateway → pivot nella rete OT/IT |
| Application | AppKey hard-coded o prevedibili | Brute-force/decrittazione del traffico, impersonificazione dei sensori |

---

## Vulnerabilità recenti (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* accettavano pacchetti TCP che aggiravano le regole stateful del firewall sui gateway Kerlink, consentendo l’esposizione dell’interfaccia di gestione remota. Risolto rispettivamente nelle versioni 4.0.11 / 4.2.1 .
* **Serie Dragino LG01/LG308** – Diverse CVE del periodo 2022-2024 (ad esempio 2022-45227 directory traversal, 2022-45228 CSRF) risultano ancora non risolte nel 2025; consentono un firmware dump non autenticato o la sovrascrittura della configurazione su migliaia di gateway pubblici .
* Overflow del *packet-forwarder UDP* di Semtech (advisory non pubblicato, patch del 2023-10): un uplink appositamente creato, più grande di 255 B, attivava uno stack-smash ‑> RCE sui gateway di riferimento SX130x (individuato durante il Black Hat EU 2023 “LoRa Exploitation Reloaded”).

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
### 2. OTAA join-replay (DevNonce reuse)

1. Cattura un **JoinRequest** legittimo.
2. Ritrasmettilo immediatamente (oppure incrementa l'RSSI) prima che il dispositivo originale trasmetta di nuovo.
3. Il network-server alloca un nuovo DevAddr e nuove session keys mentre il dispositivo target continua a utilizzare la vecchia sessione → l'attaccante controlla la sessione vacante e può iniettare uplink contraffatti.

### 3. Adaptive Data-Rate (ADR) downgrading

Forza SF12/125 kHz per aumentare l'airtime → esaurisci il duty-cycle del gateway (denial-of-service) mantenendo basso l'impatto sulla batteria dell'attaccante (è sufficiente inviare comandi MAC a livello di rete).

### 4. Reactive jamming

*HackRF One* con un flowgraph GNU Radio attiva un chirp a banda larga ogni volta che rileva un preambolo, bloccando tutti gli spreading factor con ≤200 mW TX; è stata misurata un'interruzione completa a una distanza di 2 km .

---

## Strumenti offensivi (2025)

| Tool | Scopo | Note |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Creare, analizzare e attaccare frame LoRaWAN, analyzer basati su DB, brute-forcer | Immagine Docker, supporta input Semtech UDP |
| **LoRaPWN** | Utility Python di Trend Micro per eseguire brute OTAA, generare downlink e decrittografare payload | Demo rilasciata nel 2023, indipendente dall'SDR |
| **LoRAttack** | Sniffer multi-canale + replay con USRP; esporta PCAP/LoRaTap | Buona integrazione con Wireshark |
| **gr-lora / gr-lorawan** | Blocchi GNU Radio OOT per TX/RX in baseband | Base per attacchi personalizzati |

---

## Raccomandazioni difensive (checklist per pentester)

1. Preferisci dispositivi **OTAA** con DevNonce realmente casuali; monitora i duplicati.
2. Applica **LoRaWAN 1.1**: frame counter a 32 bit, FNwkSIntKey / SNwkSIntKey distinti.
3. Memorizza il frame-counter in memoria non volatile (**ABP**) o migra a OTAA.
4. Implementa un **secure-element** (ATECC608A/SX1262-TRX-SE) per proteggere le root keys dall'estrazione tramite firmware.
5. Disabilita le porte UDP remote del packet-forwarder (1700/1701) o limita l'accesso con WireGuard/VPN.
6. Mantieni aggiornati i gateway; Kerlink/Dragino forniscono immagini con patch del 2024.
7. Implementa il **rilevamento delle anomalie del traffico** (ad esempio, l'analyzer LAF): segnala reset dei counter, join duplicati e improvvisi cambiamenti ADR.<sup>[[1]](#references)</sup>



## Riferimenti

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Panoramica di Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
