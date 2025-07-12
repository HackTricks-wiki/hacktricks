# Rete a Larga Area a Basso Consumo

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

**Rete a Larga Area a Basso Consumo** (LPWAN) è un gruppo di tecnologie di rete wireless, a basso consumo e a larga area progettate per **comunicazioni a lungo raggio** a bassa velocità di trasmissione.
Possono raggiungere più di **sei miglia** e le loro **batterie** possono durare fino a **20 anni**.

Long Range (**LoRa**) è attualmente il livello fisico LPWAN più distribuito e la sua specifica MAC-layer aperta è **LoRaWAN**.

---

## LPWAN, LoRa e LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) livello fisico sviluppato da Semtech (proprietario ma documentato).
* LoRaWAN – Livello MAC/Rete aperto mantenuto dalla LoRa-Alliance. Le versioni 1.0.x e 1.1 sono comuni sul campo.
* Architettura tipica: *dispositivo finale → gateway (inoltratore di pacchetti) → server di rete → server applicativo*.

> Il **modello di sicurezza** si basa su due chiavi radice AES-128 (AppKey/NwkKey) che derivano chiavi di sessione durante la procedura di *join* (OTAA) o sono hard-coded (ABP). Se una chiave viene compromessa, l'attaccante ottiene piena capacità di lettura/scrittura sul traffico corrispondente.

---

## Riepilogo della superficie di attacco

| Livello | Vulnerabilità | Impatto pratico |
|-------|----------|------------------|
| PHY | Jammazione reattiva / selettiva | 100 % di perdita di pacchetti dimostrata con un singolo SDR e <1 W di output |
| MAC | Replay di Join-Accept e data-frame (riutilizzo nonce, rollover contatore ABP) | Spoofing del dispositivo, iniezione di messaggi, DoS |
| Server di rete | Inoltratore di pacchetti insicuro, filtri MQTT/UDP deboli, firmware del gateway obsoleto | RCE sui gateway → pivot nel network OT/IT |
| Applicazione | AppKeys hard-coded o prevedibili | Attacco di forza bruta/decrittazione del traffico, impersonificazione dei sensori |

---

## Vulnerabilità recenti (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* ha accettato pacchetti TCP che bypassavano le regole del firewall stateful sui gateway Kerlink, consentendo l'esposizione dell'interfaccia di gestione remota. Risolto in 4.0.11 / 4.2.1 rispettivamente.
* **Dragino LG01/LG308 series** – Molteplici CVE dal 2022 al 2024 (ad es. 2022-45227 traversata di directory, 2022-45228 CSRF) ancora osservati non patchati nel 2025; abilitano il dump del firmware non autenticato o la sovrascrittura della configurazione su migliaia di gateway pubblici.
* Overflow *packet-forwarder UDP* di Semtech (avviso non rilasciato, patchato 2023-10): uplink creato più grande di 255 B ha attivato uno stack-smash ‑> RCE sui gateway di riferimento SX130x (trovato da Black Hat EU 2023 “LoRa Exploitation Reloaded”).

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
### 2. OTAA join-replay (riutilizzo di DevNonce)

1. Cattura un legittimo **JoinRequest**.
2. Ritrasmettilo immediatamente (o incrementa RSSI) prima che il dispositivo originale trasmetta di nuovo.
3. Il server di rete assegna un nuovo DevAddr e chiavi di sessione mentre il dispositivo target continua con la vecchia sessione → l'attaccante possiede una sessione vacante e può iniettare uplink falsificati.

### 3. Downgrading Adaptive Data-Rate (ADR)

Forza SF12/125 kHz per aumentare il tempo di trasmissione → esaurisci il ciclo di lavoro del gateway (denial-of-service) mantenendo basso l'impatto sulla batteria dell'attaccante (invia solo comandi MAC a livello di rete).

### 4. Jamming reattivo

*HackRF One* che esegue un flusso GNU Radio attiva un chirp a banda larga ogni volta che viene rilevato un preambolo – blocca tutti i fattori di diffusione con ≤200 mW TX; interruzione totale misurata a 2 km di distanza.

---

## Strumenti offensivi (2025)

| Strumento | Scopo | Note |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Creare/analizzare/attaccare i frame LoRaWAN, analizzatori supportati da DB, brute-forcer | Immagine Docker, supporta input Semtech UDP |
| **LoRaPWN** | Utility Python di Trend Micro per brute OTAA, generare downlink, decrittografare payload | Demo rilasciata nel 2023, SDR-agnostico |
| **LoRAttack** | Sniffer multi-canale + replay con USRP; esporta PCAP/LoRaTap | Buona integrazione con Wireshark |
| **gr-lora / gr-lorawan** | Blocchi OOT di GNU Radio per TX/RX a banda base | Fondazione per attacchi personalizzati |

---

## Raccomandazioni difensive (checklist per pentester)

1. Preferire dispositivi **OTAA** con DevNonce veramente casuali; monitorare i duplicati.
2. Applicare **LoRaWAN 1.1**: contatori di frame a 32 bit, FNwkSIntKey / SNwkSIntKey distinti.
3. Memorizzare il contatore di frame in memoria non volatile (**ABP**) o migrare a OTAA.
4. Implementare **secure-element** (ATECC608A/SX1262-TRX-SE) per proteggere le chiavi radice contro l'estrazione del firmware.
5. Disabilitare le porte di inoltro pacchetti UDP remoti (1700/1701) o limitare con WireGuard/VPN.
6. Tenere i gateway aggiornati; Kerlink/Dragino forniscono immagini patchate per il 2024.
7. Implementare **rilevamento delle anomalie nel traffico** (ad es., analizzatore LAF) – segnalare ripristini del contatore, join duplicati, cambiamenti improvvisi di ADR.

## Riferimenti

* LoRaWAN Auditing Framework (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Panoramica di Trend Micro LoRaPWN – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
