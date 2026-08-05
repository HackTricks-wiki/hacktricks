# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Le **Low-Power Wide Area Network** (LPWAN) est un ensemble de technologies de réseau sans fil, basse consommation et longue portée, conçues pour des **communications longue distance** à faible débit.
Elles peuvent atteindre plus de **six miles** et leurs **batteries** peuvent durer jusqu’à **20 ans**.

Long Range (**LoRa**) est actuellement la couche physique LPWAN la plus déployée et sa spécification ouverte de couche MAC est **LoRaWAN**.

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – couche physique Chirp Spread Spectrum (CSS) développée par Semtech (propriétaire, mais documentée).
* LoRaWAN – couche MAC/réseau ouverte maintenue par la LoRa-Alliance. Les versions 1.0.x et 1.1 sont courantes sur le terrain.
* Architecture typique : *end-device → gateway (packet-forwarder) → network-server → application-server*.

> Le **modèle de sécurité** repose sur deux clés racines AES-128 (AppKey/NwkKey) qui dérivent des clés de session pendant la procédure de *join* (OTAA), ou qui sont codées en dur (ABP). Si une clé fait l’objet d’un leak, l’attaquant obtient une capacité complète de lecture/écriture sur le trafic correspondant.

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 100 % de perte de paquets démontrée avec un seul SDR et une puissance de sortie <1 W |
| MAC | Join-Accept & data-frame replay (nonce reuse, ABP counter rollover) | Spoofing de device, injection de messages, DoS |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | RCE sur les gateways → pivot vers le réseau OT/IT |
| Application | Hard-coded or predictable AppKeys | Brute-force/déchiffrement du trafic, usurpation de capteurs |

---

## Recent vulnerabilities (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* acceptaient des paquets TCP qui contournaient les règles de firewall stateful sur les gateways Kerlink, permettant l’exposition de l’interface de gestion à distance. Corrigé respectivement dans les versions 4.0.11 / 4.2.1 .
* **Dragino LG01/LG308 series** – Plusieurs CVE de 2022-2024 (par ex. 2022-45227 directory traversal, 2022-45228 CSRF) sont toujours observés sans correctif en 2025 ; ils permettent un firmware dump non authentifié ou la réécriture de la configuration sur des milliers de gateways publiques .
* Débordement du *packet-forwarder UDP* de Semtech (advisory non publié, corrigé en 2023-10) : un uplink forgé de plus de 255 B déclenchait un stack-smash ‑> RCE sur les gateways de référence SX130x (découvert par Black Hat EU 2023 « LoRa Exploitation Reloaded »).

---

## Practical attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (DevNonce reuse)

1. Capturer un **JoinRequest** légitime.
2. Le retransmettre immédiatement (ou augmenter le RSSI) avant que l'appareil d'origine ne transmette à nouveau.
3. Le network-server alloue un nouveau DevAddr et de nouvelles clés de session, tandis que l'appareil ciblé continue avec l'ancienne session → l'attaquant contrôle la session vacante et peut injecter des uplinks forgés.

### 3. Downgrade de l'Adaptive Data-Rate (ADR)

Forcer SF12/125 kHz pour augmenter le temps d'occupation radio → épuiser le duty-cycle de la gateway (denial-of-service), tout en limitant l'impact sur la batterie de l'attaquant (il suffit d'envoyer des commandes MAC au niveau du réseau).

### 4. Jamming réactif

*HackRF One* exécutant un flowgraph GNU Radio déclenche un chirp à large bande dès qu'un préambule est détecté – bloque tous les spreading factors avec ≤200 mW TX ; une interruption totale a été mesurée à 2 km de distance .

---

## Offensive tooling (2025)

| Outil | Objectif | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Créer, analyser et attaquer des trames LoRaWAN, analyzers adossés à une DB, brute-forcer | Image Docker, prend en charge les entrées UDP Semtech |
| **LoRaPWN** | Utilitaire Python de Trend Micro pour brute OTAA, générer des downlinks et déchiffrer des payloads | Demo publiée en 2023, indépendant du SDR |
| **LoRAttack** | Sniffer multi-canal + replay avec USRP ; exporte vers PCAP/LoRaTap | Bonne intégration avec Wireshark |
| **gr-lora / gr-lorawan** | Blocs GNU Radio OOT pour TX/RX en bande de base | Base pour les attaques personnalisées |

---

## Recommandations défensives (checklist pentester)

1. Privilégier les appareils **OTAA** avec un DevNonce réellement aléatoire ; surveiller les doublons.
2. Appliquer **LoRaWAN 1.1** : compteurs de trames sur 32 bits, FNwkSIntKey / SNwkSIntKey distinctes.
3. Stocker le frame-counter dans une mémoire non volatile (**ABP**) ou migrer vers OTAA.
4. Déployer un **secure-element** (ATECC608A/SX1262-TRX-SE) pour protéger les clés racines contre l'extraction du firmware.
5. Désactiver les ports UDP distants du packet-forwarder (1700/1701) ou les restreindre avec WireGuard/VPN.
6. Maintenir les gateways à jour ; Kerlink/Dragino fournissent des images corrigées en 2024.
7. Mettre en œuvre une **détection des anomalies de trafic** (p. ex. analyzer LAF) – signaler les réinitialisations de compteurs, les joins en double et les changements soudains d'ADR.<sup>[[1]](#references)</sup>



## Références

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Présentation de LoRaPWN par Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
