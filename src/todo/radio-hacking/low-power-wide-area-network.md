# Réseau à large bande à faible consommation

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Réseau à large bande à faible consommation** (LPWAN) est un groupe de technologies de réseau sans fil, à faible consommation et à large bande, conçues pour des **communications à longue portée** à un faible débit binaire. 
Ils peuvent atteindre plus de **six miles** et leurs **batteries** peuvent durer jusqu'à **20 ans**.

Long Range (**LoRa**) est actuellement la couche physique LPWAN la plus déployée et sa spécification de couche MAC ouverte est **LoRaWAN**.

---

## LPWAN, LoRa et LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) couche physique développée par Semtech (propriétaire mais documentée).
* LoRaWAN – Couche MAC/réseau ouverte maintenue par la LoRa-Alliance. Les versions 1.0.x et 1.1 sont courantes sur le terrain.
* Architecture typique : *dispositif final → passerelle (transmetteur de paquets) → serveur de réseau → serveur d'application*.

> Le **modèle de sécurité** repose sur deux clés racines AES-128 (AppKey/NwkKey) qui dérivent des clés de session lors de la procédure de *jointure* (OTAA) ou sont codées en dur (ABP). Si une clé fuit, l'attaquant obtient une capacité de lecture/écriture complète sur le trafic correspondant.

---

## Résumé de la surface d'attaque

| Couche | Faiblesse | Impact pratique |
|--------|-----------|-----------------|
| PHY    | Brouillage réactif / sélectif | 100 % de perte de paquets démontrée avec un seul SDR et <1 W de sortie |
| MAC    | Rejeu de Join-Accept & trame de données (réutilisation de nonce, débordement de compteur ABP) | Usurpation de dispositif, injection de message, DoS |
| Serveur de réseau | Transmetteur de paquets non sécurisé, filtres MQTT/UDP faibles, firmware de passerelle obsolète | RCE sur les passerelles → pivot vers le réseau OT/IT |
| Application | AppKeys codées en dur ou prévisibles | Brute-force/décryptage du trafic, usurpation de capteurs |

---

## Vulnérabilités récentes (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* a accepté des paquets TCP qui contournaient les règles de pare-feu d'état sur les passerelles Kerlink, permettant l'exposition de l'interface de gestion à distance. Corrigé dans 4.0.11 / 4.2.1 respectivement.
* **Série Dragino LG01/LG308** – Plusieurs CVEs 2022-2024 (par exemple, 2022-45227 traversée de répertoire, 2022-45228 CSRF) encore observées non corrigées en 2025 ; permettent un vidage de firmware non authentifié ou un écrasement de configuration sur des milliers de passerelles publiques.
* Débordement de *packet-forwarder UDP* de Semtech (avis non publié, corrigé en 2023-10) : un uplink conçu plus grand que 255 B a déclenché un écrasement de pile ‑> RCE sur les passerelles de référence SX130x (découvert par Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Techniques d'attaque pratiques

### 1. Sniffer & Décrypter le trafic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. Rejeu de jointure OTAA (réutilisation de DevNonce)

1. Capturez une **JoinRequest** légitime.
2. Retransmettez-la immédiatement (ou augmentez le RSSI) avant que l'appareil d'origine ne transmette à nouveau.
3. Le serveur réseau attribue un nouveau DevAddr et des clés de session pendant que l'appareil cible continue avec l'ancienne session → l'attaquant possède une session vacante et peut injecter des uplinks falsifiés.

### 3. Rétrogradation du taux de données adaptatif (ADR)

Forcez SF12/125 kHz pour augmenter le temps d'occupation → épuiser le cycle de service de la passerelle (déni de service) tout en maintenant un impact faible sur la batterie de l'attaquant (envoyez simplement des commandes MAC au niveau du réseau).

### 4. Brouillage réactif

*HackRF One* exécutant un flux GNU Radio déclenche un chirp large bande chaque fois qu'un préambule est détecté – bloque tous les facteurs d'étalement avec ≤200 mW TX ; panne totale mesurée à 2 km de portée.

---

## Outils offensifs (2025)

| Outil | Objectif | Remarques |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Créer/analyser/attaquer des trames LoRaWAN, analyseurs soutenus par une base de données, brute-forcer | Image Docker, prend en charge l'entrée UDP Semtech |
| **LoRaPWN** | Utilitaire Python de Trend Micro pour brute forcer OTAA, générer des downlinks, déchiffrer des charges utiles | Démo publiée en 2023, SDR-agnostique |
| **LoRAttack** | Sniffer multi-canal + replay avec USRP ; exporte PCAP/LoRaTap | Bonne intégration avec Wireshark |
| **gr-lora / gr-lorawan** | Blocs OOT GNU Radio pour TX/RX de baseband | Fondation pour des attaques personnalisées |

---

## Recommandations défensives (liste de contrôle pour pentester)

1. Préférez les appareils **OTAA** avec un DevNonce véritablement aléatoire ; surveillez les doublons.
2. Appliquez **LoRaWAN 1.1** : compteurs de trames de 32 bits, FNwkSIntKey / SNwkSIntKey distincts.
3. Stockez le compteur de trames dans une mémoire non volatile (**ABP**) ou migrez vers OTAA.
4. Déployez un **élément sécurisé** (ATECC608A/SX1262-TRX-SE) pour protéger les clés racines contre l'extraction de firmware.
5. Désactivez les ports de transfert de paquets UDP distants (1700/1701) ou restreignez avec WireGuard/VPN.
6. Gardez les passerelles à jour ; Kerlink/Dragino fournissent des images corrigées en 2024.
7. Mettez en œuvre une **détection d'anomalies de trafic** (par exemple, analyseur LAF) – signalez les réinitialisations de compteurs, les jointures dupliquées, les changements soudains d'ADR.

## Références

* LoRaWAN Auditing Framework (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Aperçu de Trend Micro LoRaPWN – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
