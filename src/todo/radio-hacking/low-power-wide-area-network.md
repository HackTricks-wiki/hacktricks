# Réseau étendu à faible consommation

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Le **Réseau étendu à faible consommation** (**Low-Power Wide Area Network**, LPWAN) est un ensemble de technologies de réseaux sans fil, à faible consommation et à couverture étendue, conçues pour les **communications longue portée** à faible débit binaire.
Selon les paramètres radio, l’antenne, la région réglementaire, le terrain et le cycle d’utilisation, les déploiements LPWAN peuvent échanger du débit contre une couverture de plusieurs kilomètres et une autonomie de plusieurs années. Considérez les valeurs de portée et d’autonomie fournies par les vendors comme des objectifs de conception plutôt que comme des garanties.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) est actuellement la couche physique LPWAN la plus déployée, et sa spécification ouverte de la couche MAC est **LoRaWAN**.

---

## LPWAN, LoRa et LoRaWAN

* LoRa – Couche physique Chirp Spread Spectrum (CSS) développée par Semtech (propriétaire, mais documentée).
* LoRaWAN – Couche MAC/réseau ouverte maintenue par la LoRa-Alliance. Les versions 1.0.x et 1.1 sont courantes sur le terrain.
* Architecture typique : *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> Dans LoRaWAN 1.1, le **modèle de sécurité** utilise des clés racines d’application et de réseau AES-128 distinctes afin de dériver des clés de session spécifiques à chaque rôle pendant l’OTAA. Les déploiements antérieurs en 1.0.x utilisent généralement une seule AppKey pour dériver les clés de session réseau et applicative, tandis qu’ABP provisionne directement les clés de session. La capacité obtenue à partir d’une clé ayant fait l’objet d’un leak dépend donc de la version de LoRaWAN et de la clé exposée.<sup>[[3]](#references)</sup>

---

## Résumé de la surface d’attaque

| Couche | Faiblesse | Impact pratique |
|-------|----------|------------------|
| PHY | Jamming réactif / sélectif | Perte localisée de paquets ; l’efficacité dépend du budget de liaison, du timing, de la bande passante et des contraintes réglementaires |
| MAC | Replay de requêtes de connexion et de trames de données lorsque l’état des nonces/compteurs est réutilisé | Désynchronisation des appareils, spoofing ou injection si le serveur/l’appareil ne respecte pas les protections contre le replay |
| Network-Server | Packet-forwarder non sécurisé, filtres MQTT/UDP faibles, firmware de gateway obsolète | RCE sur les gateways → pivot vers le réseau OT/IT |
| Application | AppKeys codées en dur ou prévisibles | Brute-force/déchiffrement du trafic, usurpation de capteurs |

---

## Vulnérabilités représentatives des implémentations

* **CVE-2024-29862** – Les versions de ChirpStack Gateway Bridge antérieures à 4.0.11 et de MQTT Forwarder antérieures à 4.2.1 pouvaient se connecter à un broker MQTT contrôlé par un attaquant, car la validation du certificat serveur TLS était désactivée. Cela pouvait exposer les identifiants et le trafic de la gateway ; effectuez une mise à niveau vers les versions corrigées.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 décrit une liste de répertoires `/lib/` accessible sans authentification et contenant un fichier de sauvegarde téléchargeable ; CVE-2022-45228 est une vulnérabilité CSRF de faible gravité dans la page de déconnexion. Ces enregistrements n’établissent pas l’impact allégué sur le LG308, l’écrasement de la configuration, la taille de la population ou l’état des correctifs en 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Une version antérieure de cette page décrivait un prétendu problème du packet-forwarder UDP de Semtech comme **un uplink forgé de plus de 255 octets provoquant un stack smash et une RCE sur les gateways de référence SX130x**, attribué à une présentation Black Hat Europe 2023 intitulée « LoRa Exploitation Reloaded » et à un patch privé d’octobre 2023. Ces détails précis sont conservés ici comme piste de recherche, mais aucun advisory, aucune présentation ni aucun patch public correspondant n’a pu être corroboré. Ne considérez pas ce problème comme une vulnérabilité connue sans obtenir le produit/la version concernés et une source primaire vérifiable.

---

## Techniques d’attaque pratiques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
Ces commandes préservent le workflow d’origine sous forme de **syntaxe illustrative** ; l’organisation des dépôts et les flags diffèrent selon les projets/releases. Une capture passive ne révèle pas d’AppKey forte. Le guessing hors ligne n’est utile que lorsque la clé racine est suffisamment faible pour être trouvée et qu’un échange de jointure capturé fournit une valeur permettant de valider les candidats.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Tester la protection contre les replay OTAA et l’état des nonce

1. Dans un réseau de test autorisé, capturez un **JoinRequest** légitime.
2. Rejouez la même requête et confirmez que le network server rejette le `DevNonce` réutilisé.
3. Redémarrez ou réinitialisez le périphérique de test et répétez la vérification afin de détecter une perte de l’état des nonce. Un serveur conforme doit suivre les nonce utilisés ; rejouer un JoinRequest seul ne révèle pas les clés de session nouvellement dérivées et ne donne pas au replayer le contrôle d’une session.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Dégradation de l’Adaptive Data-Rate (ADR)

Un attaquant capable de s’authentifier auprès des commandes MAC de la couche réseau — par exemple après avoir compromis la clé de session réseau applicable ou le network server — peut tenter d’imposer des paramètres de data-rate inefficaces et d’augmenter l’airtime. Un émetteur non authentifié situé à proximité ne peut pas légitimement envoyer de commandes ADR simplement en connaissant l’adresse d’un périphérique.<sup>[[3]](#references)</sup>

### 4. Jamming réactif

Un jammer réactif peut émettre après avoir détecté un préambule LoRa et perturber sélectivement les trames. La page précédente affirmait qu’une configuration HackRF/GNU Radio provoquait une panne complète à **2 km avec au plus 200 mW**, mais aucune source de mesure justificative n’a été fournie ; conservez ces chiffres uniquement comme objectif de reproduction, et non comme résultat attendu. La puissance d’émission requise, le timing, la bande passante, les spreading factors affectés et la portée dépendent de l’environnement. Effectuez les tests uniquement dans une configuration autorisée et confinée aux RF, et respectez les règles locales relatives au spectre.

---

## Outils offensifs (2025)

| Outil | Objectif | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Créer/analyser/attaquer des trames LoRaWAN, analyzers adossés à une DB, brute-forcer | Image Docker ; prend en charge les entrées UDP Semtech<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utilitaire Python de Trend Micro pour brute OTAA, générer des downlinks et déchiffrer des payloads | Utilitaire de recherche public ; vérifiez le matériel et les versions de protocole pris en charge<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework de recherche pour la capture LoRaWAN multicanal, l’analyse des sessions, la dérivation de clés et les tests de replay | Décrit dans un mémoire de master de 2024 ; obtenez et vérifiez l’implémentation exacte avant de vous fier aux flags de l’exemple<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Blocs GNU Radio out-of-tree pour la réception de la bande de base LoRa ou la recherche sur les transceivers | Les projets diffèrent en matière de compatibilité avec GNU Radio et d’ensemble de fonctionnalités<sup>[[9]](#references)</sup> |

---

## Recommandations défensives (checklist de pentester)

1. Préférez **OTAA** et vérifiez que les périphériques et les serveurs persistent l’état requis des nonce ; surveillez les jointures dupliquées rejetées.
2. Préférez **LoRaWAN 1.1** lorsqu’il est pris en charge afin que les fonctions réseau utilisent des clés de session distinctes et une gestion mise à jour des nonce.<sup>[[3]](#references)</sup>
3. Stockez le frame-counter dans une mémoire non volatile (**ABP**) ou migrez vers OTAA.
4. Déployez un **secure element** approprié (par exemple, un ATECC608A dans une conception prise en charge) afin de réduire l’exposition des clés racines dans le stockage firmware ordinaire.
5. N’exposez pas les écouteurs UDP des packet-forwarders configurés (généralement 1700) à des réseaux non fiables ; authentifiez/chiffrez le backhaul des gateways ou restreignez-le avec un VPN.
6. Maintenez les gateways sur un firmware pris en charge par le fournisseur et vérifiez le modèle/la version exacts par rapport aux advisories applicables.
7. Implémentez une **détection des anomalies de trafic** (p. ex. analyzer LAF) – signalez les réinitialisations de compteurs, les jointures dupliquées et les changements soudains d’ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Présentation de LoRaPWN par Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - spécification LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - paramètres régionaux LoRaWAN 1.1 et synchronisation des jointures](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catalogue des mémoires de la CTU - Analyse de la sécurité des protocoles LPWAN avec la technologie SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceiver GNU Radio `gr-lora_sdr` de l’EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
