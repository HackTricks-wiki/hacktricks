# Réseau étendu basse consommation

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Le **réseau étendu basse consommation** (LPWAN) regroupe des technologies de réseau sans fil, basse consommation et à grande portée, conçues pour les **communications longue portée** à faible débit binaire.
Selon les paramètres radio, l’antenne, la région réglementaire, le terrain et le cycle de service, les déploiements LPWAN peuvent sacrifier du débit au profit d’une couverture de plusieurs kilomètres et d’une autonomie de plusieurs années. Considérez les portées et les autonomies annoncées par les fabricants comme des objectifs de conception plutôt que comme des garanties.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) est actuellement la couche physique LPWAN la plus déployée, et sa spécification ouverte de couche MAC est **LoRaWAN**.

---

## LPWAN, LoRa et LoRaWAN

* LoRa – Couche physique à étalement de spectre par chirp (CSS), développée par Semtech (propriétaire, mais documentée).
* LoRaWAN – Couche MAC/réseau ouverte, maintenue par la LoRa-Alliance. Les versions 1.0.x et 1.1 sont courantes sur le terrain.
* Architecture typique : *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> Dans LoRaWAN 1.1, le **modèle de sécurité** utilise des clés racines d’application et de réseau distinctes en AES-128 pour dériver des clés de session propres à chaque rôle pendant OTAA. Les déploiements antérieurs en version 1.0.x utilisent généralement une seule AppKey pour dériver les clés de session réseau et applicative, tandis qu’ABP configure directement les clés de session. Les capacités obtenues à partir d’une clé leakée dépendent donc de la version LoRaWAN et de la clé exposée.<sup>[[3]](#references)</sup>

---

## Résumé de la surface d’attaque

| Couche | Faiblesse | Impact pratique |
|-------|----------|------------------|
| PHY | Brouillage réactif / sélectif | Perte localisée de paquets ; l’efficacité dépend du budget de liaison, du timing, de la bande passante et des contraintes réglementaires |
| MAC | Rejeu de trames de jonction et de données lorsque l’état du nonce/compteur est réutilisé | Désynchronisation de l’appareil, usurpation ou injection si le serveur/l’appareil ne respecte pas les protections contre le rejeu |
| Network-Server | packet-forwarder non sécurisé, filtres MQTT/UDP faibles, firmware de gateway obsolète | RCE sur les gateways → pivot vers le réseau OT/IT |
| Application | AppKeys codées en dur ou prévisibles | Forcer par brute force/déchiffrer le trafic, usurper des capteurs |

---

## Vulnérabilités d’implémentations représentatives

* **CVE-2024-29862** – Les versions de ChirpStack Gateway Bridge antérieures à 4.0.11 et les versions de MQTT Forwarder antérieures à 4.2.1 pouvaient se connecter à un broker MQTT contrôlé par un attaquant, car la validation du certificat serveur TLS était désactivée. Cela pouvait exposer des identifiants et le trafic des gateways ; effectuez la mise à niveau vers les versions corrigées.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 décrit un listing non authentifié du répertoire `/lib/` contenant un fichier de sauvegarde téléchargeable ; CVE-2022-45228 est une CSRF de faible gravité sur la page de déconnexion. Ces enregistrements ne confirment pas l’impact allégué sur le LG308, l’écrasement de configuration, la taille du parc ni l’état des correctifs en 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Une version antérieure de cette page décrivait un problème allégué du packet-forwarder UDP de Semtech : **un paquet montant forgé de plus de 255 octets provoquant un écrasement de pile et une RCE sur les gateways de référence SX130x**, attribué à une présentation « LoRa Exploitation Reloaded » lors de Black Hat Europe 2023 et à un correctif privé d’octobre 2023. Ces détails précis sont conservés ici comme piste de recherche, mais aucune alerte publique, présentation ou correctif correspondant n’a pu être corroboré. Ne considérez pas ce problème comme une vulnérabilité connue sans obtenir le produit/la version concernés et une source primaire vérifiable.

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

Ces commandes préservent le workflow d’origine à titre de **syntaxe illustrative** ; la structure des dépôts et les options diffèrent selon les projets et les versions. Une capture passive ne révèle pas une AppKey robuste. La recherche hors ligne n’est utile que si la clé racine est suffisamment faible pour être trouvée et si un échange de connexion capturé fournit une valeur permettant de valider les candidats.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Tester la protection contre les attaques par rejeu OTAA et l’état des nonces

1. Sur un réseau de test autorisé, capturez un **JoinRequest** légitime.
2. Rejouez la même requête et vérifiez que le serveur réseau rejette le `DevNonce` réutilisé.
3. Redémarrez ou réinitialisez l’appareil de test et répétez la vérification pour détecter toute perte de l’état des nonces. Un serveur conforme doit suivre les nonces utilisés ; rejouer uniquement un JoinRequest ne révèle pas les nouvelles clés de session dérivées et ne permet pas à l’auteur du rejeu de prendre le contrôle d’une session.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Rétrogradation de l’Adaptive Data-Rate (ADR)

Un attaquant capable d’authentifier les commandes MAC de la couche réseau — par exemple, après avoir compromis la clé de session réseau applicable ou le serveur réseau — peut tenter d’imposer des paramètres de débit inefficaces et d’augmenter le temps d’antenne. Un émetteur proche non authentifié ne peut pas légitimement envoyer des commandes ADR simplement en connaissant l’adresse d’un appareil.<sup>[[3]](#references)</sup>

### 4. Brouillage réactif

Un brouilleur réactif peut émettre après avoir détecté un préambule LoRa et perturber sélectivement les trames. La page précédente affirmait qu’une configuration HackRF/GNU Radio provoquait une panne complète à **2 km avec une puissance maximale de 200 mW**, mais aucune source de mesure à l’appui n’était fournie ; conservez ces chiffres uniquement comme objectif de reproduction, et non comme résultat attendu. La puissance d’émission, le timing, la bande passante, les facteurs d’étalement affectés et la portée nécessaires dépendent de l’environnement. Effectuez des tests uniquement dans un environnement autorisé et confiné aux RF, et respectez la réglementation locale sur le spectre.

---

## Outils offensifs (2025)

| Outil | Objectif | Remarques |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Créer/analyser des trames LoRaWAN, outils d’analyse adossés à une base de données, brute-forcer | Image Docker ; prend en charge l’entrée UDP Semtech<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utilitaire Python de Trend Micro pour brute-forcer OTAA, générer des downlinks et déchiffrer des payloads | Outil de recherche public ; vérifiez le matériel et les versions du protocole pris en charge<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework de recherche pour la capture LoRaWAN multicanal, l’analyse des sessions, la dérivation des clés et les tests de rejeu | Décrit dans un mémoire de master de 2024 ; obtenez et vérifiez l’implémentation exacte avant de vous fier aux options d’exemple<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Blocs GNU Radio hors arborescence pour la réception de la bande de base LoRa ou la recherche sur les émetteurs-récepteurs | Les projets diffèrent par leur compatibilité avec GNU Radio et leurs fonctionnalités<sup>[[9]](#references)</sup> |

---

## Recommandations défensives (liste de contrôle pour pentester)

1. Privilégiez **OTAA** et vérifiez que les appareils et les serveurs conservent l’état requis des nonces ; surveillez les connexions en double rejetées.
2. Privilégiez **LoRaWAN 1.1** lorsqu’il est pris en charge, afin que les fonctions réseau utilisent des clés de session distinctes et une gestion actualisée des nonces.<sup>[[3]](#references)</sup>
3. Stockez le compteur de trames dans une mémoire non volatile (**ABP**) ou migrez vers OTAA.
4. Déployez un **secure element** adapté (par exemple, ATECC608A dans une conception prise en charge) pour réduire l’exposition des clés racines dans le stockage ordinaire du firmware.
5. N’exposez pas les écouteurs UDP configurés du packet-forwarder (souvent le port 1700) aux réseaux non fiables ; authentifiez/chiffrez la liaison de retour des gateways ou limitez-la à l’aide d’un VPN.
6. Maintenez les gateways sur un firmware pris en charge par le fournisseur et vérifiez le modèle/la version exacts par rapport aux avis de sécurité applicables.
7. Mettez en place une **détection des anomalies de trafic** (p. ex., l’analyseur LAF) – signalez les réinitialisations de compteurs, les connexions en double et les changements soudains d’ADR.<sup>[[1]](#references)</sup>



## References

- [1] [Framework d’audit LoRaWAN (LAF)](https://github.com/IOActive/laf)
- [2] [Présentation de Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Spécification LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Paramètres régionaux LoRaWAN 1.1 et synchronisation des connexions](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catalogue des mémoires CTU - Analyse de la sécurité des protocoles LPWAN à l’aide de la technologie SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Émetteur-récepteur GNU Radio `gr-lora_sdr` d’EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
