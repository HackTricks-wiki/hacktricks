# Attaques side-channel sur les delivery receipts dans les messengers E2EE

{{#include ../banners/hacktricks-training.md}}

Les delivery receipts sont obligatoires dans les messengers modernes end-to-end encrypted (E2EE) parce que les clients doivent savoir quand un ciphertext a été déchiffré afin de pouvoir supprimer l'état de ratcheting et les clés éphémères. Le serveur relaie des blobs opaques, donc les acknowledgements du device (double coche) sont émis par le destinataire après un déchiffrement réussi. Mesurer le temps aller-retour (RTT) entre une action déclenchée par l'attaquant et le delivery receipt correspondant expose un canal de timing haute résolution qui leak l'état du device, la présence en ligne, et peut être abusé pour un covert DoS. Les déploiements multi-device "client-fanout" amplifient le leak parce que chaque device enregistré déchiffre le probe et renvoie son propre receipt.

## Delivery receipt sources vs. signaux visibles par l'utilisateur

Choisissez des types de message qui émettent toujours un delivery receipt mais n'affichent aucun artefact UI sur la victime. Le tableau ci-dessous résume le comportement confirmé empiriquement :

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Toujours bruyant → utile seulement pour amorcer l'état. |
| | Reaction | ● | ◐ (uniquement si réaction sur un message de la victime) | Les auto-réactions et suppressions restent silencieuses. |
| | Edit | ● | Silent push dépendant de la plateforme | Fenêtre d'édition ≈20 min ; toujours ack’d après expiration. |
| | Delete for everyone | ● | ○ | L'UI autorise ~60 h, mais les paquets ultérieurs sont toujours ack’d. |
| **Signal** | Text message | ● | ● | Même limitations que WhatsApp. |
| | Reaction | ● | ◐ | Les auto-réactions sont invisibles pour la victime. |
| | Edit/Delete | ● | ○ | Le serveur impose une fenêtre d'environ ~48 h, autorise jusqu'à 10 edits, mais les paquets tardifs sont toujours ack’d. |
| **Threema** | Text message | ● | ● | Les receipts multi-device sont agrégés, donc un seul RTT par probe devient visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement UI dépendant de la plateforme est noté inline. Désactivez les read receipts si besoin, mais les delivery receipts ne peuvent pas être désactivés dans WhatsApp ou Signal.

## Objectifs et modèles de l'attaquant

* **G1 – Device fingerprinting :** Compter combien de receipts arrivent par probe, regrouper les RTT pour inférer l'OS/client (Android vs iOS vs desktop), et surveiller les transitions online/offline.
* **G2 – Surveillance comportementale :** Traiter la série temporelle de RTT à haute fréquence (≈1 Hz est stable) comme une time-series et inférer écran allumé/éteint, app au premier plan/en arrière-plan, trajets vs heures de travail, etc.
* **G3 – Épuisement des ressources :** Garder les radios/CPUs de chaque device victime éveillés en envoyant des silent probes sans fin, ce qui vide la batterie/données et dégrade la qualité VoIP/RTC.

Deux acteurs de menace suffisent pour décrire la surface d'abus :

1. **Creepy companion :** partage déjà un chat avec la victime et abuse des auto-reactions, des suppressions de réactions, ou des edits/deletes répétés liés à des message IDs existants.
2. **Spooky stranger :** enregistre un compte burner et envoie des réactions référençant des message IDs qui n'ont jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les ack pourtant même si l'UI rejette le changement d'état, donc aucune conversation préalable n'est requise.

## Outils pour l'accès brut au protocole

Appuyez-vous sur des clients qui exposent le protocole E2EE sous-jacent afin de pouvoir fabriquer des paquets en dehors des contraintes de l'UI, spécifier des `message_id`s arbitraires, et journaliser des timestamps précis :

* **WhatsApp :** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ou [Cobalt](https://github.com/Auties00/Cobalt) (orienté mobile) permettent d'émettre des frames brutes `ReactionMessage`, `ProtocolMessage` (edit/delete), et `Receipt` tout en gardant l'état double-ratchet synchronisé.
* **Signal :** [signal-cli](https://github.com/AsamK/signal-cli) combiné avec [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expose tous les types de message via CLI/API. Exemple de toggle self-reaction :
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema :** Le code source du client Android documente comment les delivery receipts sont consolidés avant de quitter le device, expliquant pourquoi le side channel y a une bande passante négligeable.
* **Turnkey PoCs :** des projets publics tels que `device-activity-tracker` et `careless-whisper-python` automatisent déjà les silent delete/reaction probes et la classification des RTT. Traitez-les comme des assistants de reconnaissance prêts à l'emploi plutôt que comme des références de protocole ; la partie intéressante est qu'ils confirment que l'attaque est opérationnellement simple une fois l'accès brut au client disponible.

Quand aucun outil personnalisé n'est disponible, vous pouvez quand même déclencher des actions silencieuses depuis WhatsApp Web ou Signal Desktop et sniffer le canal websocket/WebRTC chiffré, mais les API brutes suppriment les délais UI et permettent des opérations invalides.

## Creepy companion : boucle d'échantillonnage silencieuse

1. Choisissez n'importe quel message historique que vous avez écrit dans le chat afin que la victime ne voie jamais les bulles de "reaction" changer.
2. Alternez entre un emoji visible et un payload de réaction vide (encodé comme `""` dans les protobufs WhatsApp ou `--remove` dans signal-cli). Chaque transmission génère un device ack malgré l'absence de delta UI pour la victime.
3. Timestamp le moment d'envoi et l'arrivée de chaque delivery receipt. Une boucle à 1 Hz comme la suivante donne des traces RTT par device indéfiniment :
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Comme WhatsApp/Signal acceptent des mises à jour de reaction illimitées, l'attaquant n'a jamais besoin de publier de nouveau contenu de chat ni de se soucier des fenêtres d'édition.

## Spooky stranger : probe de numéros de téléphone arbitraires

1. Enregistrez un compte WhatsApp/Signal fraîchement créé et récupérez les clés d'identité publiques du numéro cible (fait automatiquement pendant la configuration de session).
2. Fabriquez un paquet de reaction/edit/delete qui référence un `message_id` aléatoire jamais vu par l'une ou l'autre partie (WhatsApp accepte des GUID `key.id` arbitraires ; Signal utilise des timestamps en millisecondes).
3. Envoyez le paquet même si aucun thread n'existe. Les devices de la victime le déchiffrent, échouent à faire correspondre le message de base, rejettent le changement d'état, mais ack quand même le ciphertext entrant, renvoyant des delivery receipts à l'attaquant.
4. Répétez en continu pour construire des séries de RTT sans jamais apparaître dans la liste de chat de la victime.

## Réutiliser edits et deletes comme déclencheurs covert

* **Deletes répétés :** Après qu'un message a été deleted-for-everyone une fois, les paquets delete supplémentaires référençant le même `message_id` n'ont aucun effet UI mais chaque device les déchiffre et les ack quand même.
* **Opérations hors fenêtre :** WhatsApp impose environ ~60 h pour delete / ~20 min pour edit dans l'UI ; Signal impose environ ~48 h. Les messages de protocole fabriqués en dehors de ces fenêtres sont ignorés silencieusement sur le device victime mais les receipts sont tout de même transmis, donc les attaquants peuvent sonder indéfiniment longtemps après la fin de la conversation.
* **Payloads invalides :** Les corps d'edit malformés ou les deletes référençant des messages déjà purgés provoquent le même comportement—déchiffrement plus receipt, zéro artefact visible par l'utilisateur.

## Amplification multi-device & fingerprinting

* Chaque device associé (phone, desktop app, browser companion) déchiffre le probe indépendamment et renvoie son propre ack. Compter les receipts par probe révèle le nombre exact de devices.
* Si un device est offline, son receipt est mis en file d'attente et émis à la reconnexion. Les gaps leak donc les cycles online/offline et même les horaires de trajet (par ex. les receipts desktop s'arrêtent pendant le déplacement).
* Les distributions de RTT diffèrent selon la plateforme à cause de la gestion d'énergie de l'OS et des réveils push. Regroupez les RTT (par ex. k-means sur des features médiane/variance) pour étiqueter “Android handset", “iOS handset", “Electron desktop", etc.
* Comme l'expéditeur doit récupérer l'inventaire de clés du destinataire avant de chiffrer, l'attaquant peut aussi voir quand de nouveaux devices sont appairés ; une augmentation soudaine du nombre de devices ou un nouveau cluster RTT est un indicateur fort.

## Inférence comportementale à partir des traces RTT

1. Échantillonnez à ≥1 Hz pour capter les effets de scheduling de l'OS. Avec WhatsApp sur iOS, des RTT <1 s corrèlent fortement avec écran allumé/premier plan, >1 s avec throttling écran éteint/arrière-plan.
2. Construisez des classificateurs simples (seuillage ou k-means à deux clusters) qui étiquettent chaque RTT comme "active" ou "idle". Agrégez les labels en streaks pour dériver heures de coucher, trajets, heures de travail, ou quand le companion desktop est actif.
3. Corrélez les probes simultanées vers chaque device pour voir quand les utilisateurs passent du mobile au desktop, quand les companions passent offline, et si l'app est rate limited par push ou socket persistant.

## Inférence de localisation à partir du delivery RTT

Le même primitive temporel peut être réutilisé pour inférer où se trouve le destinataire, pas seulement s'il est actif. Le travail `Hope of Delivery` a montré que l'entraînement sur des distributions de RTT pour des localisations connues du récepteur permet ensuite à un attaquant de classer la localisation de la victime à partir des seules confirmations de delivery :

* Construisez un baseline pour la même cible pendant qu'elle se trouve dans plusieurs endroits connus (home, office, campus, country A vs country B, etc.).
* Pour chaque localisation, collectez de nombreux RTT de messages normaux et extrayez des features simples comme médiane, variance ou buckets de percentiles.
* Pendant l'attaque réelle, comparez la nouvelle série de probes aux clusters entraînés. Le paper rapporte que même des localisations dans la même ville peuvent souvent être séparées, avec une précision `>80%` dans un scénario à 3 localisations.
* Cela fonctionne mieux lorsque l'attaquant contrôle l'environnement d'envoi et sonde sous des conditions réseau similaires, car le chemin mesuré inclut le réseau d'accès du destinataire, la latence de réveil, et l'infrastructure du messenger.

Contrairement aux attaques silencieuses de reaction/edit/delete ci-dessus, l'inférence de localisation ne nécessite pas de message IDs invalides ni de paquets modifiant l'état de manière furtive. De simples messages avec des confirmations de delivery normales suffisent, donc le compromis est une furtivité plus faible mais une applicabilité plus large à travers les messengers.

## Épuisement de ressources furtif

Comme chaque probe silencieux doit être déchiffré et ack, envoyer en continu des toggles de reaction, des edits invalides, ou des paquets delete-for-everyone crée un DoS au niveau applicatif :

* Force la radio/le modem à transmettre/recevoir chaque seconde → drain de batterie notable, surtout sur des handsets inactifs.
* Génère du trafic upstream/downstream non comptabilisé qui consomme les forfaits de données mobiles tout en se fondant dans le bruit TLS/WebSocket.
* Occupe les threads crypto et introduit du jitter dans les fonctionnalités sensibles à la latence (VoIP, appels vidéo) même si l'utilisateur ne voit jamais de notifications.

## Références

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
