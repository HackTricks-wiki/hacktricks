# Attaques par side-channel sur les Delivery Receipts dans les messagers E2EE

{{#include ../banners/hacktricks-training.md}}

Les delivery receipts sont obligatoires dans les messagers modernes de chiffrement de bout en bout (E2EE) parce que les clients doivent savoir quand un ciphertext a été déchiffré afin de pouvoir supprimer l’état de ratcheting et les clés éphémères. Le serveur relaie des blobs opaques, donc les acquittements des appareils (double coche) sont émis par le destinataire après un déchiffrement réussi. Mesurer le temps aller-retour (RTT) entre une action déclenchée par l’attaquant et le delivery receipt correspondant expose un canal temporel haute résolution qui leak l’état de l’appareil, la présence en ligne, et peut être abusé pour un DoS furtif. Les déploiements multi-device de type "client-fanout" amplifient le leak parce que chaque appareil enregistré déchiffre la sonde et renvoie son propre receipt.

## Sources de delivery receipt vs. signaux visibles par l’utilisateur

Choisissez des types de messages qui émettent toujours un delivery receipt mais n’affichent aucun artefact UI chez la victime. Le tableau ci-dessous résume le comportement confirmé empiriquement :

| Messenger | Action | Delivery receipt | Notification victime | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Message texte | ● | ● | Toujours bruyant → utile seulement pour amorcer l’état. |
| | Reaction | ● | ◐ (seulement si reaction au message de la victime) | Les auto-reactions et leurs suppressions restent silencieuses. |
| | Edit | ● | push silencieux dépendant de la plateforme | Fenêtre d’édition ≈20 min ; toujours ack’d après expiration. |
| | Delete for everyone | ● | ○ | L’UI autorise ~60 h, mais les paquets plus tardifs sont toujours ack’d. |
| **Signal** | Message texte | ● | ● | Même limitations que WhatsApp. |
| | Reaction | ● | ◐ | Les auto-reactions sont invisibles pour la victime. |
| | Edit/Delete | ● | ○ | Le serveur applique une fenêtre d’environ ~48 h, autorise jusqu’à 10 edits, mais les paquets tardifs sont toujours ack’d. |
| **Threema** | Message texte | ● | ● | Les receipts multi-device sont agrégés, donc un seul RTT par sonde devient visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement UI dépendant de la plateforme est noté inline. Désactivez les read receipts si nécessaire, mais les delivery receipts ne peuvent pas être désactivés dans WhatsApp ou Signal.

## Objectifs et modèles de l’attaquant

* **G1 – Fingerprinting de l’appareil :** Compter combien de receipts arrivent par sonde, regrouper les RTT pour inférer l’OS/client (Android vs iOS vs desktop), et observer les transitions en ligne/hors ligne.
* **G2 – Surveillance comportementale :** Traiter la série de RTT à haute fréquence (≈1 Hz est stable) comme une série temporelle et inférer l’écran allumé/éteint, l’app en avant-plan/arrière-plan, les heures de trajet vs travail, etc.
* **G3 – Épuisement des ressources :** Maintenir les radios/CPUs de chaque appareil victime éveillés en envoyant des sondes silencieuses sans fin, en drainant la batterie et les données tout en dégradant la qualité VoIP/RTC.

Deux acteurs de menace suffisent pour décrire la surface d’abus :

1. **Creepy companion:** partage déjà un chat avec la victime et abuse des self-reactions, des suppressions de reactions, ou des edits/deletes répétés liés à des message IDs existants.
2. **Spooky stranger:** enregistre un compte jetable et envoie des reactions qui référencent des message IDs n’ayant jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les ack quand même même si l’UI ignore le changement d’état, donc aucune conversation préalable n’est requise.

## Outils pour l’accès brut au protocole

Appuyez-vous sur des clients qui exposent le protocole E2EE sous-jacent afin de pouvoir forger des paquets hors des contraintes de l’UI, spécifier des `message_id`s arbitraires, et journaliser des timestamps précis :

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocole WhatsApp Web) ou [Cobalt](https://github.com/Auties00/Cobalt) (orienté mobile) permettent d’émettre des frames brutes `ReactionMessage`, `ProtocolMessage` (edit/delete), et `Receipt` tout en gardant l’état double-ratchet synchronisé.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combiné avec [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expose chaque type de message via CLI/API. La syntaxe actuelle de `signal-cli` utilise `sendReaction RECIPIENT --target-author --target-timestamp`; gardez `receive` ou `daemon` en cours d’exécution pour que les delivery receipts soient réellement collectés. Exemple de bascule self-reaction :
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Le source du client Android documente comment les delivery receipts sont consolidés avant de quitter l’appareil, expliquant pourquoi le side channel y a une bande passante négligeable.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) fournit des backends WhatsApp/Signal, utilise par défaut des silent delete probes, et étiquette `active` vs `standby` avec un seuil de médiane glissante (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) est un CLI WhatsApp plus léger avec `--delay`, `--concurrent`, exporteurs CSV/Prometheus, et une sortie compatible Grafana. Considérez les deux comme des aides de reconnaissance plutôt que comme des références de protocole ; l’idée importante est le peu de code nécessaire une fois l’accès client brut disponible.

Quand aucun outil custom n’est disponible, vous pouvez toujours déclencher des actions silencieuses depuis WhatsApp Web ou Signal Desktop et sniffer le channel websocket/WebRTC chiffré, mais les API brutes suppriment les délais de l’UI et permettent des opérations invalides.

## Creepy companion : boucle d’échantillonnage silencieuse

1. Choisissez n’importe quel message historique que vous avez écrit dans le chat afin que la victime ne voie jamais les bulles de "reaction" changer.
2. Alternez entre un emoji visible et un payload de reaction vide (encodé comme `""` dans les protobufs WhatsApp ou `--remove` dans signal-cli). Chaque transmission produit un device ack malgré l’absence de delta UI pour la victime.
3. Timestamp le send time et l’arrivée de chaque delivery receipt. Une boucle à 1 Hz comme celle-ci fournit indéfiniment des traces de RTT par appareil :
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Comme WhatsApp/Signal acceptent des mises à jour de reaction illimitées, l’attaquant n’a jamais besoin de publier du nouveau contenu de chat ni de se soucier des fenêtres d’édition.

## Spooky stranger : sondage de numéros de téléphone arbitraires

1. Enregistrez un compte WhatsApp/Signal frais et récupérez les clés d’identité publiques du numéro cible (fait automatiquement pendant la configuration de session).
2. Forgez un paquet reaction/edit/delete qui référence un `message_id` aléatoire jamais vu par l’une ou l’autre partie (WhatsApp accepte des GUID arbitraires `key.id`; Signal utilise des timestamps en millisecondes).
3. Envoyez le paquet même si aucun thread n’existe. Les appareils de la victime le déchiffrent, échouent à faire correspondre le message de base, abandonnent le changement d’état, mais ack quand même le ciphertext entrant, renvoyant les delivery receipts à l’attaquant.
4. Répétez en continu pour construire des séries de RTT sans jamais apparaître dans la liste de chats de la victime.

Si vous devez d’abord découvrir quels numéros sont enregistrés ou souhaitez pré-remplir des inventaires d’appareils à grande échelle, enchaînez cela avec [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) plutôt que de deviner des plages E.164 au hasard à la main.

Les travaux publiés sur la contact-discovery ont montré pourquoi cela est opérationnellement important : avec des tables de préfixes téléphoniques exactes et des ressources modestes, les chercheurs ont pu interroger environ `10%` des numéros mobiles US sur WhatsApp et `100%` sur Signal avant de passer au sondage ciblé. En pratique, pré-filtrer d’abord les comptes vivants garde votre budget de silent-probe concentré sur les numéros qui déchiffreront réellement les paquets.

Les builds récents de WhatsApp exposent aussi `Settings -> Privacy -> Advanced -> Block unknown account messages`. Considérez cela comme un limiteur de débit, pas comme un correctif : cela gêne surtout le flooding soutenu par des inconnus et devient sans objet une fois que vous êtes déjà un contact connu.

## Réutiliser edits et deletes comme déclencheurs furtifs

* **Deletes répétés:** Après qu’un message a été deleted-for-everyone une fois, les paquets delete ultérieurs référençant le même `message_id` n’ont aucun effet UI mais chaque appareil les déchiffre et les ack quand même.
* **Opérations hors fenêtre:** WhatsApp applique dans l’UI des fenêtres d’environ ~60 h pour delete / ~20 min pour edit ; Signal applique ~48 h. Les messages de protocole forgés en dehors de ces fenêtres sont ignorés silencieusement sur l’appareil victime mais les receipts sont transmis, donc les attaquants peuvent sonder indéfiniment longtemps après la fin de la conversation.
* **Payloads invalides:** Des corps d’edit malformés ou des deletes référençant des messages déjà purgés provoquent le même comportement — déchiffrement plus receipt, zéro artefact visible par l’utilisateur.

## Amplification multi-device et fingerprinting

* Chaque appareil associé (téléphone, app desktop, compagnon navigateur) déchiffre la sonde indépendamment et renvoie son propre ack. Compter les receipts par sonde révèle le nombre exact d’appareils.
* Si un appareil est hors ligne, son receipt est mis en queue et émis lors de la reconnexion. Les gaps leak donc les cycles en ligne/hors ligne et même les horaires de trajet (par ex. les receipts desktop s’arrêtent pendant les déplacements).
* Les distributions de RTT diffèrent selon la plateforme à cause de la gestion d’énergie de l’OS et des wakeups push. Regroupez les RTT (par ex. k-means sur des features médiane/variance) pour étiqueter “Android handset", “iOS handset", “Electron desktop", etc.
* Comme l’expéditeur doit récupérer l’inventaire de clés du destinataire avant de chiffrer, l’attaquant peut aussi observer quand de nouveaux appareils sont appairés ; une hausse soudaine du nombre d’appareils ou un nouveau cluster de RTT est un indicateur fort.

## Cadence d’échantillonnage, queueing, et stacked receipts

* **Tolérance aux bursts WhatsApp :** Les mesures publiées ont rapporté que WhatsApp acceptait des bursts de silent-reaction aussi vite qu’une sonde toutes les `50 ms` sans queueing serveur évident. C’est utile pour de courts bursts de calibration, un comptage rapide d’appareils, ou pour accélérer une attaque de drain.
* **Queueing long-run Signal :** Signal tolère de courts bursts mais commence à mettre en queue un trafic soutenu à plusieurs sondes par seconde. Pour une surveillance longue durée, gardez une cadence autour de `1 Hz` (ou moins) afin que chaque receipt reflète encore l’état actuel de l’appareil au lieu de drainer un backlog.
* **Artefacts de reconnexion :** Quand un appareil revient en ligne, certains clients batchent ou flushent rapidement plusieurs receipts retardés. Traitez ces bursts de receipts comme un marqueur de transition d’état plutôt que comme des échantillons RTT indépendants, sinon votre clustering / classifieur `active` vs `idle` sur-apprendra le bruit de reconnexion.

## Inférence comportementale à partir de traces RTT

1. Échantillonnez à ≥1 Hz pour capturer les effets de scheduling de l’OS. Avec WhatsApp sur iOS, des RTT < 1 s corrèlent fortement avec écran allumé/foreground, des RTT > 1 s avec écran éteint/background throttling.
2. Construisez des classifieurs simples (seuil ou k-means à deux clusters) qui étiquettent chaque RTT comme "active" ou "idle". Agrégez les labels en séquences pour déduire les heures de coucher, les trajets, les heures de travail, ou quand le compagnon desktop est actif.
3. Corrélez des sondes simultanées vers chaque appareil pour voir quand les utilisateurs passent du mobile au desktop, quand les compagnons se déconnectent, et si l’app est limitée par le push ou par un socket persistant.
4. Sur les réseaux réels, évitez un seuil fixe codé en dur à `1 s`. Amorcez chaque appareil avec une courte fenêtre de warm-up et gardez une baseline glissante (par exemple, `threshold = 0.9 * median RTT`) afin que la dérive Wi-Fi/cellulaire ne casse pas votre classifieur.

## Inférence de localisation à partir du delivery RTT

Le même primitive temporelle peut être réutilisé pour inférer où se trouve le destinataire, pas seulement s’il est actif. Le travail `Hope of Delivery` a montré qu’en entraînant sur des distributions de RTT pour des emplacements connus du receveur, un attaquant peut ensuite classifier la localisation de la victime à partir des seules confirmations de livraison :

* Construisez une baseline pour la même cible pendant qu’elle se trouve à plusieurs endroits connus (domicile, bureau, campus, pays A vs pays B, etc.).
* Pour chaque emplacement, collectez de nombreux RTT de messages normaux et extrayez des features simples telles que médiane, variance ou buckets de percentiles.
* Pendant l’attaque réelle, comparez la nouvelle série de sondes aux clusters entraînés. L’article rapporte que même des emplacements dans la même ville peuvent souvent être séparés, avec une précision `>80%` dans un scénario à 3 emplacements.
* Cela fonctionne mieux lorsque l’attaquant contrôle l’environnement d’envoi et sonde dans des conditions réseau similaires, car le chemin mesuré inclut le réseau d’accès du destinataire, la latence de réveil, et l’infrastructure du messager.

Contrairement aux attaques silencieuses de reaction/edit/delete ci-dessus, l’inférence de localisation ne nécessite pas de message IDs invalides ni de paquets furtifs changeant l’état. De simples messages avec des confirmations de livraison normales suffisent, donc le compromis est une furtivité moindre mais une applicabilité plus large à travers les messagers.

## Épuisement furtif des ressources

Parce que chaque sonde silencieuse doit être déchiffrée et ack, envoyer continuellement des bascules de reaction, des edits invalides, ou des paquets delete-for-everyone crée un DoS de couche application :

* Force la radio/le modem à transmettre et recevoir chaque seconde → drain notable de la batterie, surtout sur les handsets au repos.
* Génère du trafic montant/descendant non mesuré qui consomme les forfaits data mobiles tout en se fondant dans le bruit TLS/WebSocket.
* Occupe les threads crypto et introduit de la gigue dans les fonctionnalités sensibles à la latence (VoIP, appels vidéo) même si l’utilisateur ne voit jamais de notifications.
* Sur WhatsApp, les reactions invalides acceptent beaucoup plus de données qu’un emoji normal ne le suggère : des mesures publiées ont trouvé une acceptation côté serveur jusqu’à environ `1 MB` par reaction.
* Les reactions surdimensionnées cessent de produire des delivery receipts fiables une fois que le corps dépasse environ `30 bytes`, mais elles sont toujours relayées et traitées avant d’être rejetées. Gardez les corps de reaction minuscules quand vous avez besoin d’ACKs ; agrandissez-les seulement quand l’objectif est un pur drain ou un transport unidirectionnel furtif.
* Des mesures publiques ont atteint environ `3.7 MB/s` (`~13.3 GB/h`) de trafic victime dans ce mode.

## Références

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
