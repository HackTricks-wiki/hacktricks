# Attaques par canal auxiliaire des accusés de réception de livraison dans les messageries E2EE

{{#include ../banners/hacktricks-training.md}}

Les accusés de réception de livraison sont obligatoires dans les messageries modernes chiffrées de bout en bout (E2EE), car les clients doivent savoir quand un ciphertext a été déchiffré afin de pouvoir supprimer l'état du ratchet et les clés éphémères. Le serveur relaie des blobs opaques ; les accusés des appareils (doubles coches) sont donc émis par le destinataire après un déchiffrement réussi. La mesure du temps aller-retour (RTT) entre une action déclenchée par l'attaquant et l'accusé de réception de livraison correspondant expose un canal temporel haute résolution qui leak l'état de l'appareil et sa présence en ligne, et peut être exploité pour un DoS furtif. Les déploiements multi-appareils de type « client-fanout » amplifient le leak, car chaque appareil enregistré déchiffre la sonde et renvoie son propre accusé.<sup>[[1]](#references)</sup>

## Sources des accusés de réception de livraison et signaux visibles par l'utilisateur

Choisissez des types de messages qui émettent toujours un accusé de réception de livraison, mais qui ne génèrent aucun artefact UI visible sur la victime. Le tableau ci-dessous résume le comportement confirmé empiriquement :<sup>[[1]](#references)</sup>

| Messagerie | Action | Accusé de réception de livraison | Notification de la victime | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Message texte | ● | ● | Toujours bruyant → utile uniquement pour amorcer l'état. |
| | Réaction | ● | ◐ (uniquement en cas de réaction au message de la victime) | Les auto-réactions et leurs suppressions restent silencieuses. |
| | Modification | ● | Push silencieux dépendant de la plateforme | Fenêtre de modification ≈20 min ; toujours acquittée après expiration. |
| | Suppression pour tout le monde | ● | ○ | L'UI autorise ~60 h, mais les paquets ultérieurs sont toujours acquittés. |
| **Signal** | Message texte | ● | ● | Mêmes limitations que WhatsApp. |
| | Réaction | ● | ◐ | Les auto-réactions sont invisibles pour la victime. |
| | Modification/Suppression | ● | ○ | Le serveur impose une fenêtre d'environ ~48 h et autorise jusqu'à 10 modifications, mais les paquets tardifs sont toujours acquittés. |
| **Threema** | Message texte | ● | ● | Les accusés multi-appareils sont agrégés ; un seul RTT par sonde devient donc visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement de l'UI dépendant de la plateforme est indiqué dans les notes. Désactivez les accusés de lecture si nécessaire, mais les accusés de réception de livraison ne peuvent pas être désactivés dans WhatsApp ou Signal.<sup>[[1]](#references)</sup>

## Objectifs et modèles de l'attaquant

* **G1 – Fingerprinting des appareils :** Compter le nombre d'accusés reçus par sonde, regrouper les RTT pour déduire l'OS/client (Android contre iOS ou desktop) et surveiller les transitions en ligne/hors ligne.
* **G2 – Monitoring comportemental :** Traiter la série de RTT haute fréquence (≈1 Hz est stable) comme une série temporelle et déduire l'écran allumé/éteint, l'application au premier plan/arrière-plan, les heures de trajet par rapport aux heures de travail, etc.
* **G3 – Épuisement des ressources :** Maintenir les radios/CPU de chaque appareil de la victime actifs en envoyant des sondes silencieuses sans fin, ce qui décharge la batterie, consomme des données et dégrade la qualité de la VoIP/RTC.<sup>[[1]](#references)</sup>

Deux threat actors suffisent à décrire la surface d'abus :<sup>[[1]](#references)</sup>

1. **Creepy companion :** partage déjà une conversation avec la victime et abuse des auto-réactions, de la suppression de réactions ou de modifications/suppressions répétées liées à des IDs de messages existants.
2. **Spooky stranger :** enregistre un compte burner et envoie des réactions faisant référence à des IDs de messages qui n'ont jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les acquittent tout de même, bien que l'UI ignore le changement d'état. Aucune conversation préalable n'est donc nécessaire.

## Tooling pour l'accès au protocole brut

Appuyez-vous sur des clients qui exposent le protocole E2EE sous-jacent afin de forger des paquets en dehors des contraintes de l'UI, de spécifier des `message_id` arbitraires et d'enregistrer des timestamps précis :

* **WhatsApp :** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocole WhatsApp Web) ou [Cobalt](https://github.com/Auties00/Cobalt) (orienté mobile) permettent d'émettre des trames brutes `ReactionMessage`, `ProtocolMessage` (modification/suppression) et `Receipt` tout en maintenant l'état du double ratchet synchronisé.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal :** [signal-cli](https://github.com/AsamK/signal-cli), combiné à [libsignal-service-java](https://github.com/signalapp/libsignal-service-java), expose chaque type de message via CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> La syntaxe actuelle de `signal-cli` utilise `sendReaction RECIPIENT --target-author --target-timestamp` ; laissez `receive` ou `daemon` fonctionner afin que les accusés de réception de livraison soient effectivement collectés.<sup>[[6]](#references)</sup> Exemple de basculement d'auto-réaction :
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema :** Le code source du client Android documente la manière dont les accusés de réception de livraison sont consolidés avant de quitter l'appareil, ce qui explique pourquoi le canal auxiliaire y possède une bande passante négligeable.<sup>[[1]](#references)</sup>
* **PoCs turnkey :** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) fournit des backends WhatsApp/Signal, utilise par défaut des sondes de suppression silencieuses et étiquette les états `active` et `standby` avec un seuil de médiane glissante (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) est une CLI WhatsApp-first plus légère avec `--delay`, `--concurrent`, des exporters CSV/Prometheus et une sortie adaptée à Grafana.<sup>[[8]](#references)</sup> <sup>[[9]](#references)</sup> Considérez-les tous deux comme des helpers de reconnaissance plutôt que comme des références de protocole ; le point important est de constater le peu de code nécessaire une fois que l'accès au client brut existe.

Lorsque le tooling personnalisé n'est pas disponible, vous pouvez toujours déclencher des actions silencieuses depuis WhatsApp Web ou Signal Desktop et sniffer le canal websocket/WebRTC chiffré, mais les APIs brutes suppriment les délais de l'UI et permettent des opérations invalides.

## Creepy companion : boucle d'échantillonnage silencieuse

1. Choisissez n'importe quel message historique que vous avez vous-même envoyé dans la conversation, afin que la victime ne voie jamais les bulles de « réaction » changer.
2. Alternez entre un emoji visible et un payload de réaction vide (encodé sous la forme `""` dans les protobufs WhatsApp ou `--remove` dans signal-cli). Chaque transmission produit un ack de l'appareil malgré l'absence de changement UI pour la victime.
3. Enregistrez l'heure d'envoi et l'arrivée de chaque accusé de réception de livraison. Une boucle à 1 Hz comme la suivante fournit indéfiniment des traces RTT par appareil :
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Comme WhatsApp/Signal acceptent un nombre illimité de mises à jour de réactions, l'attaquant n'a jamais besoin de publier de nouveau contenu dans la conversation ni de se soucier des fenêtres de modification.<sup>[[1]](#references)</sup>

## Spooky stranger : sonder des numéros de téléphone arbitraires

1. Enregistrez un compte WhatsApp/Signal fraîchement créé et récupérez les clés d'identité publiques du numéro cible (ce qui est fait automatiquement lors de la configuration de la session).
2. Forgez un paquet de réaction/modification/suppression qui fait référence à un `message_id` aléatoire jamais observé par l'une ou l'autre partie (WhatsApp accepte des GUID `key.id` arbitraires ; Signal utilise des timestamps en millisecondes).
3. Envoyez le paquet même si aucun thread n'existe. Les appareils de la victime le déchiffrent, échouent à trouver le message de base, ignorent le changement d'état, mais acquittent tout de même le ciphertext entrant et renvoient les accusés des appareils à l'attaquant.
4. Répétez continuellement afin de construire des séries RTT sans jamais apparaître dans la liste des conversations de la victime.<sup>[[1]](#references)</sup>

Si vous devez d'abord découvrir quels numéros sont enregistrés ou souhaitez préremplir des inventaires d'appareils à grande échelle, combinez cette technique avec les [oracles de contact-discovery / registration](../pentesting-web/registration-vulnerabilities.md) plutôt que de deviner manuellement des plages E.164 aléatoires.

Les travaux publiés sur le contact-discovery ont montré pourquoi cela est important sur le plan opérationnel : avec des tables précises de préfixes téléphoniques et des ressources modestes, les chercheurs ont pu interroger environ `10%` des numéros mobiles américains sur WhatsApp et `100%` sur Signal avant de passer au probing ciblé.<sup>[[11]](#references)</sup> En pratique, le pré-filtrage des comptes actifs permet de concentrer le budget de sondes silencieuses sur les numéros qui déchiffreront effectivement les paquets.

Les versions récentes de WhatsApp exposent également `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Considérez cette option comme une limitation du débit, et non comme une correction : elle gêne principalement le flooding soutenu réalisé uniquement par des strangers et est sans effet une fois que vous êtes déjà un contact connu.

## Recyclage des modifications et suppressions comme triggers furtifs

* **Suppressions répétées :** Après la suppression d'un message pour tout le monde, les paquets de suppression ultérieurs faisant référence au même `message_id` n'ont aucun effet sur l'UI, mais chaque appareil les déchiffre et les acquitte toujours.
* **Opérations hors fenêtre :** WhatsApp impose des fenêtres d'environ 60 h pour la suppression et 20 min pour la modification dans l'UI ; Signal impose environ 48 h. Les messages de protocole forgés en dehors de ces fenêtres sont silencieusement ignorés sur l'appareil de la victime, mais les accusés sont transmis. Les attaquants peuvent donc sonder indéfiniment, longtemps après la fin de la conversation.
* **Payloads invalides :** Les corps de modifications malformés ou les suppressions faisant référence à des messages déjà purgés provoquent le même comportement : déchiffrement et accusé de réception, sans aucun artefact visible par l'utilisateur.<sup>[[1]](#references)</sup>

## Amplification et fingerprinting multi-appareils

* Chaque appareil associé (téléphone, application desktop, browser companion) déchiffre la sonde indépendamment et renvoie son propre ack. Compter les accusés par sonde révèle le nombre exact d'appareils.
* Si un appareil est hors ligne, son accusé est mis en file d'attente et émis lors de la reconnexion. Les interruptions leakent donc les cycles en ligne/hors ligne et même les horaires de déplacement (par exemple, les accusés du desktop cessent pendant les trajets).
* Les distributions de RTT diffèrent selon la plateforme en raison de la gestion de l'alimentation de l'OS et des réveils push. Regroupez les RTT (par exemple avec k-means sur des caractéristiques de médiane/variance) pour étiqueter « Android handset », « iOS handset », « Electron desktop », etc.
* Comme l'expéditeur doit récupérer l'inventaire des clés du destinataire avant le chiffrement, l'attaquant peut également surveiller l'association de nouveaux appareils ; une augmentation soudaine du nombre d'appareils ou l'apparition d'un nouveau cluster RTT constitue un indicateur fort.<sup>[[1]](#references)</sup>

## Cadence d'échantillonnage, mise en file d'attente et accusés empilés

* **Tolérance aux bursts de WhatsApp :** Des mesures publiées ont indiqué que WhatsApp acceptait des bursts de réactions silencieuses à raison d'une sonde toutes les `50 ms` sans mise en file d'attente évidente côté serveur. Cela est utile pour de courts bursts de calibration, un comptage rapide des appareils ou une montée en puissance rapide d'une attaque de drain.
* **Mise en file d'attente à long terme de Signal :** Signal tolérait les bursts courts, mais commençait à mettre en file d'attente un trafic soutenu de plusieurs sondes par seconde. Pour un monitoring longue durée, maintenez la cadence autour de `1 Hz` (ou moins) afin que chaque accusé reflète toujours l'état actuel de l'appareil plutôt qu'une vidange de backlog.
* **Artefacts de reconnexion :** Lorsqu'un appareil revient en ligne, certains clients regroupent plusieurs accusés différés ou les envoient rapidement. Traitez ces bursts d'accusés comme un marqueur de transition d'état plutôt que comme des échantillons RTT indépendants ; sinon, votre clustering ou votre classifieur `active` contre `idle` surajustera le bruit de reconnexion.<sup>[[1]](#references)</sup>

## Inférence du comportement à partir des traces RTT

1. Échantillonnez à ≥1 Hz afin de capturer les effets de scheduling de l'OS. Avec WhatsApp sur iOS, les RTT <1 s sont fortement corrélés à un écran allumé/une application au premier plan, tandis que les RTT >1 s correspondent à une limitation en arrière-plan ou lorsque l'écran est éteint.
2. Construisez des classifieurs simples (seuil ou k-means à deux clusters) qui étiquettent chaque RTT comme « active » ou « idle ». Agrégez les étiquettes en séquences pour déduire les heures de sommeil, les trajets, les heures de travail ou les périodes d'activité du companion desktop.
3. Corrélez les sondes simultanées vers chaque appareil afin d'observer quand les utilisateurs passent du mobile au desktop, quand les companions se déconnectent et si l'application est limitée par le push ou par le socket persistant.
4. Dans les réseaux réels, évitez un seuil fixe de `1 s`. Initialisez chaque appareil avec une courte fenêtre de warm-up et conservez une baseline glissante (par exemple, `threshold = 0.9 * median RTT`) afin que les variations Wi-Fi/cellulaires ne rendent pas votre classifieur inutilisable.<sup>[[1]](#references)</sup>

## Inférence de la localisation à partir du RTT de livraison

La même primitive temporelle peut être réutilisée pour inférer l'emplacement du destinataire, et pas seulement son activité. Le travail `Hope of Delivery` a montré que l'entraînement sur les distributions RTT de localisations connues du récepteur permet ensuite à un attaquant de classifier la localisation de la victime à partir des seules confirmations de livraison :<sup>[[2]](#references)</sup>

* Établissez une baseline pour la même cible lorsqu'elle se trouve dans plusieurs lieux connus (domicile, bureau, campus, pays A contre pays B, etc.).
* Pour chaque localisation, collectez de nombreux RTT de messages normaux et extrayez des caractéristiques simples telles que la médiane, la variance ou des intervalles de percentiles.
* Pendant l'attaque réelle, comparez la nouvelle série de sondes aux clusters entraînés. L'article indique que même des emplacements situés dans une même ville peuvent souvent être distingués, avec une précision de `>80%` dans une configuration à 3 localisations.
* Cette technique fonctionne mieux lorsque l'attaquant contrôle l'environnement de l'expéditeur et sonde dans des conditions réseau similaires, car le chemin mesuré inclut le réseau d'accès du destinataire, la latence de réveil et l'infrastructure de la messagerie.<sup>[[2]](#references)</sup>

Contrairement aux attaques silencieuses par réaction/modification/suppression décrites ci-dessus, l'inférence de localisation ne nécessite ni IDs de messages invalides ni paquets furtifs modifiant l'état. Des messages ordinaires avec des confirmations de livraison normales suffisent ; le compromis est donc une furtivité moindre, mais une applicabilité plus large entre les messageries.

## Épuisement furtif des ressources

Comme chaque sonde silencieuse doit être déchiffrée et acquittée, l'envoi continu de basculements de réactions, de modifications invalides ou de paquets de suppression pour tout le monde crée un DoS au niveau applicatif :<sup>[[1]](#references)</sup>

* Force la radio/le modem à transmettre/recevoir chaque seconde → décharge notable de la batterie, en particulier sur les téléphones inactifs.
* Génère du trafic montant/descendant non mesuré qui consomme les forfaits de données mobiles tout en se fondant dans le bruit TLS/WebSocket.
* Occupe les threads cryptographiques et introduit de la gigue dans les fonctionnalités sensibles à la latence (VoIP, appels vidéo), même si l'utilisateur ne voit aucune notification.
* Sur WhatsApp, les réactions invalides acceptent beaucoup plus de données que ne le laisse penser un emoji normal : des mesures publiées ont constaté une acceptation côté serveur allant jusqu'à environ `1 MB` par réaction.
* Les réactions surdimensionnées cessent de produire des accusés de réception de livraison fiables lorsque leur corps dépasse environ `30 bytes`, mais elles sont tout de même relayées et traitées avant d'être ignorées. Gardez les corps de réaction petits lorsque vous avez besoin d'ACKs ; augmentez leur taille uniquement lorsque l'objectif est un drain pur ou un transport furtif unidirectionnel.
* Les mesures publiques ont atteint environ `3.7 MB/s` (`~13.3 GB/h`) de trafic sur la victime dans ce mode.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
