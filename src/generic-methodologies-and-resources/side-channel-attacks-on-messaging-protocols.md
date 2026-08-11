# Attaques side-channel basées sur les accusés de réception dans les messageries E2EE

{{#include ../banners/hacktricks-training.md}}

Les accusés de réception sont obligatoires dans les messageries modernes chiffrées de bout en bout (E2EE), car les clients doivent savoir quand un ciphertext a été déchiffré afin de pouvoir supprimer l’état du ratchet et les clés éphémères. Le serveur relaie des blobs opaques ; les acquittements des appareils (doubles coches) sont donc émis par le destinataire après un déchiffrement réussi. La mesure du temps aller-retour (RTT) entre une action déclenchée par l’attaquant et l’accusé de réception correspondant expose un canal temporel haute résolution qui leak l’état de l’appareil et la présence en ligne, et peut être exploité pour un DoS furtif. Les déploiements multi-appareils de type « client-fanout » amplifient la fuite, car chaque appareil enregistré déchiffre la sonde et renvoie son propre accusé de réception.<sup>[[1]](#references)</sup>

## Sources des accusés de réception vs. signaux visibles par l’utilisateur

Choisissez des types de messages qui émettent toujours un accusé de réception, mais qui ne produisent aucun artefact d’interface sur la victime. Le tableau ci-dessous résume le comportement confirmé expérimentalement :<sup>[[1]](#references)</sup>

| Messenger | Action | Accusé de réception | Notification à la victime | Remarques |
|-----------|--------|---------------------|---------------------------|-----------|
| **WhatsApp** | Message texte | ● | ● | Toujours bruyant → utile uniquement pour amorcer l’état. |
| | Réaction | ● | ◐ (uniquement en cas de réaction au message de la victime) | Les auto-réactions et leurs suppressions restent silencieuses. |
| | Modification | ● | Push silencieux dépendant de la plateforme | Fenêtre de modification ≈20 min ; les paquets sont tout de même acquittés après expiration. |
| | Suppression pour tout le monde | ● | ○ | L’interface autorise ~60 h, mais les paquets ultérieurs sont toujours acquittés. |
| **Signal** | Message texte | ● | ● | Mêmes limitations que WhatsApp. |
| | Réaction | ● | ◐ | Les auto-réactions sont invisibles pour la victime. |
| | Modification/Suppression | ● | ○ | Le serveur impose une fenêtre d’environ ~48 h et autorise jusqu’à 10 modifications, mais les paquets tardifs sont toujours acquittés. |
| **Threema** | Message texte | ● | ● | Les accusés de réception multi-appareils sont agrégés ; un seul RTT par sonde devient donc visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement de l’interface dépendant de la plateforme est indiqué directement dans le tableau. Désactivez les accusés de lecture si nécessaire, mais les accusés de réception ne peuvent pas être désactivés dans WhatsApp ou Signal.<sup>[[1]](#references)</sup>

## Objectifs et modèles d’attaquant

* **G1 – Empreinte des appareils :** Compter le nombre d’accusés de réception reçus par sonde, regrouper les RTT pour déduire l’OS/le client (Android contre iOS contre desktop) et observer les transitions en ligne/hors ligne.
* **G2 – Surveillance comportementale :** Traiter la série de RTT haute fréquence (≈1 Hz est stable) comme une série temporelle et déduire l’écran allumé/éteint, l’application au premier plan/en arrière-plan, les heures de trajet et de travail, etc.
* **G3 – Épuisement des ressources :** Maintenir les radios/CPU de chaque appareil victime éveillés en envoyant des sondes silencieuses sans fin, déchargeant la batterie et consommant des données tout en dégradant la qualité des appels vidéo.<sup>[[1]](#references)</sup>

Deux acteurs de la menace suffisent pour décrire la surface d’abus :<sup>[[1]](#references)</sup>

1. **Compagnon inquiétant :** partage déjà une conversation avec la victime et abuse des auto-réactions, de la suppression des réactions ou de modifications/suppressions répétées liées à des ID de messages existants.
2. **Inconnu inquiétant :** crée un compte jetable et envoie des réactions faisant référence à des ID de messages qui n’ont jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les acquittent tout de même, même si l’interface ignore le changement d’état. Aucune conversation préalable n’est donc nécessaire.

## Outils pour l’accès au protocole brut

Utilisez des clients qui exposent suffisamment du protocole E2EE sous-jacent pour créer des paquets pris en charge en dehors des contraintes de l’interface et journaliser des horodatages précis ; les ID de messages arbitraires doivent être vérifiés pour chaque implémentation :

* **WhatsApp :** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidevice de WhatsApp Web) documente l’envoi et la réception des accusés de réception ; [Cobalt](https://github.com/Auties00/Cobalt) (API Java/Kotlin non officielle pour le Web et les appareils mobiles) documente des opérations sur les messages telles que la réaction, la modification et la suppression. Utilisez leurs API documentées plutôt que de supposer que chaque frame interne est exposée.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal :** [signal-cli](https://github.com/AsamK/signal-cli) expose des interfaces CLI, JSON-RPC et D-Bus, tandis que [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) est une bibliothèque Java permettant de communiquer avec Signal.<sup>[[5]](#references)[[7]](#references)</sup> La syntaxe actuelle de `signal-cli` utilise `sendReaction RECIPIENT --target-author --target-timestamp` ; laissez `receive` ou `daemon` s’exécuter afin que les mises à jour du protocole continuent d’être traitées.<sup>[[6]](#references)</sup> Exemple de bascule d’auto-réaction :
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema :** Les mesures de l’article Careless Whisper ont montré que les accusés de réception sont synchronisés entre les appareils ; un seul accusé de réception par message est donc exposé, même dans une configuration multi-appareils.<sup>[[1]](#references)</sup>
* **PoCs clés en main :** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) fournit des backends WhatsApp/Signal, utilise par défaut des sondes de suppression silencieuses et étiquette les états `active` et `standby` avec un seuil de médiane glissante (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) est un CLI plus léger, d’abord orienté WhatsApp, avec `--delay`, `--concurrent`, des exportateurs CSV/Prometheus et une sortie adaptée à Grafana.<sup>[[9]](#references)</sup> Considérez les deux comme des outils auxiliaires de reconnaissance plutôt que comme des références de protocole ; le point important est de constater le peu de code nécessaire une fois l’accès au client brut disponible.

Lorsque les outils personnalisés ne sont pas disponibles, les clients officiels ou les outils de développement des navigateurs peuvent tout de même déclencher des actions silencieuses et exposer le timing du trafic chiffré ; les API brutes suppriment les délais de l’interface et permettent des opérations invalides.<sup>[[1]](#references)</sup>

## Compagnon inquiétant : boucle d’échantillonnage silencieuse

1. Choisissez n’importe quel message historique que vous avez envoyé dans la conversation afin que la victime ne voie jamais les bulles de « réaction » changer.
2. Alternez entre un emoji visible et une charge utile de réaction vide (encodée par `""` dans les protobufs WhatsApp ou par `--remove` dans signal-cli). Chaque transmission produit un acquittement de l’appareil malgré l’absence de changement d’interface pour la victime.
3. Horodatez l’envoi et l’arrivée de chaque accusé de réception. Une boucle à 1 Hz comme la suivante fournit indéfiniment des traces de RTT par appareil :
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp et Signal acceptant un nombre illimité de mises à jour de réactions, l’attaquant n’a jamais besoin de publier de nouveau contenu dans la conversation ni de se soucier des fenêtres de modification.<sup>[[1]](#references)</sup>

## Inconnu inquiétant : sondage de numéros de téléphone arbitraires

1. Créez un nouveau compte WhatsApp/Signal et récupérez les clés d’identité publiques du numéro cible (ce qui est effectué automatiquement lors de l’établissement de la session).
2. Créez un paquet de réaction faisant référence à un `message_id` aléatoire qui n’a jamais été vu par aucune des deux parties ; l’article indique que WhatsApp et Signal acceptent ces réactions et génèrent tout de même des accusés de réception.<sup>[[1]](#references)</sup>
3. Envoyez le paquet même si aucune conversation n’existe. Les appareils de la victime le déchiffrent, ne trouvent pas le message de base, ignorent le changement d’état, mais acquittent tout de même le ciphertext entrant et renvoient les accusés de réception à l’attaquant.
4. Répétez continuellement afin de construire des séries de RTT sans conversation préalable ni notification visible.<sup>[[1]](#references)</sup>

Si vous devez d’abord découvrir quels numéros sont enregistrés ou souhaitez préremplir des inventaires d’appareils à grande échelle, combinez ceci avec les [oracles de découverte de contacts / d’enregistrement](../pentesting-web/registration-vulnerabilities.md) plutôt que de deviner manuellement des plages E.164 aléatoires.

Les travaux publiés sur la découverte de contacts ont montré pourquoi cela est important sur le plan opérationnel : avec des tables précises de préfixes téléphoniques et des ressources modestes, les chercheurs ont pu interroger environ `10%` des numéros mobiles américains sur WhatsApp et `100%` sur Signal avant de passer au sondage ciblé.<sup>[[11]](#references)</sup> En pratique, le préfiltrage des comptes actifs permet de concentrer le budget de sondes silencieuses sur les numéros qui déchiffreront effectivement les paquets.

Les versions récentes de WhatsApp exposent également `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Considérez cette option comme un limiteur de débit : la documentation du tracker indique que WhatsApp bloque les messages à haut volume provenant de comptes inconnus, mais ne divulgue pas le seuil ; elle n’empêche donc pas complètement les réactions de sondage.<sup>[[8]](#references)</sup>

## Recyclage des modifications et suppressions comme déclencheurs furtifs

* **Suppressions répétées :** Après la suppression d’un message pour tout le monde, les paquets de suppression ultérieurs faisant référence au même `message_id` n’ont aucun effet sur l’interface, mais chaque appareil les déchiffre et les acquitte toujours.
* **Opérations hors fenêtre :** WhatsApp impose des fenêtres d’environ ~60 h pour la suppression et ~20 min pour la modification dans l’interface ; Signal impose ~48 h. Les messages de protocole créés en dehors de ces fenêtres sont ignorés silencieusement sur l’appareil victime, mais les accusés de réception sont transmis, ce qui permet aux attaquants de sonder indéfiniment longtemps après la fin de la conversation.
* **Charges utiles invalides :** L’article indique que les messages invalides peuvent tout de même être acquittés ; le comportement exact concernant les corps malformés ou les ID supprimés dépend de l’implémentation. Testez donc avant de vous y fier.<sup>[[1]](#references)</sup>

## Amplification multi-appareils et fingerprinting

* Sur WhatsApp et Signal, chaque appareil associé (téléphone, application desktop, compagnon de navigateur) déchiffre la sonde indépendamment et renvoie son propre acquittement. Le comptage des accusés de réception par sonde révèle le nombre exact d’appareils.<sup>[[1]](#references)</sup>
* Si un appareil est hors ligne, son accusé de réception est mis en file d’attente puis émis lors de la reconnexion. Les interruptions leakent donc les cycles en ligne/hors ligne et même les horaires de déplacement (par exemple, les accusés du desktop s’arrêtent pendant les trajets).
* Les distributions de RTT diffèrent selon la plateforme et l’environnement, car l’OS, le modèle, le client et les conditions réseau influencent le timing. Regroupez les RTT (par exemple avec k-means sur des caractéristiques de médiane/variance) afin d’étiqueter les appareils comme « combiné Android », « combiné iOS », « desktop Electron », etc.
* Comme l’expéditeur doit récupérer l’inventaire des clés du destinataire avant le chiffrement, l’attaquant peut également observer l’ajout de nouveaux appareils ; une augmentation soudaine du nombre d’appareils ou l’apparition d’un nouveau cluster de RTT constitue un indicateur fort.<sup>[[1]](#references)</sup>

## Cadence d’échantillonnage, mise en file et accusés de réception empilés

* **Tolérance aux rafales de WhatsApp :** Des mesures publiées indiquent que WhatsApp acceptait des rafales de réactions silencieuses à raison d’une sonde toutes les `50 ms` sans mise en file évidente côté serveur. Cela est utile pour de courtes rafales de calibration, un comptage rapide des appareils ou une montée en charge rapide d’une attaque d’épuisement.
* **Mise en file à long terme de Signal :** Signal tolérait les courtes rafales, mais commençait à mettre en file le trafic continu de plusieurs sondes par seconde. Pour une surveillance de longue durée, maintenez la cadence autour de `1 Hz` (ou moins) afin que chaque accusé de réception reflète toujours l’état actuel de l’appareil plutôt que la purge d’un backlog.
* **Artefacts de reconnexion :** Lorsqu’un appareil revient en ligne, certains clients regroupent ou envoient rapidement plusieurs accusés de réception retardés. Traitez ces rafales comme un marqueur de transition d’état plutôt que comme des échantillons de RTT indépendants ; sinon votre clustering ou votre classifieur `active` contre `idle` s’ajustera excessivement au bruit de reconnexion.<sup>[[1]](#references)</sup>

## Inférence du comportement à partir des traces de RTT

1. Échantillonnez à ≥1 Hz afin de capturer les effets de planification de l’OS. Avec WhatsApp sur iOS, les RTT <1 s sont fortement corrélés à un écran allumé/une application au premier plan, tandis que les RTT >1 s correspondent à une limitation en arrière-plan ou lorsque l’écran est éteint.
2. Créez des classifieurs simples (seuil ou k-means à deux clusters) qui étiquettent chaque RTT comme « actif » ou « inactif ». Regroupez les étiquettes en séquences afin de déduire les heures de sommeil, les trajets, les horaires de travail ou les périodes d’activité du compagnon desktop.
3. Corrélez les sondes simultanées vers chaque appareil afin d’observer les passages du mobile au desktop, les moments où les compagnons se déconnectent et si l’application est limitée par les push ou par le socket persistant.
4. Sur les réseaux réels, évitez un seuil unique codé en dur de `1 s`. Initialisez chaque appareil avec une courte fenêtre de préchauffage et conservez une référence glissante (par exemple, la PoC device-activity-tracker utilise `threshold = 0.9 * median RTT`) afin que les variations Wi-Fi/cellulaire ne rendent pas votre classifieur inutilisable.<sup>[[1]](#references)[[8]](#references)</sup>

## Inférence de localisation à partir du RTT de livraison

Le même primitive temporelle peut être réutilisé pour déduire où se trouve le destinataire, et pas seulement s’il est actif. Les travaux `Hope of Delivery` ont montré que l’entraînement sur les distributions de RTT correspondant à des emplacements connus permet ensuite à un attaquant de classifier la localisation de la victime à partir des seules confirmations de livraison :<sup>[[2]](#references)</sup>

* Créez une référence pour la même cible lorsqu’elle se trouve dans plusieurs lieux connus (domicile, bureau, campus, pays A contre pays B, etc.).
* Pour chaque emplacement, recueillez de nombreux RTT de messages normaux et extrayez des caractéristiques simples telles que la médiane, la variance ou des intervalles de percentiles.
* Pendant l’attaque réelle, comparez la nouvelle série de sondes aux clusters entraînés. L’article indique que même des emplacements situés dans la même ville peuvent souvent être différenciés, avec une précision `>80%` dans une configuration à 3 emplacements.
* Cette méthode fonctionne mieux lorsque l’attaquant contrôle l’environnement de l’expéditeur et effectue les sondes dans des conditions réseau similaires, car le chemin mesuré inclut le réseau d’accès du destinataire, la latence de réveil et l’infrastructure du Messenger.<sup>[[2]](#references)</sup>

Contrairement aux attaques silencieuses par réaction/modification/suppression décrites ci-dessus, l’inférence de localisation ne nécessite ni ID de messages invalides ni paquets furtifs modifiant l’état. Des messages ordinaires avec des confirmations de livraison normales suffisent ; le compromis est donc une furtivité moindre, mais une applicabilité plus large entre les Messengers.

## Épuisement furtif des ressources

Comme chaque sonde silencieuse doit être déchiffrée et acquittée, l’envoi continu de bascules de réactions, de modifications invalides ou de paquets de suppression pour tout le monde crée un DoS au niveau applicatif :<sup>[[1]](#references)</sup>

* Force la radio/le modem à transmettre et recevoir chaque seconde → décharge notable de la batterie, surtout sur les combinés inactifs.
* Génère du trafic montant/descendant qui consomme les forfaits de données mobiles et peut entrer en concurrence avec des fonctions sensibles à la latence, comme les appels vidéo.<sup>[[1]](#references)</sup>
* Les grandes charges utiles invalides ajoutent du travail de traitement, mais l’article indique que la cryptographie elle-même représente une part négligeable du coût énergétique.<sup>[[1]](#references)</sup>
* Sur WhatsApp, les réactions invalides acceptent bien plus de données que ne le laisse supposer un emoji normal : des mesures publiées ont constaté une acceptation côté serveur allant jusqu’à environ `1 MB` par réaction.
* Les réactions surdimensionnées cessent de produire des accusés de réception fiables lorsque le corps dépasse environ `30 bytes`, mais elles sont tout de même relayées et traitées avant d’être supprimées. Gardez les corps des réactions minuscules lorsque vous avez besoin d’ACKs ; augmentez leur taille uniquement lorsque l’objectif est l’épuisement pur ou un transport unidirectionnel furtif.
* Des mesures publiques ont atteint environ `3.7 MB/s` (`~13.3 GB/h`) de trafic vers la victime dans ce mode.

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
