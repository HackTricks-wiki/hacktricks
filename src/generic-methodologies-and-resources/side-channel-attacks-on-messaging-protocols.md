# Attaques par canal auxiliaire via les accusés de réception dans les messageries E2EE

Les accusés de réception sont obligatoires dans les messageries modernes chiffrées de bout en bout (E2EE), car les clients doivent savoir quand un ciphertext a été déchiffré afin de pouvoir supprimer l'état de ratcheting et les clés éphémères. Le serveur relaie des blobs opaques ; les accusés de réception des appareils (doubles coches) sont donc émis par le destinataire après un déchiffrement réussi. La mesure du temps aller-retour (RTT) entre une action déclenchée par l'attaquant et l'accusé de réception correspondant expose un canal temporel haute résolution qui leak l'état de l'appareil et la présence en ligne, et peut être détourné pour un DoS furtif. Les déploiements multi-appareils de type « client-fanout » amplifient le leak, car chaque appareil enregistré déchiffre la sonde et renvoie son propre accusé.<sup>[[1]](#references)</sup>

## Sources des accusés de réception vs. signaux visibles par l'utilisateur

Choisissez des types de messages qui émettent toujours un accusé de réception, mais qui ne produisent aucun élément visible dans l'UI de la victime. Le tableau ci-dessous résume le comportement confirmé empiriquement :<sup>[[1]](#references)</sup>

| Messagerie | Action | Accusé de réception | Notification de la victime | Remarques |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Message texte | ● | ● | Toujours bruyant → utile uniquement pour initialiser l'état. |
| | Réaction | ● | ◐ (uniquement en réaction au message de la victime) | Les auto-réactions et leurs suppressions restent silencieuses. |
| | Modification | ● | Push silencieux dépendant de la plateforme | Fenêtre de modification ≈20 min ; toujours acquittée après expiration. |
| | Suppression pour tout le monde | ● | ○ | L'UI autorise ~60 h, mais les paquets ultérieurs sont toujours acquittés. |
| **Signal** | Message texte | ● | ● | Mêmes limitations que WhatsApp. |
| | Réaction | ● | ◐ | Les auto-réactions sont invisibles pour la victime. |
| | Modification/Suppression | ● | ○ | Le serveur impose une fenêtre d'environ 48 h et autorise jusqu'à 10 modifications, mais les paquets tardifs sont toujours acquittés. |
| **Threema** | Message texte | ● | ● | Les accusés multi-appareils sont agrégés ; un seul RTT par sonde devient donc visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement de l'UI dépendant de la plateforme est indiqué dans le tableau. Désactivez les accusés de lecture si nécessaire, mais les accusés de réception ne peuvent pas être désactivés dans WhatsApp ou Signal.<sup>[[1]](#references)</sup>

## Objectifs et modèles de l'attaquant

* **G1 – Fingerprinting des appareils :** Compter le nombre d'accusés reçus par sonde, regrouper les RTT pour déduire l'OS/client (Android contre iOS contre desktop) et surveiller les transitions en ligne/hors ligne.
* **G2 – Surveillance comportementale :** Traiter la série de RTT haute fréquence (≈1 Hz est stable) comme une série temporelle et déduire l'écran allumé/éteint, l'application au premier plan/arrière-plan, les heures de trajet contre les heures de travail, etc.
* **G3 – Épuisement des ressources :** Maintenir les radios/CPU de chaque appareil de la victime éveillés en envoyant des sondes silencieuses sans fin, ce qui décharge la batterie, consomme les données et dégrade la qualité des appels vidéo.<sup>[[1]](#references)</sup>

Deux threat actors suffisent pour décrire la surface d'abus :<sup>[[1]](#references)</sup>

1. **Creepy companion :** partage déjà une conversation avec la victime et abuse des auto-réactions, des suppressions de réactions ou des modifications/suppressions répétées liées à des IDs de messages existants.
2. **Spooky stranger :** enregistre un burner account et envoie des réactions faisant référence à des IDs de messages qui n'ont jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les accusent tout de même, même si l'UI ignore le changement d'état. Aucune conversation préalable n'est donc nécessaire.

## Outils pour l'accès au protocole brut

Appuyez-vous sur des clients qui exposent suffisamment du protocole E2EE sous-jacent pour créer des paquets pris en charge en dehors des contraintes de l'UI et journaliser des timestamps précis ; les IDs de messages arbitraires doivent être vérifiés pour chaque implémentation :

* **WhatsApp :** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidevice WhatsApp Web) documente l'envoi et la réception des accusés de réception ; [Cobalt](https://github.com/Auties00/Cobalt) (API Web et mobile Java/Kotlin non officielle) documente les opérations sur les messages, comme les réactions, modifications et suppressions. Utilisez leurs APIs documentées plutôt que de supposer que chaque frame interne est exposée.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal :** [signal-cli](https://github.com/AsamK/signal-cli) expose des interfaces CLI, JSON-RPC et D-Bus, tandis que [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) est une bibliothèque Java permettant de communiquer avec Signal.<sup>[[5]](#references)[[7]](#references)</sup> La syntaxe actuelle de `signal-cli` utilise `sendReaction RECIPIENT --target-author --target-timestamp` ; laissez `receive` ou `daemon` s'exécuter afin que les mises à jour du protocole continuent d'être traitées.<sup>[[6]](#references)</sup> Exemple de basculement d'auto-réaction :
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema :** Les mesures de l'article Careless Whisper ont montré que les accusés de réception sont synchronisés entre les appareils ; un seul accusé par message est donc exposé, même dans une configuration multi-appareils.<sup>[[1]](#references)</sup>
* **PoCs turnkey :** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) fournit des backends WhatsApp/Signal, utilise par défaut des sondes de suppression silencieuses et étiquette les états `active` et `standby` avec un seuil basé sur la médiane glissante (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) est un CLI plus léger, axé sur WhatsApp, avec `--delay`, `--concurrent`, des exporters CSV/Prometheus et une sortie adaptée à Grafana.<sup>[[9]](#references)</sup> Considérez les deux comme des assistants de reconnaissance plutôt que comme des références de protocole ; l'essentiel est de constater le peu de code nécessaire une fois que l'accès au client brut existe.

Lorsque les outils personnalisés ne sont pas disponibles, les clients officiels ou les outils de développement du navigateur peuvent toujours déclencher des actions silencieuses et exposer le timing du trafic chiffré ; les APIs brutes suppriment les délais de l'UI et permettent des opérations invalides.<sup>[[1]](#references)</sup>

## Creepy companion : boucle d'échantillonnage silencieuse

1. Choisissez n'importe quel ancien message que vous avez envoyé dans la conversation afin que la victime ne voie jamais les bulles de « réaction » changer.
2. Alternez entre un emoji visible et un payload de réaction vide (encodé comme `""` dans les protobufs WhatsApp ou avec `--remove` dans signal-cli). Chaque transmission produit un ack de l'appareil malgré l'absence de changement d'UI pour la victime.
3. Enregistrez le moment de l'envoi et l'arrivée de chaque accusé de réception. Une boucle à 1 Hz comme la suivante fournit indéfiniment des traces RTT par appareil :
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Comme WhatsApp/Signal acceptent un nombre illimité de mises à jour de réactions, l'attaquant n'a jamais besoin de publier du nouveau contenu dans la conversation ni de se soucier des fenêtres de modification.<sup>[[1]](#references)</sup>

## Spooky stranger : sonder des numéros de téléphone arbitraires

1. Enregistrez un nouveau compte WhatsApp/Signal et récupérez les clés d'identité publiques du numéro ciblé (automatiquement lors de l'établissement de la session).
2. Créez un paquet de réaction faisant référence à un `message_id` aléatoire jamais vu par aucune des deux parties ; l'article indique que WhatsApp et Signal acceptent ces réactions et génèrent tout de même des accusés de réception.<sup>[[1]](#references)</sup>
3. Envoyez le paquet même si aucune conversation n'existe. Les appareils de la victime le déchiffrent, échouent à trouver le message de base, ignorent le changement d'état, mais accusent tout de même la réception du ciphertext entrant, en envoyant les accusés de l'appareil à l'attaquant.
4. Répétez continuellement afin de construire des séries RTT sans conversation préalable ni notification visible.<sup>[[1]](#references)</sup>

Si vous devez d'abord découvrir quels numéros sont enregistrés ou souhaitez pré-initialiser des inventaires d'appareils à grande échelle, combinez cette approche avec des [oracles de découverte de contacts / d'enregistrement](../pentesting-web/registration-vulnerabilities.md) plutôt que de deviner manuellement des plages E.164 aléatoires.

Les travaux publiés sur la découverte de contacts ont montré pourquoi cela est opérationnellement important : avec des tables précises de préfixes téléphoniques et des ressources modestes, des chercheurs ont pu interroger environ `10%` des numéros mobiles américains sur WhatsApp et `100%` sur Signal avant de passer au probing ciblé.<sup>[[11]](#references)</sup> En pratique, filtrer d'abord les comptes actifs permet de concentrer le budget de sondes silencieuses sur les numéros qui déchiffreront effectivement les paquets.

Les versions récentes de WhatsApp exposent également `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Considérez cette option comme un limiteur de débit : la documentation du tracker indique que WhatsApp bloque les messages en grand volume provenant de comptes inconnus, mais ne révèle pas le seuil. Elle n'empêche donc pas complètement les réactions de sondage.<sup>[[8]](#references)</sup>

## Réutiliser les modifications et suppressions comme déclencheurs furtifs

* **Suppressions répétées :** Après qu'un message a été supprimé pour tout le monde une première fois, les paquets de suppression ultérieurs faisant référence au même `message_id` n'ont aucun effet sur l'UI, mais chaque appareil les déchiffre et les accuse toujours.
* **Opérations hors fenêtre :** WhatsApp impose des fenêtres d'environ 60 h pour la suppression et 20 min pour la modification dans l'UI ; Signal impose 48 h. Les messages de protocole créés en dehors de ces fenêtres sont ignorés silencieusement sur l'appareil de la victime, mais les accusés sont transmis. Les attaquants peuvent donc sonder indéfiniment, longtemps après la fin de la conversation.
* **Payloads invalides :** L'article indique que les messages invalides peuvent tout de même être acquittés ; le comportement exact pour les corps malformés ou les IDs purgés dépend de l'implémentation. Testez donc avant de vous y fier.<sup>[[1]](#references)</sup>

## Amplification multi-appareils et fingerprinting

* Sur WhatsApp et Signal, chaque appareil associé (téléphone, application desktop, browser companion) déchiffre indépendamment la sonde et renvoie son propre ack. Compter les accusés par sonde révèle le nombre exact d'appareils.<sup>[[1]](#references)</sup>
* Si un appareil est hors ligne, son accusé est mis en file d'attente et émis lors de la reconnexion. Les interruptions leakent donc les cycles en ligne/hors ligne et même les horaires de déplacement (par exemple, les accusés du desktop s'arrêtent pendant les trajets).
* Les distributions de RTT diffèrent selon la plateforme et l'environnement, car l'OS, le modèle, le client et les conditions réseau influencent le timing. Regroupez les RTT (par exemple avec k-means sur des caractéristiques de médiane/variance) pour étiqueter les appareils : « Android handset », « iOS handset », « Electron desktop », etc.
* Comme l'expéditeur doit récupérer l'inventaire des clés du destinataire avant le chiffrement, l'attaquant peut également surveiller l'association de nouveaux appareils ; une hausse soudaine du nombre d'appareils ou l'apparition d'un nouveau cluster RTT constitue un indicateur fort.<sup>[[1]](#references)</sup>

## Cadence d'échantillonnage, mise en file et accusés empilés

* **Tolérance aux bursts de WhatsApp :** Des mesures publiées indiquent que WhatsApp acceptait des bursts de réactions silencieuses jusqu'à une sonde toutes les `50 ms` sans mise en file évidente côté serveur. Cela est utile pour de courtes phases de calibration, le comptage rapide des appareils ou l'accélération rapide d'une attaque d'épuisement.
* **Mise en file à long terme dans Signal :** Signal tolère les bursts courts, mais commence à mettre en file le trafic soutenu de plusieurs sondes par seconde. Pour une surveillance de longue durée, maintenez la cadence autour de `1 Hz` (ou moins) afin que chaque accusé reflète toujours l'état actuel de l'appareil plutôt que la vidange d'une file d'attente.
* **Artefacts de reconnexion :** Lorsqu'un appareil revient en ligne, certains clients regroupent ou émettent rapidement plusieurs accusés retardés. Considérez ces bursts d'accusés comme un marqueur de transition d'état plutôt que comme des échantillons RTT indépendants ; sinon, votre clustering ou votre classifieur `active` contre `idle` s'ajustera excessivement au bruit de reconnexion.<sup>[[1]](#references)</sup>

## Inférence du comportement à partir des traces RTT

1. Échantillonnez à ≥1 Hz pour capturer les effets de scheduling de l'OS. Avec WhatsApp sur iOS, les RTT <1 s sont fortement corrélés à un écran allumé/une application au premier plan, tandis que les RTT >1 s correspondent à la limitation en arrière-plan/écran éteint.
2. Créez des classifieurs simples (seuil ou k-means à deux clusters) qui étiquettent chaque RTT comme « active » ou « idle ». Agrégez les étiquettes en séquences afin de déduire les heures de coucher, les trajets, les heures de travail ou les périodes d'activité du browser companion.
3. Corrélez les sondes simultanées vers chaque appareil pour déterminer quand les utilisateurs passent du mobile au desktop, quand les companions se déconnectent et si l'application est limitée par les push ou par le socket persistant.
4. Sur les réseaux réels, évitez un seuil unique codé en dur de `1 s`. Initialisez chaque appareil avec une courte fenêtre de chauffe et maintenez une baseline glissante (par exemple, le PoC device-activity-tracker utilise `threshold = 0.9 * median RTT`) afin que les variations Wi-Fi/cellulaires ne détruisent pas votre classifieur.<sup>[[1]](#references)[[8]](#references)</sup>

## Inférence de la localisation à partir du RTT de livraison

La même primitive temporelle peut être réutilisée pour déduire où se trouve le destinataire, et pas seulement s'il est actif. Les travaux `Hope of Delivery` ont montré que l'entraînement sur les distributions RTT de lieux connus permet ensuite à un attaquant de classifier la localisation de la victime à partir des seules confirmations de livraison :<sup>[[2]](#references)</sup>

* Établissez une baseline pour la même cible lorsqu'elle se trouve dans plusieurs lieux connus (domicile, bureau, campus, pays A contre pays B, etc.).
* Pour chaque localisation, collectez de nombreux RTT de messages normaux et extrayez des caractéristiques simples comme la médiane, la variance ou des intervalles de percentiles.
* Pendant l'attaque réelle, comparez la nouvelle série de sondes aux clusters entraînés. L'article indique que même des localisations situées dans la même ville peuvent souvent être distinguées, avec une précision `>80%` dans une configuration à 3 localisations.
* Cette méthode fonctionne mieux lorsque l'attaquant contrôle l'environnement de l'expéditeur et effectue les sondes dans des conditions réseau similaires, car le chemin mesuré inclut le réseau d'accès du destinataire, la latence de réveil et l'infrastructure de la messagerie.<sup>[[2]](#references)</sup>

Contrairement aux attaques silencieuses par réaction/modification/suppression décrites ci-dessus, l'inférence de localisation ne nécessite ni IDs de messages invalides ni paquets furtifs modifiant l'état. Des messages ordinaires avec des confirmations de livraison normales suffisent ; le compromis est donc une furtivité moindre, mais une applicabilité plus large entre les messageries.

## Épuisement furtif des ressources

Comme chaque sonde silencieuse doit être déchiffrée et acquittée, l'envoi continu de basculements de réactions, de modifications invalides ou de paquets de suppression pour tout le monde crée un DoS au niveau applicatif :<sup>[[1]](#references)</sup>

* Force la radio/le modem à transmettre et recevoir chaque seconde → décharge notable de la batterie, en particulier sur les handsets inactifs.
* Génère du trafic montant/descendant qui consomme les forfaits de données mobiles et peut entrer en concurrence avec des fonctionnalités sensibles à la latence, comme les appels vidéo.<sup>[[1]](#references)</sup>
* Les payloads invalides ajoutent du travail de traitement, mais l'article indique que la cryptographie représente elle-même une part négligeable du coût énergétique.<sup>[[1]](#references)</sup>
* Sur WhatsApp, les réactions invalides acceptent beaucoup plus de données que ne le suggère un emoji normal : des mesures publiées ont constaté une acceptation côté serveur allant jusqu'à environ `1 MB` par réaction.
* Les réactions surdimensionnées cessent de produire des accusés fiables lorsque le corps dépasse environ `30 bytes`, mais elles sont tout de même relayées et traitées avant d'être supprimées. Gardez les corps des réactions courts lorsque vous avez besoin d'ACKs ; augmentez leur taille uniquement si l'objectif est un épuisement pur ou un transport unidirectionnel furtif.
* Des mesures publiques ont atteint environ `3.7 MB/s` (`~13.3 GB/h`) de trafic vers la victime dans ce mode.

## References

- [1] [Careless Whisper : Exploiter les accusés de réception silencieux pour surveiller les utilisateurs sur les messageries instantanées mobiles](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery : Extraire la localisation des utilisateurs à partir des messageries instantanées mobiles](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Page de manuel de signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Comment bloquer un grand nombre de messages provenant de comptes inconnus | Centre d'aide WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Tous les numéros sont américains : abus à grande échelle de la découverte de contacts dans les messageries mobiles](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
