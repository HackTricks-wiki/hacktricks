# Attaques par canal auxiliaire via les accusés de réception dans les messageries E2EE

{{#include ../banners/hacktricks-training.md}}

Les accusés de réception sont obligatoires dans les messageries modernes chiffrées de bout en bout (E2EE), car les clients doivent savoir quand un texte chiffré a été déchiffré afin de pouvoir supprimer l’état du ratchet et les clés éphémères. Le serveur transmet des blobs opaques ; les appareils du destinataire envoient donc des accusés de réception (doubles coches) après le déchiffrement réussi. Mesurer le temps aller-retour (RTT) entre une action déclenchée par l’attaquant et l’accusé de réception correspondant expose un canal temporel haute résolution qui révèle l’état de l’appareil et la présence en ligne, et peut être exploité pour un DoS furtif. Les déploiements multi-appareils « client-fanout » amplifient la fuite, car chaque appareil enregistré déchiffre la sonde et renvoie son propre accusé de réception.<sup>[[1]](#references)</sup>

## Sources d’accusés de réception et signaux visibles par l’utilisateur

Choisissez des types de messages qui génèrent toujours un accusé de réception sans laisser de trace visible dans l’interface de la victime. Le tableau ci-dessous résume les comportements confirmés empiriquement :<sup>[[1]](#references)</sup>

| Messagerie | Action | Accusé de réception | Notification de la victime | Remarques |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Message texte | ● | ● | Toujours bruyant → utile uniquement pour amorcer l’état. |
| | Réaction | ● | ◐ (uniquement si elle réagit à un message de la victime) | Les réactions à soi-même et leur suppression restent silencieuses. |
| | Modification | ● | Push silencieux selon la plateforme | Fenêtre de modification ≈20 min ; les paquets sont tout de même acquittés après expiration. |
| | Suppression pour tous | ● | ○ | L’interface autorise environ 60 h, mais les paquets ultérieurs sont toujours acquittés. |
| **Signal** | Message texte | ● | ● | Mêmes limites que WhatsApp. |
| | Réaction | ● | ◐ | Les réactions à soi-même sont invisibles pour la victime. |
| | Modification/Suppression | ● | ○ | Le serveur impose une fenêtre d’environ 48 h et autorise jusqu’à 10 modifications, mais les paquets tardifs sont toujours acquittés. |
| **Threema** | Message texte | ● | ● | Les accusés de réception multi-appareils sont agrégés ; un seul RTT par sonde est donc visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement de l’interface selon la plateforme est indiqué dans le tableau. Désactivez les accusés de lecture si nécessaire, mais les accusés de réception ne peuvent pas être désactivés dans WhatsApp ou Signal.<sup>[[1]](#references)</sup>

## Objectifs et modèles d’attaquant

* **G1 – Empreinte des appareils :** compter le nombre d’accusés de réception reçus par sonde, regrouper les RTT pour déduire le système d’exploitation/client (Android ou iOS, ou ordinateur), et surveiller les transitions en ligne/hors ligne.
* **G2 – Surveillance comportementale :** traiter la série de RTT à haute fréquence (≈1 Hz est stable) comme une série temporelle et en déduire l’écran allumé/éteint, l’application au premier plan/en arrière-plan, les trajets domicile-travail par rapport aux heures de travail, etc.
* **G3 – Épuisement des ressources :** maintenir actives les radios/CPU de chaque appareil de la victime en envoyant sans fin des sondes silencieuses, épuisant la batterie et les données et dégradant la qualité des appels vidéo.<sup>[[1]](#references)</sup>

Deux acteurs malveillants suffisent à décrire la surface d’abus :<sup>[[1]](#references)</sup>

1. **Compagnon flippant :** partage déjà une conversation avec la victime et abuse des réactions à soi-même, de leur suppression ou de modifications/suppressions répétées liées à des ID de message existants.
2. **Inconnu sinistre :** crée un compte jetable et envoie des réactions faisant référence à des ID de message qui n’ont jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les acquittent tout de même, même si l’interface ignore le changement d’état. Aucune conversation préalable n’est donc nécessaire.

## Outils d’accès au protocole brut

Utilisez des clients qui exposent suffisamment le protocole E2EE sous-jacent pour créer des paquets pris en charge en dehors des contraintes de l’interface et enregistrer des horodatages précis ; la prise en charge d’ID de message arbitraires doit être vérifiée pour chaque implémentation :

* **WhatsApp :** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidevice WhatsApp Web) documente l’envoi et la réception des accusés de réception ; [Cobalt](https://github.com/Auties00/Cobalt) (API Web et mobile non officielle en Java/Kotlin) documente des opérations sur les messages comme réagir, modifier et supprimer. Utilisez leurs API documentées au lieu de supposer que chaque trame interne est exposée.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal :** [signal-cli](https://github.com/AsamK/signal-cli) expose des interfaces CLI, JSON-RPC et D-Bus, tandis que [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) est une bibliothèque Java permettant de communiquer avec Signal.<sup>[[5]](#references)[[7]](#references)</sup> La syntaxe actuelle de `signal-cli` utilise `sendReaction RECIPIENT --target-author --target-timestamp` ; laissez `receive` ou `daemon` en cours d’exécution pour que les mises à jour du protocole continuent d’être traitées.<sup>[[6]](#references)</sup> Exemple d’activation/désactivation d’une réaction à soi-même :
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema :** Les mesures présentées dans l’article Careless Whisper ont montré que les accusés de livraison sont synchronisés entre les appareils : un seul accusé par message est donc exposé, même dans une configuration multi-appareils.<sup>[[1]](#references)</sup>
* **PoCs prêts à l’emploi :** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) inclut des backends WhatsApp/Signal, utilise par défaut des sondes de suppression silencieuses et distingue `active` de `standby` à l’aide d’un seuil fondé sur la médiane glissante (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) est une CLI plus légère, principalement destinée à WhatsApp, qui propose `--delay`, `--concurrent`, des exportateurs CSV/Prometheus et une sortie compatible avec Grafana.<sup>[[9]](#references)</sup> Considérez ces deux outils comme des aides à la reconnaissance plutôt que comme des références sur les protocoles ; l’essentiel est de voir qu’il faut très peu de code dès lors qu’on dispose d’un accès direct au client.

Lorsque les outils personnalisés ne sont pas disponibles, les clients officiels ou les outils de développement du navigateur peuvent tout de même déclencher des actions silencieuses et révéler le timing du trafic chiffré ; les API brutes suppriment les délais de l’interface et permettent des opérations non valides.<sup>[[1]](#references)</sup>

## Compagnon inquiétant : boucle d’échantillonnage silencieuse

1. Choisissez n’importe quel ancien message que vous avez envoyé dans la conversation afin que la victime ne voie jamais les bulles de « réaction » changer.
2. Alternez entre un emoji visible et une charge utile de réaction vide (encodée sous la forme `""` dans les protobufs WhatsApp ou avec `--remove` dans signal-cli). Chaque transmission génère un accusé de l’appareil, même si l’interface de la victime ne change pas.
3. Horodatez l’envoi ainsi que l’arrivée de chaque accusé de livraison. Une boucle à 1 Hz comme celle ci-dessous fournit indéfiniment des traces RTT par appareil :
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Comme WhatsApp/Signal acceptent un nombre illimité de mises à jour de réaction, l’attaquant n’a jamais besoin de publier de nouveau contenu dans le chat ni de se soucier des fenêtres d’édition.<sup>[[1]](#references)</sup>

## Inconnu inquiétant : sonder des numéros de téléphone arbitraires

1. Créez un nouveau compte WhatsApp/Signal et récupérez les clés d’identité publiques du numéro cible (cette opération est effectuée automatiquement lors de l’initialisation de la session).
2. Créez un paquet de réaction faisant référence à un `message_id` aléatoire, jamais vu par l’une ou l’autre partie ; l’article indique que WhatsApp et Signal acceptent de telles réactions et génèrent quand même des accusés de réception de livraison.<sup>[[1]](#references)</sup>
3. Envoyez le paquet même s’il n’existe aucun fil de discussion. Les appareils de la victime le déchiffrent, ne parviennent pas à trouver le message d’origine, ignorent le changement d’état, mais accusent tout de même réception du texte chiffré entrant et renvoient des accusés de réception d’appareil à l’attaquant.
4. Répétez l’opération continuellement pour constituer des séries de RTT sans conversation préalable ni notification visible.<sup>[[1]](#references)</sup>

Si vous devez d’abord découvrir quels numéros sont enregistrés ou souhaitez inventorier les appareils à grande échelle, combinez cette méthode avec les [oracles de contact-discovery / d’enregistrement](../pentesting-web/registration-vulnerabilities.md) au lieu de deviner manuellement des plages E.164 aléatoires.

Les travaux publiés sur le contact-discovery ont montré l’importance opérationnelle de cette méthode : avec des tables précises de préfixes téléphoniques et des ressources modestes, les chercheurs ont pu interroger environ `10%` des numéros mobiles américains sur WhatsApp et `100%` sur Signal avant de passer à des sondes ciblées.<sup>[[11]](#references)</sup> En pratique, filtrer d’abord les comptes actifs permet de réserver le budget de sondes silencieuses aux numéros qui déchiffreront réellement les paquets.

Les versions récentes de WhatsApp proposent également `Paramètres -> Confidentialité -> Avancé -> Bloquer les messages provenant de comptes inconnus`.<sup>[[10]](#references)</sup> Considérez cette option comme un limiteur de débit : la documentation du tracker indique que WhatsApp bloque les messages à haut volume provenant de comptes inconnus, sans préciser le seuil. Elle n’empêche donc pas complètement les réactions de sondage.<sup>[[8]](#references)</sup>

## Recycler les modifications et les suppressions comme déclencheurs covert

* **Suppressions répétées :** après la suppression d’un message pour tout le monde, les paquets de suppression suivants faisant référence au même `message_id` n’ont aucun effet dans l’interface, mais chaque appareil les déchiffre et les accuse tout de même réception.
* **Opérations hors délai :** WhatsApp applique des fenêtres d’environ 60 h pour la suppression et 20 min pour la modification dans l’interface ; Signal applique une fenêtre d’environ 48 h. Les messages de protocole forgés en dehors de ces délais sont ignorés silencieusement par l’appareil de la victime, mais des accusés de réception sont transmis. Les attaquants peuvent donc sonder indéfiniment, longtemps après la fin de la conversation.
* **Charges utiles invalides :** l’article indique que les messages invalides peuvent tout de même être acquittés ; le comportement exact pour les corps malformés ou les ID purgés dépend de l’implémentation. Effectuez donc des tests avant de vous y fier.<sup>[[1]](#references)</sup>

## Amplification multi-appareils et fingerprinting

* Sur WhatsApp et Signal, chaque appareil associé (téléphone, application de bureau, navigateur compagnon) déchiffre la sonde indépendamment et renvoie son propre accusé de réception. Le nombre d’accusés de réception par sonde révèle le nombre exact d’appareils.<sup>[[1]](#references)</sup>
* Si un appareil est hors ligne, son accusé de réception est mis en file d’attente et envoyé à sa reconnexion. Les intervalles révèlent donc les cycles de connexion et de déconnexion, voire les horaires de déplacement (par exemple, les accusés de réception de l’ordinateur de bureau cessent pendant les trajets).
* Les distributions de RTT varient selon la plateforme et l’environnement, car le système d’exploitation, le modèle, le client et les conditions réseau influent sur le timing. Regroupez les RTT (par exemple, avec k-means sur des caractéristiques de médiane/variance) pour identifier « téléphone Android », « téléphone iOS », « ordinateur de bureau Electron », etc.
* Comme l’expéditeur doit récupérer l’inventaire des clés du destinataire avant le chiffrement, l’attaquant peut également surveiller l’association de nouveaux appareils ; une hausse soudaine du nombre d’appareils ou l’apparition d’un nouveau groupe de RTT constitue un indicateur fort.<sup>[[1]](#references)</sup>

**Fingerprinting à partir des accusés de réception mis en file d’attente :** envoyez plusieurs sondes avec des ID de message distincts alors que l’appareil cible est hors ligne. À sa reconnexion, corrélez les ID dans les accusés de réception de livraison renvoyés, puis vérifiez s’ils sont séparés ou regroupés dans un seul accusé, et si les ID regroupés conservent ou inversent l’ordre d’envoi. Dans les clients testés, WhatsApp sur Android/iOS renvoyait des accusés de réception de livraison séparés, tandis que Web, Windows et macOS les regroupaient ; macOS inversait l’ordre des ID regroupés. Signal Desktop regroupait les accusés de réception, contrairement à ses clients mobiles. Cela permet de classer un client qui se reconnecte même lorsque les distributions de RTT se chevauchent. Ne confondez pas les accusés de réception de livraison avec les confirmations de lecture, dont les règles de regroupement diffèrent.<sup>[[1]](#references)</sup>

Pour une sonde WhatsApp distincte qui lit les **renouvellements de prekey côté serveur** sans livrer de messages, consultez [Canal auxiliaire d’épuisement et de renouvellement des bundles de prekey](whatsapp-prekey-bundle-side-channel.md).

## Cadence d’échantillonnage, mise en file d’attente et accusés de réception regroupés

* **Tolérance aux rafales de WhatsApp :** des mesures publiées indiquent que WhatsApp acceptait des rafales de réactions silencieuses à raison d’une sonde toutes les `50 ms`, sans mise en file d’attente côté serveur manifeste. Cela convient aux courtes rafales d’étalonnage, au comptage rapide des appareils ou à la montée en charge rapide d’une attaque d’épuisement.
* **Mise en file d’attente prolongée sur Signal :** Signal tolérait les rafales courtes, mais commençait à mettre en file d’attente le trafic soutenu de plusieurs sondes par seconde. Pour une surveillance de longue durée, maintenez la cadence autour de `1 Hz` (ou moins), afin que chaque accusé de réception reflète toujours l’état actuel de l’appareil plutôt que l’écoulement d’une file d’attente.
* **Artefacts de reconnexion :** lorsqu’un appareil se reconnecte, certains clients regroupent plusieurs accusés de réception retardés ou les envoient rapidement. Considérez ces rafales d’accusés comme un marqueur de transition d’état plutôt que comme des échantillons RTT indépendants, faute de quoi votre clustering / classificateur `actif` vs `inactif` sera surajusté au bruit des reconnexions.<sup>[[1]](#references)</sup>

## Inférence du comportement à partir des traces RTT

1. Échantillonnez à ≥1 Hz pour capturer les effets de l’ordonnancement du système d’exploitation. Avec WhatsApp sur iOS, les RTT <1 s sont fortement corrélés à un écran allumé et à l’application au premier plan ; les RTT >1 s sont associés à un écran éteint et à la limitation en arrière-plan.
2. Créez des classificateurs simples (seuil ou k-means à deux groupes) qui étiquettent chaque RTT comme « actif » ou « inactif ». Regroupez les étiquettes en séquences pour déduire les heures de coucher, les trajets, les heures de travail ou les périodes d’activité de l’appareil compagnon de bureau.
3. Corrélez les sondes simultanées vers chaque appareil pour déterminer quand les utilisateurs passent du mobile à l’ordinateur de bureau, quand les appareils compagnons se déconnectent et si l’application est limitée par les notifications push ou par la socket persistante.
4. Sur les réseaux réels, évitez un seuil unique codé en dur de `1 s`. Effectuez une courte phase de chauffe pour chaque appareil et maintenez une référence glissante (par exemple, le PoC device-activity-tracker utilise `threshold = 0.9 * median RTT`) afin que les variations entre Wi-Fi et réseau cellulaire ne faussent pas le classificateur.<sup>[[1]](#references)[[8]](#references)</sup>

## Inférence de la localisation à partir des RTT de livraison

Le même mécanisme temporel peut servir à inférer où se trouve le destinataire, et pas seulement s’il est actif. Les travaux `Hope of Delivery` ont montré qu’en entraînant un modèle sur les distributions de RTT correspondant à des emplacements connus du destinataire, un attaquant peut ensuite classifier la localisation de la victime à partir des seules confirmations de livraison :<sup>[[2]](#references)</sup>

* Établissez une référence pour la même cible lorsqu’elle se trouve dans plusieurs lieux connus (domicile, bureau, campus, pays A ou pays B, etc.).
* Pour chaque lieu, collectez de nombreux RTT de messages normaux et extrayez des caractéristiques simples, comme la médiane, la variance ou des intervalles de percentiles.
* Pendant l’attaque réelle, comparez les nouvelles séries de sondes aux groupes d’entraînement. L’article indique que des lieux situés dans une même ville peuvent souvent être distingués, avec une précision `>80%` dans une configuration à 3 lieux.
* Cette méthode fonctionne mieux lorsque l’attaquant contrôle l’environnement de l’expéditeur et envoie les sondes dans des conditions réseau similaires, car le chemin mesuré inclut le réseau d’accès du destinataire, la latence de réveil et l’infrastructure de messagerie.<sup>[[2]](#references)</sup>

Contrairement aux attaques silencieuses par réaction, modification ou suppression décrites ci-dessus, l’inférence de localisation ne nécessite ni ID de message invalides ni paquets discrets modifiant l’état. De simples messages avec des confirmations de livraison normales suffisent ; le compromis est donc une discrétion moindre, mais une applicabilité plus large à différents services de messagerie.

## Épuisement discret des ressources

Comme chaque sonde silencieuse doit être déchiffrée et acquittée, l’envoi continu de bascules de réaction, de modifications invalides ou de paquets de suppression pour tout le monde crée un DoS au niveau de la couche applicative :<sup>[[1]](#references)</sup>

* Force la radio/le modem à émettre et recevoir chaque seconde → consommation de batterie perceptible, surtout sur les téléphones inactifs.
* Génère du trafic montant et descendant qui consomme les forfaits de données mobiles et peut concurrencer des fonctionnalités sensibles à la latence, comme les appels vidéo.<sup>[[1]](#references)</sup>
* Les charges utiles invalides volumineuses ajoutent du travail de traitement, mais l’article indique que la cryptographie elle-même représente une part négligeable du coût énergétique.<sup>[[1]](#references)</sup>
* Sur WhatsApp, les réactions invalides acceptent beaucoup plus de données que ne le laisse penser un emoji normal : des mesures publiées ont constaté une acceptation côté serveur allant jusqu’à environ `1 MB` par réaction.
* Les réactions surdimensionnées ne produisent plus d’accusés de réception de livraison fiables lorsque le corps dépasse environ `30 bytes`, mais elles sont tout de même transférées et traitées avant d’être ignorées. Gardez les corps des réactions très petits lorsque vous avez besoin d’accusés de réception ; augmentez leur taille uniquement si l’objectif est l’épuisement pur ou le transport covert à sens unique.
* Des mesures publiques ont atteint environ `3.7 MB/s` (`~13.3 GB/h`) de trafic sur l’appareil de la victime dans ce mode.



## References

- [1] [Murmure imprudent : exploiter les accusés de réception silencieux pour surveiller les utilisateurs sur les messageries instantanées mobiles](https://arxiv.org/html/2411.11194v4)
- [2] [Espoir de livraison : extraire la localisation des utilisateurs à partir des messageries instantanées mobiles](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [page de manuel de signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Comment bloquer les volumes importants de messages inconnus | Centre d’aide WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Tous les numéros sont américains : abus à grande échelle du contact-discovery dans les messageries mobiles](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
