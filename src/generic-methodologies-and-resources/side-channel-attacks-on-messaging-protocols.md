# Attaques Side-Channel sur les accusés de livraison dans les messageries E2EE

{{#include ../banners/hacktricks-training.md}}

Les accusés de livraison sont obligatoires dans les messageries modernes chiffrées de bout en bout (E2EE) parce que les clients doivent savoir quand un ciphertext a été déchiffré afin de pouvoir supprimer l'état de ratcheting et les clés éphémères. Le serveur relaie des blobs opaques, donc les accusés de réception côté appareil (double coche) sont émis par le destinataire après un déchiffrement réussi. Mesurer le temps aller-retour (RTT) entre une action déclenchée par l'attaquant et l'accusé de livraison correspondant expose un canal temporel à haute résolution qui leak l'état de l'appareil, la présence en ligne, et peut être abusé pour un DoS furtif. Les déploiements multi-device "client-fanout" amplifient la fuite parce que chaque appareil enregistré déchiffre le probe et renvoie son propre accusé.

## Sources d'accusés de livraison vs. signaux visibles par l'utilisateur

Choisissez des types de messages qui émettent toujours un accusé de livraison mais ne génèrent aucun artefact UI chez la victime. Le tableau ci-dessous résume le comportement confirmé empiriquement :

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Message texte | ● | ● | Toujours bruyant -> utile uniquement pour amorcer l'état. |
| | Réaction | ● | ◐ (uniquement si la réaction cible un message de la victime) | Les auto-réactions et les suppressions restent silencieuses. |
| | Édition | ● | Push silencieux dépendant de la plateforme | Fenêtre d'édition ≈20 min ; reste ack’d après expiration. |
| | Delete for everyone | ● | ○ | L'UI autorise ~60 h, mais les paquets plus tardifs sont toujours ack’d. |
| **Signal** | Message texte | ● | ● | Mêmes limites que WhatsApp. |
| | Réaction | ● | ◐ | Les auto-réactions sont invisibles pour la victime. |
| | Edit/Delete | ● | ○ | Le serveur impose une fenêtre d'environ ~48 h, autorise jusqu'à 10 éditions, mais les paquets tardifs sont toujours ack’d. |
| **Threema** | Message texte | ● | ● | Les accusés multi-device sont agrégés, donc un seul RTT par probe devient visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement UI dépendant de la plateforme est noté en ligne. Désactivez les accusés de lecture si nécessaire, mais les accusés de livraison ne peuvent pas être désactivés dans WhatsApp ou Signal.

## Objectifs et modèles d'attaquant

* **G1 - Empreinte device fingerprinting :** Compter combien d'accusés arrivent par probe, regrouper les RTT pour inférer l'OS/le client (Android vs iOS vs desktop), et surveiller les transitions en ligne/hors ligne.
* **G2 - Suivi comportemental :** Traiter la série temporelle RTT à haute fréquence (≈1 Hz est stable) comme une série temporelle et inférer écran allumé/éteint, app au premier-plan/en arrière-plan, trajets vs heures de travail, etc.
* **G3 - Épuisement des ressources :** Maintenir les radios/CPU de chaque appareil victime éveillés en envoyant des silent probes sans fin, ce qui vide la batterie/les données et dégrade la qualité VoIP/RTC.

Deux acteurs de menace suffisent pour décrire la surface d'abus :

1. **Creepy companion :** partage déjà un chat avec la victime et abuse des auto-réactions, des suppressions de réactions ou des éditions/suppressions répétées liées à des message IDs existants.
2. **Spooky stranger :** enregistre un compte jetable et envoie des réactions référençant des message IDs qui n'ont jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les accusent quand même même si l'UI rejette le changement d'état, donc aucune conversation préalable n'est requise.

## Outillage pour l'accès brut au protocole

Appuyez-vous sur des clients qui exposent le protocole E2EE sous-jacent afin de pouvoir fabriquer des paquets hors des contraintes UI, spécifier des `message_id`s arbitraires, et journaliser des timestamps précis :

* **WhatsApp :** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocole WhatsApp Web) ou [Cobalt](https://github.com/Auties00/Cobalt) (orienté mobile) permettent d'émettre des frames brutes `ReactionMessage`, `ProtocolMessage` (edit/delete) et `Receipt` tout en gardant l'état double-ratchet synchronisé.
* **Signal :** [signal-cli](https://github.com/AsamK/signal-cli) combiné avec [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expose chaque type de message via CLI/API. La syntaxe actuelle de `signal-cli` utilise `sendReaction RECIPIENT --target-author --target-timestamp`; laissez `receive` ou `daemon` en cours d'exécution pour que les accusés de livraison soient réellement collectés. Exemple d'auto-reaction toggle :
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema :** Le code source du client Android documente comment les accusés de livraison sont consolidés avant de quitter l'appareil, expliquant pourquoi le side channel y a une bande passante négligeable.
* **Turnkey PoCs :** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) fournit des backends WhatsApp/Signal, utilise par défaut des probes de delete silencieux, et étiquette `active` vs `standby` avec un seuil à médiane glissante (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) est un CLI plus léger centré sur WhatsApp avec `--delay`, `--concurrent`, des exporteurs CSV/Prometheus, et une sortie compatible Grafana. Considérez les deux comme des aides de reconnaissance plutôt que comme des références protocolaire ; l'enseignement important est combien peu de code est nécessaire une fois l'accès brut au client obtenu.

Quand l'outillage personnalisé n'est pas disponible, vous pouvez toujours déclencher des actions silencieuses depuis WhatsApp Web ou Signal Desktop et sniffer le canal websocket/WebRTC chiffré, mais les API brutes suppriment les délais UI et permettent des opérations invalides.

## Creepy companion : boucle d'échantillonnage silencieuse

1. Choisissez n'importe quel message historique que vous avez rédigé dans le chat afin que la victime ne voie jamais les bulles de "reaction" changer.
2. Alternez entre un emoji visible et un payload de réaction vide (encodé comme `""` dans les protobufs WhatsApp ou `--remove` dans signal-cli). Chaque transmission produit un ack d'appareil malgré l'absence de delta UI pour la victime.
3. Horodatez le moment d'envoi et chaque arrivée d'accusé de livraison. Une boucle à 1 Hz comme celle-ci fournit des traces RTT par appareil indéfiniment :
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Comme WhatsApp/Signal acceptent des mises à jour de réaction illimitées, l'attaquant n'a jamais besoin de publier de nouveau contenu de chat ni de se soucier des fenêtres d'édition.

## Spooky stranger : sondage de numéros de téléphone arbitraires

1. Enregistrez un nouveau compte WhatsApp/Signal et récupérez les clés d'identité publiques pour le numéro cible (fait automatiquement pendant la configuration de session).
2. Fabriquez un paquet de réaction/édition/suppression qui référence un `message_id` aléatoire jamais vu par l'une ou l'autre partie (WhatsApp accepte des GUID arbitraires `key.id` ; Signal utilise des timestamps en millisecondes).
3. Envoyez le paquet même si aucun thread n'existe. Les appareils de la victime le déchiffrent, échouent à faire correspondre le message de base, rejettent le changement d'état, mais accusent quand même le ciphertext entrant, renvoyant les accusés de livraison à l'attaquant.
4. Répétez en continu pour construire des séries RTT sans jamais apparaître dans la liste de chats de la victime.

Si vous devez d'abord découvrir quels numéros sont enregistrés ou si vous voulez pré-semer des inventaires d'appareils à grande échelle, enchaînez cela avec [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) plutôt que de deviner manuellement des plages E.164 aléatoires.

Les versions récentes de WhatsApp exposent aussi `Settings -> Privacy -> Advanced -> Block unknown account messages`. Considérez cela comme un limiteur de débit, pas comme une correction : cela pénalise surtout l'inondation soutenue par des inconnus et devient sans importance une fois que vous êtes déjà un contact connu.

## Réutiliser edits et deletes comme déclencheurs furtifs

* **Suppressions répétées :** Après qu'un message a été supprimé-for-everyone une fois, les paquets delete supplémentaires référençant le même `message_id` n'ont aucun effet UI mais chaque appareil les déchiffre et les accuse quand même.
* **Opérations hors fenêtre :** WhatsApp impose dans l'UI des fenêtres d'environ ~60 h pour delete / ~20 min pour edit ; Signal impose ~48 h. Les messages protocole fabriqués en dehors de ces fenêtres sont ignorés silencieusement sur l'appareil victime mais les accusés sont transmis, de sorte que les attaquants peuvent sonder indéfiniment bien après la fin de la conversation.
* **Payloads invalides :** Des corps d'édition malformés ou des suppressions référençant des messages déjà purgés déclenchent le même comportement - déchiffrement plus accusé, zéro artefact visible par l'utilisateur.

## Amplification multi-device et empreinte fingerprinting

* Chaque appareil associé (téléphone, app desktop, navigateur compagnon) déchiffre le probe indépendamment et renvoie son propre ack. Compter les accusés par probe révèle le nombre exact d'appareils.
* Si un appareil est hors ligne, son accusé est mis en file et émis lors de la reconnexion. Les écarts leak donc les cycles en ligne/hors ligne et même les horaires de trajet (par ex., les accusés desktop s'arrêtent pendant les déplacements).
* Les distributions RTT diffèrent selon la plateforme à cause de la gestion d'énergie de l'OS et des réveils push. Regroupez les RTT (par ex., k-means sur des features médiane/variance) pour étiqueter "Android handset", "iOS handset", "Electron desktop", etc.
* Comme l'expéditeur doit récupérer l'inventaire des clés du destinataire avant de chiffrer, l'attaquant peut aussi observer quand de nouveaux appareils sont appairés ; une augmentation soudaine du nombre d'appareils ou un nouveau cluster RTT est un fort indicateur.

## Inférence comportementale à partir des traces RTT

1. Échantillonnez à ≥1 Hz pour capturer les effets de scheduling de l'OS. Avec WhatsApp sur iOS, des RTT <1 s corrèlent fortement avec écran allumé/premier-plan, >1 s avec throttling écran éteint/arrière-plan.
2. Construisez des classifieurs simples (seuils ou k-means à deux clusters) qui étiquettent chaque RTT comme "active" ou "idle". Agrégez les étiquettes en séquences pour déduire les heures de coucher, les trajets, les horaires de travail, ou quand le compagnon desktop est actif.
3. Corrélez des probes simultanés vers chaque appareil pour voir quand les utilisateurs passent du mobile au desktop, quand les compagnons passent hors ligne, et si l'app est limitée en débit par le push ou par une socket persistante.
4. Sur de vrais réseaux, évitez un seuil dur codé en dur `1 s`. Initialisez chaque appareil avec une courte fenêtre de warm-up et maintenez une baseline glissante (par exemple, `threshold = 0.9 * median RTT`) afin que la dérive Wi-Fi/cellulaire ne fasse pas s'effondrer votre classifieur.

## Inférence de localisation à partir du RTT de livraison

Le même primitive temporelle peut être réutilisé pour inférer où se trouve le destinataire, pas seulement s'il est actif. Le travail `Hope of Delivery` a montré qu'un entraînement sur des distributions RTT pour des emplacements de réception connus permet à un attaquant de classifier plus tard la localisation de la victime à partir des seules confirmations de livraison :

* Construisez une baseline pour la même cible pendant qu'elle se trouve dans plusieurs lieux connus (domicile, bureau, campus, pays A vs pays B, etc.).
* Pour chaque localisation, collectez de nombreux RTT de messages normaux et extrayez des features simples comme médiane, variance ou buckets de percentiles.
* Pendant l'attaque réelle, comparez la nouvelle série de probes aux clusters entraînés. L'article rapporte que même des localisations dans la même ville peuvent souvent être séparées, avec une précision `>80%` dans un scénario à 3 localisations.
* Cela fonctionne au mieux lorsque l'attaquant contrôle l'environnement d'envoi et sonde dans des conditions réseau similaires, parce que le chemin mesuré inclut le réseau d'accès du destinataire, la latence de réveil et l'infrastructure du messenger.

Contrairement aux attaques silencieuses de réaction/edit/delete ci-dessus, l'inférence de localisation ne requiert pas de message IDs invalides ni de paquets furtifs modifiant l'état. De simples messages avec des confirmations de livraison normales suffisent, donc le compromis est une furtivité plus faible mais une applicabilité plus large à travers les messengers.

## Épuisement furtif des ressources

Parce que chaque probe silencieuse doit être déchiffrée et accusée, l'envoi continu de toggles de réaction, d'édits invalides ou de paquets delete-for-everyone crée un DoS au niveau application :

* Force la radio/le modem à transmettre/recevoir chaque seconde -> drain de batterie visible, surtout sur les téléphones inactifs.
* Génère du trafic upstream/downstream non comptabilisé qui consomme les forfaits de données mobiles tout en se fondant dans le bruit TLS/WebSocket.
* Occupe les threads crypto et introduit du jitter dans les fonctionnalités sensibles à la latence (VoIP, appels vidéo) même si l'utilisateur ne voit jamais de notifications.
* Sur WhatsApp, les réactions invalides acceptent beaucoup plus de données qu'un emoji normal ne le suggère : des mesures publiées ont trouvé une acceptation côté serveur jusqu'à environ `1 MB` par réaction.
* Les réactions trop volumineuses cessent de produire des accusés de livraison fiables une fois que le corps dépasse environ `30 bytes`, mais elles sont toujours relayées et traitées avant rejet. Gardez les corps de réaction petits quand vous avez besoin d'ACKs ; gonflez-les uniquement lorsque l'objectif est un drain pur ou un transport furtif unidirectionnel.
* Des mesures publiques ont atteint environ `3.7 MB/s` (`~13.3 GB/h`) de trafic victime dans ce mode.

## Références

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
