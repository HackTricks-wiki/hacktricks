# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Les delivery receipts sont obligatoires dans les messengers end-to-end encrypted (E2EE) modernes parce que les clients doivent savoir quand un ciphertext a été déchiffré afin de jeter l'état de ratchet et les clés éphémères. Le serveur relaie des blobs opaques, donc les acknowledgements des appareils (double checkmarks) sont émis par le destinataire après un déchiffrement réussi. Mesurer le round-trip time (RTT) entre une action déclenchée par l'attaquant et le delivery receipt correspondant expose un canal temporel haute résolution qui leaks l'état de l'appareil, la présence en ligne, et peut être abusé pour un covert DoS. Les déploiements multi-device "client-fanout" amplifient la leakage parce que chaque appareil enregistré déchiffre la sonde et renvoie son propre receipt.

## Delivery receipt sources vs. user-visible signals

Choisissez des types de message qui émettent toujours un delivery receipt mais n'affichent pas d'artefacts UI chez la victime. Le tableau ci-dessous résume le comportement empiriquement confirmé :

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Toujours bruyant → utile uniquement pour bootstrapper l'état. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

Légende : ● = toujours, ◐ = conditionnel, ○ = jamais. Le comportement UI dépendant de la plateforme est noté inline. Désactivez les read receipts si nécessaire, mais les delivery receipts ne peuvent pas être désactivés dans WhatsApp ou Signal.

## Attacker goals and models

* **G1 – Device fingerprinting :** Compter combien de receipts arrivent par sonde, clusteriser les RTT pour inférer OS/client (Android vs iOS vs desktop), et surveiller les transitions online/offline.
* **G2 – Behavioural monitoring :** Traiter la série temporelle RTT haute fréquence (≈1 Hz est stable) comme une time-series et inférer écran allumé/éteint, app en foreground/background, trajets domicile-travail vs heures de travail, etc.
* **G3 – Resource exhaustion :** Garder les radios/CPU de chaque appareil victime réveillés en envoyant des probes silencieuses sans fin, vidant la batterie/les données et dégradant la qualité VoIP/RTC.

Deux acteurs de menace suffisent pour décrire la surface d'abus :

1. **Creepy companion :** partage déjà un chat avec la victime et abuse des self-reactions, des suppression de réaction, ou des edits/deletes répétés liés à des message IDs existants.
2. **Spooky stranger :** enregistre un compte burner et envoie des reactions référencant des message IDs qui n'ont jamais existé dans la conversation locale ; WhatsApp et Signal les déchiffrent et les acknowlegde même si l'UI jette le changement d'état, donc aucune conversation préalable n'est requise.

## Tooling for raw protocol access

Fiez-vous à des clients qui exposent le protocole E2EE sous-jacent afin de pouvoir fabriquer des paquets hors des contraintes UI, spécifier des `message_id` arbitraires, et logger des timestamps précis :

* **WhatsApp :** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ou [Cobalt](https://github.com/Auties00/Cobalt) (orienté mobile) permettent d'émettre des `ReactionMessage`, `ProtocolMessage` (edit/delete) et des frames `Receipt` brutes tout en gardant l'état double-ratchet en synchro.
* **Signal :** [signal-cli](https://github.com/AsamK/signal-cli) combiné avec [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expose tous les types de message via CLI/API. Exemple de bascule de self-reaction :
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema :** Le source du client Android documente comment les delivery receipts multi-device sont consolidés avant de quitter l'appareil, expliquant pourquoi le side channel a une bande passante négligeable là-bas.

Quand des outils personnalisés ne sont pas disponibles, vous pouvez toujours déclencher des actions silencieuses depuis WhatsApp Web ou Signal Desktop et renifler le websocket/WebRTC chiffré, mais les APIs brutes suppriment les délais UI et permettent des opérations invalides.

## Creepy companion: silent sampling loop

1. Choisissez n'importe quel message historique que vous avez envoyé dans le chat pour que la victime ne voie jamais les "reaction" balloons changer.
2. Alternez entre un emoji visible et une payload de réaction vide (encodée comme `""` dans les protobufs WhatsApp ou `--remove` dans signal-cli). Chaque transmission génère un ack appareil malgré aucun delta UI pour la victime.
3. Timestamptez l'heure d'envoi et chaque arrivée de delivery receipt. Une boucle à 1 Hz telle que la suivante fournit des traces RTT par appareil indéfiniment :
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Parce que WhatsApp/Signal acceptent des mises à jour de reaction illimitées, l'attaquant n'a jamais besoin de poster du nouveau contenu de chat ni de se soucier des fenêtres d'édition.

## Spooky stranger: probing arbitrary phone numbers

1. Enregistrez un compte WhatsApp/Signal frais et récupérez les public identity keys pour le numéro ciblé (fait automatiquement pendant la configuration de session).
2. Fabriquez un paquet reaction/edit/delete qui référence un `message_id` aléatoire jamais vu par aucune des parties (WhatsApp accepte des `key.id` GUIDs arbitraires ; Signal utilise des timestamps en millisecondes).
3. Envoyez le paquet même si aucun thread n'existe. Les appareils de la victime le déchiffrent, échouent à matcher le message de base, jettent le changement d'état, mais ackent quand même le ciphertext entrant, renvoyant des device receipts à l'attaquant.
4. Répétez continuellement pour construire une série RTT sans jamais apparaître dans la liste de chat de la victime.

## Recycling edits and deletes as covert triggers

* **Repeated deletes :** Après qu'un message ait été deleted-for-everyone une fois, d'autres paquets delete référencant le même `message_id` n'ont aucun effet UI mais chaque appareil les déchiffre et les acknowledge.
* **Out-of-window operations :** WhatsApp impose des fenêtres d'édition ≈20 min / suppression ≈60 h dans l'UI ; Signal impose ≈48 h. Les protocol messages fabriqués hors de ces fenêtres sont silencieusement ignorés sur l'appareil de la victime mais des receipts sont transmis, donc les attaquants peuvent sonder indéfiniment longtemps après la fin de la conversation.
* **Invalid payloads :** Les bodies d'edit mal formés ou les deletes référencant des messages déjà purgés provoquent le même comportement — déchiffrement plus receipt, zéro artefact visible par l'utilisateur.

## Multi-device amplification & fingerprinting

* Chaque device associé (téléphone, app desktop, companion navigateur) déchiffre la sonde indépendamment et renvoie son propre ack. Compter les receipts par sonde révèle le nombre exact d'appareils.
* Si un appareil est offline, son receipt est mis en file et émis à la reconnexion. Les gaps leak donc les cycles online/offline et même les horaires de déplacement (par ex. les receipts desktop s'arrêtent pendant un voyage).
* Les distributions de RTT diffèrent selon la plateforme en raison de la gestion d'énergie OS et des wakeups push. Clusterisez les RTT (par ex. k-means sur des features médianes/variance) pour étiqueter “Android handset", “iOS handset", “Electron desktop", etc.
* Parce que l'expéditeur doit récupérer l'inventaire de clés du destinataire avant de chiffrer, l'attaquant peut aussi observer quand de nouveaux appareils sont appairés ; une augmentation soudaine du nombre d'appareils ou un nouveau cluster RTT est un fort indicateur.

## Behaviour inference from RTT traces

1. Échantillonnez à ≥1 Hz pour capturer les effets d'ordonnancement OS. Avec WhatsApp sur iOS, des RTT <1 s corrèlent fortement avec écran allumé/foreground, >1 s avec throttling écran éteint/background.
2. Construisez des classifieurs simples (seuillage ou k-means à deux clusters) qui étiquettent chaque RTT comme "active" ou "idle". Agrégez les étiquettes en séries pour dériver heures de coucher, trajets, heures de travail, ou quand le companion desktop est actif.
3. Corrélez des probes simultanés vers chaque appareil pour voir quand les utilisateurs passent du mobile au desktop, quand les companions se déconnectent, et si l'app est rate limited par push vs socket persistant.

## Stealthy resource exhaustion

Parce que chaque sonde silencieuse doit être déchiffrée et acked, envoyer en continu des toggles de reaction, des edits invalides, ou des paquets delete-for-everyone crée un application-layer DoS :

* Force la radio/modem à émettre/recevoir chaque seconde → drain de batterie notable, surtout sur des handsets au repos.
* Génère du trafic upstream/downstream non mesuré qui consomme les forfaits data mobile tout en se fondant dans le bruit TLS/WebSocket.
* Occupe des threads crypto et introduit du jitter dans des fonctionnalités sensibles à la latence (VoIP, appels vidéo) même si l'utilisateur ne voit jamais de notifications.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
