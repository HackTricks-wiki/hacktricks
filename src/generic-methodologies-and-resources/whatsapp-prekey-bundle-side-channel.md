# Épuisement et reconstitution des bundles de préclés WhatsApp : canal auxiliaire

{{#include ../banners/hacktricks-training.md}}

WhatsApp stocke une clé d'identité, une préclé signée et une réserve de préclés à usage unique pour chaque appareil. Récupérer le bundle d'un appareil consomme une préclé à usage unique stockée sur le serveur, même si le demandeur n'envoie aucun message. Cela fournit à un attaquant disposant d'un compte WhatsApp et du numéro de téléphone cible une sonde **côté serveur**, distincte du [timing des accusés de réception côté client](side-channel-attacks-on-messaging-protocols.md). L'absence d'une préclé à usage unique affaiblit également la confidentialité persistante des *premiers* messages d'une nouvelle session établie ; elle ne révèle pas à elle seule le texte en clair.<sup>[[1]](#references)[[2]](#references)</sup>

## Inspecter les bundles d'appareils d'une cible

L'[artefact Prekey Pogo](https://github.com/sbaresearch/prekey-pogo) s'associe en tant que session compagnon WhatsApp et permet d'effectuer des requêtes **manuelles** sur les appareils et les préclés. Associez-le à un compte de test, puis utilisez ses commandes interactives `target`, `devices`, `prekey` (appareil principal) et `combine` (tous les appareils). L'artefact publié omet délibérément les fonctions automatisées d'épuisement et de saturation du serveur.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Pour chaque réponse, consignez le JID de l’appareil, l’horodatage du bundle `t`, l’ID de la signed-prekey `skey.id` et la présence ou non de la `key` à usage unique. L’ID d’appareil `0` correspond au téléphone ; les ID non nuls, aux appareils compagnons. Dans les implémentations testées dans l’article, l’ID initial de la signed-prekey distingue également certains clients : Android commence à `0`, iOS et macOS utilisent une valeur aléatoire, et WhatsApp Web et Windows Desktop commencent à `1`. Considérez cela comme une empreinte d’implémentation, et non comme une règle immuable du protocole.<sup>[[1]](#references)</sup>

## Transformer les réapprovisionnements en oracle de statut en ligne

Commencez par calibrer la procédure sur un appareil que vous contrôlez : demandez son bundle à plusieurs reprises jusqu’à ce que le serveur cesse de renvoyer une `key` à usage unique, en notant le dernier horodatage et les ID des clés. Pour un appareil cible, répétez l’épuisement des clés, puis effectuez une nouvelle requête après un intervalle contrôlé : une nouvelle clé à usage unique et un horodatage de bundle plus récent indiquent que l’appareil a téléversé un nouveau lot. Lors des tests WhatsApp rapportés, le serveur demandait un réapprovisionnement lorsqu’il restait moins de 11 clés, et les clients téléversaient 812 nouvelles clés. Appliquez la procédure à chaque JID d’appareil pour distinguer un téléphone de ses appareils compagnons. Un réapprovisionnement tardif **suggère** seulement que l’appareil est hors ligne : la planification en arrière-plan, une perte de réseau et la latence propre au réapprovisionnement du client peuvent produire la même observation. Contrairement à un RTT de reçu, cette sonde ne nécessite ni ciphertext livré ni accusé de réception côté victime.<sup>[[1]](#references)[[2]](#references)</sup>

Chaque requête consomme une clé à usage unique. Un oracle utilisé de manière prolongée nécessite donc un client personnalisé capable de récupérer les prekeys à répétition ; l’artefact public ne montre que des requêtes manuelles. Maintenir la réserve vide peut amener d’autres utilisateurs à établir de nouvelles sessions sans prekey à usage unique. Cela réduit la forward secrecy des premiers messages jusqu’à une nouvelle étape de ratchet, mais l’exploitation d’un ciphertext enregistré nécessite également d’accéder au ciphertext E2EE, puis de compromettre ultérieurement les clés privées à long et moyen terme concernées. Les sessions déjà établies ne sont pas automatiquement rétrogradées.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo : enquête sur les problèmes de sécurité et de confidentialité du mécanisme de handshake de WhatsApp](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [Le protocole d’accord de clés X3DH](https://signal.org/docs/specifications/x3dh/)
- [3] [Artefacts de Prekey Pogo](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
