# Protocoles de paiement préservant la confidentialité

{{#include ../banners/hacktricks-training.md}}

Les systèmes de paiement avancés peuvent dissimuler le payeur au marchand, dissimuler un destinataire ou un montant dans un registre public, ou empêcher un mint de relier un retrait à une rédemption. Il s'agit de propriétés différentes. Aucun de ces systèmes n'efface les traces d'acquisition, d'appareil, de réseau, de livraison, de comptabilité, de sanctions ou de terminal.

L'[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) fournit une entrée standardisée `Pros`, `Cons`, `Procedure` et `Detection` pour chaque famille de paiements. Cette page développe les protocoles avancés.

{% hint style="danger" %}
Utilisez uniquement des fonds et des contreparties légaux. N'utilisez pas de protocoles de confidentialité pour contourner les obligations d'identification, les sanctions, les obligations fiscales, les contrôles de source des fonds ou la déclaration des transactions. N'exploitez pas un exchange, un mint ou un service de transmission sans comprendre les obligations liées aux licences, à la conservation, à l'AML et à la protection des consommateurs.
{% endhint %}

## Comparer les options avancées

| Protocole | Dissimulation vis-à-vis du public/marchand | Partie de confiance ou observatrice | Maturité/disponibilité |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Les tiers ne peuvent pas relier un code de paiement réutilisable à ses outputs à usage unique | Le graphe public de Bitcoin reste visible ; le serveur de wallet/index peut voir les scans | Spécification terminée ; le support des wallets varie |
| Zcash entièrement shielded Orchard | L'expéditeur, le destinataire et le montant sont chiffrés on-chain | Le backend/réseau du wallet et l'acquisition/off-ramp restent visibles | Déployé ; le support shielded varie selon le wallet/exchange |
| GNU Taler | Le marchand n'a pas besoin de connaître l'identité du payeur ; les revenus du marchand restent traçables | L'exchange/la banque Taler voit le financement ; le marchand voit la commande | Les déploiements sont géographiquement limités |
| Federated Chaumian e-cash | La fédération ne devrait pas relier les notes émises aux transferts/rédemptions internes | Le quorum de guardians conserve les réserves ; les gateways voient l'activité aux frontières | Déploiements communautaires émergents |
| Lightning BOLT 12/route blinding | Réduit la divulgation du destinataire/nœud et de la route | Les endpoints, certains hops, la chaîne de financement et les services de wallet | Le support dépend du wallet |
| Carte virtuelle/token | Le marchand reçoit un identifiant limité, et non un PAN réutilisable | L'émetteur/le réseau conservent l'identité du payeur et la transaction | Mature et largement disponible |

## Bitcoin Silent Payments (BIP 352)

Silent Payments permet à un destinataire de publier un seul code de paiement statique, tandis que chaque expéditeur dérive un output Taproot unique. Un observateur externe de la chain ne peut pas relier directement ces outputs au code publié, et aucune demande d'adresse interactive ni aucun output de notification on-chain n'est nécessaire. Le BIP 352 est marqué **Terminé**, mais il introduit un coût de scan et est incompatible avec les wallets qui ne l'ont pas implémenté.<sup>[[1]](#references)</sup>

### Workflow du destinataire

1. Sélectionnez un wallet maintenu qui prend explicitement en charge la réception BIP 352 ; vérifiez cette fonctionnalité dans la documentation actuelle du wallet, et non à partir d'une affirmation sur les réseaux sociaux.
2. Sauvegardez le seed du wallet ainsi que les données du descripteur/du matériel de clé Silent Payment en utilisant la méthode de récupération documentée par le wallet. Testez la découverte avec un petit montant sur testnet/mainnet avant de publier le code.
3. Générez des **labels** distincts pour les campagnes, factures ou contreparties lorsque le wallet prend en charge les labels BIP 352. Les labels facilitent la comptabilité locale sans publier d'adresses permettant le link.
4. Publiez le code Silent Payment statique via un canal authentifié. Il est réutilisable, mais un imposteur peut le remplacer par son propre code.
5. Effectuez les scans via un full node local lorsque cela est possible. Un serveur tiers d'indexation/de scan peut apprendre le moment des requêtes ou les données de filtre, même s'il ne peut pas dépenser les fonds.
6. Conservez les UTXO découverts avec leurs labels et appliquez les mêmes règles de coin control qu'avec Bitcoin ordinaire. Les dépenser ou les consolider peut révéler des relations de propriété.
7. Confirmez que la récupération permet de découvrir les paiements sans dépendre d'un index externe non sauvegardé.

### Workflow de l'expéditeur

1. Confirmez que le wallet prend en charge l'envoi vers la version d'adresse concernée et authentifiez le code statique long du destinataire.
2. Laissez le wallet construire l'output ; ne convertissez pas et ne tronquez jamais le code manuellement.
3. Examinez attentivement les inputs sélectionnés. Silent Payments améliorent la confidentialité de l'adresse du destinataire, mais les inputs de l'expéditeur restent présents dans le graphe public.
4. Utilisez le fee bumping/PSBT pris en charge par le wallet. Le BIP 352 exige une nouvelle dérivation des outputs si les inputs changent, et certains modes de signature sont dangereux.
5. Conservez un reçu ou une preuve chiffré nécessaire en cas de litige ou pour la comptabilité.

Silent Payments résout la publication répétée de l'adresse du destinataire. Il ne dissimule ni le montant, ni le moment de la transaction, ni le cluster de l'expéditeur, ni l'historique d'acquisition, ni les dépenses ultérieures conjointes.

## Paiements Zcash entièrement shielded

Zcash prend en charge des pools de valeur transparents et shielded. Les transactions shielded Orchard utilisent des preuves zero-knowledge afin que les nœuds puissent vérifier la validité tandis que les détails de la transaction sont chiffrés ; les Unified Addresses peuvent contenir plusieurs types de destinataires.<sup>[[2]](#references)</sup> La confidentialité dépend du chemin effectivement sélectionné par le wallet, et non du premier caractère d'une adresse affichée.

### Workflow shielded

1. Choisissez un wallet maintenu qui indique clairement un comportement **shielded-by-default** et la prise en charge actuelle d'Orchard. Vérifiez le téléchargement et sauvegardez/testez le seed.
2. Obtenez des ZEC légalement et consignez la base/la source. Un exchange connaît toujours l'acquisition et le retrait.
3. Recevez les fonds sur une Unified Address prise en charge par le wallet, puis vérifiez si la transaction a abouti dans un pool shielded. Ne supposez pas un shielding automatique sans confirmer le comportement du wallet.
4. Préférez les transferts **shielded-to-shielded**. Les mouvements transparent-to-shielded et shielded-to-transparent aux frontières exposent les valeurs/horodatages publics et peuvent permettre une corrélation des montants ; la spécification Orchard indique qu'une dépense vers une adresse non-Orchard révèle la valeur de la transaction.<sup>[[3]](#references)</sup>
5. Évitez les allers-retours avec des montants exacts distinctifs et les franchissements immédiats de frontière. Il s'agit d'une mesure d'hygiène de confidentialité, et non d'une autorisation de dissimuler la propriété ou les déclarations.
6. Utilisez le chemin de network privacy pris en charge par le wallet. La cryptographie shielded ne dissimule pas l'IP/le moment des communications aux serveurs du wallet ou aux pairs.
7. Conservez les éléments de conformité internes et utilisez les viewing keys uniquement pour un audit ou une divulgation délibérés, après avoir compris leur portée.
8. Confirmez la prise en charge par le wallet/l'exchange du destinataire avant l'envoi ; un destinataire transparent imposé modifie la propriété de confidentialité.

## GNU Taler : payeur anonyme, marchand traçable

GNU Taler est un protocole de paiement électronique ouvert utilisant des devises traditionnelles, des signatures aveugles et une intégration avec un exchange/une banque réglementés. Sa conception vise à préserver l'anonymat des clients vis-à-vis des marchands, tandis que les marchands restent identifiables et imposables.<sup>[[4]](#references)</sup> Il ne s'agit pas d'une cryptomonnaie et sa disponibilité dépend d'un exchange régional, d'une banque, d'un wallet et d'un marchand compatibles.

### Workflow utilisateur lorsque le système est déployé

1. Identifiez un exchange Taler et un marchand opérationnels dans la devise/la juridiction concernée ; lisez leurs conditions actuelles, leurs frais, leurs exigences KYC et leurs avis de confidentialité.
2. Installez le wallet officiel et vérifiez sa source. Protégez les données de sauvegarde/récupération du wallet comme de l'argent liquide, car sa valeur peut être un bearer asset.
3. Retirez les fonds via le flux bancaire/de l'exchange pris en charge en utilisant des informations exactes. L'institution de financement/l'exchange peut connaître le retrait, même si les signatures aveugles empêchent le lien direct entre la coin et le retrait.
4. Examinez le contrat du marchand dans le wallet : identité du marchand, article/récapitulatif, montant, frais, remboursement et conditions de livraison.
5. Payez et conservez les données du reçu nécessaires pour un remboursement, une garantie, la comptabilité ou les impôts.
6. Ne réutilisez pas les identifiants de session/de compte facultatifs du marchand si l'absence de link avec le marchand est requise.
7. Intégrez les métadonnées du wallet, du réseau et de la livraison dans le threat model ; la cryptographie de paiement de Taler ne dissimule ni une adresse de livraison ni un endpoint compromis.

Le marchand et l'exchange restent responsables, et l'exploitation de l'un ou l'autre composant peut constituer une activité réglementée de service de paiement.

## Federated Chaumian e-cash

Chaumian e-cash utilise des signatures aveugles afin qu'un mint signe un token sans voir ultérieurement le token désaveuglé dépensé. Fedimint distribue la conservation des réserves et la signature entre une fédération de guardians ; sa documentation indique que les guardians voient les réserves agrégées/les notes en circulation, mais ne devraient pas voir le solde individuel ni qui a payé qui au sein de la fédération.<sup>[[5]](#references)</sup>

Il s'agit d'une **valeur custodial bearer**. Un quorum suffisant de guardians contrôle les réserves ; une défaillance de la fédération, des guardians malhonnêtes, des bugs logiciels ou la perte de l'état client peuvent entraîner une perte. Les dépôts, retraits et gateways Lightning sont des événements de frontière visibles et peuvent corréler le moment et le montant.

### Workflow à risque limité

1. N'utilisez qu'un petit montant que vous pouvez vous permettre de perdre. Considérez les fédérations publiques/inconnues comme présentant un risque supérieur à celui de guardians ayant une responsabilité dans le monde réel.
2. Vérifiez l'invitation de la fédération via un canal authentifié et consignez les identités des guardians, le quorum, la juridiction, les frais, la récupération et la politique d'arrêt.
3. Installez un wallet compatible et maintenu, vérifiez-le et comprenez son mécanisme de sauvegarde avant de déposer des fonds.
4. Déposez des Bitcoin acquis légalement via le chemin documenté. Consignez le peg-in pour la comptabilité et supposez que son moment/son montant sont publics ou connus à la frontière.
5. Au sein de la fédération, utilisez de nouvelles demandes de paiement et évitez d'ajouter des identifiants de compte/chat/livraison qui recréeraient le lien supprimé par la signature aveugle.
6. Pour les paiements Lightning, considérez la gateway comme un observateur supplémentaire des factures et du moment des événements de frontière.
7. Effectuez la rédemption/le retrait conformément à la politique, en vous attendant à ce qu'un montant distinctif et un moment immédiat puissent être corrélés à un dépôt ou à un paiement externe.
8. Conservez en privé les informations fiscales, de source et d'autorisation ; ne demandez pas aux guardians ou aux gateways de falsifier l'activité.

Ne décrivez pas le federated e-cash comme trustless, self-custodial ou garantissant l'anonymat.

## Offres BOLT 12 et route blinding

Les offres BOLT 12 peuvent être réutilisables sans publier une adresse on-chain stable et peuvent utiliser des chemins blinded afin qu'un payeur n'ait pas besoin de connaître l'identité ou le chemin clair du nœud destinataire. Cela complète le onion routing existant de Lightning, sans le remplacer.

Avant utilisation :

1. Confirmez que les wallets de l'expéditeur et du destinataire prennent en charge les mêmes fonctionnalités BOLT 12 actuelles ; ne déduisez pas cette prise en charge d'une simple appellation générique « Lightning ».
2. Authentifiez l'offre out of band et vérifiez le montant, l'émetteur/la description et les règles de récurrence.
3. Utilisez un contexte de facture/paiement frais généré à partir de l'offre.
4. Réduisez au minimum les alias de nœuds, les informations de contact publiques et les endpoints réseau stables.
5. Supposez que l'expéditeur/le destinataire, le premier/dernier hop, le service de wallet, le graphe des channels et le financement/la fermeture on-chain divulguent encore certaines parties de la relation.

## Auditabilité sans divulgation publique

La confidentialité et l'audit peuvent coexister :

- Conservez les labels, factures, autorisations, coûts d'acquisition et mappages de propriété chiffrés en dehors du protocole public.
- Séparez une **clé de consultation/d'audit** d'une clé de dépense lorsque le protocole en fournit une ; testez d'abord sa divulgation exacte sur un wallet d'échantillon.
- Fournissez à l'auditeur la preuve minimale et limitée requise, plutôt qu'un seed ou un identifiant de dépense sans restriction.
- Consignez la version du logiciel, le protocole/pool, l'identifiant de transaction ou la preuve, l'objet de la contrepartie et la source du taux de change au moment de la transaction.
- Définissez la conservation et la suppression au lieu d'accumuler un graphe d'identité permanent non chiffré.

## Checklist de sélection

- [ ] Le champ dissimulé et l'observateur sont nommés avec précision.
- [ ] La prise en charge par le wallet/protocole a été vérifiée à la date de la transaction.
- [ ] Les liens d'acquisition, de réseau, de nœud/RPC, de contrepartie, de livraison et de dépense ultérieure sont documentés.
- [ ] Les risques liés à la conservation, à la récupération, à la liquidité, à la solvabilité de l'émetteur/de la fédération et aux remboursements sont acceptés.
- [ ] Les informations obligatoires d'identité, fiscales, de sanctions, de source et d'organisation restent exactes.
- [ ] Un petit test de bout en bout, incluant la récupération et la preuve d'audit, a réussi.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Adresses unifiées](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Protocole shielded Orchard](https://zips.z.cash/zip-0224)
- [4] [Documentation GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Fonctionnement](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offres](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
