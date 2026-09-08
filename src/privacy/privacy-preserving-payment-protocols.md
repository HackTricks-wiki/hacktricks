# Protocoles de paiement préservant la confidentialité

Les systèmes de paiement avancés peuvent dissimuler le payeur au marchand, dissimuler un destinataire ou un montant dans un registre public, ou empêcher un mint d'associer un retrait à une rédemption. Il s'agit de propriétés différentes. Aucun de ces systèmes n'efface les traces d'acquisition, d'appareil, de réseau, de livraison, de comptabilité, de sanctions ou de endpoints.

L'[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) fournit une entrée standardisée `Pros`, `Cons`, `Procedure` étape par étape et `Detection` pour chaque famille de paiements. Cette page détaille les protocoles avancés.

{% hint style="danger" %}
Utilisez uniquement des fonds et des contreparties licites. N'utilisez pas de protocoles de confidentialité pour contourner les obligations d'identification, les sanctions, les contrôles fiscaux, les vérifications de l'origine des fonds ou la déclaration des transactions. N'exploitez pas de service d'échange, de mint ou de transmission sans comprendre les obligations de licence, de garde, d'AML et de protection des consommateurs.
{% endhint %}

## Comparer les options avancées

| Protocole | Dissimulation vis-à-vis du public/marchand | Partie de confiance ou observatrice | Maturité/disponibilité |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Les tiers ne peuvent pas relier un code de paiement réutilisable à ses outputs à usage unique | Le graphe public de Bitcoin demeure ; le serveur de wallet/indexation peut voir les scans | Spécification terminée ; le support des wallets varie |
| Zcash fully shielded Orchard | L'expéditeur, le destinataire et le montant sont chiffrés on-chain | Le backend/réseau du wallet ainsi que l'acquisition et l'off-ramp restent visibles | Déployé ; le support du shielded varie selon le wallet/exchange |
| GNU Taler | Le marchand n'a pas besoin de connaître l'identité du payeur ; les revenus du marchand restent traçables | L'exchange/la banque Taler voit le financement ; le marchand voit la commande | Les déploiements sont géographiquement limités |
| Federated Chaumian e-cash | La fédération ne devrait pas relier les notes émises aux transferts/rédemptions internes | Le quorum de guardians conserve les réserves ; les gateways voient l'activité aux frontières | Déploiements communautaires émergents |
| Lightning BOLT 12/route blinding | Réduit la divulgation du destinataire/nœud et de la route | Les endpoints, certains hops, la chaîne de financement et les services de wallet | Le support dépend du wallet |
| Virtual card/token | Le marchand reçoit un credential limité, et non un PAN réutilisable | L'émetteur/le réseau conservent l'identité du payeur et la transaction | Mature et largement disponible |

## Bitcoin Silent Payments (BIP 352)

Silent Payments permet à un destinataire de publier un unique code de paiement statique, tandis que chaque expéditeur dérive un output Taproot unique. Un observateur externe de la blockchain ne peut pas relier directement ces outputs au code publié, et aucune demande d'adresse interactive ni aucun output de notification on-chain n'est requis. BIP 352 est marqué **Complete**, mais il introduit un coût de scanning et est incompatible avec les wallets qui ne l'ont pas implémenté.<sup>[[1]](#references)</sup>

### Workflow du destinataire

1. Sélectionnez un wallet maintenu qui prend explicitement en charge la réception BIP 352 ; vérifiez cette fonctionnalité dans la documentation actuelle du wallet, et non sur la base d'une publication sur les réseaux sociaux.
2. Sauvegardez le seed du wallet ainsi que les données de descripteur/matériel de clé Silent Payment en utilisant la méthode de récupération documentée par le wallet. Testez la découverte avec un petit montant sur testnet/mainnet avant de publier le code.
3. Générez des **labels** distincts pour les campagnes, factures ou contreparties lorsque le wallet prend en charge les labels BIP 352. Les labels facilitent la comptabilité locale sans publier d'adresses pouvant être reliées.
4. Publiez le code Silent Payment statique via un canal authentifié. Il est réutilisable, mais un imposteur peut le remplacer par son propre code.
5. Effectuez le scan via un full node local lorsque c'est possible. Un serveur tiers d'indexation/scanning peut connaître le moment des requêtes ou les données de filtrage, même s'il ne peut pas dépenser les fonds.
6. Conservez les UTXOs découverts avec leurs labels et appliquez les mêmes règles de coin control qu'avec Bitcoin ordinaire. Les dépenser ou les consolider peut révéler des relations de propriété.
7. Vérifiez que la récupération permet de découvrir les paiements sans dépendre d'un index externe non sauvegardé.

### Workflow de l'expéditeur

1. Confirmez que le wallet prend en charge l'envoi vers la version d'adresse concernée et authentifiez le code statique long du destinataire.
2. Laissez le wallet construire l'output ; ne convertissez ni ne tronquez jamais le code manuellement.
3. Examinez attentivement les inputs sélectionnés. Silent Payments améliore la confidentialité de l'adresse du destinataire, mais les inputs de l'expéditeur restent présents dans le graphe public.
4. Utilisez le fee bumping/PSBT pris en charge par le wallet. BIP 352 exige une nouvelle dérivation des outputs si les inputs changent, et certains modes de signature sont dangereux.
5. Conservez un reçu ou une preuve chiffrée nécessaire aux litiges/à la comptabilité.

Silent Payments résout le problème de la publication répétée de l'adresse du destinataire. Il ne dissimule ni le montant, ni le moment de la transaction, ni le cluster de l'expéditeur, ni l'historique d'acquisition, ni les dépenses ultérieures communes.

## Paiements Zcash fully shielded

Zcash prend en charge des pools de valeur transparents et shielded. Les transactions shielded Orchard utilisent des preuves zero-knowledge afin que les nœuds puissent vérifier leur validité tandis que les détails de la transaction sont chiffrés ; les Unified Addresses peuvent contenir plusieurs types de destinataires.<sup>[[2]](#references)</sup> La confidentialité dépend du chemin effectivement sélectionné par le wallet, et non du premier caractère d'une adresse affichée.

### Workflow shielded

1. Choisissez un wallet maintenu qui identifie clairement son comportement **shielded-by-default** et son support actuel d'Orchard. Vérifiez le téléchargement et sauvegardez/testez le seed.
2. Obtenez des ZEC légalement et enregistrez leur justification/source. Un exchange connaît toujours l'acquisition et le retrait.
3. Recevez les fonds vers une Unified Address prise en charge par le wallet, puis vérifiez si la transaction est arrivée dans un pool shielded. Ne supposez pas un shielding automatique sans confirmer le comportement du wallet.
4. Préférez les transferts **shielded-to-shielded**. Les mouvements transparent-to-shielded et shielded-to-transparent exposent les valeurs/moments publics et peuvent permettre une corrélation des montants ; la spécification Orchard indique que dépenser vers une adresse non-Orchard révèle la valeur de la transaction.<sup>[[3]](#references)</sup>
5. Évitez les allers-retours avec des montants exacts et distinctifs ainsi que les passages immédiats entre les frontières. Il s'agit d'une mesure d'hygiène de confidentialité, et non d'une autorisation à dissimuler la propriété ou les déclarations.
6. Utilisez le chemin de network-privacy pris en charge par le wallet. La cryptographie shielded ne dissimule pas l'IP/le timing aux serveurs du wallet ou aux pairs.
7. Conservez les dossiers internes de conformité et utilisez les viewing keys uniquement pour un audit/une divulgation délibéré(e), après avoir compris leur périmètre.
8. Confirmez la compatibilité du wallet/exchange du destinataire avant l'envoi ; un destinataire transparent imposé modifie la propriété de confidentialité.

## GNU Taler : payeur anonyme, marchand responsable

GNU Taler est un protocole ouvert de paiement électronique utilisant des monnaies traditionnelles, des signatures aveugles et une intégration avec des exchanges/banques réglementés. Sa conception vise à préserver l'anonymat des clients vis-à-vis des marchands, tandis que les marchands restent identifiables et imposables.<sup>[[4]](#references)</sup> Il ne s'agit pas d'une cryptomonnaie et sa disponibilité dépend d'un exchange régional, d'une banque, d'un wallet et d'un marchand compatibles.

### Workflow utilisateur lorsqu'il est déployé

1. Identifiez un exchange Taler et un marchand opérationnels dans la devise/juridiction concernée ; lisez leurs conditions, frais, exigences de KYC et avis de confidentialité actuels.
2. Installez le wallet officiel et vérifiez sa source. Protégez les données de sauvegarde/récupération du wallet comme de l'argent liquide, car sa valeur peut être un bearer asset.
3. Retirez les fonds via le flux bancaire/exchange pris en charge en utilisant des informations exactes. L'institution de financement/l'exchange peut connaître le retrait, même si les signatures aveugles brisent le lien direct entre la coin et le retrait.
4. Examinez le contrat du marchand dans le wallet : identité du marchand, article/récapitulatif, montant, frais, remboursement et conditions de livraison.
5. Payez et conservez les données du reçu nécessaires au remboursement, à la garantie, à la comptabilité ou à la fiscalité.
6. Ne réutilisez pas les identifiants facultatifs de session/compte du marchand si l'absence de lien entre paiements du marchand est requise.
7. Intégrez les métadonnées du wallet, du réseau et de la livraison dans le threat model ; la cryptographie de paiement de Taler ne dissimule ni une adresse de livraison ni un endpoint compromis.

Le marchand et l'exchange restent responsables, et l'exploitation de l'un ou l'autre peut constituer une activité réglementée de service de paiement.

## Federated Chaumian e-cash

Chaumian e-cash utilise des signatures aveugles afin qu'un mint signe un token sans voir ultérieurement le token désaveuglé qui est dépensé. Fedimint distribue la garde des réserves et la signature entre une fédération de guardians ; sa documentation indique que les guardians voient les réserves agrégées/les notes en circulation, mais ne devraient pas voir le solde individuel ni qui a payé qui au sein de la fédération.<sup>[[5]](#references)</sup>

Il s'agit d'une **valeur custodiale au porteur**. Un quorum suffisant de guardians contrôle les réserves ; une défaillance de la fédération, des guardians malhonnêtes, des bugs logiciels ou la perte de l'état client peuvent entraîner une perte. Les dépôts, retraits et gateways Lightning sont des événements visibles aux frontières et peuvent corréler le moment et le montant.

### Workflow à risque limité

1. N'utilisez qu'un petit montant que vous pouvez vous permettre de perdre. Considérez les fédérations publiques/inconnues comme plus risquées que les guardians ayant une responsabilité dans le monde réel.
2. Vérifiez l'invitation à la fédération via un canal authentifié et consignez l'identité des guardians, le quorum, la juridiction, les frais, la récupération et la politique d'arrêt.
3. Installez un wallet compatible et maintenu, vérifiez-le et comprenez son système de sauvegarde avant tout dépôt.
4. Déposez des Bitcoin acquis légalement via le chemin documenté. Enregistrez le peg-in pour la comptabilité et supposez que son moment et son montant sont publics ou connus à la frontière.
5. Au sein de la fédération, utilisez des demandes de paiement fraîches et évitez d'ajouter des identifiants de compte/chat/livraison qui recréeraient le lien supprimé par la signature aveugle.
6. Pour les paiements Lightning, considérez la gateway comme un observateur supplémentaire des factures et du timing aux frontières.
7. Effectuez la rédemption/le retrait conformément à la politique, en vous attendant à ce qu'un montant distinctif et un timing immédiat puissent être corrélés à un dépôt ou à un paiement externe.
8. Conservez les justificatifs fiscaux, de source et d'autorisation de manière privée ; ne demandez pas aux guardians ou aux gateways de déclarer faussement l'activité.

Ne décrivez pas le federated e-cash comme trustless, self-custodial ou garantissant l'anonymat.

## Offres BOLT 12 et route blinding

Les offres BOLT 12 peuvent être réutilisées sans publier une adresse on-chain stable et peuvent utiliser des chemins masqués afin qu'un payeur n'ait pas besoin de connaître l'identité ou le chemin clair du nœud destinataire. Cela complète le onion routing existant de Lightning, mais ne le remplace pas.

Avant utilisation :

1. Confirmez que les wallets de l'expéditeur et du destinataire prennent en charge les mêmes fonctionnalités BOLT 12 actuelles ; ne déduisez pas ce support d'une simple marque « Lightning ».
2. Authentifiez l'offre hors bande et vérifiez le montant, l'émetteur/la description ainsi que les règles de récurrence.
3. Utilisez un contexte de facture/paiement frais généré à partir de l'offre.
4. Réduisez au minimum les alias de nœuds, les informations de contact publiques et les endpoints réseau stables.
5. Supposez que l'expéditeur/le destinataire, le premier/dernier hop, le service de wallet, le graphe des channels et le financement/la fermeture on-chain divulguent encore des éléments de la relation.

## Auditabilité sans divulgation publique

La confidentialité et l'audit peuvent coexister :

- Conservez les labels, factures, autorisations, prix de revient et correspondances de propriété de manière chiffrée en dehors du protocole public.
- Séparez une **clé de consultation/audit** d'une clé de dépense lorsque le protocole en fournit une ; testez d'abord sa divulgation exacte sur un wallet d'échantillon.
- Donnez à l'auditeur la preuve minimale et limitée au périmètre requis plutôt qu'un seed ou un credential de dépense sans restriction.
- Enregistrez, au moment de la transaction, la version logicielle, le protocole/pool, l'ID de transaction ou la preuve, l'objet de la contrepartie et la source du taux de change.
- Définissez la conservation et la suppression au lieu d'accumuler un graphe d'identité permanent non chiffré.

## Checklist de sélection

- [ ] Le champ dissimulé et l'observateur sont nommés précisément.
- [ ] Le support du wallet/protocole a été vérifié à la date de la transaction.
- [ ] Les liens d'acquisition, de réseau, de nœud/RPC, de contrepartie, de livraison et de dépense ultérieure sont documentés.
- [ ] Les risques liés à la garde, la récupération, la liquidité, la solvabilité de l'émetteur/de la fédération et les remboursements sont acceptés.
- [ ] Les dossiers requis d'identité, fiscaux, de sanctions, de source et d'organisation restent exacts.
- [ ] Un petit test de bout en bout, incluant la récupération et la preuve d'audit, a réussi.

## References

- [1] [BIP 352 — Paiements silencieux](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Adresses unifiées](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Protocole shielded Orchard](https://zips.z.cash/zip-0224)
- [4] [Documentation GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Fonctionnement](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offres](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
