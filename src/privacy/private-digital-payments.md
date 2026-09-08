# Paiements numériques privés

La confidentialité des paiements est la divulgation contrôlée des données de transaction. Ce n’est pas un moyen de légitimer des fonds illégaux, d’éviter l’impôt ou les sanctions, de contourner le KYC, d’utiliser de fausses identités ou de dissimuler une mission non autorisée. Un paiement peut être privé vis-à-vis d’un commerçant tout en restant entièrement visible par un émetteur, un réseau, un employeur, une autorité fiscale ou un enquêteur.

Le [Catalogue des techniques de paiement anonyme](anonymous-payment-techniques.md) est l’inventaire normalisé comprenant les `Pros`, les `Cons`, une `Procedure` légale étape par étape et la `Detection` pour chaque famille. Cette page développe les méthodes de paiement conventionnelles.

{% hint style="danger" %}
N’utilisez jamais de comptes volés, d’identités synthétiques, de money mules, de résidences fictives ou de déclarations fictives concernant l’origine des fonds, de fractionnement de transactions (« structuring »), ni de courtiers opaques proposant des « cartes sans KYC ». Vérifiez la législation en vigueur et les conditions des prestataires dans chaque juridiction concernée.
{% endhint %}

## Définir la propriété de confidentialité

Identifiez l’observateur avant de choisir un rail de paiement :

| Observateur | Données habituelles | Contrôle utile | Ce qui demeure |
|---|---|---|---|
| Commerçant | Nom, e-mail, adresse, token de carte, IP/appareil, panier | Passage en caisse invité, données facultatives minimales, carte virtuelle spécifique au commerçant | Livraison, compte et télémétrie antifraude |
| Émetteur/ processeur de paiement | Identité légale, source des fonds, commerçant, montant, heure, appareil | Choisir un prestataire réglementé avec de bonnes conditions de confidentialité/sécurité | Le prestataire traite toujours les données et peut conserver/divulguer les enregistrements |
| Employeur/propriétaire de la mission | Dépense, opérateur et objectif | Budget de mission séparé et registre à accès contrôlé | Une gouvernance légitime exige une attribution interne |
| Observateur d’une blockchain publique | Adresses, flux, montants et heures, selon la chaîne | Protocole approprié et discipline du wallet | L’acquisition, les points de terminaison et les dépenses ultérieures peuvent relier à nouveau l’activité |
| Opérateur de réseau/RPC/nœud | IP, requêtes du wallet, diffusions de transactions | Nœud local ou réseau de confidentialité adapté | Le comportement temporel et celui du point de terminaison peuvent encore être corrélés |
| Observateur physique | Visage, emplacement, véhicule, vidéosurveillance, reçu | Confidentialité situationnelle ordinaire | L’argent liquide ne rend pas une personne physiquement invisible |

Le CFPB décrit les applications de paiement comme capables de collecter des données d’identité, d’appareil, de localisation, de contacts, de transaction et de comportement ; les règles de confidentialité des États n’empêchent pas nécessairement la monétisation ni tous les usages secondaires.<sup>[[1]](#references)</sup> Lisez l’avis réel du prestataire plutôt que de déduire la confidentialité du nom d’un produit.

## Comparer les méthodes de paiement

| Méthode | Avantage en matière de confidentialité | Principaux observateurs/liens | Usage approprié |
|---|---|---|---|
| Espèces | Aucun registre du réseau de paiement | Destinataire, caméras, témoins, règles de déclaration des espèces | Achats locaux légaux lorsque les espèces sont acceptées |
| Carte prépayée/gift card en boucle ouverte | Sépare le numéro de carte de la carte principale | Vendeur, prestataire d’activation/d’enregistrement, source des fonds, commerçant | Budgétisation ou compartimentation limitée vis-à-vis des commerçants |
| Numéro de carte virtuel/à usage unique | Masque le PAN réutilisable au commerçant ; révocation facile | L’émetteur connaît toujours l’identité et la transaction | Compartimentation vis-à-vis des commerçants en ligne |
| Token de wallet mobile | L’appareil/le commerçant reçoit un token au lieu du PAN sous-jacent | Prestataire du wallet, émetteur, réseau de paiement et commerçant | Sécurité des identifiants, pas anonymat |
| Virement bancaire/application | Piste d’audit pratique | Banque/application, contrepartie et identité associée | Paiements organisationnels traçables |
| Cryptomonnaie | Varie selon le protocole ; la self-custody peut réduire l’exposition au dépositaire | Registre public ou protocole de confidentialité, exchange, point de terminaison, contrepartie | Transferts légaux après analyse spécifique au protocole |

## Espèces

Les espèces sont toujours considérées comme importantes pour la confidentialité et l’inclusion, et évitent un enregistrement dans le réseau de paiement.<sup>[[2]](#references)</sup> Elles ne neutralisent pas la vidéosurveillance, les témoins, la localisation de l’appareil, les reçus, le traçage des numéros de série dans certains cas, ni les obligations légales de déclaration.

### Procédure légale

1. Vérifiez l’acceptation et les plafonds locaux d’utilisation des espèces avant la transaction. Les plafonds diffèrent selon le pays et le type de partie, et évoluent avec le temps.
2. Effectuez l’achat ordinaire en une seule transaction honnête. **Ne le fractionnez jamais** pour éviter un seuil ou une déclaration.
3. Refusez le suivi facultatif de fidélité ou la collecte à des fins marketing. Fournissez honnêtement les données exigées pour la garantie, la sécurité, la livraison, la fiscalité ou la loi.
4. Conservez les preuves d’achat nécessaires et les documents comptables requis dans un stockage chiffré avec une date de conservation.
5. Pour une organisation, demandez le remboursement via la procédure approuvée et enregistrez l’opérateur, l’autorisation, l’objectif, le montant, la date et le reçu.

Aux États-Unis, certaines activités commerciales doivent déposer le formulaire 8300 pour les paiements en espèces supérieurs à 10 000 $, y compris les transactions liées ; le fait de fractionner intentionnellement les transactions peut en soi constituer du structuring illégal.<sup>[[3]](#references)</sup> Les autres juridictions diffèrent — par exemple, l’Espagne publie ses propres restrictions légales sur les paiements en espèces.<sup>[[4]](#references)</sup>

## Cartes prépayées et gift cards

« Prépayée » ne signifie pas anonyme. Un magasin, un émetteur, un gestionnaire de programme, une banque de financement et un commerçant peuvent corréler l’achat, l’activation, l’appareil, l’IP, la localisation et les dépenses. Les rechargements, l’accès aux distributeurs automatiques, l’utilisation internationale, les plafonds élevés ou la protection contre la perte exigent généralement un enregistrement.

Les recommandations destinées aux consommateurs aux États-Unis expliquent que les émetteurs peuvent demander des données d’identité pour la vérification légale et refuser une carte enregistrée lorsque la vérification échoue.<sup>[[5]](#references)</sup> Les règles de la FinCEN définissent les programmes et participants de cartes prépayées soumis à des obligations AML.<sup>[[6]](#references)</sup> Dans l’UE, les exceptions étroites concernant la monnaie électronique anonyme ont été réduites par la Directive (UE) 2018/843 ; le Règlement (UE) 2024/1624 modifie à nouveau le cadre, mais s’applique généralement à partir du **10 juillet 2027**. Ne le décrivez donc pas comme déjà en vigueur en 2026.<sup>[[7]](#references)</sup>

N’utilisez une valeur prépayée que lorsqu’elle a été obtenue légalement auprès d’un émetteur identifiable, que ses conditions autorisent l’usage prévu et que l’objectif est la budgétisation ou la séparation d’avec un moyen de paiement principal. Évitez les marchés de revente et les courtiers proposant des cartes « sans nom » invérifiables : la valeur peut être volée, déjà utilisée, limitée géographiquement ou susceptible d’être saisie.

## Cartes virtuelles et tokens de wallet

Un numéro de carte virtuel (VCN) est généralement émis derrière un compte réel et vérifié. Les numéros spécifiques à un commerçant ou à usage unique réduisent les risques liés aux fuites et la corrélation du PAN entre commerçants ; ils ne masquent **pas** la transaction à l’émetteur. La tokenisation du réseau remplace de même un identifiant de carte par un token limité.<sup>[[8]](#references)</sup>

### Procédure de compartimentation vis-à-vis du commerçant

1. Ouvrez un compte auprès d’un émetteur réglementé en utilisant des données exactes concernant l’identité, la résidence et le financement.
2. Sécurisez-le avec un mot de passe unique, une MFA résistante au phishing lorsqu’elle est disponible, des alertes de connexion et des codes de récupération stockés hors ligne.
3. Générez un VCN verrouillé sur le commerçant ou à usage unique. Définissez une limite raisonnable de montant/durée si cette fonction est proposée.
4. Utilisez le passage en caisse invité et ne renseignez que les champs **facultatifs** de profil, de fidélité et de marketing. Fournissez des données exactes de facturation, de livraison et de fiscalité lorsque cela est exigé.
5. Évitez de vous connecter à des identity providers sans rapport ; utilisez un compartiment de navigateur dédié à la mission/au compte et le chemin réseau approuvé.
6. Enregistrez le reçu et la correspondance VCN-objectif dans un registre interne chiffré.
7. Gelez ou révoquez le numéro après l’expiration du délai de remboursement/chargeback ; surveillez le compte parent pour détecter toute autorisation inattendue.

Capital One et Google indiquent que les numéros virtuels restent liés au compte sous-jacent, tandis qu’EMVCo/Visa décrivent la tokenisation comme une substitution d’identifiant et une restriction de domaine, et non comme un anonymat du payeur.<sup>[[8]](#references)</sup>

## Livraison, comptes et remboursements

Le paiement n’est qu’un seul maillon du graphe de liaison :

- Une carte unique est rendue inutile par la réutilisation d’un e-mail personnel, d’un numéro de téléphone, d’un profil de navigateur, d’une adresse IP ou d’un compte de fidélité.
- Une livraison physique nécessite normalement un destinataire et un lieu légitimes. N’utilisez pas l’adresse d’une personne non impliquée et ne vous faites pas passer pour un résident. Les services de réception professionnels approuvés sont plus sûrs que des informations fabriquées.
- Les biens numériques peuvent enregistrer l’identité du compte, l’IP, l’empreinte de l’appareil, l’activation de la licence et les téléchargements.
- Les remboursements sont généralement renvoyés vers le rail d’origine. Les demandes visant à recevoir des fonds puis à les transférer/rembourser ailleurs constituent un signal de fraude et de money mule.
- Les libellés des commerçants, le texte des factures et les notifications d’expédition peuvent exposer un achat sensible aux délégués du compte ; configurez délibérément les accès et les alertes.

## Achats autorisés de red team

Une mission doit être discrète à l’extérieur et traçable en interne :

1. Obtenez un périmètre écrit précisant l’objectif, le plafond de dépenses, l’approbateur, les commerçants/actifs autorisés et la règle de remboursement.
2. Utilisez un compte de paiement contrôlé par l’organisation et un VCN ou un sous-compte séparé par mission ou commerçant.
3. Conservez des données exactes de facturation et d’enregistrement auprès des prestataires. La confidentialité de l’enregistrement public peut réduire l’exposition, mais n’autorise pas à mentir.
4. Tenez un registre chiffré indiquant l’opérateur, l’approbation, l’objectif, la date, le montant, la contrepartie, l’identifiant de l’actif et le reçu.
5. Contrôlez les contreparties lorsque cela est requis et respectez les obligations des prestataires, les sanctions, la fiscalité et les obligations de déclaration.
6. N’accordez aux équipes financières que les accès nécessaires ; n’accordez aux opérateurs que la capacité de dépense limitée dont ils ont besoin.
7. Fermez ou gelez les identifiants de paiement lors du démantèlement, rapprochez les frais/remboursements en attente et conservez les documents conformément à la politique.

Pour les choix spécifiques aux cryptomonnaies, consultez [Confidentialité des cryptomonnaies](cryptocurrency-privacy.md). Pour l’infrastructure soutenue par ces achats, voir [Infrastructure de red team autorisée](authorized-red-team-infrastructure.md).

## Liste de vérification

- [ ] La propriété de confidentialité recherchée et les observateurs sont consignés.
- [ ] Les règles du prestataire, du commerçant et de la juridiction ont été vérifiées récemment.
- [ ] Les déclarations d’identité et d’origine des fonds sont exactes.
- [ ] Les données facultatives du commerçant sont minimisées sans contourner la vérification requise.
- [ ] Les liens entre financement, appareil, réseau, compte, livraison et remboursement sont compris.
- [ ] Aucun évitement de seuil, aucune contrepartie interdite, money mule, identifiant volé ou identité tierce n’est impliqué.
- [ ] Les reçus, approbations, documents fiscaux et informations de récupération requis sont chiffrés et soumis à un contrôle d’accès.

## References

- [1] [US CFPB — Demande d’informations concernant la collecte, l’utilisation et la monétisation des données de paiement des consommateurs et autres données financières personnelles](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Banque centrale européenne — Étude sur les attitudes des consommateurs de la zone euro à l’égard des paiements (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instructions pour le formulaire 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Agence fiscale espagnole — Déclaration des paiements en espèces](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Pourquoi me demande-t-on des informations personnelles pour activer ou enregistrer une carte prépayée ?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) et [Peut-on me refuser une carte prépayée ?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Règle finale sur l’accès prépayé](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (UE) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Utilisation des cartes de crédit virtuelles](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
