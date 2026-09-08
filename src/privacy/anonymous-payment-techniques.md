# Catalogue des techniques de paiement anonymes

Ce catalogue couvre les **familles** de paiement, de l'argent liquide ordinaire à l'e-cash à signature aveugle et à l'obfuscation sur les chaînes publiques. « Anonyme » signifie toujours anonyme vis-à-vis d'un observateur identifié. Un commerçant, un émetteur, une mint, un exchange, un analyste blockchain, un fournisseur réseau, un employeur et un observateur physique voient des faits différents.

Les procédures ci-dessous concernent des fonds licites, des comptes véridiques et des achats autorisés. Les techniques dont le but était, dans les cas cités, le blanchiment, l'évasion de sanctions ou la fraude à l'identité sont expliquées et détectées, mais leur procédure constitue un exercice forensique synthétique, et non des instructions pour commettre ces infractions.

## Matrice de couverture

| Famille | Propriété principale de confidentialité | Observateur/confiance principal | Traitement |
|---|---|---|---|
| Espèces et équivalents | aucune trace distante du réseau de paiement | bénéficiaire et environnement physique | workflow licite |
| Valeur prépayée/cadeau/bon | sépare le remboursement de la carte principale | vendeur, émetteur et service de remboursement | workflow licite, selon la juridiction |
| Carte virtuelle/tokenisée | masque le PAN réutilisable ou sépare les commerçants | émetteur/réseau/wallet identifient toujours le payeur | workflow licite |
| Payment app/intermédiaire | le commerçant peut ne voir qu'un alias/intermédiaire | l'app collecte identité, appareil et transaction | référence comparative |
| Hygiène Bitcoin/Silent Payments | pseudonymes et impossibilité de relier le destinataire | graphe public et frontière wallet/réseau | déployable |
| PayJoin/CoinJoin | affaiblit les heuristiques de propriété commune/lien | participants/coordinator/réseau/graphe public | déployable si pris en charge ; revue juridique |
| Lightning/BOLT 12 | routage off-chain et réduction du chemin visible du destinataire | extrémités, hops, services et graphe des channels | déployable si pris en charge |
| Monero/Zcash/MWEB | confidentialité on-chain au niveau du protocole | acquisition, extrémité, réseau et frontières | déployable si licite et pris en charge |
| Application Ethereum ZK | masque une déclaration ou un lien d'action donné | entrées publiques, RPC, relayer et app | spécifique à l'application |
| Cashu/Fedimint/Taler | confidentialité du payeur par signature aveugle | mint/federation/exchange, garde et frontières | émergent/spécifique au déploiement |
| Stablecoins | règlement numérique pratique | chaîne transparente et contrôle/gel par l'émetteur | pas une base anonyme |
| Swaps/bridges/DEX | déplace la valeur entre actifs/chaînes | deux graphes, contrats et fournisseurs | mécanique forensique ; swaps licites uniquement |
| Mixers/peel/structuring | accroît l'ambiguïté et le travail du graphe | graphe entrée/sortie et journaux du service | exercice synthétique de détection uniquement |
| Nominees/mules/fronts/OTC | insère des intermédiaires humains/commerciaux | facilitateurs, banques et communications | analyse des abus criminels uniquement |
| Adresses de paiement réutilisables/stealth | nouvelle adresse du destinataire par paiement | annonce/notification publique et frontières du wallet | déployable si pris en charge |
| Sidechain confidentielle/state channel | masque montant/actif ou mises à jour intermédiaires | pairs, bridge/federation et règlement final | spécifique au protocole |
| Opérateur mobile/open banking/facturation plateforme | masque la carte principale au commerçant | opérateur, banque/PISP ou plateforme identifient le client | paiement ordinaire identifié |
| Crédit mutuel/règlement net | moins de traces externes de règlement | l'opérateur du registre privé possède toute la correspondance | participants identifiés uniquement |

## Espèces

**Mécanisme :** une valeur physique au porteur change de mains sans autorisation en ligne de l'émetteur ni registre public.

**Avantages :** le commerçant n'a pas besoin de connaître l'identité bancaire/de la carte ; aucun graphe de transaction distant ; méthode largement comprise et définitive.

**Inconvénients :** uniquement en face à face ; vol/perte ; contrôles de monnaie rendue, reçus, numéros de série ou déclaration ; retrait, caméras, témoins et localisation peuvent toujours relier le payeur.

**Procédure :** (1) confirmer que les espèces sont légales et acceptées, ainsi que les éventuelles règles de montant/déclaration ; (2) les retirer ou recevoir légalement et conserver une comptabilité privée ; (3) payer un commerçant ordinaire sans identifiants de fidélité ou de compte inutiles ; (4) demander uniquement le reçu requis ; (5) éviter les données d'expédition/de compte si l'achat ne les nécessite pas ; (6) consigner en interne le motif commercial légitime.

**Détection :** rapprocher caisse, reçus et inventaire avec les caméras et journaux d'accès selon la politique applicable ; examiner les remboursements inhabituels en espèces ou les montants répétés juste sous les seuils de contrôle, sans considérer l'usage ordinaire des espèces comme suspect en soi.

## Mandat, mandat postal, chèque de caisse et paiement à la livraison

**Mécanisme :** un émetteur réglementé convertit des espèces ou des fonds de compte en un instrument numéroté payable à un bénéficiaire nommé ; le COD reporte l'encaissement à la livraison.

**Avantages :** le bénéficiaire peut ne pas recevoir le numéro de banque/carte principal du payeur ; utilisable lorsque les espèces ne peuvent pas être envoyées à distance ; reçu clair.

**Inconvénients :** l'émetteur/le détaillant conserve les données d'achat/d'identité requises ; suivi du numéro de série ; adresse du bénéficiaire/livraison ; risques de perte/fraude et restrictions régionales ; généralement non anonyme.

**Procédure :** (1) vérifier règles, limites, identification et acceptation par le bénéficiaire ; (2) acheter avec des informations véridiques et des fonds licites ; (3) remplir immédiatement le bénéficiaire et le montant ; (4) conserver numéro de série et reçu ; (5) utiliser une livraison suivie adaptée à la valeur ; (6) rapprocher encaissement et remboursement.

**Détection :** registres d'achat/encaissement de l'émetteur, numéro de série, détaillant/caméra, expédition et compte du bénéficiaire ; signaler les altérations, doublons de numéros et encaissements rapides géographiquement incohérents.

## Carte prépayée open-loop

**Mécanisme :** un moyen de paiement marqué par un réseau autorise les dépenses sur un solde prépayé plutôt que sur un compte de crédit principal.

**Avantages :** limite l'exposition du commerçant et les pertes ; sépare le commerçant du PAN principal ; utilisable en ligne lorsqu'elle est acceptée.

**Inconvénients :** traces d'achat, d'activation, de recharge et d'appareil ; KYC et limites variables ; échecs d'adresse de facturation ; restrictions de retrait/remboursement ; « sans nom » ne signifie pas sans registre de l'émetteur.

**Procédure :** (1) vérifier l'émetteur actuel, les frais, le KYC, la zone géographique et la prise en charge du online/récurrent ; (2) acheter auprès d'un vendeur autorisé avec des fonds licites ; (3) enregistrer les données véridiques requises ; (4) l'utiliser pour un seul contexte ou objectif ; (5) ne pas structurer les recharges ni fabriquer une résidence ; (6) conserver les justificatifs d'achat/dépense et fermer ou éliminer la carte selon les conditions de l'émetteur.

**Détection :** relier vendeur/activation, financement, appareil/IP, autorisation commerçant, vérification du solde et remboursement. Les schémas comptent davantage que l'étiquette prépayée.

## Carte cadeau closed-loop, bon et crédit de service transférable

**Mécanisme :** une valeur numérotée n'est échangeable qu'auprès d'un commerçant, service ou écosystème donné. Les crédits de téléphonie, de jeu et de boutique sont des variantes.

**Avantages :** le commerçant bénéficiaire peut ne voir que le code/solde ; portée limitée ; don facile et séparation budgétaire.

**Inconvénients :** le vendeur et le service enregistrent achat, activation et utilisation ; compte, appareil et livraison peuvent toujours relier les opérations ; escroqueries, remises de revente et limites d'expiration/région ; faibles droits de remboursement.

**Procédure :** (1) acheter uniquement par des canaux autorisés ; (2) enregistrer la valeur du code sans exposer le secret ; (3) ne pas rattacher de compte de fidélité identifiant si cela n'est pas nécessaire ; (4) utiliser un compte/contexte commerçant distinct et légitime ; (5) conserver le reçu jusqu'à acceptation ; (6) ne jamais acheter de codes à la suite d'une demande non sollicitée de « taxes/support/ransomware ».

**Détection :** heure d'émission/utilisation, convergence appareil/compte, achats en volume ou selon des seuils, appareil vérifiant de nombreux soldes et utilisation rapide à distance.

## Carte ou code cadeau financé par cryptocurrency

**Mécanisme :** un intermédiaire accepte de la cryptocurrency et émet une carte, un bon ou un code commerçant. Il s'agit d'une conversion entre rails : le commerçant voit une valeur ordinaire, tandis que le broker relie le dépôt on-chain à l'émission et à la livraison.

**Avantages :** le commerçant ne reçoit pas le wallet de financement ; utile pour les commerçants licites n'acceptant pas la crypto ; valeur stockée limitée.

**Inconvénients :** pas anonyme vis-à-vis du broker/émetteur ; règles KYC, sanctions, exchange et programme de cartes ; graphe public du dépôt ; compte/appareil/email et utilisation du code reconnectent les deux côtés ; risques d'escroquerie/insolvabilité.

**Procédure :** (1) vérifier l'entité légale, l'émetteur de la carte, la juridiction, le KYC, les frais et la politique de remboursement ; (2) utiliser uniquement des fonds licites et documentés ; (3) tester la plus petite valeur ; (4) vérifier les restrictions de réseau/commerçant avant l'achat ; (5) conserver la transaction blockchain et le reçu du broker pour la comptabilité ; (6) ne jamais utiliser un broker promettant fraude à l'identité, contournement des sanctions ou retrait « intraçable ».

**Détection :** corréler les adresses de dépôt du broker, montant/heure uniques, compte/appareil et autorisation de carte ou utilisation du code ; les registres de l'émetteur et du broker relient la chaîne publique au commerçant.

## Carte virtuelle ou limitée à un commerçant

**Mécanisme :** l'émetteur associe un PAN/token généré au compte réel, avec souvent des restrictions de commerçant, montant ou expiration.

**Avantages :** empêche la divulgation du PAN réutilisable ; compartimentation par commerçant ; limites de dépense et révocation facile ; contrôle mature de la fraude.

**Inconvénients :** l'émetteur connaît toujours le payeur, le financement, le commerçant, l'appareil/IP et l'heure ; le commerçant voit le compte/livraison ; certains remboursements ou paiements récurrents échouent ; non anonyme.

**Procédure :** (1) utiliser la fonction officielle de l'émetteur réglementé ; (2) créer une carte pour un commerçant ou engagement unique ; (3) définir la plus petite limite utile et l'expiration ; (4) utiliser une facturation exacte lorsque nécessaire ; (5) vérifier le libellé du relevé et le comportement des remboursements ; (6) geler/supprimer après le règlement final tout en conservant les preuves d'audit.

**Détection :** correspondance token-compte de l'émetteur, autorisation commerçant, appareil et livraison. Les défenseurs utilisent la réutilisation spécifique au commerçant, la vélocité et les signaux de prise de contrôle.

## Token de réseau de mobile wallet

**Mécanisme :** la tokenisation EMV remplace le PAN par un identifiant limité, souvent lié à un appareil, un commerçant ou un scénario de paiement.<sup>[[1]](#references)</sup>

**Avantages :** le commerçant ne reçoit pas le PAN réutilisable ; cryptographie de l'appareil et données dynamiques réduisant le clonage ; révocation sans remplacement de la carte.

**Inconvénients :** l'émetteur, le token service, la plateforme wallet et le réseau conservent les correspondances et transactions ; compte de plateforme/appareil et localisation peuvent identifier le payeur.

**Procédure :** (1) enregistrer une carte légitime dans le wallet officiel ; (2) protéger le compte de plateforme et l'appareil par une authentification forte ; (3) vérifier le token de l'appareil/les derniers chiffres à l'achat ; (4) désactiver la localisation/les analytics inutiles lorsque c'est possible ; (5) désactiver immédiatement les tokens des appareils perdus ; (6) examiner les registres de l'émetteur et du wallet.

**Détection :** correspondance requestor de token/cryptogramme d'appareil-émetteur, télémétrie wallet/compte, terminal commerçant et éléments physiques.

## Payment app, wallet de marketplace et intermédiaire centralisé

**Mécanisme :** le service gère les comptes et transfère les fonds en interne ou par des rails bancaires/de cartes ; le commerçant peut voir un alias tandis que le service voit les deux parties.

**Avantages :** commodité et mécanismes de litige/remboursement ; le bénéficiaire ne voit pas nécessairement les coordonnées bancaires/de carte.

**Inconvénients :** graphe centralisé d'identité, de relations, de transactions et d'appareils ; gels et procédures légales ; les contreparties peuvent exposer le profil ; l'utilisation des données peut dépasser le nécessaire au paiement.<sup>[[2]](#references)</sup>

**Procédure :** (1) lire les conditions d'identité, de confidentialité, de conservation et de protection de l'acheteur ; (2) limiter la synchronisation facultative du profil et des contacts ; (3) utiliser un compte distinct et véridique uniquement si les conditions l'autorisent ; (4) activer MFA et alertes ; (5) vérifier le bénéficiaire et la confidentialité du mémo/profil ; (6) exporter les registres et fermer les liens inutilisés.

**Détection :** compte du fournisseur, appareil/IP, graphe de contacts, financement/retrait, mémo et registres commerçants. Un alias est une pseudonymie vis-à-vis d'une contrepartie, pas un anonymat vis-à-vis de la plateforme.

## Virement bancaire, ACH, wire et paiement instantané par compte

**Mécanisme :** des établissements réglementés déplacent la valeur entre des comptes identifiés et échangent les données de paiement requises.

**Avantages :** rapide, traçable, parfois réversible, avec des registres solides ; les numéros de compte virtuels peuvent réduire la divulgation au commerçant.

**Inconvénients :** les banques et processors connaissent les deux côtés ; relevés et références ; non anonyme ; données transfrontalières et Travel Rule/AML.

**Procédure :** utiliser uniquement lorsque la traçabilité est acceptable : vérifier indépendamment le bénéficiaire, limiter les données facultatives du mémo, utiliser si possible un compte/référence virtuel fourni par la banque, activer les alertes, conserver la facture et rapprocher les comptes.

**Détection :** registres bancaires/de paiement déterministes, propriété du bénéficiaire/compte, session/appareil et contrôles de fraude. Il s'agit d'une référence, pas d'une technique d'anonymat.

## Compartimentation des comptes et commerçants

**Mécanisme :** des identités, comptes, alias email, cartes et contextes de livraison distincts empêchent des commerçants sans lien de regrouper trivialement l'activité, tandis qu'un émetteur/contrôleur conserve la correspondance.

**Avantages :** réduit les fuites et le lien inter-commerçants ; facile à auditer ; compatible avec les paiements réglementés.

**Inconvénients :** le fournisseur relie toujours les compartiments ; téléphone de récupération, appareil/IP et expédition peuvent les reconnecter ; certaines politiques interdisent plusieurs comptes.

**Procédure :** (1) définir un objectif unique ; (2) créer uniquement des alias/sous-comptes conformes aux conditions ; (3) utiliser un token ou une carte spécifique au commerçant ; (4) désactiver la personnalisation publicitaire/contact inter-comptes ; (5) conserver un registre de contrôle chiffré ; (6) retirer les identifiants après la fin des besoins de remboursement/conservation.

**Détection :** les fournisseurs relient récupération, appareil, financement et IP ; les commerçants relient livraison, navigateur et comportement du compte. Les défenseurs doivent distinguer compartimentation légitime et fraude à l'identité synthétique.

## Achat contrôlé de red team

**Mécanisme :** le SOC ignore l'achat tandis qu'un contrôleur d'exercice conserve la correspondance entre entité légale, opérateur et infrastructure.

**Avantages :** exercice de détection réaliste ; aucune exposition personnelle ; déconfliction et audit immédiats.

**Inconvénients :** non anonyme pour l'organisation/le fournisseur ; charge de gouvernance ; fuites si le registre d'attribution est mal géré.

**Procédure :** (1) attribuer une carte/wallet/budget d'organisation spécifique à l'engagement ; (2) séparer les rôles d'acheteur et d'opérateur ; (3) consigner actif, montant, service, objectif et date d'arrêt ; (4) stocker la correspondance d'attribution avec un accès limité au contrôleur ; (5) ne jamais utiliser fausse identité, mule ou fonds volés ; (6) révéler et rapprocher les indicateurs et remboursements à la clôture.

**Détection :** le contrôleur relie facture du fournisseur et actif ; le SOC teste la découverte indépendante via domaine, certificat, hébergement et trafic plutôt que par les données du porteur.

## Hygiène Bitcoin et coin control

**Mécanisme :** des adresses de réception nouvelles, des libellés locaux et une dépense sélective des UTXO réduisent la réutilisation d'adresses et la fusion accidentelle de compartiments sur un registre public.

**Avantages :** largement pris en charge ; self-custodial ; évite les liens publics les plus simples.

**Inconvénients :** toutes les transactions et tous les montants restent publics ; heuristiques common-input/change, timing et consolidations peuvent relier les activités ; les registres d'acquisition, RPC et réseau demeurent.

**Procédure :** (1) installer/vérifier un wallet maintenu ; (2) sauvegarder et tester la récupération de la seed ; (3) utiliser une nouvelle adresse par facture ; (4) libeller localement source et objectif ; (5) utiliser coin control pour éviter de fusionner les contextes ; (6) préférer un nœud local ou une connexion respectueuse de la confidentialité ; (7) vérifier change et frais et conserver la comptabilité licite.<sup>[[3]](#references)</sup>

**Détection :** graphe d'adresses, heuristiques common-input/change avec incertitude, montant/heure exacts, consolidation, dépôts auprès de services, moment de diffusion node/RPC et registres off-chain.

## Bitcoin Silent Payments

**Mécanisme :** BIP 352 permet au destinataire de publier un code statique tandis que les payeurs dérivent des sorties Taproot uniques par ECDH ; les observateurs externes ne peuvent pas relier directement les sorties au code.<sup>[[4]](#references)</sup>

**Avantages :** identifiant public réutilisable sans réutilisation d'adresse ; aucune demande interactive d'adresse ni sortie de notification ; se fond dans les sorties Taproot.

**Inconvénients :** coût de scan du destinataire ; support wallet variable ; graphe montant/expéditeur et dépenses toujours publics ; le serveur d'indexation peut observer les scans.

**Procédure :** (1) choisir un wallet BIP 352 récent ; (2) sauvegarder/tester le descriptor et la récupération du scan ; (3) générer un code libellé lorsque c'est pris en charge ; (4) authentifier le code publié ; (5) l'expéditeur vérifie les inputs et envoie un petit test ; (6) le destinataire scanne de préférence via son propre nœud ; (7) garder les UTXO reçus séparés.

**Détection :** non identifiable de manière fiable à partir de la seule sortie, par conception ; les analystes utilisent les inputs de l'expéditeur, montant/heure, dépenses ultérieures, wallet/réseau/index et registres de contreparties.

## PayJoin

**Mécanisme :** le payeur et le bénéficiaire apportent des inputs à une même transaction, rompant l'hypothèse selon laquelle tous les inputs appartiennent au même propriétaire.<sup>[[5]](#references)</sup>

**Avantages :** paiement ordinaire avec confidentialité améliorée ; bénéfice pour le graphe global en affaiblissant une heuristique commune ; aucun groupe de sorties égales nécessaire.

**Inconvénients :** interaction et support nécessaires ; disponibilité de l'endpoint du bénéficiaire ; montant et transaction finale publics ; métadonnées d'implémentation et de repli.

**Procédure :** (1) confirmer que les deux wallets maintenus prennent en charge la même version PayJoin ; (2) authentifier la facture/l'endpoint ; (3) commencer via l'URI de paiement PayJoin du wallet ; (4) examiner montant/frais finaux et ne signer que les inputs attendus ; (5) éviter toute modification manuelle de transaction ; (6) vérifier diffusion et réception ; (7) documenter le repli si la négociation échoue.

**Détection :** les analystes blockchain ne doivent pas forcer le clustering common-input ; l'endpoint/le fournisseur peut journaliser la négociation ; utiliser les preuves wallet/réseau et les dépenses ultérieures, pas uniquement la forme de la transaction.

## CoinJoin

**Mécanisme :** plusieurs participants créent collaborativement une transaction comportant de nombreux inputs/outputs, souvent de dénominations égales, accroissant l'ambiguïté de correspondance inputs-outputs.

**Avantages :** ensemble d'ambiguïté on-chain plus large ; designs self-custodial existants ; structure de rounds mesurable.

**Inconvénients :** métadonnées coordinator/peer/réseau ; frais et liquidité ; forme de transaction identifiable ; change toxique et consolidation ultérieure détruisent les gains ; disponibilité légale/fournisseur variable.

**Procédure :** (1) vérifier disponibilité et légalité actuelles du wallet/coordinator ; (2) installer le wallet officiel et le sauvegarder ; (3) n'utiliser que des UTXO licites ; (4) comprendre dénomination, frais et modèle du coordinator ; (5) garder le change et les outputs mixtes libellés et séparés ; (6) ne jamais les consolider ensemble ; (7) acheminer le trafic réseau comme officiellement pris en charge et conserver la comptabilité.

**Détection :** identifier la structure collaborative sans supposer un crime ; calculer les correspondances possibles et l'ensemble d'anonymat, puis surveiller change/consolidation, frontières des services et registres réseau/coordinator.

## Lightning Network

**Mécanisme :** les paiements HTLC traversent des channels routés par onion ; la plupart des détails ne sont pas publiés on-chain, tandis que financement/clôture et informations publiques des channels le sont.

**Avantages :** rapide et peu coûteux ; les intermédiaires voient normalement les hops adjacents ; les détails ordinaires restent off-chain.

**Inconvénients :** expéditeur/destinataire et premier/dernier hop en savent davantage ; probing, timing, graphe des channels, liquidité, wallets et registres LSP ; les custodial wallets identifient les utilisateurs.

**Procédure :** (1) choisir consciemment self-custodial ou custodial ; (2) vérifier wallet/seed/récupération des channels ; (3) utiliser une invoice correspondant exactement au paiement ; (4) préférer les channels privés/fonctions LSP seulement après étude des compromis ; (5) protéger l'IP du nœud via Tor pris en charge si nécessaire ; (6) éviter les invoices identifiantes réutilisées ; (7) conserver la comptabilité des channels et paiements.<sup>[[6]](#references)</sup>

**Détection :** journaux node/LSP/custodian, graphe/probes de channels, échecs et timing des paiements, financement/clôture on-chain ; aucune transaction publique ne signifie pas absence de registres.

## Offres BOLT 12 et route blinding

**Mécanisme :** une offer réutilisable produit de nouvelles invoices et peut annoncer des chemins masqués afin que le payeur n'apprenne pas le node/chemin clair du destinataire.

**Avantages :** confidentialité du destinataire ; endpoint réutilisable pour dons/paiements sans invoice statique ; intégration au routage onion de Lightning.

**Inconvénients :** support wallet variable ; endpoints, hops sélectionnés et financement restent visibles ; contact public ou endpoint réseau peut réidentifier le destinataire.

**Procédure :** (1) confirmer le support BOLT 12 correspondant ; (2) authentifier l'offer ; (3) demander une nouvelle invoice ; (4) vérifier montant, émetteur et récurrence ; (5) payer via le wallet ; (6) vérifier réception/remboursement ; (7) limiter alias/contact du nœud et conserver la comptabilité.<sup>[[7]](#references)</sup>

**Détection :** télémétrie wallet/LSP et premier/dernier hop, compte de diffusion de l'offer, timing/valeur et graphe du financement ; le route blinding limite volontairement la visibilité du payeur.

## Monero

**Mécanisme :** les stealth addresses à usage unique masquent le lien avec le destinataire, RingCT masque les montants et les ring signatures fournissent l'ambiguïté de l'expéditeur.

**Avantages :** confidentialité activée par défaut on-chain ; confidentialité de l'expéditeur, du destinataire et du montant ; écosystème mature de wallets/nodes dédiés.

**Inconvénients :** acquisition/off-ramp et registres endpoint/réseau/contrepartie ; un remote node voit requêtes et IP ; support des exchanges et traitement juridique variables ; les erreurs opérationnelles peuvent toujours relier les contextes.

**Procédure :** (1) acquérir légalement et conserver le motif/la source ; (2) installer/vérifier un wallet officiel maintenu ; (3) sauvegarder/tester la seed ; (4) utiliser un nœud local ou un chemin remote node Tor/I2P documenté ; (5) utiliser une nouvelle subaddress par payeur/facture ; (6) libeller localement les contextes ; (7) ne divulguer une preuve de transaction ou un accès view qu'intentionnellement.<sup>[[8]](#references)</sup>

**Détection :** se concentrer sur les preuves d'exchange, commerçant, appareil, réseau et wallet saisi ; l'utilisation du protocole seule n'est pas suspecte et la chaîne publique expose volontairement moins d'informations.

## Zcash Orchard entièrement shielded

**Mécanisme :** les zero-knowledge proofs valident les transferts shielded tandis que l'expéditeur, le destinataire et le montant sont chiffrés ; les pools transparents et transitions de pool restent publics.

**Avantages :** forte confidentialité on-chain shielded ; viewing keys permettant un audit limité ; validité imposée par le protocole.

**Inconvénients :** support wallet/exchange et choix réel du pool variables ; corrélation temps/valeur aux frontières transparentes ; réseau/RPC et endpoints persistants.

**Procédure :** (1) choisir un wallet Orchard maintenu et shielded par défaut ; (2) vérifier et sauvegarder ; (3) obtenir des ZEC légalement ; (4) recevoir vers une Unified Address prise en charge et confirmer le pool ; (5) préférer shielded-to-shielded ; (6) utiliser la confidentialité réseau prise en charge ; (7) tester la divulgation de viewing key avec une petite valeur avant l'audit.<sup>[[9]](#references)</sup>

**Détection :** frontières transparentes et registres des services, métadonnées wallet/réseau et viewing keys lorsqu'elles sont fournies légalement ; ne pas supposer que tous les paiements Unified Address étaient shielded.

## Mimblewimble et Litecoin MWEB

**Mécanisme :** les confidential transactions masquent les montants et l'agrégation de type Mimblewimble retire l'historique conventionnel riche en adresses ; Litecoin implémente une extension optionnelle parallèle à sa chaîne transparente.

**Avantages :** montants confidentiels et meilleure fongibilité dans le domaine privé ; pruning/agrégation efficaces.

**Inconvénients :** la frontière opt-in peg-in/out est publique et corrélable ; support wallet/exchange ; différences de modèle interactif/adresse ; registres réseau et d'acquisition.

**Procédure :** (1) choisir un wallet maintenu prenant explicitement MWEB en charge ; (2) vérifier/sauvegarder et tester un petit montant ; (3) acquérir légalement ; (4) faire le peg vers MWEB et vérifier le domaine du solde ; (5) transacter uniquement avec un destinataire compatible ; (6) éviter un peg-out immédiatement distinctif ; (7) conserver des registres d'audit privés.<sup>[[10]](#references)</sup>

**Détection :** timing/valeur des peg-in/out publics, données exchange/wallet/node et dépenses transparentes ultérieures ; les transferts confidentiels internes réduisent intentionnellement les détails disponibles.

## Applications Ethereum de confidentialité zero-knowledge

**Mécanisme :** un circuit prouve une déclaration — appartenance, propriété valide d'une note ou autorisation — sans révéler le secret ; un contrat verifier la contrôle. Dépôts, retraits, entrées publiques, événements et gas peuvent toujours exposer les liens.

**Avantages :** divulgation sélective programmable ; applications à ensemble anonyme ; règles vérifiables sans révélation de toutes les données.

**Inconvénients :** bugs de contrat/circuit ; petit ensemble d'anonymat ; frontières publiques ; RPC/IP/session/analytics/gas funding ; risques applicatifs, juridiques et de sanctions.

**Procédure :** (1) définir exactement ce que la preuve masque ; (2) utiliser légalement une application auditée et maintenue ; (3) examiner entrées publiques, événements et règles de dépôt/retrait ; (4) séparer wallet d'action et sponsorship du gas comme le prévoit le protocole ; (5) utiliser un chemin RPC/réseau respectueux de la confidentialité ; (6) tester avec une petite valeur ; (7) conserver les registres de conformité.<sup>[[11]](#references)</sup>

**Détection :** événements de contrats, timing/valeur dépôt-retrait, relayer/paymaster, RPC/session, stockage/analytics frontend et frontière exchange/commerçant finale. Ne pas prétendre que la preuve ZK masque les champs déclarés publics.

## Stablecoins

**Mécanisme :** les tokens sont transférés sur une chaîne publique ; les émetteurs centralisés peuvent geler, blacklister ou racheter auprès de comptes identifiés.

**Avantages :** stabilité du prix, liquidité et support commerçant ; règlement rapide ; comptabilité simple.

**Inconvénients :** graphe transparent des adresses, montants et contrats ; financement du gas ; identité/contrôle de l'émetteur et de l'exchange ; filtrage des sanctions ; anonymat généralement faible.

**Procédure :** traiter comme un paiement identifié : utiliser une adresse commerciale nouvelle uniquement pour la compartimentation, vérifier contrat token/réseau, tester un petit montant, protéger le wallet, utiliser un RPC de confiance ou un nœud local, conserver source/motif et filtrer les parties requises.

**Détection :** graphe complet des événements token, listes/actions de gel de l'émetteur et relations exchange/RPC/appareil/financement du gas.

## Cashu Chaumian e-cash

**Mécanisme :** une mint signe aveuglément des secrets bearer générés par le client et garantis par des réserves Bitcoin/Lightning de la mint ; elle peut empêcher la double dépense sans relier directement l'émission au remboursement ultérieur.

**Avantages :** tokens bearer sans compte ; transferts peer instantanés ; la mint ne peut pas relier directement le retrait aveugle à la dépense ; tokens transmissibles comme données/QR.

**Inconvénients :** garde/solvabilité/censure de la mint ; perte/vol des données bearer ; frontières de dénomination/timing et Lightning ; métadonnées réseau ; écosystème logiciel précoce.<sup>[[12]](#references)</sup>

**Procédure :** (1) utiliser d'abord une mint de test officielle ou une valeur minime jetable ; (2) installer un wallet maintenu et tester les limites de backup/restore ; (3) authentifier la mint et examiner garde/frais ; (4) minter une petite valeur ; (5) envoyer le token par canal privé/QR authentifié ; (6) le destinataire swap le token avant de le considérer définitif ; (7) rembourser et rapprocher. Ne jamais stocker une valeur significative dans une mint non fiable.

**Détection :** la mint voit réseau, frontières émission/remboursement/Lightning et ensemble des tokens dépensés, mais le blinding retire le lien direct du token ; endpoints/messages et montant/timing distinctifs peuvent rétablir les liens.

## Fedimint federated e-cash

**Mécanisme :** un quorum de guardians détient les réserves et signe aveuglément l'e-cash ; les transferts bearer internes sont privés vis-à-vis des guardians, tandis que les gateways Lightning relient les paiements externes.

**Avantages :** garde distribuée ; transfert interne privé ; gouvernance communautaire ; aucun guardian seul ne contrôle la réserve sous le seuil.

**Inconvénients :** risque de quorum/garde/logiciel ; gateway voyant invoices et timing ; frontières dépôt/retrait ; récupération complexe de l'état client.

**Procédure :** (1) vérifier invitation, guardians, quorum et juridiction de la federation ; (2) installer un client maintenu et tester la récupération ; (3) déposer une petite valeur licite ; (4) utiliser de nouvelles payment requests internes ; (5) considérer la gateway comme observateur des paiements Lightning ; (6) tester le remboursement ; (7) conserver les registres source/taxe hors des données de paiement publiques.<sup>[[13]](#references)</sup>

**Détection :** la federation voit les émissions/remboursements agrégés, les gateways voient les invoices externes, Bitcoin/Lightning montrent les frontières et les preuves endpoint/communication peuvent relier les transferts internes.

## GNU Taler

**Mécanisme :** l'e-cash à signature aveugle intégré à une banque vise à garder le payeur anonyme vis-à-vis des commerçants, tout en rendant les commerçants et revenus responsables.

**Avantages :** confidentialité du payeur par conception ; monnaie ordinaire ; responsabilité/remboursement du commerçant ; aucun token spéculatif requis.

**Inconvénients :** déploiements limités ; exchange/banque voient le financement ; le commerçant voit commande/livraison ; risque bearer/récupération du wallet ; opérateurs réglementés.

**Procédure :** (1) trouver un exchange/commerçant actuel pour la juridiction et la devise ; (2) lire KYC, frais et confidentialité ; (3) installer le wallet officiel ; (4) retirer légalement auprès de la banque/exchange pris en charge ; (5) examiner le contrat commerçant ; (6) payer et conserver reçus/remboursements ; (7) éviter les identifiants de session commerçant inutiles.<sup>[[14]](#references)</sup>

**Détection :** le retrait banque/exchange et le dépôt commerçant sont des frontières responsables ; commande, appareil, livraison et timing peuvent corréler même lorsque les coins sont blindés.

## Bridge inter-chaînes, atomic swap et exchange décentralisé

**Mécanisme :** un contrat/service verrouille ou brûle un actif et libère/minte un autre, ou des contreparties échangent atomiquement. Cela rompt une vue mono-registre, pas la continuité économique.

**Avantages :** interopérabilité actif/réseau ; possibilité d'éviter un custodian centralisé ; usage ordinaire de portefeuille/liquidité.

**Inconvénients :** les deux chaînes sont publiques ; temps, valeur, frais, liquidité et contrats sont corrélables ; registres bridge/relayer/frontend/RPC ; risques de contrat, contrepartie et réglementation.

**Procédure pour les swaps licites :** (1) vérifier le contrat/service officiel et la disponibilité légale ; (2) examiner garde, audit, frais et slippage ; (3) effectuer un petit test ; (4) consigner les deux transaction IDs et le taux ; (5) protéger les approvals ; (6) rapprocher l'actif de destination et révoquer les approvals inutiles. Ne pas utiliser les swaps pour dissimuler la source des fonds.

**Détection :** événements dépôt/retrait du bridge, montant unique moins frais, ordre temporel, liquidité, relayer/RPC/frontend et dépôts ultérieurs auprès de services.

## Mixer centralisé ou tumbler

**Mécanisme :** un service reçoit des dépôts dans un pool et restitue ultérieurement d'autres unités, tentant d'obscurcir la correspondance directe entre entrées et sorties.

**Avantages :** peut théoriquement agrandir l'ambiguïté transactionnelle.

**Inconvénients :** l'opérateur peut voler ou journaliser ; analyse des montants/timing d'entrée-sortie ; exposition aux sanctions, au money transmission et au crime ; une saisie peut révéler les correspondances ; risque de rejet/taint.

**Procédure :** aucun guide opérationnel de mixing n'est fourni. Reproduire le graphe en sécurité en étendant [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) : créer des dépôts synthétiques, sorties groupées, frais et délais ; fournir aux analystes des correspondances incomplètes ; mesurer les heuristiques efficaces ; puis révéler la vérité terrain.

**Détection :** identification du wallet/contrat du service, ensembles de candidats entrée-sortie, montant/frais/timing, réutilisation d'adresses de dépôt, journaux saisis/fournisseur et consolidations en aval. Étiqueter l'attribution probabiliste.

## Peel chains, fan-out/fan-in et structuring

**Mécanisme :** des transactions répétées prélèvent de petits paiements sur le change, répartissent la valeur entre de nombreuses adresses, reconvergent vers des collecteurs ou divisent les montants pour éviter un examen.

**Avantages :** accroît la charge de travail d'un analyste naïf et le nombre d'adresses.

**Inconvénients :** continuité de valeur/cadence/transaction reconnaissable ; consolidations et endpoints de services ; le structuring peut être illégal en lui-même ; frais et erreurs opérationnelles.

**Procédure :** utiliser uniquement des données CSV/testnet synthétiques : générer une source importante, des arêtes paiement/change répétées, des branches parallèles et un collecteur ; ajouter des exemples bénins ressemblant à des exchanges ; régler la détection et documenter les faux positifs.

**Détection :** continuité du graphe, schéma de change répété, cadence, montants juste sous les contrôles, endpoint de service commun et registres off-chain. Les hot wallets d'exchange peuvent ressembler à ces schémas : le contexte est obligatoire.<sup>[[15]](#references)</sup>

## Nominee, money mule, broker OTC et société écran

**Mécanisme :** une autre personne, un autre compte ou une autre société reçoit, convertit ou dépense les fonds, insérant des couches juridiques et opérationnelles entre le contrôleur et la transaction.

**Avantages pour un adversaire :** le compte nommé n'identifie pas immédiatement le contrôleur ; peut relier espèces, crypto, biens et juridictions.

**Inconvénients :** exposition à la fraude d'identité et au blanchiment ; chaque participant ajoute communications, données bancaires/commerciales/fiscales/d'expédition, frais, incohérences et témoins ; la réutilisation d'un facilitateur crée des hubs.

**Procédure :** ne pas émuler avec de vraies personnes ou de vrais comptes. Construire un graphe synthétique avec contrôleur, recruteur, mule, OTC, commerçant écran et bénéficiaire ; ajouter les arêtes appareil/IP/message/banque ; demander aux enquêteurs de distinguer titulaire du compte et contrôleur et de consigner la confiance dans les preuves.

**Détection :** appareil/IP/récupération partagés, bénéficiaire/vélocité inhabituels, nombreux expéditeurs sans lien, mouvement immédiat vers l'extérieur, incohérences société/directeur/facture, communications et livraison d'espèces/marchandises.

## NFT, jeu d'argent, biens marchands et boucles de remboursement

**Mécanisme :** la valeur est convertie en actif auto-évalué, solde de pari, biens revendables ou remboursements afin de créer un récit transactionnel différent.

**Avantages pour un adversaire :** changement de forme de l'actif et ajout d'intermédiaires marketplace/commerçant.

**Inconvénients :** graphe marketplace/compte/appareil et wash trading ; registres de jeu et de remboursements ; livraison/revente ; frais/pertes ; responsabilité pour fraude/blanchiment.

**Procédure :** aucun workflow de dissimulation. Utiliser des données marketplace synthétiques avec trades liés entre wallets, prix invraisemblables, jeu minimal, instrument de remboursement incohérent et expédition commune ; valider la détection sur des collectionneurs/clients légitimes.

**Détection :** trades circulaires/auto-financés, propriété/financement communs, prix aberrants, revente/remboursement immédiat, activité économique minimale, appareil/livraison partagés et reconvergence des produits.

## Wallet physique au porteur ou transfert de token offline

**Mécanisme :** un appareil, papier/QR, instrument hardware bearer ou token e-cash transfère le contrôle d'un secret au lieu de diffuser un paiement au moment de la remise.

**Avantages :** aucun événement réseau en direct durant l'échange ; utilisable offline ; garde physique comparable aux espèces.

**Inconvénients :** copie/vol/perte et exclusivité incertaine ; remboursement/diffusion ultérieurs créent des liens ; rencontre/expédition physiques ; contrefaçon/altération.

**Procédure :** (1) utiliser uniquement un instrument/protocole examiné ; (2) initialiser et vérifier l'authenticité en privé ; (3) charger seulement une petite valeur licite ; (4) transférer dans un contexte autorisé et documenté ; (5) le destinataire vérifie ou sweep rapidement selon le protocole ; (6) ne jamais supposer que l'expéditeur n'a pas conservé de copie ; (7) consigner en privé les preuves de propriété et fiscales.

**Détection :** achat/financement et sweep/remboursement final, numéro de série/altération de l'appareil, livraison/rencontre et registres des endpoints.

## Invoice limitée au commerçant ou demande de paiement unique

**Mécanisme :** le commerçant crée une demande à usage unique contenant montant, expiration et référence de commande. Le payeur la règle via un rail pris en charge sans exposer directement un identifiant réutilisable au commerçant ; l'émetteur ou processor peut néanmoins identifier les deux parties.

**Avantages :** limite la réutilisation des identifiants et les liens inter-commerçants accidentels ; montant/expiration exacts réduisent les erreurs ; compatible avec comptabilité et remboursements ordinaires.

**Inconvénients :** invoice, livraison, navigateur, processor et émetteur relient encore la commande ; montant/heure uniques peuvent renforcer la corrélation ; les liens de paiement malveillants sont fréquents.

**Procédure :** (1) authentifier indépendamment le commerçant ; (2) demander une invoice fraîche avec montant, actif/réseau et expiration exacts ; (3) examiner destination et règles de remboursement ; (4) payer depuis le compartiment d'engagement approuvé ; (5) vérifier que le commerçant reconnaît la même invoice ; (6) conserver reçu et référence de transaction ; (7) laisser expirer plutôt que réutiliser la demande.

**Détection :** commerçant et processor relient invoice, session et règlement ; montants/heures uniques et livraison identifient le payeur. **Wallet/appareil capturé :** l'historique des invoices expose contreparties et objectifs ; minimiser les mémos inutiles, chiffrer l'appareil et conserver la comptabilité de référence dans le système financier contrôlé.

## Crédit de service prépayé et capability token

**Mécanisme :** un service convertit un paiement classique en crédits internes limités ou en capability bearer. L'utilisation ultérieure d'API/ressources peut éviter de présenter la carte initiale à chaque requête, mais le service peut souvent relier émission et utilisation.

**Avantages :** limite les dépenses et les pertes en cas de compromission ; sépare les opérateurs quotidiens de l'identifiant de financement ; permet budgets par projet et révocation.

**Inconvénients :** généralement pseudonyme, non anonyme ; base du service, IP de remboursement et schéma d'utilisation unique relient l'activité ; vol des tokens bearer ; remboursement pouvant exiger le payeur initial.

**Procédure :** (1) acheter les crédits via un compte d'organisation ; (2) créer un projet et budget uniques ; (3) émettre un token limité par service, montant et expiration ; (4) le stocker uniquement dans le secret manager approuvé ou le chemin workload identity ; (5) tester le rejet hors périmètre et après expiration ; (6) surveiller la consommation ; (7) révoquer et rapprocher la valeur inutilisée.

**Détection :** le fournisseur relie compte de financement, projet, émission du token et utilisation ; alerter sur changements géographiques/processus et consommation anormale. **Node capturé :** supposer que sa capability restante peut être dépensée ; utiliser courte expiration, faible solde, audience binding et révocation serveur immédiate.

## Token d'autorisation Privacy Pass ou aveugle

**Mécanisme :** un émetteur produit un token d'autorisation respectueux de la confidentialité qu'un origin peut valider sans relier le remboursement à l'émission. Il peut représenter un droit payé ou un accès limité, mais n'est pas une monnaie générale. L'architecture sépare les rôles client, attester, issuer et origin et avertit que IP/timing ou collusion peuvent annuler l'absence de lien.<sup>[[18]](#references)</sup>

**Avantages :** remboursement non lié pour les services pris en charge ; aucun cookie de compte réutilisable à l'origin ; les tokens mis en cache séparent émission et utilisation dans le temps.

**Inconvénients :** spécifique à l'application ; confiance issuer/attester et partitionnement de l'ensemble d'anonymat ; IP et métadonnées du navigateur persistent ; vol ou timing distinctif de l'émission pouvant corréler l'utilisation.

**Procédure :** (1) utiliser une implémentation conforme au type de token Privacy Pass concerné ; (2) définir exactement le droit prouvé ; (3) séparer administration issuer et origin lorsque le modèle de menace l'exige ; (4) minimiser les métadonnées du challenge ; (5) émettre plusieurs tokens de test et les rembourser une seule fois sur des origins possédés ; (6) comparer les logs à la recherche d'identifiants stables interdits ; (7) tester rejeu, expiration, révocation et abus.

**Détection :** les origins voient IP/heure de remboursement et validité ; issuers/attesters voient le contexte d'émission ; les analystes testent timing et partitions de métadonnées sans supposer une rupture cryptographique. **Client capturé :** les tokens bearer non dépensés peuvent être utilisables ; limiter leur valeur, durée et audience, et ne jamais mettre la credential de financement en cache avec eux.

## Achat délégué d'organisation ou fiscal sponsor

**Mécanisme :** une équipe d'achat autorisée, un revendeur ou un fiscal sponsor contracte et paie tandis que l'équipe opérationnelle reçoit un service limité. Il s'agit d'une séparation des rôles avec des registres véridiques, non d'un nominee ou d'une fausse identité.

**Avantages :** les fournisseurs n'ont pas besoin de recevoir l'identité ou les données de paiement personnelles de chaque opérateur ; conformité, fiscalité et remboursements centralisés ; budget et retrait clairs.

**Inconvénients :** le sponsor connaît le bénéficiaire et l'objectif ; contrats, approbations, livraison et comptes restent ; délais/frais supplémentaires ; séparation faible si la même personne administre toutes les couches.

**Procédure :** (1) documenter motif commercial, bénéficiaire et autorité d'approbation ; (2) choisir un intermédiaire approuvé par l'organisation ; (3) contracter sous des informations véridiques ; (4) provisionner un sous-compte limité au projet sans credential personnelle de facturation ; (5) séparer administrateurs financiers et opérateurs ; (6) rapprocher factures et accès ; (7) terminer service et accès délégué à la clôture.

**Détection :** registres d'achat, identity provider, fournisseur et livraison relient la chaîne. **Appareil opérationnel capturé :** il doit révéler le projet de service, mais pas les credentials financières ; conserver factures et identités des payeurs dans le système financier, pas sur les field nodes.

## Escrow ou règlement conditionnel

**Mécanisme :** un agent escrow de confiance ou un smart contract conserve la valeur jusqu'à la satisfaction de conditions documentées. Il peut réduire la divulgation directe entre payeur et bénéficiaire, tandis que l'escrow et les rails sous-jacents conservent la relation.

**Avantages :** protection contre litiges et problèmes de livraison ; payeur et commerçant peuvent éviter de s'exposer mutuellement des credentials réutilisables ; conditions de libération auditables.

**Inconvénients :** risques de garde/contrat, frais et obligations d'identité ; contrats on-chain publics ; commande, expédition et litiges demeurent ; non anonyme vis-à-vis de l'intermédiaire.

**Procédure :** (1) vérifier entité légale, garde, frais, forum de litige et actifs pris en charge ; (2) créer une étape écrite exacte et un chemin de remboursement ; (3) financer depuis un compte d'organisation approuvé ; (4) vérifier indépendamment réception et autorisation de libération ; (5) libérer uniquement après preuve ; (6) conserver l'audit complet ; (7) fermer permissions ou approvals inutilisés.

**Détection :** événements compte/contrat escrow, financement et libération, bénéficiaire et litige révèlent la transaction. **Appareil capturé :** session tokens ou approvals de contrat peuvent permettre une libération ; exiger approbateur séparé/MFA et révoquer les sessions actives en cas de perte.

## Règlement organisationnel groupé ou mutualisé

**Mécanisme :** plusieurs obligations approuvées sont agrégées et réglées par moins de transactions bancaires ou blockchain, avec un registre interne privé attribuant chaque part. Le batching peut réduire le détail public par achat, mais le coordinateur conserve l'attribution complète.

**Avantages :** frais réduits ; moins d'arêtes publiques ; lignes individuelles masquées à un observateur public lorsque les montants sont agrégés ; comptabilité interne simple.

**Inconvénients :** le coordinateur est un observateur complet et une cible importante ; totaux/heures distinctifs corrélables ; risques de garde et de rapprochement ; peut ressembler à du structuring s'il est détourné.

**Procédure :** (1) définir participants et obligations licites dans le système comptable ; (2) établir une fenêtre régulière justifiée commercialement plutôt que des seuils destinés à éviter les contrôles ; (3) exiger une double approbation de l'agrégat ; (4) régler vers des bénéficiaires authentifiés ; (5) rapprocher chaque ligne interne avec le batch ; (6) traiter les remboursements comme corrections liées ; (7) protéger l'accès au registre et le conserver selon la politique.

**Détection :** registre du coordinateur, approbations et bénéficiaires fournissent la vérité terrain ; les analystes publics utilisent prudemment les clusters d'inputs/outputs/valeur/temps. **Appareil du payeur capturé :** il ne doit contenir que sa demande, pas la clé de signature du pool ni le registre des participants.

## Paymaster d'account abstraction ou gas sponsorisé

**Mécanisme :** un relayer/bundler soumet une opération de smart account et un paymaster paie les frais de transaction, évitant une arête directe de financement du gas natif depuis le wallet utilisateur. Cela améliore une propriété du graphe ; opération, contrat et télémétrie du service restent publics ou observables.<sup>[[19]](#references)</sup>

**Avantages :** retire un lien courant de financement du gas ; permet sponsorship limité et rate limits ; facilite l'intégration d'applications licites de confidentialité.

**Inconvénients :** paymaster/bundler/RPC/frontend peuvent corréler les requêtes ; événements de contrat et entrées publiques persistent ; la politique de sponsorship caractérise une cohorte ; contrats ou approvals malveillants peuvent voler des actifs.

**Procédure :** (1) utiliser un smart account et paymaster audités et maintenus sur le bon réseau ; (2) examiner les champs publics et les logs du sponsor ; (3) limiter le sponsorship par contrat, fonction, montant, nonce et expiration ; (4) tester avec une faible valeur ; (5) soumettre via le chemin de l'application prévu et respectueux de la confidentialité ; (6) vérifier on-chain l'opération et le payeur du gas ; (7) révoquer allowances/session keys et conserver les registres de conformité.

**Détection :** relier UserOperation, EntryPoint, paymaster, bundler/RPC et logs applicatifs ; regrouper prudemment les politiques de sponsorship identiques. **Wallet capturé :** session keys et approvals en attente peuvent être utilisés même sans gas ; les limiter strictement et les révoquer via la politique de récupération du compte.

## Autorisation de paiement threshold ou multisignature

**Mécanisme :** une dépense exige un seuil de signataires indépendants. Cela ne masque pas la transaction, mais sépare l'autorité de paiement d'un laptop, field node ou opérateur compromis.

**Avantages :** forte résistance à la compromission et à l'insider ; approbation responsable ; aucun appareil terrain ne détient toute l'autorité ; récupération prise en charge.

**Inconvénients :** coordination et disponibilité ; métadonnées des signataires/appareils/comptes pouvant corréler les participants ; mauvaise sauvegarde entraînant une perte ; scripts/contrats multisig publics parfois identifiables.

**Procédure :** (1) définir signataires, seuil, limites et récupération avant financement ; (2) initialiser sur hardware/comptes séparés ; (3) vérifier indépendamment adresses et sauvegardes ; (4) donner aux workloads terrain uniquement la capacité de demande non signée ; (5) exiger une revue hors bande du bénéficiaire, montant et motif ; (6) tester récupération et perte d'un signataire avec une petite valeur ; (7) faire tourner un signataire après compromission.

**Détection :** système d'approbation, appareils des signataires et script/contrat public fournissent les preuves ; alerter sur les changements de politique ou d'ensemble de signataires. **Node capturé :** il ne doit exposer au maximum qu'une session key de faible autorité ou une demande non signée ; ne jamais mettre le matériel du quorum en cache ensemble.

## Monnaie communautaire ou événementielle closed-loop

**Mécanisme :** une coopérative, une conférence ou un environnement de test privé émet des crédits échangeables uniquement entre participants inscrits. Les transferts internes peuvent moins exposer les réseaux de paiement globaux, tandis que l'opérateur contrôle émission et remboursement.

**Avantages :** domaine économique limité ; test d'UX de paiement offline ou respectueuse de la confidentialité ; exposition moindre de la carte externe ; contrôles expérimentaux clairs.

**Inconvénients :** petit ensemble d'anonymat ; opérateur et commerçants voient l'activité ; acceptation/remboursement limités ; licences, protection du consommateur et règles fiscales peuvent s'appliquer.

**Procédure :** (1) obtenir revue juridique/conformité et publier les conditions de l'émetteur ; (2) inscrire des participants consentants ; (3) limiter l'émission et interdire les abus assimilables aux espèces ; (4) utiliser de nouvelles demandes de paiement et limiter les identifiants publics ; (5) enregistrer réserves agrégées et reçus individuels privés ; (6) tester perte/remboursement/rachat ; (7) fermer le registre et restituer la valeur résiduelle comme promis.

**Détection :** registre émetteur, inscription, commerçants et remboursements reconstruisent les flux ; transferts circulaires inhabituels ou cash-out rapides justifient un examen. **Wallet capturé :** solde local et contreparties peuvent être exposés ; plafonner la valeur, chiffrer l'état et permettre gel/réémission côté émetteur avec trace auditable.

## Payment codes Bitcoin réutilisables et instructions privées

**Mécanisme :** les payment codes BIP 47 utilisent un identifiant public réutilisable et des adresses de dépôt à usage unique dérivées par ECDH ; BIP 351 spécifie un design plus récent d'instructions de paiement privées. Ils réduisent la réutilisation publique des adresses, mais notification, support wallet, financement et sélection ultérieure des coins influencent encore la confidentialité.<sup>[[20]](#references)</sup>

**Avantages :** une instruction publique peut produire des adresses distinctes ; le destinataire n'a pas à publier chaque adresse de facture ; les wallets compatibles peuvent surveiller les paiements dérivés ; utile pour des donateurs/clients licites récurrents.

**Inconvénients :** interopérabilité wallet variable ; transactions de notification ou publication du payment code lient un contexte relationnel ; expéditeur, destinataire et graphe public voient toujours les transactions ; consolidation ou gestion du change imprudentes annulent le bénéfice.

**Procédure :** (1) confirmer que les deux wallets maintenus prennent en charge exactement la même spécification/version ; (2) sauvegarder et tester la récupération avec un wallet de faible valeur ; (3) authentifier hors bande le payment code du destinataire ; (4) envoyer un petit test licite ; (5) vérifier qu'une nouvelle adresse dérivée a été utilisée ; (6) libeller localement la relation et appliquer coin control ; (7) tester récupération et remboursement avant de s'y fier.

**Détection :** examiner notifications, financement/change, consolidations ultérieures et frontières des services ; la publication du code public identifie le contexte du destinataire même si les adresses de dépôt diffèrent. **OPSEC résistante à la capture :** conserver les spend keys hors des appareils terrain et exposer au maximum une vue watch-only de la relation. **Surveillance :** alerter sur notifications inattendues, adresses dérivées réutilisées, erreurs gap-limit/récupération et consolidations non prévues.

## Stealth addresses EVM (ERC-5564)

**Mécanisme :** un expéditeur dérive un compte stealth à usage unique depuis la stealth meta-address du destinataire et publie une annonce contenant une clé publique éphémère et un view tag. Le destinataire scanne les annonces avec une viewing key et dérive la spend key correspondante. Le lien avec le destinataire s'améliore, mais expéditeur, montant/token, gas, annonce et dépenses ultérieures restent visibles.<sup>[[21]](#references)</sup>

**Avantages :** nouvelle adresse de réception non interactive ; meta-address réutilisable ; rôles viewing et spending séparés ; fonctionne avec les actifs/applications EVM pris en charge.

**Inconvénients :** scan et spam des annonces ; financement du gas de la nouvelle adresse pouvant la relier ; l'expéditeur connaît le destinataire ; token/montant publics et consolidation ultérieure ; support d'implémentation et de wallet variable.

**Procédure :** (1) utiliser d'abord une implémentation auditée et maintenue sur un testnet ; (2) générer et sauvegarder séparément le matériel de viewing et de spending ; (3) authentifier la meta-address ; (4) envoyer un test de faible valeur avec annonce ; (5) scanner et dériver le compte stealth ; (6) tester un sponsorship du gas pris en charge sans arête personnelle de financement ; (7) consigner les champs publics et conserver une comptabilité licite.

**Détection :** suivre appelant de l'annonce, token/montant, timing, sponsor du gas, dépenses et consolidations ; une view key peut prouver une réception sans permettre une dépense. **OPSEC résistante à la capture :** un scanner réseau ne doit avoir que le rôle viewing lorsque possible ; conserver ailleurs les clés de dépense et de récupération. **Surveillance :** alerter sur annonces malformées/spam, accès view-key, dérivation de dépense inattendue et sorties stealth déplacées sans approbation.

## Liquid Confidential Transactions

**Mécanisme :** Liquid masque par défaut montants et types d'actifs des outputs au moyen de commitments et proofs, tout en laissant visibles graphe, nombre d'inputs/outputs, frais et heure du bloc. Peg-in/peg-out et frontières de service restent liables, et les utilisateurs peuvent divulguer sélectivement les données de blinding.<sup>[[22]](#references)</sup>

**Avantages :** montant et type d'actif confidentiels par défaut ; règlement sidechain rapide ; audit sélectif via clés/descriptors de blinding ; valeurs commerciales masquées aux observateurs publics.

**Inconvénients :** structure du graphe et timing persistants ; confiance envers federation/bridge/exchange ; frontières peg et outputs non confidentiels ; registres wallet/node/réseau ; expéditeur et destinataire connaissent leur transaction.

**Procédure :** (1) choisir un wallet Liquid maintenu et vérifier son modèle de sauvegarde ; (2) utiliser testnet ou une petite valeur licite ; (3) recevoir vers une adresse confidentielle et vérifier que le wallet marque l'output comme blindé ; (4) envoyer une transaction confidentielle de test ; (5) examiner les champs encore publics dans l'explorer ; (6) exporter uniquement la preuve de blinding nécessaire à l'audit ; (7) documenter frontières peg/exchange et rapprocher les fonds.

**Détection :** analyser graphe/frais/temps visibles, registres peg/exchange, métadonnées réseau et preuves ultérieures de déblindage ; ne pas déduire montant ou actif masqués. **OPSEC résistante à la capture :** séparer seed de dépense, données blinding/view et opérations watch-only. **Surveillance :** alerter sur adresses accidentellement non confidentielles, demandes peg inconnues, changements de descriptor et export non approuvé de clés de déblindage.

## General payment ou state channel

**Mécanisme :** les participants verrouillent des fonds, échangent des mises à jour d'état signées off-chain et ne publient on-chain que l'ouverture, la fermeture ou l'état contesté. Les paiements intermédiaires ne sont pas diffusés globalement, mais les pairs et services de routage/intermédiaires voient leur portion et les endpoints doivent conserver le dernier état exécutable.<sup>[[23]](#references)</sup>

**Avantages :** nombreuses interactions rapides et peu coûteuses, privées vis-à-vis du registre public ; moins de détails transactionnels globaux ; solde de channel limité ; utile pour services mesurés et contreparties récurrentes.

**Inconvénients :** les pairs se connaissent et peuvent conserver les mises à jour ; ouverture/fermeture/valeur/timing corrélables ; surveillance en ligne parfois nécessaire pendant les fenêtres de contestation ; risques d'implémentation/liquidité ; pas un grand ensemble d'anonymat en soi.

**Procédure :** (1) choisir une implémentation auditée et maintenue et comprendre la fenêtre de litige ; (2) ouvrir un channel de test de faible valeur entre parties possédées ; (3) échanger des mises à jour signées avec des nonces uniques ; (4) sauvegarder le dernier état exécutable ; (5) fermer de manière coopérative ; (6) répéter sur testnet le rejet d'un état obsolète ; (7) conserver comptabilité et registres des pairs.

**Détection :** la chaîne publique expose cycle de vie/litiges ; pairs, services de veille et transport applicatif exposent timing et parties off-chain. **OPSEC résistante à la capture :** plafonner le solde hot et conserver le dernier état signé dans un stockage chiffré récupérable séparé des field nodes. **Surveillance :** surveiller publication d'état obsolète, sauvegarde manquée, changement de clé du pair et échéance de contestation proche.

## Facturation par opérateur mobile

**Mécanisme :** un service en ligne facture un achat sur un abonnement mobile ou un solde prépayé via le système de facturation opérateur. Le commerçant peut recevoir une autorisation opérateur plutôt que les données de carte/banque, tandis que l'opérateur connaît abonné/ligne, contexte appareil/réseau, commerçant, montant et heure.<sup>[[24]](#references)</sup>

**Avantages :** aucun numéro de carte chez le commerçant ; disponibilité téléphonique étendue ; utilisable pour biens numériques de faible valeur ; l'opérateur peut plafonner et annuler les frais.

**Inconvénients :** fortement identifié par SIM/compte et souvent appareil ; limites basses et frais élevés ; restrictions de catégories ; risque de prise de compte/SIM swap ; opérateur et agrégateur créent une trace complète.

**Procédure :** (1) confirmer disponibilité, limite, frais et conditions de remboursement avec le compte opérateur de l'organisation ; (2) l'activer uniquement sur une ligne d'organisation dédiée si justifié ; (3) fixer le plafond utile minimal ; (4) acheter un article de test bénin ; (5) vérifier les reçus commerçant/opérateur ; (6) désactiver l'autorisation récurrente ; (7) rapprocher et désactiver la fonction après l'évaluation.

**Détection :** registres opérateur, agrégateur et commerçant relient ligne, abonné, IP/appareil et frais ; les factures télécom d'entreprise l'exposent. **OPSEC résistante à la capture :** ne pas utiliser de numéro personnel et exiger la MFA du compte opérateur hors de l'appareil terrain. **Surveillance :** activer alertes instantanées de frais/changement SIM et arrêter en cas d'inscription inattendue à un service premium, transfert ou récupération de compte.

## Initiation de paiement open banking

**Mécanisme :** avec le consentement explicite de l'utilisateur, un PISP réglementé demande à la banque teneuse du compte d'initier un transfert. Le commerçant peut ne pas recevoir de credential de carte, mais PISP et banques conservent les registres réglementés du payeur, bénéficiaire, consentement, appareil et transaction.<sup>[[25]](#references)</sup>

**Avantages :** aucun numéro de carte réutilisable au checkout ; authentification bancaire forte ; règlement compte-à-compte exact ; APIs de consentement/statut ; rapprochement clair.

**Inconvénients :** non anonyme pour banques/PISP ; le bénéficiaire voit souvent coordonnées ou référence du compte légal ; risques phishing/redirection ; protections variables selon juridiction ; les métadonnées de consentement ajoutent un observateur.

**Procédure :** (1) vérifier que le PISP est actuellement réglementé et que le domaine callback du commerçant est authentique ; (2) partir de la demande du commerçant ; (3) vérifier bénéficiaire, montant, référence et consentement demandé dans la banque ; (4) autoriser uniquement le paiement unique ; (5) vérifier indépendamment le statut final ; (6) révoquer tout consentement résiduel ; (7) conserver le reçu et rapprocher.

**Détection :** logs banque/PISP/commerçant et références du transfert fournissent une attribution solide. **OPSEC résistante à la capture :** garder authentification et récupération bancaires hors des appareils opérationnels/terrain ; l'appareil ne doit contenir qu'un droit au service payé. **Surveillance :** utiliser alertes de transaction/consentement et examiner nouveaux grants PISP, bénéficiaire modifié ou callbacks de statut hors de la session attendue.

## Wallet de plateforme, solde d'app store ou crédit in-app

**Mécanisme :** une plateforme facture l'utilisateur ou rachète le crédit du compte, puis fournit à une application un reçu signé ou une entitlement. Le développeur peut ne pas recevoir l'instrument de financement initial, tandis que la plateforme relie compte, appareil, financement, produit et utilisation.<sup>[[26]](#references)</sup>

**Avantages :** le commerçant/développeur ne reçoit pas le PAN principal ; contrôles de fraude/remboursement et familiaux/commerciaux ; petit solde prépayé limitant l'exposition ; reçus signés simplifiant la vérification.

**Inconvénients :** le compte de plateforme est un hub fort d'identité et de comportement ; appareil et géographie du store ; traces d'achat/utilisation du solde cadeau ; retrait limité ; contrôles de fraude pouvant geler les fonds ; pas une monnaie interplateforme.

**Procédure :** (1) utiliser un compte de plateforme géré par l'organisation lorsque la politique le permet ; (2) examiner financement, région, remboursement et règles de valeur transférable ; (3) n'ajouter que le budget approuvé ; (4) acheter un produit bénin via le store officiel ; (5) vérifier que l'application ne reçoit que les champs attendus du reçu ; (6) désactiver les achats récurrents ; (7) rapprocher et retirer le compte du hardware opérationnel.

**Détection :** reçus/notifications serveur de la plateforme, connexions compte/appareil et financement reconstruisent l'achat. **OPSEC résistante à la capture :** ne jamais connecter un field node à un compte store personnel ; fournir seulement une entitlement applicative limitée lorsque possible. **Surveillance :** activer alertes nouvel appareil/achat et examiner rejeu de reçu, changements familiaux/de compte ou restaurations inattendues.

## Crédit mutuel, clearing ou règlement net périodique

**Mécanisme :** les participants enregistrent leurs obligations dans un registre privé et ne règlent périodiquement que chaque position nette. Les événements de service individuels peuvent ne pas créer de paiements publics séparés, mais l'opérateur et les contreparties conservent une attribution détaillée.

**Avantages :** moins de transactions et de frais externes ; les observateurs publics ne voient que le règlement net ; adapté aux organisations récurrentes ; limites de crédit explicites contenant l'exposition.

**Inconvénients :** le registre centralisé est une preuve complète et une cible de fraude ; risque de contrepartie/défaut ; obligations juridiques, comptables et fiscales ; petit groupe ; les transferts nets inhabituels peuvent révéler les relations.

**Procédure :** (1) utiliser uniquement des organisations identifiées et consentantes avec approbation juridique/comptable ; (2) définir unité, limite de crédit, intervalle de règlement et litiges ; (3) enregistrer chaque obligation avec approbation immuable ; (4) faire calculer et approuver les positions nettes par des rôles financiers séparés ; (5) régler via un rail licite ordinaire ; (6) rapprocher les lignes individuelles du règlement ; (7) fermer les accès et conserver les registres selon la politique.

**Détection :** registre, factures, approbations et règlement bancaire/chaîne final fournissent la vérité terrain ; les analystes ne doivent pas déduire l'activité brute manquante du seul transfert net. **OPSEC résistante à la capture :** les appareils opérationnels peuvent soumettre des demandes limitées mais ne peuvent modifier les soldes ni autoriser le règlement. **Surveillance :** alerter sur dépassement de limite, écritures antidatées, changements d'administrateur, écart de rapprochement et règlement vers un nouveau bénéficiaire.

## Matrice d'exposition à la capture/compromission

Elle applique un test de saisie/perte à chaque famille. L'objectif est de limiter l'autorité de dépense et la divulgation d'identités sans lien tout en conservant une comptabilité licite — pas d'effacer les transactions ni de contrecarrer une enquête.

| Famille de techniques | Ce qu'un wallet/appareil/compte capturé peut révéler | Contrôle autorisé minimal |
|---|---|---|
| Espèces, mandat/COD, valeur physique bearer | reçus, numéros, notes, valeur restante et contacts physiques | transporter uniquement le montant approuvé ; comptabilité privée séparée ; signaler rapidement la perte ; aucun faux registre |
| Prépayé, cadeau, bon, crédits de service | solde, émetteur, activation, utilisation et tokens de session/compte | solde faible ; un objectif ; inscription véridique ; gel/révocation par l'émetteur si disponible |
| Carte virtuelle/tokenisée, wallet token, payment app | compte émetteur, token appareil, transactions, récupération et historique commerçant | verrouillage appareil ; alertes ; portée commerçant ; suspension distante ; aucun compte de récupération partagé |
| Banque compartimentée, achat délégué/red team | organisation, approbateurs, fournisseur, factures et projet | séparation des rôles ; sous-compte least privilege ; credentials financières jamais sur field nodes |
| Invoice, escrow, règlement groupé | contrepartie, objectif, approbation en attente, coordinateur ou litige | demande unique ; approbateur séparé ; session limitée ; registre central de référence |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/clés, libellés, adresses, graphe et configuration réseau | signature hardware/offline ; wallet chiffré ; limites passphrase ; vue watch-only terrain ; récupération documentée |
| Lightning/BOLT 12 | seed, channels, invoices, pairs/LSP et base de paiements | solde hot minimal ; backup chiffré ; identité node séparée ; fermeture/récupération documentée |
| Monero, Zcash, MWEB, applications ZK | spend/view keys, historique local, RPC et transactions frontières | rôles spend/view séparés ; hardware si disponible ; aucune session exchange sur le field node |
| Stablecoins, swaps, bridges, DEX | graphe transparent, approvals, état RPC/frontend et actifs de destination | révoquer allowances ; contrats vérifiés ; petit test ; rapprochement complet |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, cache émission/remboursement | petit solde ; backup chiffré selon protocole ; rembourser/réémettre ; jamais de credential de financement colocalisée |
| Paymaster, multisig/threshold | session key, un signataire, opérations en attente et politique sponsor | session key étroite ; quorum indépendant ; rotation ; appareil terrain hors seuil |
| Mixer/peel/structuring, nominees/fronts, abus remboursement/jeu | fournisseur incriminant, communications, graphe et participants | aucun usage opérationnel ; émulation synthétique/testnet uniquement |
| Monnaie communautaire/événementielle | inscription, solde local, contreparties et remboursement | valeur plafonnée ; gel/réémission émetteur ; registre privé auditable et consentement |
| Stealth address Bitcoin/EVM réutilisable | clés paiement/view/spend, métadonnées relationnelles, annonces et sorties dérivées | rôle réseau watch/view-only ; rôle spend offline/hardware ; aucune session de financement personnelle |
| Liquid confidential/state channels | seed, données blinding/dernier état, pairs, frontières et litiges | sauvegardes spend/view/state séparées ; faible solde hot ; moniteur de litige indépendant |
| Facturation opérateur/open banking/platform | compte téléphone/banque/store, consentement, reçu, appareil et source de financement | compte organisation ; MFA externe ; limite faible ; aucun compte personnel sur hardware terrain |
| Clearing de crédit mutuel | membres, obligations, limites, approbations et registre de règlement | demandes opérationnelles uniquement ; registre immuable séparé et double approbation financière |

## Surveillance d'une découverte ou compromission possible du paiement

Un refus de paiement, une revue de conformité ou la mise hors ligne d'un wallet ne prouvent pas l'existence d'une enquête. Surveiller uniquement les comptes, registres et infrastructures que l'organisation est autorisée à observer ; ne jamais sonder les fournisseurs ou contreparties pour vérifier s'ils coopèrent avec des enquêteurs.

| Techniques couvertes | Signaux de surveillance sûrs | Condition de gel/arrêt |
|---|---|---|
| Espèces, mandat/COD, prépayé/cadeau/bon, valeur bearer physique | écart inventaire/reçu, numéro dupliqué, remboursement/utilisation inattendu ou signalement de perte | instrument manquant, utilisation hors commande approuvée, reçu altéré ou rupture de garde |
| Carte virtuelle/tokenisée, payment app, banque/ACH/wire, open banking, facturation opérateur/plateforme | alertes émetteur/banque/plateforme, nouvel appareil/consentement/bénéficiaire, réutilisation token, récupération SIM/compte | autorisation inconnue, changement bénéficiaire, nouveau facteur de récupération, SIM swap ou frais récurrent |
| Compartiment compte/commerçant, achat contrôlé/délégué, crédits service | changement IdP/fournisseur de projet, rôle/token/budget, facture et consommation | token interprojets, admin inconnu, dépassement, facture incohérente ou destination non prise en charge |
| Invoice, escrow, règlement groupé, crédit mutuel | expiration demande, approbation/libération, intégrité registre, rapprochement et changement bénéficiaire | montant/payee modifié, registre antidaté, libération unilatérale ou batch non rapproché |
| Adresse Bitcoin/coin control, Silent Payments, BIP47/BIP351 | transactions watch-only, état notification/scan, réutilisation d'adresse, labels UTXO et consolidation | dépense inconnue, output destinataire réutilisé, échec gap/recovery ou fusion non approuvée |
| PayJoin/CoinJoin | inputs/outputs/frais de proposition, disponibilité coordinator, transaction finale | output substitué, frais excessifs, divulgation inattendue d'input ou changement de politique coordinator |
| Lightning/BOLT12/channels généraux | backup channel, usage invoice/offer, liquidité, pair/LSP et litige de chaîne | paiement invoice inconnu, changement clé pair, close obsolète ou échéance de litige proche |
| Monero/Zcash/MWEB/Liquid CT | événements view/watch, type pool/domaine/adresse, descriptor et transaction frontière | dépense non approuvée, downgrade transparent/non confidentiel, export de clé ou frontière inconnue |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contrat/annonce, RPC/bundler, sponsor gas, allowance/session key et action émetteur | mauvais contrat/champ public, approval/dépense inconnue, changement paymaster ou gel émetteur |
| Cashu/Fedimint/Taler/Privacy Pass | santé mint/federation/exchange, double dépense/rejeu, gateway et solde bearer | remboursement inconnu, changement clé/conditions mint, échec restore ou incohérence solde |
| Swaps/bridges/DEX | contrat vérifié, allowance, confirmations des deux chaînes, taux et destination | contrat/route incohérent, approval illimité, destination absente ou incident bridge |
| Multisig/threshold | changement ensemble/politique, proposition en attente, quorum et audit récupération | proposition/signataire inconnu, réduction seuil, activation récupération ou contournement |
| Mixer/peel/structuring, nominees/fronts, NFT/jeu/remboursement | uniquement vérité terrain du lab synthétique et résultat de détection | tout compte, personne ou valeur réelle entrant dans l'émulation : arrêt immédiat |

## Workflow de sélection et de vérification

1. Nommer la partie qui ne doit pas apprendre quel champ.
2. Identifier émetteur/mint/custodian, registre public, réseau/RPC, commerçant et observateurs physiques.
3. Vérifier support actuel, légalité, limites, garde, récupération et comportement de remboursement.
4. Effectuer un petit test de bout en bout avec des fonds licites.
5. Examiner reçu commerçant, relevé fournisseur, chaîne publique et logs wallet/node.
6. Tester sauvegarde/récupération et divulgation d'audit volontaire.
7. Conserver correctement, avec contrôle d'accès, les registres requis de source, propriété, fiscalité, sanctions et engagement.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observations on data collection by large payment platforms](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Protect your privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — A Simple Payjoin Proposal](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Building privacy applications with zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — How it works](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — The Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
