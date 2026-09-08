# Infrastructure de Red Team autorisée

{{#include ../banners/hacktricks-training.md}}

Pour les appareils durables déployés sur site, utilisez la conception et le runbook de découverte suspecte [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Pour une red team professionnelle, l'objectif est une **attribution contrôlée**, et non l'immunité face à la responsabilité. La cible ne doit pas pouvoir voir trivialement l'IP personnelle ou les comptes personnels d'un opérateur, tandis que le responsable de l'engagement doit pouvoir identifier la source, arrêter l'opération, gérer les signalements d'abus, préserver les preuves et démontrer l'autorisation.

Cette page constitue la base de déploiement pour un engagement légal. Pour les techniques adverses qu'elle vise à émuler — notamment les ORB compromis, les relais résidentiels, le fronting, les dead drops et les pivots wireless à proximité — commencez par [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) et [Government and APT Case Studies](government-and-apt-case-studies.md), puis reproduisez la télémétrie requise dans les [authorized labs](authorized-adversary-emulation-labs.md).

Le NIST définit les rules of engagement (ROE) comme des contraintes préétablies qui accordent l'autorité nécessaire à des activités de test définies.<sup>[[1]](#references)</sup> L'architecture de confidentialité ne peut pas étendre cette autorité.

## Choisir un modèle d'egress

| Modèle | Meilleur usage | Ce que voit la cible | Ce que voit le provider/l'observateur local | Responsabilité |
|---|---|---|---|---|
| VPN/jump host fourni par le client | La plupart des évaluations | Plage d'adresses du client | Identité du client et accès de l'opérateur | La plus forte |
| Bastion de l'organisation de red team | Egress contrôlé et reproductible | Plage de l'organisation | Hosting provider et organisation | Forte |
| VPS spécifique à l'engagement | Isoler les clients/campagnes | Adresse du VPS | Compte d'hébergement, facturation, journaux du control plane et des accès | Forte si documentée |
| VPN commercial approuvé | Recherche/scanning autorisés par le provider et les ROE | Egress VPN partagé/dédié | Compte VPN et connexion source | Moyenne |
| Tor Browser | Recherche Web nécessitant de dissocier la destination | Nœud de sortie Tor | Le réseau local voit Tor/bridge ; la destination voit Tor | Peu adapté à l'attribution d'une source allowlistée |
| Drop on-site approuvé par le client | Simulation interne | Appareil/adresse on-site | Réseau du site et provider du tunnel distant | Forte s'il est inventorié |
| Wi-Fi invité légal | Usage administratif/recherche à faible risque | IP publique du lieu ou egress du tunnel | Lieu, ISP, VPN/Tor | Faible et physiquement observable |

Pour la plupart des opérations, un egress fixe fourni par le client ou contrôlé par l'organisation est plus sûr et plus rapide que les services d'anonymat grand public. Il permet également aux défenseurs d'allowlister, de surveiller ou de **ne pas allowlister délibérément** les plages sources connues, conformément à la conception de l'exercice.

## Annexe d'infrastructure des ROE

À consigner avant le déploiement :

- entités légales accordant et recevant l'autorisation ;
- cibles exactes et exclusions explicites ;
- heures de début et de fin, fuseau horaire et techniques autorisées ;
- IP sources, noms des autonomous systems/providers, domaines, redirectors, infrastructure mail et identifiants des appareils on-site ;
- autorisation ou non du phishing, du C2, de la capture d'identifiants, des tests wireless, de l'accès physique, du denial-of-service, de la persistence ou des services tiers ;
- approbations du client et du provider, y compris toute référence de pré-notification ;
- phrase d'arrêt d'urgence, contacts abuse du client et du provider disponibles 24/7, et délai de réponse maximal ;
- classes de données pouvant être collectées, chiffrement, accès, conservation et suppression ;
- exigences relatives aux preuves et aux logs, notamment l'identité de la personne détenant la correspondance entre l'infrastructure publique et l'opérateur ;
- teardown, expiration des domaines, révocation des certificats, rotation des credentials, récupération des appareils et attestation finale.

Vérifiez que les IP publiques et les domaines sont effectivement contrôlés par la partie autorisatrice ou explicitement inclus dans le périmètre. Le NIST SP 800-115 recommande de confirmer que les adresses publiques des cibles relèvent bien de l'organisation avant les tests.<sup>[[2]](#references)</sup>

## Egress rapide spécifique à l'engagement

### Workflow de build

1. **Créez un compte/projet d'engagement** au sein de l'organisation de red team, en utilisant des informations exactes de facturation et de propriété. Séparez les rôles, les clés API, les budgets et les audit logs de ceux des autres clients.
2. **Vérifiez la policy de chaque provider.** Les providers cloud, VPS, CDN, de domaines, d'email et de VPN appliquent des règles différentes. AWS, par exemple, autorise certaines évaluations, mais exige une approbation préalable pour les simulations C2/covert hébergées et interdit les activités listées.<sup>[[3]](#references)</sup>
3. **Allouez des adresses d'egress fixes** et inscrivez-les dans l'annexe des ROE. Évitez la rotation rapide des IP/ressources ; elle complique la réponse à incident et peut enfreindre la policy du provider.
4. **Renforcez la gestion :** SSH avec clés uniquement ou management plane identity-aware, MFA résistant au phishing, réseau d'administration séparé, moindre privilège, images patchées, aucun port d'administration public et stockage chiffré des secrets.
5. **Créez un chemin full-tunnel** depuis l'endpoint de l'opérateur jusqu'au bastion. Acheminez le DNS et l'IPv6 de manière explicite et imposez un deny du firewall lorsque le tunnel est indisponible.
6. **Limitez les destinations et ports sortants** au périmètre autorisé lorsque cela est possible. Limitez le débit des scanners et placez les techniques irréversibles/destructives derrière une gate d'approbation distincte.
7. **Journalisez pour assurer la responsabilité, pas pour surveiller :** authentification de l'opérateur, modifications de configuration, démarrage/arrêt, adresse source, destination dans le périmètre et identifiants des outils/jobs. Évitez la capture de payloads/credentials sauf si elle est requise par l'exercice et protégée par le plan de données.
8. **Validez via un endpoint contrôlé** appartenant à l'organisation : IPv4/IPv6 observés, chemin DNS, reverse DNS, horloge, comportement des ports sources, échec/reconnexion et contact abuse du provider.
9. **Partagez la cartographie d'attribution de manière sécurisée** avec le contrôleur de l'exercice ou un contact d'escrow convenu. Ne la publiez pas auprès de l'équipe cible si la détection en aveugle fait partie du test.

### Architecture
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
Un VPS est pseudonyme uniquement vis-à-vis de la destination. L'hébergeur peut conserver des enregistrements de contact, de facturation, d'identité, d'adresse IP source, d'API, d'appareil, de localisation et d'utilisation ; l'historique AWS CloudTrail visible par le client peut à lui seul exposer l'activité de gestion.<sup>[[4]](#references)</sup> Payer l'hébergement avec des cryptomonnaies n'efface pas ces enregistrements.

## Domaines et certificats

- Utilisez un compte de registrar dédié à l'engagement et détenu par l'organisation.
- Activez le verrouillage du registrar, DNSSEC lorsqu'il est pris en charge, la MFA/les security keys, et le renouvellement automatique uniquement pour la période approuvée.
- Utilisez la confidentialité de l'enregistrement pour réduire l'exposition publique, et non pour présenter des informations inexactes sur le registrant. La politique de l'ICANN exige que les registrars collectent les données d'enregistrement, même lorsque leur affichage public est masqué ou proxyfié.<sup>[[5]](#references)</sup>
- Évitez les noms qui usurpent illégalement l'identité de parties non liées. Les domaines de typosquatting/lookalike nécessitent l'approbation explicite du client et du fournisseur.
- Inventoriez le DNS, les certificats, la configuration du CDN/redirector et les analytics tiers qui pourraient leak des informations sur les opérateurs ou les clients.
- Lors du teardown, supprimez les enregistrements, révoquez les certificats/tokens, conservez les éléments de preuve convenus et décidez si le domaine doit être conservé à des fins défensives.

## Nœuds drop autorisés sur site

Un Raspberry Pi ou un appliance similaire n'est acceptable que lorsque le propriétaire du bien/réseau et le client autorisent explicitement son emplacement exact et son comportement. Un plan sûr :

1. Enregistrez le numéro de série de l'appareil, l'adresse MAC/la politique relative aux MAC privées, une photo, le propriétaire, l'emplacement exact approuvé, la source d'alimentation, la date limite de récupération et le contact en cas d'altération.
2. Utilisez une image signée minimale, des secrets chiffrés, un stockage en lecture seule ou récupérable, un firewall hôte, les mises à jour de sécurité automatiques lorsque cela est possible, et aucun identifiant par défaut.
3. Configurez une communication sortante uniquement vers un endpoint d'engagement nommé. N'exposez pas de listener non authentifié.
4. Mettez en allowlist les destinations et les fonctionnalités. La capture de paquets, la collecte d'identifiants, l'usurpation wireless et le mouvement latéral doivent chacun être explicitement autorisés.
5. Utilisez une authentification mutuelle, des clés à courte durée de vie, un kill à distance, un reporting d'état et des limites de bande passante.
6. Assurez-vous qu'une perte ou un vol ne révèle pas d'identifiants réutilisables ni de données client.
7. Planifiez la récupération et l'effacement sécurisé/la mise hors service ; obtenez un rapport de récupération signé.

Ne dissimulez pas de matériel dans un café, un hôtel, un bureau partagé, la propriété d'un voisin ou un lieu public sans l'autorisation écrite du propriétaire/de l'opérateur.

## Réseaux invités et travel routers

Si un scénario autorisé exige un accès invité :

- vérifiez le SSID et la politique d'utilisation acceptable auprès du lieu/du client ;
- utilisez un travel router détenu par l'organisation ou un bridge device à faible niveau de confiance pour isoler le poste de travail privilégié ;
- effectuez les captive portals en dehors du poste de travail privilégié ;
- démarrez le tunnel approuvé avant le trafic d'assessment ;
- confirmez que les appareils tethered utilisent réellement ce tunnel ;
- partez du principe que le lieu peut corréler l'association radio, le portail, la présence physique et les enregistrements de caméra/paiement ;
- ne contournez jamais les contrôles d'accès, ne clonez pas un autre appareil, n'attaquez pas le Wi-Fi et ne laissez pas de matériel sur place.

## Séparation opérationnelle

- Un seul client/engagement par compartiment d'endpoint, projet cloud, ensemble de secrets, groupe de domaines, ensemble de redirectors et dépôt d'éléments de preuve.
- Aucun e-mail personnel, aucune synchronisation de navigateur, aucun numéro de téléphone, cloud drive, clé SSH/GPG, identité de signature de code ou remboursement de paiement en dehors des systèmes approuvés de l'organisation.
- Ne réutilisez pas une configuration de payload distinctive, des chemins de callback, des certificats ou des dépôts publics entre clients, sauf si la conception de l'exercice accepte le fingerprinting.
- Donnez à l'infrastructure une date d'arrêt et une alerte budgétaire. Les systèmes orphelins deviennent un risque pour le client comme pour Internet.
- Conservez suffisamment d'attribution interne pour enquêter sur les accidents. « Aucun log » est généralement incompatible avec les obligations professionnelles en matière de preuves et de sécurité.

## Invisible pour les défenseurs, attribuable au contrôleur

Lorsque l'objectif de l'exercice est de mesurer la détection plutôt que de tester une allowlist, le SOC cible peut rester aveugle sans rendre l'opération non responsable :

1. Le contrôleur de l'exercice approuve chaque source publique, domaine, certificat et appareil sur site, mais en dissimule la liste au SOC.
2. Le contrôleur conserve la correspondance source-engagement/opérateur dans un coffre chiffré séparé, avec un accès d'urgence à deux personnes.
3. Chaque tâche d'opérateur reçoit un manifest signé contenant le périmètre, la fenêtre temporelle, le compartiment source et un identifiant de tâche irréversible. La cible n'a pas besoin de voir le manifest pendant le fonctionnement normal.
4. Les événements d'audit du bastion sont chaînés ou envoyés en append-only vers le stockage du contrôleur afin qu'un opérateur ne puisse pas réécrire silencieusement l'attribution après un incident.
5. Un contact abuse du fournisseur disponible 24 h/24 et 7 j/7 détient une phrase/référence de vérification confirmant l'autorisation sans divulguer publiquement le client.
6. Chaque chemin implémente un canal d'arrêt out-of-band qui ne dépend ni du C2 d'assessment, ni du réseau cible, ni du compte d'un seul opérateur.
7. Avant les tests en production, envoyez des canaris inoffensifs depuis chaque source. Confirmez que le contrôleur peut les identifier et les arrêter dans le délai de réponse défini par les ROE.
8. Après l'exercice, comparez la télémétrie du SOC avec le registre du contrôleur, divulguez la liste des sources et expliquez les détections manquées/incorrectes.

N'ajoutez pas d'anti-forensics, de destruction de logs, de relais compromis ou de fausses identités d'abonné. Ces pratiques rendent les tests responsables impossibles au lieu de les améliorer.

## Checklist de teardown

- [ ] Le contrôleur de l'exercice confirme l'arrêt.
- [ ] Le C2, les tunnels, les redirectors, la messagerie, le VPN et les tâches planifiées sont désactivés.
- [ ] Les appareils sur site sont physiquement récupérés et rapprochés de l'inventaire.
- [ ] Les tokens, clés API, clés SSH, certificats et identifiants capturés sont révoqués/renouvelés.
- [ ] Le DNS et les ressources cloud sont supprimés ou transférés pour une conservation défensive.
- [ ] Les données client sont rendues, conservées ou détruites conformément au contrat.
- [ ] Les enregistrements financiers, d'audit et d'autorisation requis restent chiffrés et soumis à un contrôle d'accès.
- [ ] Les dossiers abuse du fournisseur sont clôturés et le client reçoit les indicateurs finaux des sources.
- [ ] Un second opérateur vérifie qu'aucune infrastructure ne reste active.

## References

- [1] [NIST CSRC — Règles d'engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Guide technique des tests et évaluations de la sécurité de l'information](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Politique de support client pour le Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Avis de confidentialité](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Politique relative aux données d'enregistrement](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
