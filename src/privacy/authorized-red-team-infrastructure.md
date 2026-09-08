# Infrastructure de Red-Team autorisée

Pour les appareils durables sur site, utilisez la conception [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) et le runbook de suspected-discovery.

Pour un red team professionnel, l'objectif est une **attribution contrôlée**, et non l'immunité face à la responsabilité. La cible ne doit pas pouvoir voir trivialement l'IP du domicile ou les comptes personnels d'un opérateur, tandis que le responsable de l'engagement doit pouvoir identifier la source, arrêter l'opération, traiter les signalements d'abus, préserver les preuves et démontrer l'autorisation.

Cette page constitue la base de déploiement pour un engagement légal. Pour les techniques adverses qu'elle vise à émuler, notamment les ORBs compromis, les relais résidentiels, le fronting, les dead drops et les pivots wireless à proximité, commencez par [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) et [Government and APT Case Studies](government-and-apt-case-studies.md), puis reproduisez la télémétrie requise dans les [authorized labs](authorized-adversary-emulation-labs.md).

Le NIST définit les règles d'engagement (ROE) comme des contraintes préétablies qui accordent l'autorité nécessaire à des activités de test définies.<sup>[[1]](#references)</sup> L'architecture de confidentialité ne peut pas étendre cette autorité.

## Choisir un modèle d'egress

| Modèle | Meilleur usage | Ce que voit la cible | Ce que voit le fournisseur/l'observateur local | Responsabilité |
|---|---|---|---|---|
| VPN/jump host fourni par le client | La plupart des évaluations | Plage d'adresses du client | Identité du client et accès de l'opérateur | La plus forte |
| Bastion de l'organisation de red team | Egress contrôlé et reproductible | Plage de l'organisation | Fournisseur d'hébergement et organisation | Forte |
| VPS spécifique à l'engagement | Isoler les clients/campagnes | Adresse du VPS | Compte hôte, facturation, logs du control plane et des accès | Forte si documentée |
| VPN commercial approuvé | Recherche/scanning autorisé par le fournisseur et les ROE | Egress VPN partagé/dédié | Compte VPN et connexion source | Moyenne |
| Tor Browser | Recherche Web nécessitant la non-corrélation avec la destination | Nœud de sortie Tor | Le réseau local voit Tor/le bridge ; la destination voit Tor | Peu adapté à l'attribution d'une source allowlistée |
| Drop on-site approuvé par le client | Simulation interne | Appareil/adresse sur site | Réseau du site et fournisseur du tunnel distant | Forte si inventorié |
| Wi-Fi invité légal | Usage administratif/de recherche à faible risque | IP publique du lieu ou egress du tunnel | Lieu, FAI, VPN/Tor | Faible et observable physiquement |

Pour la plupart des opérations, un egress fixe fourni par le client ou contrôlé par l'organisation est plus sûr et plus rapide que les services d'anonymat grand public. Il permet également aux défenseurs d'autoriser, de surveiller ou de **ne pas autoriser** délibérément des plages sources connues, conformément à la conception de l'exercice.

## Annexe d'infrastructure ROE

À consigner avant le déploiement :

- les entités légales accordant et recevant l'autorisation ;
- les cibles exactes et les exclusions explicites ;
- les heures de début/fin, le fuseau horaire et les techniques autorisées ;
- les IP sources, noms des systèmes autonomes/fournisseurs, domaines, redirectors, infrastructure mail et identifiants des appareils sur site ;
- si le phishing, le C2, la capture d'identifiants, les tests wireless, l'accès physique, le denial-of-service, la persistence ou les services tiers sont autorisés ;
- les approbations du client et du fournisseur, y compris toute référence de pré-notification ;
- la phrase d'arrêt d'urgence, les contacts d'abus du client et du fournisseur disponibles 24 h/24 et 7 j/7, ainsi que le délai de réponse maximal ;
- les catégories de données pouvant être collectées, le chiffrement, l'accès, la conservation et la suppression ;
- les exigences relatives aux preuves et aux logs, notamment l'identité de la personne détenant la correspondance entre l'infrastructure publique et l'opérateur ;
- le teardown, l'expiration des domaines, la révocation des certificats, la rotation des credentials, la récupération des appareils et l'attestation finale.

Vérifiez que les IP publiques et les domaines sont effectivement contrôlés par la partie autorisatrice ou explicitement inclus dans le périmètre. Le NIST SP 800-115 recommande de confirmer que les adresses publiques des cibles relèvent de la responsabilité de l'organisation avant les tests.<sup>[[2]](#references)</sup>

## Egress rapide spécifique à l'engagement

### Workflow de déploiement

1. **Créez un compte/projet d'engagement** au sein de l'organisation de red team, avec des informations exactes de facturation et de propriété. Séparez les rôles, les clés API, les budgets et les logs d'audit de ceux des autres clients.
2. **Vérifiez la politique de chaque fournisseur.** Les fournisseurs de Cloud, VPS, CDN, domaines, messagerie et VPN ont des règles différentes. AWS, par exemple, autorise certaines évaluations, mais exige une approbation préalable pour le C2 hébergé/les simulations covert et interdit les activités listées.<sup>[[3]](#references)</sup>
3. **Allouez des adresses d'egress fixes** et inscrivez-les dans l'annexe ROE. Évitez la rotation rapide des IP/ressources ; elle complique la réponse aux incidents et peut enfreindre la politique du fournisseur.
4. **Renforcez la gestion :** SSH uniquement par clés ou plan de gestion identity-aware, MFA résistant au phishing, réseau d'administration séparé, moindre privilège, images corrigées, aucun port d'administration public et stockage chiffré des secrets.
5. **Créez un chemin full-tunnel** depuis l'endpoint de l'opérateur vers le bastion. Acheminez délibérément le DNS et l'IPv6, et imposez un deny du firewall lorsque le tunnel est interrompu.
6. **Restreignez les destinations et ports sortants** au périmètre autorisé lorsque cela est possible. Limitez le débit des scanners et placez les techniques irréversibles/destructrices derrière une étape d'approbation distincte.
7. **Journalisez pour la responsabilité, pas pour la surveillance :** authentification de l'opérateur, modifications de configuration, démarrage/arrêt, adresse source, destination dans le périmètre et identifiants des outils/jobs. Évitez la capture de payloads/credentials sauf si elle est requise par l'exercice et protégée par le plan de données.
8. **Validez via un endpoint contrôlé** appartenant à l'organisation : IPv4/IPv6 observées, chemin DNS, reverse DNS, horloge, comportement des ports sources, panne/reconnexion et contact d'abus du fournisseur.
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
Un VPS est pseudonyme uniquement vis-à-vis de la destination. L'hébergeur peut conserver des enregistrements de contact, de facturation, d'identité, d'adresse IP source, d'API, d'appareil, de localisation et d'utilisation ; l'historique AWS CloudTrail visible par le client peut à lui seul révéler l'activité de gestion.<sup>[[4]](#references)</sup> Payer l'hébergement avec des cryptomonnaies n'efface pas ces enregistrements.

## Domaines et certificats

- Utiliser un compte de registrar spécifique à l'engagement, détenu par l'organisation.
- Activer le registrar lock, DNSSEC lorsque pris en charge, la MFA/les security keys, et le renouvellement automatique uniquement pour la période approuvée.
- Utiliser la protection de la vie privée lors de l'enregistrement pour réduire l'exposition publique, et non pour falsifier les informations du registrant. La politique de l'ICANN exige que les registrars collectent les données d'enregistrement, même lorsque leur affichage public est masqué ou relayé par un proxy.<sup>[[5]](#references)</sup>
- Éviter les noms qui usurpent illégalement l'identité de parties non liées. Les domaines de typosquatting/lookalike nécessitent l'approbation explicite du client et du fournisseur.
- Inventorier le DNS, les certificats, la configuration du CDN/redirector et les analytics tiers susceptibles de leak des informations sur les opérateurs ou les clients.
- Lors du teardown, supprimer les enregistrements, révoquer les certificats/tokens, préserver les éléments convenus et décider si le domaine doit être conservé à des fins défensives.

## Nœuds drop autorisés sur site

Un Raspberry Pi ou un appareil similaire est acceptable uniquement lorsque le propriétaire du site/réseau et le client autorisent explicitement son emplacement exact et son comportement. Plan sûr :

1. Consigner le numéro de série de l'appareil, la politique relative à l'adresse MAC/MAC privée, une photo, le propriétaire, l'emplacement exact approuvé, la source d'alimentation, la date limite de récupération et le contact en cas de manipulation.
2. Utiliser une image signée minimale, des secrets chiffrés, un stockage en lecture seule ou récupérable, un pare-feu hôte, les mises à jour de sécurité automatiques lorsque cela est pratique, et aucun identifiant par défaut.
3. Configurer une communication sortante uniquement vers un endpoint d'engagement nommé. Ne pas exposer de listener non authentifié.
4. Autoriser explicitement les destinations et les capacités. La capture de paquets, la collecte d'identifiants, l'usurpation sans fil et le mouvement latéral doivent chacun être explicitement autorisés.
5. Utiliser une authentification mutuelle, des clés à courte durée de vie, un kill à distance, un reporting d'état et des limites de bande passante.
6. S'assurer qu'une perte ou un vol ne révèle ni identifiants réutilisables ni données client.
7. Planifier la récupération et l'effacement sécurisé/la mise hors service ; obtenir un justificatif de récupération signé.

Ne pas dissimuler de matériel dans un café, un hôtel, un bureau partagé, la propriété d'un voisin ou un lieu public sans l'autorisation écrite du propriétaire/de l'opérateur.

## Réseaux invités et travel routers

Si un scénario autorisé nécessite un accès invité :

- vérifier le SSID et la politique d'utilisation acceptable auprès du lieu/client ;
- utiliser un travel router appartenant à l'organisation ou un bridge device à faible niveau de confiance pour isoler le poste de travail privilégié ;
- effectuer les captive portals en dehors du poste de travail privilégié ;
- démarrer le tunnel approuvé avant le trafic d'assessment ;
- confirmer que les appareils connectés en tethering utilisent effectivement ce tunnel ;
- supposer que le lieu peut corréler l'association radio, le portail, la présence physique et les enregistrements de caméra/paiement ;
- ne jamais contourner le contrôle d'accès, cloner un autre appareil, attaquer le Wi-Fi ou laisser du matériel sur place.

## Séparation opérationnelle

- Un seul client/engagement par compartiment d'endpoint, cloud project, ensemble de secrets, groupe de domaines, ensemble de redirectors et espace de stockage des éléments de preuve.
- Aucun e-mail personnel, synchronisation de navigateur, numéro de téléphone, cloud drive, clé SSH/GPG, identité de signature de code ou remboursement de paiement en dehors des systèmes approuvés de l'organisation.
- Ne pas réutiliser une configuration de payload distinctive, des chemins de callback, des certificats ou des dépôts publics entre clients, sauf si la conception de l'exercice accepte le fingerprinting.
- Attribuer à l'infrastructure une date d'arrêt et une alerte budgétaire. Les systèmes orphelins deviennent un risque pour le client comme pour Internet.
- Préserver suffisamment d'attribution interne pour enquêter sur les incidents. « Aucun log » est généralement incompatible avec les obligations professionnelles en matière de preuve et de sécurité.

## Aveugle pour les défenseurs, attribuable au contrôleur

Lorsque l'objectif de l'exercice est de mesurer la détection plutôt que de tester une allowlist, le SOC cible peut rester aveugle sans rendre l'opération non traçable :

1. Le contrôleur de l'exercice approuve chaque source publique, domaine, certificat et appareil sur site, mais dissimule la liste au SOC.
2. Le contrôleur stocke la correspondance source-engagement/opérateur dans un vault chiffré séparé, avec un accès d'urgence à deux personnes.
3. Chaque tâche d'opérateur reçoit un manifeste signé contenant le périmètre, la fenêtre temporelle, le compartiment source et un identifiant de tâche irréversible. La cible n'a pas besoin de voir le manifeste pendant le fonctionnement normal.
4. Les événements d'audit du bastion sont chaînés ou envoyés en ajout uniquement vers le stockage du contrôleur afin qu'un opérateur ne puisse pas réécrire silencieusement l'attribution après un incident.
5. Un contact provider-abuse disponible 24 h/24 et 7 j/7 détient une phrase/référence de vérification confirmant l'autorisation sans divulguer publiquement le client.
6. Chaque chemin implémente un canal d'arrêt out-of-band qui ne dépend ni du C2 d'assessment, ni du réseau cible, ni du compte d'un seul opérateur.
7. Avant les tests en conditions réelles, envoyer des canaries bénins depuis chaque source. Confirmer que le contrôleur peut les identifier et les arrêter dans le délai de réponse du ROE.
8. Après l'exercice, comparer la télémétrie du SOC avec le registre du contrôleur, divulguer la liste des sources et expliquer les détections manquées ou incorrectes.

Ne pas ajouter d'anti-forensics, de destruction de logs, de relays compromis ou de fausses identités d'abonné. Ces pratiques compromettent les tests traçables au lieu de les améliorer.

## Checklist de teardown

- [ ] Le contrôleur de l'exercice confirme l'arrêt.
- [ ] Le C2, les tunnels, les redirectors, la messagerie, le VPN et les tâches planifiées sont désactivés.
- [ ] Les appareils sur site sont récupérés physiquement et rapprochés de l'inventaire.
- [ ] Les tokens, clés API, clés SSH, certificats et identifiants capturés sont révoqués/renouvelés.
- [ ] Le DNS et les ressources cloud sont supprimés ou transférés pour une conservation défensive.
- [ ] Les données client sont restituées, conservées ou détruites conformément au contrat.
- [ ] Les enregistrements financiers, d'audit et d'autorisation requis restent chiffrés et soumis à un contrôle d'accès.
- [ ] Les dossiers provider-abuse sont clôturés et le client reçoit les indicateurs de source finaux.
- [ ] Un second opérateur vérifie qu'aucune infrastructure ne reste active.

## References

- [1] [NIST CSRC — Règles d'engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Guide technique pour les tests et l'évaluation de la sécurité de l'information](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Politique de support client pour les tests d'intrusion](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Avis de confidentialité](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Politique relative aux données d'enregistrement](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
