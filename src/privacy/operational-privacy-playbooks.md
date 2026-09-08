# Playbooks de confidentialité opérationnelle

Ces playbooks combinent les contrôles du reste de cette section. Ils constituent des points de départ, et non des garanties : mettez à jour le modèle de menace chaque fois qu'un nouvel observateur, compte, appareil, emplacement, paiement, fichier ou interlocuteur entre dans le workflow.

## Prévol universel

1. Écrivez l'objectif légitime et ce qui doit rester privé **vis-à-vis de qui**.
2. Recensez les identités, appareils, réseaux, comptes, moyens de paiement, interlocuteurs, emplacements physiques et données auxquels l'activité aura recours.
3. Identifiez l'observateur vraisemblable le plus puissant et la conséquence d'un échec.
4. Confirmez l'autorisation, le droit applicable, les conditions du fournisseur et la politique de l'organisation.
5. Décidez de ce qui doit rester attribuable en interne pour la sécurité, la réponse aux incidents, la comptabilité et l'audit.
6. Choisissez le cloisonnement fonctionnel le plus réduit ; établissez ses voies de récupération et d'arrêt avant utilisation.
7. Testez le cloisonnement contre un service contrôlé, notamment l'IP/DNS/IPv6, l'identité du navigateur, les métadonnées des documents, le relevé de paiement et les fuites de notifications.

Utilisez le modèle détaillé dans [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Base de confidentialité quotidienne

Objectif : réduire le tracking commercial, la prise de contrôle de comptes et l'exposition inutile sans chercher à devenir anonyme.

- Utilisez un OS maintenu avec chiffrement complet du disque, mises à jour automatiques, verrouillage de l'écran et secure boot lorsque disponibles.
- Configurez d'abord le gestionnaire de mots de passe, l'adresse e-mail de récupération et la MFA/résistance au phishing avec des security keys.
- Examinez les permissions des applications, l'historique de localisation, les identifiants publicitaires, la synchronisation cloud et les connexions de comptes tierces.
- Utilisez un navigateur grand public avec peu d'extensions, une protection contre le tracking, HTTPS et des profils séparés pour la navigation professionnelle/personnelle/à haut risque.
- Utilisez des alias private relay ou des adresses e-mail distinctes selon les relations ; n'utilisez pas de numéro de téléphone personnel lorsqu'il est simplement facultatif.
- Préférez la messagerie chiffrée de bout en bout pour le contenu, tout en gardant à l'esprit que les participants, les horaires, les groupes et les endpoints restent des métadonnées.
- Supprimez délibérément les métadonnées des fichiers et inspectez la copie exportée — et non l'original — avant publication.
- Utilisez des cartes virtuelles ou des tokens de wallet pour cloisonner les identifiants de paiement ; ne les qualifiez pas d'anonymes.
- Sauvegardez le matériel de récupération chiffré et testez la restauration.

## Publication pseudonyme

Objectif : empêcher les lecteurs occasionnels et les plateformes de relier trivialement une publication à une identité civile. Cela ne permet pas de résister à une enquête ciblée compétente.

1. Définissez si la plateforme, le fournisseur d'hébergement, les lecteurs, les contacts, le réseau local, le fournisseur de paiement ou une procédure judiciaire font partie du modèle de menace.
2. Créez un contexte dédié pour l'endpoint et le compte à partir d'une base propre. Désactivez la synchronisation personnelle du navigateur, les documents cloud, l'importation des contacts et les aperçus de notifications.
3. Créez le compte pseudonyme via le cloisonnement réseau choisi. Ne réutilisez pas les noms d'utilisateur, avatars, canaux de récupération, modèles rédactionnels ou identifiants personnels du fournisseur d'identité.
4. Utilisez Tor Browser lorsque l'absence de lien avec la destination est plus importante que la vitesse ; n'ajoutez pas d'extensions, ne le redimensionnez ou personnalisez pas excessivement, et n'ouvrez pas les documents téléchargés en ligne dans une session de bureau ordinaire.
5. Rédigez avec un processus qui n'intègre pas de noms de modèles personnels, auteurs de révision, chemins d'imprimante, GPS/EXIF, vignettes ou calques masqués. Exportez une copie et inspectez-la avec les outils de métadonnées appropriés.
6. Vérifiez que le contenu ne contient pas de faits permettant de vous identifier : dates uniques, détails sur le lieu de travail, météo/fuseau horaire local, reflets, audio d'arrière-plan, habitudes linguistiques et réutilisation de textes déjà publiés.
7. Utilisez un canal de réponse distinct. Traitez chaque contact direct, pièce jointe et lien comme une tentative potentielle de corrélation ou de phishing.
8. Si de l'argent est impliqué, utilisez la méthode légale qui n'expose que les données nécessaires. Partez du principe que la plateforme et l'intermédiaire réglementé peuvent connaître le bénéficiaire, même si les lecteurs ne le connaissent pas.
9. Publiez, puis inspectez le résultat public depuis un autre contexte propre. Notez ce que la plateforme a ajouté ou transformé.
10. Maintenez une cadence planifiée uniquement si elle ne crée pas d'empreinte comportementale stable ; retirez le cloisonnement au lieu de le réaffecter discrètement.

Pour le journalisme sérieux, l'activisme, les violences conjugales ou un risque étatique, obtenez une aide adaptée auprès d'une organisation expérimentée en sécurité numérique ; une checklist statique ne peut pas modéliser le droit local ni un adversaire actif.

## Engagement de red-team autorisé

Objectif : maintenir les identités personnelles et les réseaux domestiques des opérateurs hors de la télémétrie de la cible tout en préservant l'autorisation, le contrôle et la réponse aux incidents.

### Avant la fenêtre de démarrage

- Finalisez l'annexe d'infrastructure du ROE, les cibles/exclusions, les plages sources, les dates, l'arrêt d'urgence et les autorisations des tiers/fournisseurs.
- Attribuez un profil d'opérateur ou une VM dédiée, les secrets de l'engagement, le dépôt de preuves, le projet cloud, les domaines et le budget.
- Préférez un egress fourni par le client ou un bastion fixe contrôlé par l'organisation. Testez le comportement du tunnel intégral IPv4/IPv6/DNS et la politique fail-closed.
- Stockez la correspondance entre l'opérateur et l'infrastructure publique auprès du responsable de l'exercice ou du contact d'escrow convenu.
- Établissez des limites de débit, des listes d'autorisation de destinations et une approbation distincte pour les actions destructrices, wireless, physiques, de phishing ou de collecte d'identifiants.
- Utilisez un moyen de paiement contrôlé par l'organisation et consignez les approbations en interne.

### Pendant l'engagement

- Commencez depuis l'endpoint et le tunnel approuvés ; vérifiez l'egress observé avant le trafic d'évaluation.
- Gardez les comptes, appareils, numéros de téléphone, repositories, clés SSH/GPG et la synchronisation cloud personnels hors du cloisonnement.
- Consignez l'opérateur/job, le début/la fin, la source, la destination comprise dans le périmètre et les changements de configuration sans collecter de contenu client inutile.
- Arrêtez-vous en cas d'ambiguïté sur le périmètre, de systèmes tiers inattendus, de notification d'abus d'un fournisseur, d'impact sur la sécurité, de perte d'équipement ou de perte de contact avec le responsable.
- N'improvisez jamais avec le Wi-Fi d'un voisin, des identifiants volés, une SIM/un compte non approuvé ou du matériel dissimulé dans un lieu.

### Fin de l'engagement

- Arrêtez les jobs et le C2 ; récupérez les drop devices approuvés ; révoquez les tokens, identifiants et certificats.
- Rapprochez l'infrastructure, les domaines, les adresses sources, les dépenses, les données et les dossiers fournisseurs avec l'inventaire.
- Restituez/supprimez/conservez les données client conformément au contrat, préservez le minimum de preuves d'audit requis et faites vérifier l'arrêt par un second opérateur.

Voir [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) pour le guide complet de déploiement et de démantèlement.

## Achat ou don privé légal

Objectif : minimiser les informations communiquées au commerçant ou au public tout en respectant les obligations de l'émetteur, de comptabilité, fiscales et relatives aux sanctions.

1. Dressez la liste de ceux qui ne doivent pas savoir quoi : public, commerçant, intermédiaire de paiement, employeur/délégataire du compte familial, service de livraison ou observateur de blockchain.
2. Vérifiez les règles locales, le destinataire/l'interlocuteur, les conditions du fournisseur, les limites applicables aux espèces et les besoins de conservation des documents.
3. Choisissez le moyen de paiement :
- espèces pour les paiements locaux légaux acceptés, sans enregistrement dans un réseau de paiement ;
- carte virtuelle réglementée/spécifique au commerçant pour séparer les identifiants en ligne ;
- cryptocurrency uniquement après analyse de l'acquisition, du ledger, du backend du wallet, du réseau, de l'interlocuteur et des liens avec les dépenses ultérieures.
4. Utilisez les informations obligatoires véridiques et omettez uniquement les informations facultatives de fidélité/marketing. N'utilisez pas l'identité ou l'adresse d'une autre personne et ne fractionnez pas une transaction pour contourner un seuil.
5. Séparez le contexte du navigateur/compte marchand et évitez les connexions sociales, programmes de fidélité ou canaux de récupération personnels sans rapport.
6. Confirmez ce qui apparaît sur les relevés, reçus, notifications, expéditions et listes publiques de donateurs.
7. Stockez les justificatifs requis de reçu/fiscalité/autorisation sous forme chiffrée ; révoquez les identifiants de paiement jetables après le délai de remboursement.

Voir [Private Digital Payments](private-digital-payments.md) et [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Déplacements et réseaux non fiables

Objectif : protéger les données et les comptes sur des réseaux non administrés par l'utilisateur — et non dissimuler une activité non autorisée.

- Mettez à jour les appareils et téléchargez les identifiants/cartes nécessaires avant le déplacement.
- Minimisez les données stockées ; utilisez le chiffrement complet du disque, un déverrouillage robuste, une planification de récupération à distance et des procédures d'extinction adaptées aux risques frontaliers/physiques et aux conseils juridiques.
- Vérifiez le SSID/portail captif du lieu. Préférez un hotspot personnel lorsque cela est approprié, mais gardez à l'esprit les relevés de l'abonné mobile et de localisation.
- Utilisez un VPN approuvé intégral/forcé pour les données organisationnelles ; vérifiez que les appareils connectés en partage de connexion l'utilisent et testez le comportement IPv6/DNS.
- Utilisez un travel router pour l'isolation des clients et une politique reproductible, et non comme garantie d'anonymat.
- Traitez la recharge USB publique, les ordinateurs empruntés, les imprimantes publiques et les systèmes partagés des salles de réunion comme des menaces distinctes.
- Partez du principe que la présence physique, les identifiants radio, la connexion au portail, les caméras et les relevés de paiement/localisation peuvent corréler la visite.

Les détails de comparaison et de configuration se trouvent dans [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Réponse aux défaillances et aux expositions

Lorsqu'un cloisonnement fuit ou risque d'être lié :

1. Arrêtez l'activité si sa poursuite augmente le préjudice ; utilisez l'arrêt d'urgence de l'engagement lorsque cela s'applique.
2. Préservez les preuves nécessaires sans diffuser les données sensibles. Notez l'heure exacte, l'indicateur observé et les actifs concernés.
3. Informez le propriétaire/responsable ou le contact de sécurité approprié. Ne dissimulez pas un incident pour préserver un récit de confidentialité.
4. Révoquez les sessions, tokens, identifiants de paiement et accès à l'infrastructure ; faites tourner les secrets depuis un endpoint réputé propre.
5. Déterminez quelles arêtes ont permis la liaison : endpoint, compte de récupération, réseau, paiement, métadonnées, contenu, comportement, interlocuteur ou présence physique.
6. Considérez l'ensemble du cloisonnement concerné comme compromis. Ne changez pas simplement son nom d'utilisateur ou son IP de sortie.
7. Respectez les obligations de notification relatives aux fuites, au fournisseur, au client, aux finances et au droit.
8. Ne reconstruisez qu'après avoir modifié le processus à l'origine de la liaison ; documentez le contrôle et testez-le.

## Audit périodique

- [ ] Le modèle de menace et les hypothèses juridiques/fournisseur ont été réexaminés selon un calendrier daté.
- [ ] Les appareils, comptes, alias, domaines, chemins réseau et identifiants de paiement ont été inventoriés.
- [ ] Les voies de récupération ne traversent pas les cloisonnements de manière inattendue.
- [ ] Le tunnel intégral, le DNS, l'IPv6 et le comportement fail-closed ont été testés.
- [ ] Les fichiers et profils publics ont été vérifiés concernant les métadonnées et la réutilisation de contenu.
- [ ] Les nœuds/backends de wallet et les hypothèses relatives aux protocoles crypto restent à jour.
- [ ] Les logs et reçus sont minimaux, chiffrés, contrôlés par des permissions et conservés dans la durée prévue.
- [ ] Les anciens cloisonnements et l'infrastructure d'engagement ont été entièrement retirés.
