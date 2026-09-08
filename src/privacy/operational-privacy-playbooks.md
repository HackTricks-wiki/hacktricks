# Playbooks de confidentialité opérationnelle

{{#include ../banners/hacktricks-training.md}}

Ces playbooks combinent les contrôles du reste de cette section. Ils constituent des points de départ, pas des garanties : mettez à jour le modèle de menace chaque fois qu'un nouvel observateur, compte, appareil, emplacement, paiement, fichier ou interlocuteur entre dans le workflow.

## Préparation universelle

1. Écrivez l'objectif légitime et ce qui doit rester privé **vis-à-vis de qui**.
2. Recensez les identités, appareils, réseaux, comptes, moyens de paiement, interlocuteurs, emplacements physiques et données que l'activité touchera.
3. Identifiez l'observateur probablement le plus puissant et la conséquence d'un échec.
4. Confirmez l'autorisation, le droit applicable, les conditions du fournisseur et la politique de l'organisation.
5. Décidez de ce qui doit rester attribuable en interne pour la sécurité, la réponse aux incidents, la comptabilité et l'audit.
6. Choisissez le cloisonnement fonctionnel le plus réduit ; établissez ses procédures de récupération et d'arrêt avant de l'utiliser.
7. Testez le cloisonnement avec un service contrôlé, notamment les fuites d'IP/DNS/IPv6, l'identité du navigateur, les métadonnées des documents, le relevé de paiement et les notifications.

Utilisez le modèle détaillé dans [Modélisation des menaces et séparation des identités](threat-modeling-and-identity-separation.md).

## Base de confidentialité quotidienne

Objectif : réduire le tracking commercial, la prise de contrôle de comptes et l'exposition inutile sans chercher à devenir anonyme.

- Utilisez un OS maintenu avec chiffrement complet du disque, mises à jour automatiques, verrouillage de l'écran et secure boot lorsque disponibles.
- Configurez d'abord le gestionnaire de mots de passe, l'e-mail de récupération et le MFA résistant au phishing/les security keys.
- Examinez les autorisations des applications, l'historique de localisation, les identifiants publicitaires, la synchronisation cloud et les connexions de comptes tierces.
- Utilisez un navigateur courant avec peu d'extensions, une protection contre le tracking, HTTPS et des profils séparés pour la navigation professionnelle/personnelle/à haut risque.
- Utilisez des alias private relay ou des adresses e-mail distinctes selon les relations ; n'utilisez pas de numéro de téléphone personnel lorsqu'il est simplement facultatif.
- Préférez la messagerie chiffrée de bout en bout pour le contenu, en gardant à l'esprit que les participants, les horaires, les groupes et les endpoints restent des métadonnées.
- Supprimez délibérément les métadonnées des fichiers et inspectez la copie exportée — et non l'original — avant publication.
- Utilisez des cartes virtuelles ou des tokens de wallet pour cloisonner les identifiants de paiement ; ne les qualifiez pas d'anonymes.
- Sauvegardez le matériel de récupération chiffré et testez la restauration.

## Publication pseudonyme

Objectif : empêcher les lecteurs occasionnels et les plateformes de relier trivialement une publication à une identité civile. Cela ne résiste pas à une enquête ciblée compétente.

1. Définissez si la plateforme, l'hébergeur, les lecteurs, les contacts, le réseau local, le prestataire de paiement ou une procédure judiciaire font partie du modèle de menace.
2. Créez un contexte d'endpoint/de compte dédié à partir d'une base propre. Désactivez la synchronisation personnelle du navigateur, les documents cloud, l'importation de contacts et les aperçus de notifications.
3. Créez le compte pseudonyme via le cloisonnement réseau choisi. Ne réutilisez pas les noms d'utilisateur, avatars, canaux de récupération, modèles rédactionnels ou connexions personnelles à un identity provider.
4. Utilisez Tor Browser lorsque l'absence de lien avec la destination est plus importante que la vitesse ; n'ajoutez pas d'extensions, ne le redimensionnez/personnalisez pas excessivement et n'ouvrez pas de documents téléchargés en ligne dans une session desktop ordinaire.
5. Rédigez avec un processus qui n'intègre pas de noms de modèles personnels, auteurs de révisions, chemins d'imprimante, GPS/EXIF, miniatures ou calques cachés. Exportez une copie et inspectez-la avec les outils de métadonnées appropriés.
6. Vérifiez le contenu pour détecter les faits auto-identifiants : dates uniques, détails professionnels, météo/fuseau horaire local, reflets, audio d'arrière-plan, habitudes linguistiques et réutilisation de texte publié précédemment.
7. Utilisez un canal de réponse séparé. Traitez chaque contact direct, pièce jointe et lien comme une tentative potentielle de corrélation ou de phishing.
8. Si de l'argent est impliqué, utilisez la méthode légale qui n'expose que les données nécessaires. Supposez que la plateforme et l'intermédiaire réglementé peuvent connaître le bénéficiaire, même si les lecteurs ne le connaissent pas.
9. Publiez, puis inspectez le résultat public depuis un autre contexte propre. Notez ce que la plateforme a ajouté ou transformé.
10. Maintenez une cadence planifiée uniquement si elle ne crée pas d'empreinte comportementale stable ; retirez le cloisonnement au lieu de le réutiliser discrètement.

Pour le journalisme sérieux, l'activisme, les violences conjugales ou un risque étatique, demandez une aide adaptée à une organisation expérimentée en sécurité numérique ; une checklist statique ne peut pas modéliser le droit local ou un adversaire actif.

## Engagement red team autorisé

Objectif : maintenir les identités personnelles et les réseaux domestiques des opérateurs hors de la télémétrie de la cible tout en préservant l'autorisation, le contrôle et la réponse aux incidents.

### Avant la fenêtre de démarrage

- Finalisez l'annexe infrastructure du ROE, les cibles/exclusions, les plages sources, les dates, l'arrêt d'urgence et les autorisations des tiers/fournisseurs.
- Attribuez un profil opérateur ou une VM dédiée, les secrets de l'engagement, le stockage des preuves, le projet cloud, les domaines et le budget.
- Préférez un egress fourni par le client ou un bastion fixe contrôlé par l'organisation. Testez le comportement IPv4/IPv6/DNS en full-tunnel et la politique fail-closed.
- Stockez la correspondance entre l'opérateur et l'infrastructure publique auprès du responsable de l'exercice ou du contact d'escrow convenu.
- Établissez des limites de débit, des listes d'autorisation de destinations et une approbation séparée pour les actions destructrices, wireless, physiques, de phishing ou de collecte d'identifiants.
- Utilisez un moyen de paiement contrôlé par l'organisation et consignez les approbations en interne.

### Pendant l'engagement

- Commencez depuis l'endpoint et le tunnel approuvés ; vérifiez l'egress observé avant le trafic d'évaluation.
- Gardez les comptes personnels, appareils, numéros de téléphone, repositories, clés SSH/GPG et la synchronisation cloud hors du cloisonnement.
- Journalisez l'opérateur/la tâche, le début/l'arrêt, la source, la destination autorisée et les changements de configuration sans collecter de contenu client inutile.
- Arrêtez-vous en cas d'ambiguïté sur le périmètre, de systèmes tiers inattendus, de notification d'abus d'un fournisseur, d'impact sur la sécurité, de perte d'équipement ou de perte de contact avec le responsable.
- N'improvisez jamais avec le Wi-Fi d'un voisin, des identifiants volés, une SIM/un compte non approuvé ou du matériel dissimulé dans un lieu.

### Fin de l'engagement

- Arrêtez les jobs et le C2 ; récupérez les appareils drop approuvés ; révoquez les tokens, identifiants et certificats.
- Rapprochez l'infrastructure, les domaines, les adresses sources, les dépenses, les données et les dossiers fournisseurs avec l'inventaire.
- Restituez/supprimez/conservez les données client conformément au contrat, préservez le minimum de preuves d'audit requis et faites vérifier l'arrêt par un second opérateur.

Voir [Infrastructure red team autorisée](authorized-red-team-infrastructure.md) pour le guide complet de déploiement et de démantèlement.

## Achat ou don privé légal

Objectif : minimiser les informations communiquées au commerçant ou au public tout en respectant les obligations de l'émetteur, de comptabilité, fiscales et relatives aux sanctions.

1. Listez qui ne doit pas apprendre quoi : public, commerçant, intermédiaire de paiement, employeur/délégataire d'un compte familial, service de livraison ou observateur de blockchain.
2. Vérifiez les règles locales, le bénéficiaire/l'interlocuteur, les conditions du fournisseur, les limites d'espèces et les besoins de conservation des documents.
3. Choisissez le moyen de paiement :
- espèces pour les paiements locaux légaux acceptés sans trace dans le réseau de paiement ;
- carte virtuelle réglementée/spécifique au commerçant pour séparer les identifiants en ligne ;
- cryptocurrency uniquement après analyse de l'acquisition, du ledger, du backend du wallet, du réseau, de l'interlocuteur et des liens avec les dépenses ultérieures.
4. Utilisez les informations requises véridiques et omettez uniquement les informations facultatives de fidélité/marketing. N'utilisez pas l'identité/l'adresse d'une autre personne et ne fractionnez pas une transaction autour d'un seuil.
5. Séparez le contexte du navigateur/compte du commerçant et évitez les connexions sociales, programmes de fidélité ou canaux personnels de récupération sans rapport.
6. Confirmez ce qui apparaît sur les relevés, reçus, notifications, expéditions et listes publiques de donateurs.
7. Stockez les justificatifs requis de reçu/fiscalité/autorisation sous forme chiffrée ; révoquez les identifiants de paiement jetables après la période de remboursement.

Voir [Paiements numériques privés](private-digital-payments.md) et [Confidentialité des cryptocurrency](cryptocurrency-privacy.md).

## Voyages et réseaux non fiables

Objectif : protéger les données et les comptes sur des réseaux non administrés par l'utilisateur — et non dissimuler une activité non autorisée.

- Mettez à jour les appareils et téléchargez les identifiants/cartes nécessaires avant le voyage.
- Minimisez les données stockées ; utilisez le chiffrement complet du disque, un déverrouillage robuste, une planification de récupération à distance et des procédures d'appareil éteint aux frontières/en cas de risque physique adaptées aux conseils juridiques.
- Vérifiez le SSID/le captive portal du lieu. Préférez un hotspot personnel lorsque cela est approprié, mais souvenez-vous des journaux d'abonné et de localisation cellulaires.
- Utilisez un VPN approuvé en full/forced tunnel pour les données de l'organisation ; vérifiez que les appareils connectés en tethering le partagent et testez le comportement IPv6/DNS.
- Utilisez un travel router pour l'isolation des clients et une politique reproductible, pas comme garantie d'anonymat.
- Traitez le chargement USB public, les ordinateurs empruntés, les imprimantes publiques et les systèmes partagés des salles de réunion comme des menaces distinctes.
- Supposez que la présence physique, les identifiants radio, la connexion au portail, les caméras et les relevés de paiement/localisation peuvent corréler la visite.

Les détails de comparaison et de configuration se trouvent dans [Confidentialité réseau et connectivité anonyme](network-privacy-and-anonymous-connectivity.md).

## Réponse aux échecs et à l'exposition

Lorsqu'un cloisonnement leak ou risque d'être lié :

1. Arrêtez l'activité si sa poursuite augmente les dommages ; utilisez l'arrêt d'urgence de l'engagement lorsque cela s'applique.
2. Préservez les preuves nécessaires sans diffuser de données sensibles. Notez l'heure exacte, l'indicateur observé et les actifs affectés.
3. Informez le propriétaire/responsable de la sécurité approprié. Ne dissimulez pas un incident pour préserver un récit de confidentialité.
4. Révoquez les sessions, tokens, identifiants de paiement et accès à l'infrastructure ; faites tourner les secrets depuis un endpoint connu comme propre.
5. Déterminez quelles arêtes ont permis le lien : endpoint, récupération de compte, réseau, paiement, métadonnées, contenu, comportement, interlocuteur ou présence physique.
6. Considérez l'ensemble du cloisonnement affecté comme compromis. Ne changez pas simplement son nom d'utilisateur ou son IP de sortie.
7. Respectez les obligations de notification en matière de breach, de fournisseur, de client, de finance et de droit.
8. Reconstruisez uniquement après avoir modifié le processus à l'origine du lien ; documentez le contrôle et testez-le.

## Audit périodique

- [ ] Le modèle de menace et les hypothèses juridiques/fournisseur sont réexaminés selon un calendrier daté.
- [ ] Les appareils, comptes, alias, domaines, chemins réseau et identifiants de paiement sont inventoriés.
- [ ] Les chemins de récupération ne traversent pas les cloisonnements de manière inattendue.
- [ ] Le full-tunnel, le DNS, l'IPv6 et le comportement fail-closed sont testés.
- [ ] Les fichiers et profils publics sont vérifiés pour détecter les métadonnées/la réutilisation de contenu.
- [ ] Les nodes/backends de wallet et les hypothèses des protocoles crypto restent à jour.
- [ ] Les logs et reçus sont minimaux, chiffrés, contrôlés par des permissions et conservés dans les délais.
- [ ] Les anciens cloisonnements et l'infrastructure d'engagement ont été entièrement retirés.
{{#include ../banners/hacktricks-training.md}}
