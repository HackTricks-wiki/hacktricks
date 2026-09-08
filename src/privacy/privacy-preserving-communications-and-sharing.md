# Communications et partage préservant la vie privée

{{#include ../banners/hacktricks-training.md}}

Le chiffrement de bout en bout protège le contenu. Il ne masque pas automatiquement le compte, le numéro de téléphone, le graphe de contacts, l'adresse IP, le push token, l'aperçu des notifications, les horaires, les métadonnées des fichiers ou le comportement du destinataire. Sélectionnez un outil selon les métadonnées qu'il supprime et les observateurs qu'il introduit.

## Comparer les modèles de communication

| Outil/modèle | Propriété utile | Observateurs et limites restants |
|---|---|---|
| Signal | E2EE mature ; les usernames peuvent initier un contact sans partager le numéro ; sealed sender réduit les métadonnées du service | Un numéro de téléphone est requis pour l'inscription ; le service, le fournisseur push, les contacts et les endpoints conservent certaines observations |
| SimpleX | Aucun identifiant utilisateur global ; queues par contact ; transport Tor optionnel | Horaires/transport du relay, service push, invitations et endpoints ; écosystème plus récent et plus restreint |
| Briar | Synchronisation directe ; Tor en ligne ; Bluetooth/Wi-Fi hors ligne ; aucun stockage central des messages | Contacts et endpoints ; observateurs des radios locales ; orienté Android ; les deux parties doivent être disponibles ou utiliser Mailbox |
| OnionShare | Fichier/réception/chat/site directs via un service onion temporaire ; aucun fournisseur de stockage | L'ordinateur de l'expéditeur est le service ; le détenteur du lien apprend l'accès ; les horaires et endpoints restent exposés |
| Fichier chiffré avec `age` | Chiffrement simple avec la clé du destinataire, indépendant du transport | Le transport voit l'expéditeur/le destinataire, les horaires et la taille ; les noms de fichiers/métadonnées d'archive et les endpoints restent exposés |
| E-mail ordinaire + TLS | Chiffrement du canal entre serveurs | Les deux fournisseurs de messagerie peuvent normalement lire le contenu et conserver les métadonnées de routage/compte |

## Signal : contact privé sans divulgation du numéro

Les usernames Signal peuvent démarrer une conversation sans révéler le numéro de téléphone de l'utilisateur au nouveau contact, mais un numéro de téléphone reste requis pour l'inscription.<sup>[[1]](#references)</sup> Sealed sender constitue une protection incrémentale des métadonnées, et non une résistance à toute corrélation d'IP/horaires.<sup>[[2]](#references)</sup>

### Workflow

1. Installez Signal depuis l'app store/le projet officiel et mettez d'abord à jour l'OS.
2. Inscrivez-vous avec un numéro que vous êtes légalement autorisé à utiliser. N'utilisez pas d'activations SMS louées, le numéro d'une autre personne ou un compte fournisseur obtenu avec une fausse identité.
3. Dans **Paramètres → Confidentialité → Numéro de téléphone**, définissez qui peut voir le numéro et qui peut trouver le compte grâce au numéro, selon le threat model.
4. Créez un username pour la découverte de nouveaux contacts. Partagez son lien/QR exact via un canal déjà authentifié ; les usernames peuvent changer et ne correspondent pas au nom du profil.
5. Désactivez l'importation des contacts/les permissions si la commodité ne justifie pas la liaison, et ajoutez manuellement les contacts lorsque la plateforme le permet.
6. Ouvrez les détails du contact et comparez le safety number/QR via un second canal ou en personne avant d'échanger du contenu sensible.
7. Vérifiez les appareils liés, le registration lock/PIN, les aperçus de notifications, la sécurité de l'écran, le relais des appels, les paramètres par défaut des messages éphémères et le comportement des sauvegardes.
8. Envoyez un message de test non sensible et passez un appel. Inspectez des deux côtés les traces sur l'écran verrouillé, le desktop, les wearables et les notifications cloud.
9. Considérez un safety number modifié ou un appareil lié inattendu comme un événement nécessitant une investigation, et non comme une alerte à ignorer automatiquement.

Ne mélangez pas une photo de profil pseudonyme, une bio, une appartenance à un groupe ou des horaires avec un contexte Signal permettant l'identification.

## SimpleX : connexions par contact sans identifiant global

SimpleX achemine les messages via des queues unidirectionnelles et n'attribue aucun identifiant utilisateur à l'échelle du réseau. Sa propre policy documente néanmoins les sessions de transport, les données temporaires des serveurs, les compromis des push notifications et la responsabilité des endpoints.<sup>[[3]](#references)</sup>

### Workflow

1. Téléchargez un client maintenu depuis le projet/store officiel et vérifiez l'éditeur. Utilisez un profil d'OS/app dédié lorsque les identités ne doivent pas être mélangées.
2. Créez un profil **local** avec un nom d'affichage et une image spécifiques au contexte. La suppression de l'app sans sauvegarde peut entraîner la perte du profil et des connexions.
3. Au premier lancement, choisissez délibérément le mode de notification. Le push mobile instantané peut exposer des métadonnées supplémentaires à l'infrastructure Apple/Google.
4. Créez un lien d'invitation à usage unique pour un contact. Transférez-le via un canal authentifié ; toute personne qui obtient une invitation active peut essayer de l'utiliser.
5. Après la connexion, ouvrez les détails du contact et comparez le security code en personne ou via un canal indépendant vérifié.<sup>[[4]](#references)</sup>
6. Utilisez un profil incognito par groupe lorsque cette option est prise en charge, plutôt que de réutiliser le même profil dans des groupes sans lien.
7. Configurez le transport Tor pris en charge par le client si le réseau local/serveur ne doit pas voir l'IP directe. Confirmez la connexion après la modification ; ne forcez pas un proxy système non pris en charge.
8. Vérifiez les accusés de réception, les link previews, les appels, les téléchargements automatiques et l'exportation/la sauvegarde de la base de données. Chacun modifie les métadonnées ou l'exposition de l'endpoint.
9. Testez la récupération sur un appareil isolé de secours sans exécuter un état de profil live dupliqué ; le projet avertit que des copies concurrentes peuvent perturber les conversations.

L'absence d'identifiant global n'empêche pas un contact d'identifier l'utilisateur grâce au contenu, à la réutilisation du profil, à la transmission de l'invitation, aux horaires ou au graphe social.

## Briar : messagerie directe et résistante aux perturbations

Briar synchronise directement les appareils, via Tor lorsqu'ils sont en ligne et via Bluetooth/Wi-Fi pendant les pannes locales. Le threat model officiel suppose uniquement une surveillance adversariale limitée des radios à courte portée ; le wireless local n'est donc pas invisible.<sup>[[5]](#references)</sup>

### Workflow

1. Installez depuis la distribution officielle de Briar et vérifiez la source du package. Utilisez un appareil Android pris en charge avec les mises à jour de sécurité actuelles.
2. Créez un compte local avec un nickname unique au contexte et un mot de passe fort. Il n'existe aucun mécanisme de réinitialisation du mot de passe ; vérifiez que le secret de déverrouillage peut être récupéré.
3. Ajoutez les contacts en face à face en scannant les QR codes de chacun lorsque cela est possible. Cela authentifie le contact et évite d'envoyer un lien via un canal corrélable.
4. Dans les paramètres de connectivité, activez uniquement les transports nécessaires : Tor/Internet, Wi-Fi et/ou Bluetooth. Désactivez les radios locales lorsqu'elles ne sont pas nécessaires.
5. Pour une livraison asynchrone, évaluez Briar Mailbox sur un appareil dédié et alimenté ; inventoriez-le et protégez-le physiquement comme un serveur de messages.
6. Envoyez un test bénin lorsque Internet est disponible, puis testez le chemin prévu en cas de panne avec Internet désactivé, dans un emplacement autorisé par le propriétaire.
7. Inspectez les sauvegardes Android, les aperçus de notifications, les captures d'écran et le contenu exporté. Le stockage local chiffré est exposé lorsque l'endpoint est déverrouillé ou compromis.
8. Supprimez les contacts/appareils perdus et abandonnez tout le contexte si la garde physique ou le mot de passe du compte est compromis.

## OnionShare : transfert direct temporaire

OnionShare exécute un service onion sur l'ordinateur de l'expéditeur/du destinataire ; les fichiers ne sont pas téléversés vers un fournisseur de stockage et le trafic est chiffré de bout en bout à l'intérieur de Tor.<sup>[[6]](#references)</sup> L'URL onion complète est une capacité de type bearer et doit être protégée.

### Workflow GUI de partage de fichiers

1. Installez OnionShare depuis sa distribution officielle signée, ainsi que Tor Browser du côté du destinataire.
2. Placez des **copies nettoyées** des fichiers dans un répertoire de staging dédié. Ne pointez pas OnionShare vers un répertoire personnel.
3. Ouvrez **Share Files**, ajoutez uniquement les fichiers préparés, laissez la protection par clé privée/accès activée et gardez **Stop sharing after files have been sent** activé pour un seul destinataire.
4. Démarrez le partage et envoyez l'URL onion complète via un canal E2EE déjà authentifié. Ne la collez pas dans un e-mail, un issue tracker ou des chats publics.
5. Le destinataire ouvre l'URL dans Tor Browser, vérifie avec l'expéditeur les noms et la taille attendus, puis télécharge.
6. Les deux parties comparent un digest SHA-256 convenu à l'avance ou transmis séparément afin de garantir l'intégrité lorsque le fichier lui-même constitue la frontière de sécurité.
7. Confirmez qu'OnionShare s'est arrêté après le téléchargement ; sinon, arrêtez-le manuellement et fermez l'application.
8. Supprimez la copie préparée conformément à la policy de conservation et inspectez les paramètres d'historique/log d'OnionShare afin de détecter toute divulgation involontaire de nom de fichier.

### Workflow CLI

La CLI officielle accepte les fichiers comme arguments positionnels et s'arrête après le partage unique terminé par défaut. Sur un hôte où la CLI officielle/Tor est installé :
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Transmettez l’URL complète résultante de manière sécurisée. N’ajoutez pas `--public`, `--no-autostop-sharing`, de journalisation détaillée des noms de fichiers ni de persistance, sauf si le modèle de menace exige explicitement cette exposition résultante.<sup>[[7]](#references)</sup>

Considérez les documents reçus comme hostiles. Ouvrez-les dans une VM jetable ou un renderer de type Dangerzone, plutôt que sur l’hôte portant l’identité.

## Chiffrer un fichier indépendamment avec `age`

Le chiffrement indépendant du transport est utile lorsqu’un fournisseur de stockage ou de messagerie peut voir l’objet. Il ne dissimule pas l’expéditeur, le destinataire, la taille, le moment ni le nom du fichier, sauf si ces éléments sont traités séparément.

### Configuration du destinataire
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Authentifiez la chaîne publique du destinataire via un second canal. L’expéditeur exécute ensuite :
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Le destinataire déchiffre vers un nouveau chemin :
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Le CLI officiel avertit que `-o` écrase un fichier de sortie existant ; utilisez donc un nouveau répertoire et vérifiez l’empreinte/le contenu avant de le déplacer.<sup>[[8]](#references)</sup> N’envoyez jamais le fichier d’identité avec le ciphertext.

## Pipeline reproductible de sanitization des fichiers

La suppression des métadonnées dépend du format. Conservez un original chiffré lorsque l’authenticité, la forensics ou la chaîne de conservation sont importantes ; travaillez sur une copie.

### Exemple JPEG
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Cette démarche suit les recommandations plus sûres d’ExifTool pour les fichiers JPEG : supprimer aveuglément chaque tag peut également supprimer les informations de couleur.<sup>[[9]](#references)</sup> Inspectez ensuite visuellement les pixels à la recherche de visages, de reflets, d’écrans, de points de repère et de motifs de dommages/bruit uniques.

### Flux de travail Office/PDF

1. Conservez l’original modifiable chiffré et hors ligne par rapport au contexte de publication.
2. Supprimez les commentaires, les modifications suivies, les diapositives/feuilles masquées, les fichiers incorporés, les modèles personnels et les propriétés du document dans l’application de création.
3. Exportez un nouveau PDF depuis un profil propre dédié ; ne l’« imprimez » pas vers une imprimante cloud.
4. Inspectez-le avec des outils prenant en compte le format ainsi qu’avec un moteur de rendu visuel jetable :
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Recherchez dans le rendu final les noms, chemins, adresses e-mail et textes de révision. La rastérisation peut supprimer les structures actives, mais elle nuit à l’accessibilité et à la recherche ; elle ne supprime ni le contenu visible ni le style rédactionnel.
6. Hachez l’artefact final et transférez **uniquement** cette copie via le compartiment de publication.

## Privacy Pass : autorisation anonyme pour les concepteurs de services

Privacy Pass sépare l’**émission** des tokens de leur **utilisation**. Une origine peut apprendre qu’un client possède un token approuvé par un issuer sans connaître l’interaction d’émission spécifique du client. La réutilisation d’un token, les métadonnées uniques, le timing ou la collusion peuvent réintroduire la possibilité de corrélation.<sup>[[10]](#references)</sup>

Modèle de déploiement sûr :

1. Définissez l’énoncé que le token prouve (par exemple, l’éligibilité à une limitation de débit), et non une identité globale cachée.
2. Utilisez l’architecture et les protocoles d’émission standardisés ; n’implémentez pas vous-même la cryptographie des signatures aveugles.
3. Séparez l’administration de l’issuer/attester et celle de l’origine lorsque la propriété recherchée l’exige.
4. Réduisez au minimum les métadonnées publiques/privées des tokens et assurez-vous que les ensembles d’anonymat sont suffisamment grands.
5. Émettez des lots avant leur utilisation lorsque cela est pris en charge, afin que l’heure d’émission ne corresponde pas trivialement à l’heure d’utilisation.
6. Utilisez chaque token une seule fois, validez le challenge lié à l’origine et supprimez l’état des tokens expirés.
7. Empêchez les cookies, la journalisation des adresses IP et les comptes d’application de neutraliser silencieusement la propriété de confidentialité du token.
8. Vérifiez si les logs de l’issuer et de l’origine peuvent relier un événement contrôlé d’émission et d’utilisation au moyen du timing, des métadonnées ou d’erreurs uniques.

Privacy Pass est une fonctionnalité d’application, et non quelque chose qu’un utilisateur peut ajouter à n’importe quel compte.

## Liste de vérification de la sécurité des communications

- [ ] Le contact/l’invitation/la clé a été authentifié(e) indépendamment.
- [ ] L’exposition du numéro de téléphone, du nom d’utilisateur, du profil, du groupe et de l’importation des contacts est comprise.
- [ ] Les observateurs directs des adresses IP, des relais, de Tor, du fournisseur de push et des communications radio locales sont recensés.
- [ ] Les aperçus des notifications, les wearables, les postes de travail liés et les sauvegardes ont été testés.
- [ ] Les fichiers ont été nettoyés, chiffrés si nécessaire et ouverts dans un contexte jetable.
- [ ] La récupération fonctionne sans relier des identités distinctes.
- [ ] Les logs, l’historique et les services temporaires de partage disposent d’une règle d’arrêt/de conservation.

## References

- [1] [Signal — Confidentialité du numéro de téléphone et noms d’utilisateur](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Politique de confidentialité et conditions d’utilisation](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Guide sur la confidentialité et la sécurité](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Fonctionnement](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Conception de la sécurité](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Utilisation avancée et CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI officiel et utilisation](https://github.com/FiloSottile/age)
- [9] [FAQ ExifTool — Suppression sûre des métadonnées](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architecture de Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
