# Modélisation des menaces et séparation des identités

{{#include ../banners/hacktricks-training.md}}

L’échec d’anonymat le plus courant ne vient pas d’une cryptographie défaillante. Il vient de la **mise en relation** : un identifiant, un schéma temporel, un appareil, un compte, un paiement, un fichier ou une habitude humaine relie deux contextes qui étaient censés rester séparés.

## Élaborer un modèle de menace lié à la vie privée

Le plan de sécurité en six questions de l’EFF constitue une base solide : ce qui doit être protégé, contre qui, l’impact et la probabilité d’un échec, les efforts disponibles et les alliés susceptibles d’aider.<sup>[[1]](#references)</sup> Rendez-le opérationnel avec un petit tableau :

| Actif/action | Observateur | Données observables | Moyen de corrélation | Contrôle | Risque résiduel |
|---|---|---|---|---|---|
| Rechercher des informations sur un client | FAI | Métadonnées de destination et de temps | Dossier de l’abonné résidentiel | Tor Browser | Utilisation de Tor visible ; corrélation de bout en bout |
| Compte pseudonyme | Plateforme | IP, navigateur, données de récupération | Téléphone/e-mail/photo réutilisé(e) | Contexte et alias dédiés | Corrélation du style rédactionnel/graphe social |
| Achat en ligne | Marchand | Compte, livraison, carte tokenisée | Adresse et historique du compte | Achat sans compte, champs minimaux, carte virtuelle | L’émetteur et le transporteur conservent des dossiers |
| Trafic de red team | Cible/client | IP source et comportement | Dossiers du fournisseur/de la mission | Egress dédié et autorisé | Délibérément attribuable en cas d’escalade |

Réexaminez le tableau chaque fois que le lieu, le fournisseur, l’appareil, l’interlocuteur ou les conséquences changent.

## Tracer le graphe de mise en relation

Traitez chaque identité comme un nœud distinct. Ajoutez une arête pour chaque attribut partagé :

- adresse e-mail ou adresse de récupération ;
- numéro de téléphone ou importation du carnet de contacts ;
- nom d’utilisateur, avatar, photo, biographie ou style de rédaction/code ;
- mot de passe, compte de synchronisation de passkeys ou question de récupération ;
- appareil, identifiant publicitaire, profil de navigateur, cookies, polices ou extensions ;
- adresse IP, fuseau horaire, langue, emploi du temps ou statut en ligne simultané ;
- carte bancaire, compte d’exchange, cluster de wallets, adresse de livraison ou programme de fidélité ;
- champs d’auteur des documents, emplacement EXIF, marques d’imprimante ou propriétaire d’un partage cloud ;
- collègue, appartenance à un groupe et graphe social.

Une arête n’est pas automatiquement fatale, mais elle indique quel observateur peut établir la connexion. L’EFF avertit spécifiquement que les numéros de téléphone, les adresses e-mail et les photographies réutilisées peuvent relier des profils.<sup>[[2]](#references)</sup>

## Créer un compartiment étape par étape

1. **Nommer le contexte et les liens interdits.** Exemple : `client-red-2026`, avec interdiction de l’utiliser avec l’e-mail personnel, les profils de navigateur personnels, les moyens de paiement personnels et les clients sans rapport.
2. **Choisir la limite d’isolation.** Par niveau de robustesse croissant : profil de navigateur séparé → compte OS séparé → VM/qube séparé → appareil dédié. Un onglet séparé ou une fenêtre privée ne constitue pas une limite de sécurité.
3. **Créer de nouveaux identifiants à l’intérieur de cette limite.** Utilisez une adresse e-mail/un alias, un nom d’utilisateur, un coffre ou une collection de gestionnaire de mots de passe et des clés d’authentification spécifiques au contexte. N’ajoutez pas de canal de récupération personnel si l’absence de lien avec le fournisseur est importante.
4. **Choisir une seule politique réseau.** Décidez si le contexte utilise toujours un VPN client, un VPS de mission, un VPN de confiance ou Tor. Appliquez autant que possible un routage fail-closed.
5. **Choisir une politique de paiement.** Le moyen de paiement doit correspondre au modèle d’observateur ; une carte virtuelle peut dissimuler le PAN au marchand, tout en identifiant le client auprès de l’émetteur.
6. **Définir des règles de transfert de données.** Préférez les transferts délibérés et strictement ciblés. Considérez le presse-papiers, les dossiers partagés, les périphériques USB, la synchronisation cloud, les imprimantes et les captures d’écran comme des ponts possibles.
7. **Consigner les dates de création et de suppression.** Définissez quelles preuves doivent être conservées pour les contrats, les impôts ou la conformité, et quelles données transitoires doivent expirer.
8. **Rechercher les liens avant utilisation.** Inspectez les paramètres du compte, les champs de récupération, le profil public, l’IP/DNS, l’état du navigateur, les métadonnées des fichiers et les tableaux de bord des fournisseurs.

{% hint style="warning" %}
N’inventez pas d’informations d’identité lorsqu’un service ou la loi exige une identification exacte. Un compartiment de confidentialité vise la minimisation et la séparation des données, pas la fraude à l’identité ni le contournement des obligations de connaissance du client.
{% endhint %}

## Base de sécurité des endpoints et des comptes

- Utilisez du matériel pris en charge et installez rapidement les mises à jour de l’OS, du navigateur, du wallet et du firmware.
- Activez le chiffrement de l’appareil et utilisez un code d’accès robuste. Le chiffrement au repos aide lorsqu’un appareil éteint est perdu ou saisi, mais pas lorsqu’un malware ou une session déverrouillée peut lire les données.<sup>[[3]](#references)</sup>
- Utilisez des mots de passe uniques générés aléatoirement dans un gestionnaire de mots de passe.
- Préférez une authentification résistante au phishing, telle que WebAuthn/passkeys ou des clés de sécurité matérielles, lorsque le modèle de menace permet leur modèle de récupération/synchronisation. Le NIST indique que les OTP saisis manuellement ne sont pas résistants au phishing, car un imposteur peut les relayer.<sup>[[4]](#references)</sup>
- Conservez les codes de récupération hors ligne et séparés de l’endpoint. Vérifiez si un compte de passkeys synchronisé réunit des identités qui devraient rester séparées.
- Désactivez les autorisations inutiles liées à la localisation, aux contacts, au microphone, à la caméra, au Bluetooth, à l’identifiant publicitaire et à l’exécution en arrière-plan.
- Ne mélangez pas la synchronisation cloud personnelle, la synchronisation du navigateur, les comptes de gestionnaire de mots de passe ou les app stores avec un contexte à forte séparation.

## Vie privée du navigateur

Le browser fingerprinting utilise une configuration, un appareil, un environnement et un comportement observables pour identifier ou corréler un utilisateur. Effacer les cookies ou changer d’adresse IP ne suffit pas systématiquement à le neutraliser, et le W3C considère qu’une élimination technique complète par des moyens largement déployés est improbable.<sup>[[5]](#references)</sup>

Pour la confidentialité ordinaire :

1. Utilisez un navigateur maintenu, avec le mode HTTPS-only et une protection renforcée contre le tracking.
2. Bloquez le tracking tiers et partitionnez l’état lorsque cela est pris en charge.
3. Utilisez des profils de navigateur séparés pour les contextes réellement distincts.
4. Désactivez les autorisations inutiles et effacez les données des sites selon une périodicité définie.
5. Évitez de vous connecter à des comptes riches en informations d’identité pendant des recherches sensibles sans rapport.

Pour l’anonymat sur le Web, utilisez **Tor Browser dans sa configuration standard**. Ne faites pas passer un navigateur normal par Tor : le Tor Project avertit que les navigateurs ordinaires peuvent leak via DNS/WebRTC, l’état persistant, les polices, les plugins et les différences de fingerprint.<sup>[[6]](#references)</sup> Évitez les extensions supplémentaires, les tailles de fenêtre inhabituelles, les polices personnalisées et les préférences qui rendent le navigateur identifiable.<sup>[[7]](#references)</sup>

## Communications et métadonnées

Les métadonnées comprennent l’expéditeur, le destinataire, l’heure, le lieu et d’autres éléments de contexte, même lorsque le contenu du message est chiffré.<sup>[[8]](#references)</sup>

- Préférez les outils chiffrés de bout en bout avec un minimum de métadonnées côté serveur et des protocoles/clients open source lorsque cela est possible.
- Vérifiez les contacts sensibles au moyen d’un canal indépendant ou en personne. Les safety numbers de Signal sont conçus pour cette vérification.<sup>[[9]](#references)</sup>
- Les usernames Signal peuvent initier un contact sans partager de numéro de téléphone, mais un numéro de téléphone reste nécessaire pour s’enregistrer ; configurez délibérément la visibilité et la possibilité de découverte du numéro.<sup>[[9]](#references)</sup>
- Les messages éphémères réduisent le nombre de copies conservées ; les destinataires peuvent toujours photographier, copier, transférer ou archiver le contenu.
- Les e-mails exposent normalement les métadonnées de routage. Même les fournisseurs axés sur la confidentialité ne peuvent pas rendre un message chiffré de bout en bout lorsque l’autre partie utilise un e-mail ordinaire, sauf si les deux parties utilisent une méthode E2EE compatible. Proton documente par exemple que les e-mails ordinaires envoyés à d’autres fournisseurs utilisent TLS et restent lisibles par le fournisseur destinataire.<sup>[[10]](#references)</sup>
- Séparez les carnets d’adresses et n’importez pas de contacts personnels dans un compte pseudonyme.

## Fichiers, photos et paternité

Tails avertit que les photographies peuvent contenir des données sur l’appareil photo et la localisation, et que les documents bureautiques peuvent contenir des champs relatifs à l’auteur et à l’heure de création.<sup>[[11]](#references)</sup>

Avant de partager :
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Rouvrez ensuite la copie nettoyée dans une visionneuse isolée et vérifiez :

- les propriétés du document, les commentaires, les modifications suivies, les feuilles/diapositives masquées, les miniatures et les pièces jointes ;
- les données EXIF/XMP/IPTC, les coordonnées GPS, les horodatages, les noms des appareils/logiciels et les identifiants uniques ;
- les reflets visibles, les points de repère, le contenu des écrans, les voix, les visages et les sons d’arrière-plan ;
- le nom de fichier, les chemins d’archive, le propriétaire du partage cloud, le certificat de signature et l’historique des révisions.

La sanitization peut endommager les preuves ou l’authenticité. Conservez un original chiffré lorsque la chaîne de conservation ou une vérification ultérieure est importante. La stylométrie et le style de codage peuvent également relier un auteur à son identité ; la suppression des métadonnées ne modifie pas le style humain.

## Schémas d’échec courants

- Se connecter à un compte personnel via une connexion « anonyme ».
- Réutiliser un téléphone de récupération, un avatar, un nom d’utilisateur, une clé publique, un wallet ou une adresse de donation.
- Utiliser deux identités simultanément depuis des contextes corrélés.
- Copier du texte/des fichiers via un presse-papiers cloud personnel ou un dossier partagé.
- Installer des extensions distinctives de Tor Browser ou modifier de nombreux paramètres par défaut.
- Faire confiance à une déclaration « no logs » sans comprendre ce qui est journalisé, pendant combien de temps et par quels sous-traitants.
- Supposer qu’un téléphone secondaire est anonyme alors qu’il se déplace avec un téléphone personnel. L’EFF indique que la localisation cellulaire et les déplacements simultanés peuvent corréler les appareils.<sup>[[3]](#references)</sup>
- Considérer le chiffrement comme une suppression ; les endpoints et les destinataires peuvent conserver le texte en clair.

## Liste de vérification

- [ ] Le contexte ne contient aucune adresse personnelle de récupération, aucun téléphone personnel, aucun compte de synchronisation ni aucun média réutilisé, sauf acceptation intentionnelle.
- [ ] Le chemin réseau prévu est actif et passe en mode sécurisé en cas de défaillance.
- [ ] Le fuseau horaire, la locale, les extensions et les permissions du navigateur/de l’appareil correspondent au plan.
- [ ] Aucun compte personnel n’est ouvert dans le compartiment.
- [ ] Les fichiers ont été inspectés et nettoyés ; les originaux sont traités séparément.
- [ ] Les contacts sont authentifiés via un second canal.
- [ ] Les métadonnées visibles par le fournisseur et la période de rétention sont comprises.
- [ ] Les procédures de démontage, de conservation des preuves et de récupération des comptes sont documentées.

## References

- [1] [EFF Surveillance Self-Defense — Votre plan de sécurité](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Vous protéger sur les réseaux sociaux](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Participer à une manifestation](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Gestion de l’authentification et des authentificateurs](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Atténuer le fingerprinting des navigateurs dans les spécifications Web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Utiliser Tor avec d’autres navigateurs](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins et modules complémentaires dans Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Pourquoi les métadonnées des communications sont importantes](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Confidentialité du numéro de téléphone et noms d’utilisateur : analyse approfondie](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Qu’est-ce qui est chiffré dans Proton Mail ?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Avertissements : Tails est sûr, mais ce n’est pas magique](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
