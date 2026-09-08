# Tests de confidentialité reproductibles

Une configuration de confidentialité n’est pas terminée lorsqu’elle se connecte. Elle est terminée lorsque la limite qu’elle revendique a été testée en utilisation normale, en cas de panne, de récupération et de démontage. Effectuez les tests sur une infrastructure que vous possédez ou que vous êtes autorisé à inspecter ; les sites publics de « leak test » deviennent un observateur supplémentaire.

## Créer un petit environnement de test autorisé

Utilisez trois rôles, idéalement sur des fournisseurs/réseaux distincts :
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Consignez avant chaque test :

- l’identifiant du test, les heures de début/fin UTC, l’opérateur et l’autorisation ;
- les versions et la configuration de l’endpoint/OS/client, ainsi que le hash de configuration ;
- les observations IPv4, IPv6, DNS, TLS, de compte, de paiement et physiques attendues ;
- les logs qui seront inspectés, ainsi que leurs horloges/fuseaux horaires ;
- la règle de réussite/échec et l’heure du teardown.

Ne testez jamais une identité sensible en premier. Utilisez un compte synthétique et des valeurs canary uniques et inoffensives appartenant au testeur.

## Test du chemin réseau

### 1. Capturer la baseline

Avant d’activer le chemin de confidentialité, consignez les routes locales et les resolvers :
```bash
ip route
ip -6 route
resolvectl status
```
Sur macOS, utilisez `route -n get default`, `netstat -rn -f inet6` et `scutil --dns`. Enregistrez la sortie uniquement dans le référentiel contrôlé des preuves ; elle peut contenir des identifiants locaux.

### 2. Se connecter et inspecter le routage

Activez le namespace VPN/Tor/workload, puis vérifiez la route sélectionnée pour les adresses publiques contrôlées :
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Remplacez les adresses de documentation par celles du serveur de test. Confirmez que l’interface/la table sélectionnée correspond à la conception.

### 3. Observer depuis les deux extrémités

Définissez l’URL du endpoint contrôlé, puis demandez un chemin bénin unique :
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Utilisez un domaine contrôlé par le testeur, avec un TLS authentifié et un token de chemin non sensible. Inspectez le journal du serveur pour vérifier :

- l’adresse source/ASN et l’egress attendu ;
- IPv4 contre IPv6 ;
- le comportement de Host/SNI visible au niveau de l’endpoint ;
- le user agent et les en-têtes de l’application ;
- l’heure exacte et la réutilisation de la requête.

N’ajoutez pas `X-Forwarded-For`, d’en-têtes de debug uniques ou de cookies contenant une identité à une requête supposée séparée.

### 4. Testez le DNS avec un canary contrôlé

Configurez une zone de test faisant autorité dont vous contrôlez les journaux de requêtes. Interrogez un label aléatoire unique via le compartiment :
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Inspectez le log faisant autorité. Il voit normalement le recursive resolver, et pas nécessairement le client. Comparez ce resolver avec la conception DNS prévue pour le VPN/Tor/application. Un site public aléatoire de DNS leak n’est pas nécessaire.

### 5. Tester le comportement fail-closed

Conservez une boucle de requêtes bénignes ciblant l’endpoint contrôlé, puis arrêtez le privacy path. La charge de travail doit échouer plutôt que basculer vers une interface physique. Vérifiez les deux familles d’adresses ainsi que le DNS :
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Répétez lors des événements suivants :

- crash du processus du tunnel ;
- basculement du Wi-Fi vers Ethernet ou vers un hotspot ;
- mise en veille/réactivation ;
- renouvellement DHCP ;
- changement d’état du captive portal ;
- reconnexion du provider/expiration de la clé.

Pour un namespace/conteneur Linux, arrêtez son tunnel et vérifiez qu’il n’a aucune autre route par défaut ni aucun autre resolver :
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Les noms et les commandes varient selon le déploiement. Ne les collez pas sur un hôte de production distant sans possibilité de récupération via la console.

### 6. Inspecter les sockets et les paquets locaux

Avec autorisation, vérifiez quel processus ou quelle interface communique réellement :
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Remplacez `TEST_SERVER_IP` par l’adresse explicitement détenue ; évitez toute capture étendue d’utilisateurs sans rapport. L’interface physique doit voir le pair du tunnel/bridge, tandis que le trafic à destination claire ne doit exister qu’au niveau prévu.

## Test Tor et onion-service

1. Dans Tor Browser, consultez la page de vérification de connexion du Tor Project et confirmez l’utilisation de Tor. Ne considérez pas cela comme une preuve d’identité.<sup>[[1]](#references)</sup>
2. Consultez le endpoint HTTPS détenu avec un canary unique et confirmez qu’il voit une sortie Tor, aucun cookie identifiant et le contexte standard du navigateur.
3. Sélectionnez **New Identity**, revisitez la page avec un autre canary et vérifiez que l’état local a été effacé comme prévu. Le changement d’IP de sortie n’est pas garanti et ne constitue pas le but de New Identity.
4. Pour un onion service, accédez-y uniquement via Tor Browser. Confirmez que l’hôte du service n’a aucun listener public à l’aide d’un scan externe autorisé et que les réponses de l’application ne contiennent aucun hostname/IP public.
5. Inspectez les DNS/HTTP sortants de l’origine, les templates, les pages d’erreur, les e-mails/webhooks et les assets tiers. Toute requête directe peut divulguer l’origine ou le compte de l’opérateur.
6. Si l’autorisation client est activée, confirmez qu’un Tor Browser propre et non authentifié ne peut pas se connecter et qu’un navigateur authentifié le peut.
7. Faites tourner une clé d’autorisation de test et confirmez que le client révoqué perd l’accès sans modification de l’identité onion.

## Test de compartimentation du navigateur

Créez une page contrôlée qui enregistre uniquement les champs nécessaires au test, avec une courte période de rétention. Comparez les compartiments personnel et privacy pour :

- les cookies/local storage/service workers et le cache ;
- l’état de synchronisation/connexion du navigateur ;
- la langue, le fuseau horaire, les dimensions de l’écran/de la fenêtre et les polices ;
- les candidats WebRTC/réseau ;
- les permissions et les modifications visibles par les extensions ;
- les données user-agent TLS/HTTP côté serveur.

N’essayez pas de rendre Tor Browser « plus aléatoire ». La condition de réussite est sa similarité avec son ensemble d’anonymat standard et l’absence d’état personnel, et non une différence maximale avec le navigateur personnel.

Testez le copier-coller, le glisser-déposer, l’ouverture de fichiers téléchargés, les suggestions du gestionnaire de mots de passe et les boutons des identity providers. Ce sont des ponts fréquents entre les compartiments.

## Test d’isolation du système d’exploitation

### Tails

1. Commencez avec un fichier/canary inoffensif dans une session sans Persistent Storage.
2. Éteignez complètement le système, redémarrez-le et confirmez qu’il a disparu.
3. Activez une seule catégorie de persistance requise, recommencez et confirmez que l’état sans rapport du navigateur/de l’application n’est pas conservé.
4. Vérifiez que l’Unsafe Browser ne peut pas être utilisé après la connexion au portail pour une activité sensible et que les applications Tor se reconnectent normalement.

### Whonix/Qubes

1. Arrêtez le qube Gateway/net et prouvez que le qube Workstation/app ne peut joindre ni IPv4, ni IPv6, ni DNS.
2. Tentez uniquement le chemin clipboard/fichier inter-qubes explicitement configuré et confirmez que les autres chemins de dossiers/périphériques partagés sont absents.
3. Ouvrez un document de test inoffensif dans un disposable qube, fermez-le et confirmez que son état disparaît.
4. Vérifiez que le qube vault n’a aucun NetVM et ne peut pas en acquérir un via une modification du template/des valeurs par défaut.
5. Effectuez un snapshot/restauration d’une VM de test et vérifiez si un état associé à l’identité réapparaît de manière inattendue.

## Test des métadonnées des communications

Pour chaque messenger sélectionné :

1. Créez des participants réservés aux tests sur des appareils contrôlés.
2. Notez ce que l’inscription requiert : téléphone, compte app-store, IP, push service, nom d’utilisateur ou invitation.
3. Envoyez un message inoffensif tout en inspectant les aperçus de notification, les desktops liés, les wearables et les sauvegardes.
4. Vérifiez les codes de sûreté/sécurité via un canal indépendant.
5. Désactivez les accusés de réception/push ou activez les transports Tor/local un par un, puis observez les changements de fiabilité/métadonnées.
6. Exportez ou restaurez une sauvegarde de test et documentez précisément les éléments qu’elle contient : profil, contacts et historique.
7. Perdez/révoquez un appareil de test et confirmez que les participants restants voient le changement de clé/appareil attendu.

Ne testez pas en contactant des personnes non impliquées ou en générant du trafic abusif.

## Test d’assainissement des fichiers

1. Hachez et conservez l’original dans un stockage de preuves chiffré :
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Créez une copie nettoyée à l’aide du processus spécifique au format décrit dans [Communications et partage préservant la confidentialité](privacy-preserving-communications-and-sharing.md).
3. Comparez les inventaires de métadonnées :
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Rendez/ouvrez la copie dans un contexte jetable. Vérifiez le contenu caché, les pièces jointes, les liens, les formulaires, les calques, les miniatures et les identifiants visuels.
5. Recherchez uniquement dans la copie préparée les chaînes connues de canary concernant l’auteur, l’adresse e-mail ou le chemin.
6. Hachez la sortie finale et demandez à une deuxième personne de vérifier le fichier exact qui sera publié.

L’absence de données dans la sortie d’ExifTool ne prouve pas l’anonymat ; les éléments internes au format, les pixels, la prose et les enregistrements de distribution subsistent.

## Test de privacy des paiements

Utilisez le plus petit montant autorisé ou un réseau de test/sandbox officiel :

1. Décrivez la visibilité attendue pour le payeur, le bénéficiaire/merchant, l’émetteur/exchange, le réseau/nœud, le registre public et le comptable/responsable du contrôle.
2. Créez un contexte unique de facture/merchant de test sans fausse identité.
3. Effectuez un seul paiement, puis recueillez votre propre reçu, relevé, tableau de bord du merchant, journal du wallet/nœud et vue de la blockchain publique, le cas échéant.
4. Vérifiez si le montant, l’horodatage, l’adresse/token, le compte, l’IP/appareil, la livraison et le circuit de remboursement correspondent au tableau des observateurs.
5. Pour Bitcoin, inspectez la réutilisation des adresses, les inputs sélectionnés, la monnaie rendue et la consolidation ultérieure dans la vue de coin-control du wallet.
6. Pour les protocoles shielded, vérifiez le pool/chemin réel et ce qu’une viewing key révèle ; ne déduisez pas la privacy de l’image de marque du wallet.
7. Pour l’e-cash/Taler, testez la sauvegarde/récupération, le remboursement et le rachat avec une petite valeur ; documentez les enregistrements aux limites de la mint, de l’exchange et de la federation.
8. Révoquez une carte virtuelle/un identifiant de test et confirmez qu’une autorisation ultérieure échoue, tout en conservant une compréhension correcte du traitement des remboursements légitimes.
9. Rapprochez et conservez les justificatifs fiscaux/d’autorisation requis sous forme chiffrée.

Ne créez jamais de transferts circulaires, de fractionnements pour contourner des seuils, de faux achats ou de remboursements suspects comme « test de privacy ».

## Exercice d’accountability de red team autorisé

Avant l’exercice, réalisez un exercice sur table et un drill technique :

1. Un opérateur lance un canary bénin depuis chaque source approuvée.
2. Le SOC cible enregistre ce qu’il détecte sans recevoir l’identité de l’opérateur si un test en aveugle est prévu.
3. Le responsable de l’exercice fait correspondre la source → l’engagement → l’opérateur à partir de la table séquestrée et de l’enregistrement de mission signé.
4. Le responsable envoie l’arrêt d’urgence ; l’opérateur et le responsable de l’infrastructure démontrent l’arrêt dans le délai prévu par les ROE.
5. Le service abuse du fournisseur reçoit le bon contact 24/7 et la référence d’autorisation.
6. Les preuves indiquent la cible, l’heure, l’outil/la mission et l’opérateur sans conserver de contenu de payload inutile.
7. Un deuxième opérateur vérifie la révocation des identifiants et le démontage des ressources.

Échouez à la revue de préparation si le SOC peut voir trivialement une infrastructure personnelle/domestique **ou** si le responsable ne peut pas attribuer et arrêter rapidement la source.

## Modèle d’enregistrement de test
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Vérification de la connexion](https://check.torproject.org/)
- [2] [WireGuard — Routage et espaces de noms réseau](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ et recommandations sur les métadonnées](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Guide technique pour les tests et l’évaluation de la sécurité de l’information](https://csrc.nist.gov/pubs/sp/800/115/final)
