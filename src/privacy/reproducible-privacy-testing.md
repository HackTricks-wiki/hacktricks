# Tests de confidentialité reproductibles

{{#include ../banners/hacktricks-training.md}}

Une configuration de confidentialité n'est pas terminée lorsqu'elle se connecte. Elle est terminée lorsque sa limite déclarée a été testée en conditions normales d'utilisation, de panne, de récupération et de démontage. Effectuez les tests sur une infrastructure que vous possédez ou que vous êtes autorisé à inspecter ; les sites publics de « leak test » deviennent un observateur supplémentaire.

## Construire un petit environnement de test autorisé

Utilisez trois rôles, idéalement sur des providers/réseaux distincts :
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Consignez avant chaque test :

- l’ID du test, les heures de début et de fin en UTC, l’opérateur et l’autorisation ;
- les versions et la configuration de l’endpoint/du système d’exploitation/du client, ainsi que le hash de configuration ;
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
Sur macOS, utilisez `route -n get default`, `netstat -rn -f inet6` et `scutil --dns`. Enregistrez la sortie uniquement dans le dépôt contrôlé des éléments de preuve ; elle peut contenir des identifiants locaux.

### 2. Se connecter et inspecter le routage

Activez le namespace VPN/Tor/workload, puis vérifiez la route sélectionnée pour les adresses publiques contrôlées :
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Remplacez les adresses de documentation par celles du serveur de test. Confirmez que l’interface/la table sélectionnée correspond à la conception.

### 3. Observer depuis les deux extrémités

Définissez l’URL de l’endpoint contrôlé, puis demandez un chemin unique et inoffensif :
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Utilisez un domaine contrôlé par le testeur, un TLS authentifié et un token de chemin non sensible. Inspectez le journal du serveur pour vérifier :

- l’adresse source/ASN et l’egress attendu ;
- IPv4 par rapport à IPv6 ;
- le comportement de Host/SNI visible au niveau de l’endpoint ;
- le user agent et les headers de l’application ;
- l’heure exacte et la réutilisation de la requête.

N’ajoutez pas de `X-Forwarded-For`, de headers de debug uniques ou de cookies contenant une identité à une requête supposée séparée.

### 4. Testez le DNS avec un canary contrôlé

Configurez une zone de test faisant autorité dont vous contrôlez les journaux de requêtes. Interrogez un label aléatoire unique via le compartiment :
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Inspectez le log faisant autorité. Il voit normalement le recursive resolver, pas nécessairement le client. Comparez ce resolver avec la conception DNS prévue pour le VPN/Tor/application. Un site public aléatoire de détection des DNS leaks n'est pas nécessaire.

### 5. Testez le comportement fail-closed

Maintenez une boucle de requêtes bénignes dirigées vers l'endpoint que vous contrôlez, puis arrêtez le privacy path. La charge doit échouer plutôt que de basculer vers une interface physique. Vérifiez les deux familles d'adresses ainsi que le DNS :
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Répétez lors des événements suivants :

- crash du processus tunnel ;
- basculement du Wi-Fi vers Ethernet ou vers un hotspot ;
- mise en veille/réveil ;
- renouvellement DHCP ;
- état du captive portal ;
- reconnexion du provider/expiration de la clé.

Pour un namespace/conteneur Linux, arrêtez son tunnel et vérifiez qu’il ne possède aucune autre route par défaut ni autre resolver :
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
Remplacez `TEST_SERVER_IP` par l’adresse explicitement autorisée ; évitez la capture étendue d’utilisateurs sans rapport. L’interface physique doit voir le pair du tunnel/bridge, tandis que le trafic à destination en clair ne doit exister qu’au niveau prévu.

## Test Tor et onion-service

1. Dans Tor Browser, consultez la page de vérification de connexion du Tor Project et confirmez l’utilisation de Tor. Ne considérez pas cela comme une preuve d’identité.<sup>[[1]](#references)</sup>
2. Consultez l’endpoint HTTPS autorisé avec un canary unique et confirmez qu’il voit un nœud de sortie Tor, aucun cookie identifiant et le contexte standard du navigateur.
3. Sélectionnez **New Identity**, consultez à nouveau l’endpoint avec un canary différent et vérifiez que l’état local a été effacé comme prévu. Le changement d’IP de sortie n’est pas garanti et ne constitue pas l’objectif de New Identity.
4. Pour un onion-service, accédez-y uniquement via Tor Browser. Confirmez que l’hôte du service n’a aucun listener public à l’aide d’un scan externe autorisé et que les réponses de l’application ne contiennent aucun hostname/IP public.
5. Inspectez les requêtes DNS/HTTP sortantes de l’origine, les templates, les pages d’erreur, les e-mails/webhooks et les assets tiers. Toute requête directe peut divulguer l’origine ou le compte de l’opérateur.
6. Si l’autorisation client est activée, confirmez qu’un Tor Browser propre et sans credentials ne peut pas se connecter et qu’un navigateur avec credentials le peut.
7. Faites tourner une clé d’autorisation de test et confirmez que le client révoqué perd l’accès sans modifier l’identité onion.

## Test de compartimentation du navigateur

Créez une page contrôlée qui enregistre uniquement les champs nécessaires au test, avec une courte période de rétention. Comparez les compartiments personnel et privé pour :

- les cookies/local storage/service workers et le cache ;
- l’état de synchronisation/connexion du navigateur ;
- la langue, le fuseau horaire, les dimensions de l’écran/de la fenêtre et les polices ;
- les candidats WebRTC/réseau ;
- les permissions et les modifications visibles par les extensions ;
- les données user-agent TLS/HTTP côté serveur.

N’essayez pas de rendre Tor Browser « plus aléatoire ». La condition de réussite est la similarité avec son anonymity set standard et l’absence d’état personnel, et non une différence maximale avec le navigateur personnel.

Testez le copier-coller, le glisser-déposer, l’ouverture de fichiers téléchargés, les suggestions du password manager et les boutons des identity providers. Il s’agit de bridges fréquents entre les compartiments.

## Test d’isolation du système d’exploitation

### Tails

1. Commencez avec un fichier/canary bénin dans une session sans Persistent Storage.
2. Arrêtez complètement le système, redémarrez-le et confirmez qu’il a disparu.
3. Activez une seule catégorie de persistance requise, recommencez et confirmez que l’état indépendant du navigateur/de l’application n’est pas conservé.
4. Vérifiez que l’Unsafe Browser ne peut pas être utilisé après la connexion au portail pour une activité sensible et que les applications Tor se reconnectent normalement.

### Whonix/Qubes

1. Arrêtez le qube Gateway/net et prouvez que le qube Workstation/app ne peut atteindre ni IPv4, ni IPv6, ni DNS.
2. Essayez uniquement le chemin clipboard/fichier inter-qubes explicitement configuré et confirmez que les autres chemins de dossiers/appareils partagés sont absents.
3. Ouvrez un document de test bénin dans un qube disposable, fermez-le et confirmez que son état disparaît.
4. Vérifiez que le qube vault n’a aucun NetVM et ne peut pas en obtenir un via une modification du template/de la configuration par défaut.
5. Effectuez un snapshot/restore d’une VM de test et vérifiez si un état porteur d’identité réapparaît de manière inattendue.

## Test des métadonnées des communications

Pour chaque messenger sélectionné :

1. Créez des participants uniquement destinés aux tests sur des appareils contrôlés.
2. Notez les éléments requis pour l’inscription : téléphone, compte app-store, IP, push service, username ou invitation.
3. Envoyez un message bénin tout en inspectant les aperçus de notification, les desktops liés, les wearables et les backups.
4. Vérifiez les codes de sécurité/sûreté via un canal indépendant.
5. Désactivez les receipts/push ou activez un transport Tor/local, un à la fois, et observez les changements de fiabilité/métadonnées.
6. Exportez ou restaurez un backup de test et documentez précisément les éléments de profil, contacts et historique qu’il contient.
7. Perdez/révoquez un appareil de test et confirmez que les participants restants voient le changement de clé/appareil attendu.

Ne réalisez pas le test en contactant des personnes non impliquées ou en générant du trafic abusif.

## Test de nettoyage des fichiers

1. Hachez l’original et conservez-le dans un stockage de preuves chiffré :
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Créez une copie nettoyée en utilisant le processus spécifique au format décrit dans [Communications et partage préservant la confidentialité](privacy-preserving-communications-and-sharing.md).
3. Comparez les inventaires de métadonnées :
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Rendez/ouvrez la copie dans un contexte jetable. Vérifiez le contenu caché, les pièces jointes, les liens, les formulaires, les calques, les miniatures et les identifiants visuels.
5. Recherchez uniquement dans la copie mise en staging les chaînes connues d’auteur/e-mail/chemin canary.
6. Hachez la sortie finale et faites vérifier par une seconde personne le fichier exact qui sera publié.

L’absence dans la sortie d’ExifTool ne prouve pas l’anonymat ; les éléments internes du format, les pixels, la prose et les enregistrements de distribution subsistent.

## Test de privacy des paiements

Utilisez le montant autorisé le plus faible ou un réseau de test officiel/sandbox :

1. Décrivez la vue attendue pour le payeur, le bénéficiaire/marchand, l’émetteur/exchange, le réseau/nœud, le registre public et le comptable/contrôleur.
2. Créez une facture/un contexte marchand de test unique sans fausse identité.
3. Effectuez un seul paiement, puis collectez votre propre reçu, relevé, tableau de bord marchand, journal du wallet/nœud et vue de la blockchain publique le cas échéant.
4. Vérifiez si le montant, l’horodatage, l’adresse/token, le compte, l’IP/l’appareil, la livraison et le circuit de remboursement correspondent au tableau des observateurs.
5. Pour Bitcoin, inspectez la réutilisation des adresses, les inputs sélectionnés, la monnaie rendue et la consolidation ultérieure dans la vue de coin-control du wallet.
6. Pour les protocoles shielded, vérifiez le pool/chemin réel et ce qu’une viewing key révèle ; ne déduisez pas la privacy de la seule marque du wallet.
7. Pour l’e-cash/Taler, testez la sauvegarde/récupération, le remboursement et le rachat avec une petite valeur ; documentez les enregistrements aux limites mint/exchange/federation.
8. Révoquez une carte virtuelle/un identifiant de test et confirmez qu’une autorisation ultérieure échoue, tout en conservant une compréhension correcte de la gestion des remboursements légitimes.
9. Effectuez le rapprochement et conservez les justificatifs fiscaux/d’autorisation requis sous forme chiffrée.

Ne créez jamais de transferts circulaires, de fractionnement de seuil, de faux achats ou de remboursements suspects comme « test de privacy ».

## Exercice d’accountability de red-team autorisé

Avant l’exercice, réalisez un exercice sur table et un drill technique :

1. Un opérateur lance un canary bénin depuis chaque chemin source approuvé.
2. Le SOC cible consigne ce qu’il détecte sans recevoir l’identité de l’opérateur si un test en aveugle est prévu.
3. Le contrôleur de l’exercice résout source → engagement → opérateur à partir de la map séquestrée et du job record signé.
4. Le contrôleur envoie l’arrêt d’urgence ; l’opérateur et le propriétaire de l’infrastructure démontrent l’arrêt dans le délai défini par les ROE.
5. L’abuse team du provider reçoit le contact 24/7 et la référence d’autorisation corrects.
6. Les preuves indiquent la cible, l’heure, l’outil/le job et l’opérateur sans conserver le contenu de payload superflu.
7. Un second opérateur vérifie la révocation des credentials et le teardown des ressources.

Échouez la revue de readiness si le SOC peut voir trivialement une infrastructure personnelle/domestique **ou** si le contrôleur ne peut pas attribuer et arrêter rapidement la source.

## Modèle d’enregistrement du test
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
- [3] [ExifTool — FAQ et recommandations concernant les métadonnées](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Guide technique pour les tests et l’évaluation de la sécurité de l’information](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
