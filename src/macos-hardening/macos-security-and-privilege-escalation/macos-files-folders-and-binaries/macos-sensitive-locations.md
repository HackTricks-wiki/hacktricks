# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwords

### Shadow Passwords

La password shadow è memorizzata con la configurazione dell'utente in plists situati in **`/var/db/dslocal/nodes/Default/users/`**.\
Il seguente oneliner può essere utilizzato per estrarre **tutte le informazioni sugli utenti** (inclusi i dati dell'hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Script come questo**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**questo**](https://github.com/octomagon/davegrohl.git) possono essere utilizzati per trasformare l'hash in **formato** **hashcat**.

Un'alternativa one-liner che eseguirà il dump delle credenziali di tutti gli account non di servizio in formato hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Un altro modo per ottenere il `ShadowHashData` di un utente è utilizzare `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Questo file è **utilizzato solo** quando il sistema è in **modalità utente singolo** (quindi non molto frequentemente).

### Keychain Dump

Nota che quando si utilizza il binario di sicurezza per **estrarre le password decrittografate**, verranno visualizzati diversi prompt che chiederanno all'utente di consentire questa operazione.
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
> Basato su questo commento [juuso/keychaindump#10 (commento)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), sembra che questi strumenti non funzionino più in Big Sur.

### Panoramica di Keychaindump

Uno strumento chiamato **keychaindump** è stato sviluppato per estrarre password dai portachiavi di macOS, ma presenta limitazioni sulle versioni più recenti di macOS come Big Sur, come indicato in una [discussione](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'uso di **keychaindump** richiede che l'attaccante ottenga accesso e escalare i privilegi a **root**. Lo strumento sfrutta il fatto che il portachiavi è sbloccato per impostazione predefinita al momento del login dell'utente per comodità, consentendo alle applicazioni di accedervi senza richiedere ripetutamente la password dell'utente. Tuttavia, se un utente sceglie di bloccare il proprio portachiavi dopo ogni utilizzo, **keychaindump** diventa inefficace.

**Keychaindump** opera prendendo di mira un processo specifico chiamato **securityd**, descritto da Apple come un demone per operazioni di autorizzazione e crittografia, cruciale per accedere al portachiavi. Il processo di estrazione implica l'identificazione di una **Master Key** derivata dalla password di accesso dell'utente. Questa chiave è essenziale per leggere il file del portachiavi. Per localizzare la **Master Key**, **keychaindump** scansiona l'heap di memoria di **securityd** utilizzando il comando `vmmap`, cercando potenziali chiavi all'interno delle aree contrassegnate come `MALLOC_TINY`. Il seguente comando viene utilizzato per ispezionare queste posizioni di memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Dopo aver identificato potenziali chiavi master, **keychaindump** cerca tra gli heap un modello specifico (`0x0000000000000018`) che indica un candidato per la chiave master. Ulteriori passaggi, inclusa la deoffuscazione, sono necessari per utilizzare questa chiave, come delineato nel codice sorgente di **keychaindump**. Gli analisti che si concentrano su quest'area dovrebbero notare che i dati cruciali per decrittografare il portachiavi sono memorizzati nella memoria del processo **securityd**. Un comando di esempio per eseguire **keychaindump** è:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) può essere utilizzato per estrarre i seguenti tipi di informazioni da un keychain OSX in modo forense:

- Password del keychain hashata, adatta per il cracking con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
- Password di Internet
- Password generiche
- Chiavi private
- Chiavi pubbliche
- Certificati X509
- Note sicure
- Password di Appleshare

Data la password di sblocco del keychain, una chiave master ottenuta utilizzando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un file di sblocco come SystemKey, Chainbreaker fornirà anche password in chiaro.

Senza uno di questi metodi per sbloccare il Keychain, Chainbreaker mostrerà tutte le altre informazioni disponibili.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) utilizzando SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) decifrando l'hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) con il dump della memoria**

[Segui questi passaggi](../#dumping-memory-with-osxpmem) per eseguire un **dump della memoria**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) utilizzando la password dell'utente**

Se conosci la password dell'utente, puoi usarla per **dumpare e decrittare i portachiavi che appartengono all'utente**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Il file **kcpassword** è un file che contiene la **password di accesso dell'utente**, ma solo se il proprietario del sistema ha **abilitato l'accesso automatico**. Pertanto, l'utente verrà automaticamente connesso senza essere invitato a inserire una password (il che non è molto sicuro).

La password è memorizzata nel file **`/etc/kcpassword`** xored con la chiave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se la password degli utenti è più lunga della chiave, la chiave verrà riutilizzata.\
Questo rende la password piuttosto facile da recuperare, ad esempio utilizzando script come [**questo**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Puoi trovare i dati delle Notifiche in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La maggior parte delle informazioni interessanti si troverà in **blob**. Quindi dovrai **estrarre** quel contenuto e **trasformarlo** in un formato **leggibile** **dall'uomo** o utilizzare **`strings`**. Per accedervi puoi fare:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Note

Le **note** degli utenti possono essere trovate in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferenze

In macOS, le preferenze delle app si trovano in **`$HOME/Library/Preferences`** e in iOS si trovano in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS, lo strumento cli **`defaults`** può essere utilizzato per **modificare il file delle Preferenze**.

**`/usr/sbin/cfprefsd`** rivendica i servizi XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e può essere chiamato per eseguire azioni come modificare le preferenze.

## OpenDirectory permissions.plist

Il file `/System/Library/OpenDirectory/permissions.plist` contiene le autorizzazioni applicate sugli attributi dei nodi ed è protetto da SIP.\
Questo file concede autorizzazioni a utenti specifici tramite UUID (e non uid) in modo che possano accedere a informazioni sensibili specifiche come `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys`, tra gli altri:
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
## Notifiche di Sistema

### Notifiche Darwin

Il demone principale per le notifiche è **`/usr/sbin/notifyd`**. Per ricevere notifiche, i client devono registrarsi attraverso il port Mach `com.apple.system.notification_center` (controllali con `sudo lsmp -p <pid notifyd>`). Il demone è configurabile con il file `/etc/notify.conf`.

I nomi utilizzati per le notifiche sono notazioni DNS inverse uniche e quando una notifica viene inviata a uno di essi, il/i client che hanno indicato di poterla gestire la riceveranno.

È possibile dumpare lo stato attuale (e vedere tutti i nomi) inviando il segnale SIGUSR2 al processo notifyd e leggendo il file generato: `/var/run/notifyd_<pid>.status`:
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
### Centro Notifiche Distribuito

Il **Centro Notifiche Distribuito** il cui binario principale è **`/usr/sbin/distnoted`**, è un altro modo per inviare notifiche. Espone alcuni servizi XPC e esegue alcuni controlli per cercare di verificare i client.

### Notifiche Push di Apple (APN)

In questo caso, le applicazioni possono registrarsi per **argomenti**. Il client genererà un token contattando i server di Apple tramite **`apsd`**.\
Poi, i fornitori avranno anche generato un token e saranno in grado di connettersi ai server di Apple per inviare messaggi ai client. Questi messaggi saranno ricevuti localmente da **`apsd`** che inoltrerà la notifica all'applicazione in attesa.

Le preferenze si trovano in `/Library/Preferences/com.apple.apsd.plist`.

C'è un database locale di messaggi situato in macOS in `/Library/Application\ Support/ApplePushService/aps.db` e in iOS in `/var/mobile/Library/ApplePushService`. Ha 3 tabelle: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
È anche possibile ottenere informazioni sul demone e sulle connessioni utilizzando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifiche Utente

Queste sono le notifiche che l'utente dovrebbe vedere sullo schermo:

- **`CFUserNotification`**: Queste API forniscono un modo per mostrare sullo schermo un pop-up con un messaggio.
- **La Bacheca**: Questa mostra in iOS un banner che scompare e sarà memorizzato nel Centro Notifiche.
- **`NSUserNotificationCenter`**: Questa è la bacheca di iOS in MacOS. Il database con le notifiche si trova in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
