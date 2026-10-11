# Artefatti del browser

{{#include ../../../banners/hacktricks-training.md}}

## Artefatti dei browser <a href="#id-3def" id="id-3def"></a>

Gli artefatti del browser includono vari tipi di dati memorizzati dai browser web, come la cronologia di navigazione, i segnalibri e i dati della cache. Questi artefatti si trovano in cartelle specifiche all'interno del sistema operativo, che variano per posizione e nome a seconda del browser, ma in genere memorizzano tipi di dati simili.

Ecco un riepilogo degli artefatti del browser più comuni:

- **Cronologia di navigazione**: registra i siti web visitati dall'utente ed è utile per identificare le visite a siti dannosi.
- **Dati di completamento automatico**: suggerimenti basati sulle ricerche frequenti, che offrono informazioni utili se combinati con la cronologia di navigazione.
- **Segnalibri**: siti salvati dall'utente per accedervi rapidamente.
- **Estensioni e componenti aggiuntivi**: estensioni o componenti aggiuntivi del browser installati dall'utente.
- **Cache**: memorizza contenuti web (ad es. immagini, file JavaScript) per velocizzare il caricamento dei siti web; è preziosa per l'analisi forense.
- **Accessi**: credenziali di accesso memorizzate.
- **Favicon**: icone associate ai siti web, visualizzate nelle schede e nei segnalibri, utili per ottenere ulteriori informazioni sulle visite dell'utente.
- **Sessioni del browser**: dati relativi alle sessioni del browser aperte.
- **Download**: record dei file scaricati tramite il browser.
- **Dati dei moduli**: informazioni inserite nei moduli web e salvate per i futuri suggerimenti di compilazione automatica.
- **Miniature**: immagini di anteprima dei siti web.
- **Custom Dictionary.txt**: parole aggiunte dall'utente al dizionario del browser.

## Firefox

Firefox organizza i dati dell'utente nei profili, memorizzati in posizioni specifiche a seconda del sistema operativo:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un file `profiles.ini` in queste directory elenca i profili utente. I dati di ciascun profilo sono memorizzati in una cartella il cui nome è indicato nella variabile `Path` all'interno di `profiles.ini`, che si trova nella stessa directory del file `profiles.ini`. Se la cartella di un profilo non è presente, potrebbe essere stata eliminata.

All'interno di ogni cartella del profilo si trovano diversi file importanti:<sup>[[1]](#references)</sup>

- **places.sqlite**: memorizza la cronologia, i segnalibri e i download. Su Windows, strumenti come [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) possono accedere ai dati della cronologia.
  - Usa query SQL specifiche per estrarre informazioni sulla cronologia e sui download.
- **bookmarkbackups**: contiene copie di backup dei segnalibri.
- **formhistory.sqlite**: memorizza i dati dei moduli web.
- **handlers.json**: gestisce i gestori di protocollo.
- **persdict.dat**: parole del dizionario personalizzato.
- **addons.json** e **extensions.sqlite**: informazioni sui componenti aggiuntivi e sulle estensioni installati.
- **cookies.sqlite**: memorizza i cookie; su Windows è possibile ispezionarli con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** o **startupCache**: dati della cache, accessibili con strumenti come [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: memorizza le favicon.
- **prefs.js**: impostazioni e preferenze dell'utente.
- **downloads.sqlite**: vecchio database dei download, ora integrato in places.sqlite.
- **thumbnails**: miniature dei siti web.
- **logins.json**: informazioni di accesso crittografate.
- **key4.db** o **key3.db**: memorizza le chiavi di crittografia usate per proteggere le informazioni sensibili.

Inoltre, è possibile verificare le impostazioni anti-phishing del browser cercando le voci `browser.safebrowsing` in `prefs.js`, che indicano se le funzionalità di navigazione sicura sono abilitate o disabilitate.<sup>[[2]](#references)</sup>

Per decrittare gli accessi salvati da un profilo accessibile, è necessario fornire o recuperare separatamente la [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), se configurata; il profilo non rivela tale password. Verifica che le credenziali recuperate consentano l'accesso all'account web corrispondente. Per l'accesso root in Unix occorre dimostrare separatamente che le credenziali sono accettate anche dall'autenticazione Unix per root. Puoi esaminare gli accessi salvati con [firefox_decrypt](https://github.com/unode/firefox_decrypt). L'esempio seguente verifica le password Primary candidate contenute in un file di password:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Artefatti dei browser - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome memorizza i profili utente in percorsi specifici in base al sistema operativo:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

All'interno di queste directory, la maggior parte dei dati utente si trova nelle cartelle **Default/** o **ChromeDefaultData/**. I seguenti file contengono dati rilevanti:<sup>[[1]](#references)</sup>

- **History**: contiene URL, download e parole chiave di ricerca. In Windows, è possibile usare [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) per leggere la cronologia. La colonna "Transition Type" può indicare varie attività, tra cui clic dell'utente sui link, URL digitati, invii di moduli e ricaricamenti delle pagine.
- **Cookies**: memorizza i cookie. Per esaminarli, è disponibile [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: contiene dati memorizzati nella cache. In Windows, è possibile esaminarli con [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Anche le app desktop basate su Electron (ad es., Discord) usano Chromium Simple Cache e lasciano numerosi artefatti su disco. Vedi:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: segnalibri dell'utente.
- **Web Data**: contiene la cronologia dei moduli.
- **Favicons**: memorizza le favicon dei siti web.
- **Login Data**: contiene credenziali di accesso come nomi utente e password.
- **Current Session**/**Current Tabs**: dati sulla sessione di navigazione corrente e sulle schede aperte.
- **Last Session**/**Last Tabs**: informazioni sui siti attivi durante l'ultima sessione prima della chiusura di Chrome.
- **Extensions**: directory delle estensioni e degli addon del browser.
- **Thumbnails**: memorizza le miniature dei siti web.
- **Preferences**: file ricco di informazioni, tra cui impostazioni di plugin, estensioni, pop-up, notifiche e altro.
- **Protezione anti-phishing integrata nel browser**: per verificare se la protezione anti-phishing e antimalware è abilitata, esegui `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Nell'output, cerca `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

La directory `Local Extension Settings/<extension-id>/` di un profilo Chromium può contenere dati locali dell'estensione, incluso materiale crittografico di password manager. Ad esempio, [Passbolt dichiara che la propria chiave privata crittografata viene conservata nell'archiviazione locale dell'estensione del browser](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/) e il suo [ID dell'estensione Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) identifica la directory pertinente. La sola presenza della directory non prova che contenga una chiave e non sblocca un vault: l'utente deve poter accedere ai dati del profilo e disporre di una chiave privata e di una passphrase utilizzabili, oltre che di un percorso di recupero/autenticazione autorizzato verso il server. Se un elemento del vault contiene la password di un account del sistema operativo, è necessario verificare separatamente il riutilizzo della password per quell'account. Le operazioni di enumerazione di routine dovrebbero riportare solo il percorso di archiviazione, senza estrarre i file LevelDB o i valori segreti.

## **Recupero dei dati dai database SQLite**

Come si può osservare nelle sezioni precedenti, sia Chrome sia Firefox usano database **SQLite** per memorizzare i dati. È possibile **recuperare le voci eliminate usando lo strumento** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oppure** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestisce i propri dati e metadati in varie posizioni, separando le informazioni memorizzate dai relativi dettagli per facilitarne l'accesso e la gestione.

### Archiviazione dei metadati

I metadati di Internet Explorer sono memorizzati in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (dove VX è V01, V16 o V24). Il file `V01.log` associato potrebbe mostrare discrepanze nei tempi di modifica rispetto a `WebcacheVX.data`, indicando la necessità di una riparazione con `esentutl /r V01 /d`. Questi metadati, contenuti in un database ESE, possono essere recuperati e ispezionati rispettivamente con strumenti come photorec ed [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Nella tabella **Containers** è possibile individuare le tabelle o i contenitori specifici in cui è archiviato ciascun segmento di dati, inclusi i dettagli della cache di altri strumenti Microsoft come Skype.

### Ispezione della cache

Lo strumento [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) consente di ispezionare la cache e richiede il percorso della cartella in cui estrarre i dati della cache. I metadati della cache includono nome del file, directory, numero di accessi, URL di origine e timestamp di creazione, accesso, modifica e scadenza della cache.

### Gestione dei cookie

È possibile esaminare i cookie con [IECookiesView](https://www.nirsoft.net/utils/iecookies.html); i metadati includono nomi, URL, numero di accessi e vari dettagli temporali. I cookie persistenti sono memorizzati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mentre quelli di sessione risiedono in memoria.

### Dettagli sui download

È possibile accedere ai metadati dei download tramite [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); contenitori specifici includono dati come URL, tipo di file e percorso di download. I file sono disponibili in `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Cronologia di navigazione

Per esaminare la cronologia di navigazione, è possibile usare [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html`; sono necessari il percorso dei file della cronologia estratti e la configurazione per Internet Explorer. I metadati includono gli orari di modifica e accesso, oltre al numero di accessi. I file della cronologia si trovano in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL digitati

Gli URL digitati e gli orari di inserimento sono memorizzati nel registro, in `NTUSER.DAT`, nei percorsi `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`. Queste voci registrano gli ultimi 50 URL inseriti dall'utente e i rispettivi orari di inserimento.

## Microsoft Edge

Microsoft Edge memorizza i dati utente in `%userprofile%\Appdata\Local\Packages`. I percorsi dei vari tipi di dati sono:<sup>[[1]](#references)</sup>

- **Percorso del profilo**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Cronologia, cookie e download**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Impostazioni, segnalibri e lista di lettura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Ultime sessioni attive**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

I dati di Safari sono memorizzati in `/Users/$User/Library/Safari`. I file principali includono:<sup>[[3]](#references)</sup>

- **History.db**: contiene le tabelle `history_visits` e `history_items` con URL e timestamp delle visite. Usa `sqlite3` per eseguire query.
- **Downloads.plist**: informazioni sui file scaricati.
- **Bookmarks.plist**: memorizza gli URL dei segnalibri.
- **TopSites.plist**: siti visitati più frequentemente.
- **Extensions.plist**: elenco delle estensioni del browser Safari. Usa `plutil` o `pluginkit` per recuperarlo.
- **UserNotificationPermissions.plist**: domini autorizzati a inviare notifiche push. Usa `plutil` per analizzarlo.
- **LastSession.plist**: schede dell'ultima sessione. Usa `plutil` per analizzarlo.
- **Protezione anti-phishing integrata nel browser**: verifica con `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una risposta pari a 1 indica che la funzionalità è attiva.<sup>[[2]](#references)</sup>

## Opera

I dati di Opera si trovano in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e la cronologia e i download usano lo stesso formato di Chrome.

- **Protezione anti-phishing integrata nel browser**: verifica con `grep` se `fraud_protection_enabled` nel file Preferences è impostato su `true`.<sup>[[2]](#references)</sup>

Questi percorsi e comandi sono fondamentali per accedere ai dati di navigazione memorizzati dai diversi browser web e comprenderli.

## References

- [1] [Analisi forense dei browser web: guida all'analisi forense dei browser web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Risposta agli incidenti su macOS | Parte 3: manipolazione del sistema](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Risposta agli incidenti su OS X: scripting e analisi, di Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
