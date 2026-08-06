# Artefatti del browser

{{#include ../../../banners/hacktricks-training.md}}

## Artefatti dei browser <a href="#id-3def" id="id-3def"></a>

Gli artefatti del browser includono vari tipi di dati memorizzati dai browser web, come la cronologia di navigazione, i segnalibri e i dati della cache. Questi artefatti vengono conservati in cartelle specifiche all'interno del sistema operativo, con posizione e nome diversi a seconda del browser, ma generalmente memorizzano tipi di dati simili.

Ecco un riepilogo degli artefatti del browser più comuni:

- **Cronologia di navigazione**: tiene traccia delle visite dell'utente ai siti web ed è utile per identificare le visite a siti dannosi.
- **Dati di completamento automatico**: suggerimenti basati sulle ricerche frequenti, che offrono informazioni utili se combinati con la cronologia di navigazione.
- **Segnalibri**: siti salvati dall'utente per un accesso rapido.
- **Estensioni e Add-on**: estensioni o add-on del browser installati dall'utente.
- **Cache**: memorizza contenuti web (ad esempio immagini e file JavaScript) per migliorare i tempi di caricamento dei siti web, risultando utile per l'analisi forense.
- **Accessi**: credenziali di accesso memorizzate.
- **Favicon**: icone associate ai siti web, visualizzate nelle schede e nei segnalibri, utili per ottenere ulteriori informazioni sulle visite dell'utente.
- **Sessioni del browser**: dati relativi alle sessioni del browser aperte.
- **Download**: registri dei file scaricati tramite il browser.
- **Dati dei moduli**: informazioni inserite nei moduli web, salvate per fornire suggerimenti di compilazione automatica in futuro.
- **Miniature**: immagini di anteprima dei siti web.
- **Custom Dictionary.txt**: parole aggiunte dall'utente al dizionario del browser.

## Firefox

Firefox organizza i dati dell'utente all'interno di profili, memorizzati in posizioni specifiche in base al sistema operativo:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un file `profiles.ini` all'interno di queste cartelle elenca i profili dell'utente. I dati di ciascun profilo sono memorizzati in una cartella il cui nome è indicato nella variabile `Path` all'interno di `profiles.ini`, situata nella stessa directory del file `profiles.ini`. Se la cartella di un profilo è assente, potrebbe essere stata eliminata.

All'interno di ogni cartella del profilo si trovano diversi file importanti:<sup>[[1]](#references)</sup>

- **places.sqlite**: memorizza la cronologia, i segnalibri e i download. Strumenti come [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) su Windows possono accedere ai dati della cronologia.
- Utilizzare query SQL specifiche per estrarre le informazioni sulla cronologia e sui download.
- **bookmarkbackups**: contiene backup dei segnalibri.
- **formhistory.sqlite**: memorizza i dati dei moduli web.
- **handlers.json**: gestisce i gestori dei protocolli.
- **persdict.dat**: parole del dizionario personalizzato.
- **addons.json** e **extensions.sqlite**: informazioni sugli add-on e sulle estensioni installati.
- **cookies.sqlite**: memorizza i cookie; su Windows è disponibile [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) per l'ispezione.
- **cache2/entries** o **startupCache**: dati della cache, accessibili tramite strumenti come [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: memorizza le favicon.
- **prefs.js**: impostazioni e preferenze dell'utente.
- **downloads.sqlite**: database dei download precedente, ora integrato in places.sqlite.
- **thumbnails**: miniature dei siti web.
- **logins.json**: informazioni di accesso crittografate.
- **key4.db** o **key3.db**: memorizza le chiavi di crittografia utilizzate per proteggere le informazioni sensibili.

Inoltre, è possibile controllare le impostazioni anti-phishing del browser cercando le voci `browser.safebrowsing` in `prefs.js`, che indicano se le funzionalità di navigazione sicura sono abilitate o disabilitate.<sup>[[2]](#references)</sup>

Per provare a decrittografare la password principale, è possibile utilizzare [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Con il seguente script e la relativa chiamata è possibile specificare un file di password da sottoporre a brute force:
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

Google Chrome memorizza i profili utente in posizioni specifiche in base al sistema operativo:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

All'interno di queste directory, la maggior parte dei dati utente si trova nelle cartelle **Default/** o **ChromeDefaultData/**. I seguenti file contengono dati significativi:<sup>[[1]](#references)</sup>

- **History**: Contiene URL, download e parole chiave di ricerca. Su Windows, è possibile usare [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) per leggere la cronologia. La colonna "Transition Type" ha vari significati, tra cui clic dell'utente sui link, URL digitati, invii di moduli e ricaricamenti delle pagine.
- **Cookies**: Memorizza i cookie. Per l'ispezione è disponibile [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene i dati memorizzati nella cache. Per esaminarli, gli utenti Windows possono utilizzare [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Le desktop app basate su Electron (ad esempio Discord) usano anch'esse Chromium Simple Cache e lasciano numerosi artefatti su disco. Vedere:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: I bookmark dell'utente.
- **Web Data**: Contiene la cronologia dei moduli.
- **Favicons**: Memorizza le favicon dei siti web.
- **Login Data**: Include credenziali di accesso come nomi utente e password.
- **Current Session**/**Current Tabs**: Dati relativi alla sessione di navigazione corrente e alle schede aperte.
- **Last Session**/**Last Tabs**: Informazioni sui siti attivi durante l'ultima sessione prima della chiusura di Chrome.
- **Extensions**: Directory delle estensioni e degli addon del browser.
- **Thumbnails**: Memorizza le miniature dei siti web.
- **Preferences**: Un file ricco di informazioni, incluse impostazioni per plugin, estensioni, pop-up, notifiche e altro.
- **Browser’s built-in anti-phishing**: Per verificare se la protezione anti-phishing e anti-malware è abilitata, eseguire `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Nell'output cercare `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **Recupero dei dati dai database SQLite**

Come si può osservare nelle sezioni precedenti, sia Chrome sia Firefox usano database **SQLite** per memorizzare i dati. È possibile **recuperare le entry eliminate usando il tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oppure** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestisce i propri dati e metadati in varie posizioni, facilitando la separazione delle informazioni memorizzate dai relativi dettagli per un accesso e una gestione più semplici.

### Memorizzazione dei metadati

I metadati di Internet Explorer sono memorizzati in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (dove VX può essere V01, V16 o V24). Il file `V01.log` associato potrebbe mostrare differenze nei tempi di modifica rispetto a `WebcacheVX.data`, indicando la necessità di una riparazione tramite `esentutl /r V01 /d`. Questi metadati, contenuti in un database ESE, possono essere recuperati e analizzati rispettivamente con tool come photorec ed [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Nella tabella **Containers** è possibile individuare le tabelle o i container specifici in cui è memorizzato ogni segmento di dati, inclusi i dettagli della cache per altri tool Microsoft come Skype.

### Analisi della cache

Il tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) consente di analizzare la cache e richiede il percorso della cartella in cui estrarre i dati della cache. I metadati della cache includono nome file, directory, numero di accessi, origine dell'URL e timestamp che indicano i momenti di creazione, accesso, modifica e scadenza della cache.

### Gestione dei cookie

I cookie possono essere analizzati usando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadati che includono nomi, URL, numero di accessi e vari dettagli temporali. I cookie persistenti sono memorizzati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mentre i cookie di sessione risiedono in memoria.

### Dettagli dei download

I metadati dei download sono accessibili tramite [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), con container specifici che contengono dati come URL, tipo di file e posizione del download. I file fisici si trovano in `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Cronologia di navigazione

Per esaminare la cronologia di navigazione è possibile usare [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), indicando la posizione dei file della cronologia estratti e configurando Internet Explorer. I metadati includono i tempi di modifica e accesso, oltre al numero di accessi. I file della cronologia si trovano in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL digitati

Gli URL digitati e i relativi tempi di utilizzo sono memorizzati nel registro, all'interno di `NTUSER.DAT`, nei percorsi `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`. Questi dati registrano gli ultimi 50 URL inseriti dall'utente e i relativi orari dell'ultimo inserimento.

## Microsoft Edge

Microsoft Edge memorizza i dati utente in `%userprofile%\Appdata\Local\Packages`. I percorsi per i vari tipi di dati sono:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

I dati di Safari sono memorizzati in `/Users/$User/Library/Safari`. I file principali includono:<sup>[[3]](#references)</sup>

- **History.db**: Contiene le tabelle `history_visits` e `history_items` con URL e timestamp delle visite. Usare `sqlite3` per eseguire query.
- **Downloads.plist**: Informazioni sui file scaricati.
- **Bookmarks.plist**: Memorizza gli URL aggiunti ai bookmark.
- **TopSites.plist**: I siti visitati più frequentemente.
- **Extensions.plist**: Elenco delle estensioni del browser Safari. Usare `plutil` o `pluginkit` per recuperarlo.
- **UserNotificationPermissions.plist**: Domini autorizzati a inviare notifiche push. Usare `plutil` per analizzarlo.
- **LastSession.plist**: Schede dell'ultima sessione. Usare `plutil` per analizzarlo.
- **Browser’s built-in anti-phishing**: Verificare usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una risposta pari a 1 indica che la funzionalità è attiva.<sup>[[2]](#references)</sup>

## Opera

I dati di Opera si trovano in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e condividono il formato di Chrome per cronologia e download.

- **Browser’s built-in anti-phishing**: Verificare se `fraud_protection_enabled` nel file Preferences è impostato su `true` usando `grep`.<sup>[[2]](#references)</sup>

Questi percorsi e comandi sono fondamentali per accedere ai dati di navigazione memorizzati dai diversi browser web e comprenderli.

## Riferimenti

- [1] [Web Browsers Forensics: A Guide On Doing Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
