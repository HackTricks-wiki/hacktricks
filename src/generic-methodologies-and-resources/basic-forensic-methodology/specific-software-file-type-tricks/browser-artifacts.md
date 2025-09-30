# Artefatti del Browser

{{#include ../../../banners/hacktricks-training.md}}

## Artefatti del Browser <a href="#id-3def" id="id-3def"></a>

Gli artefatti del browser includono vari tipi di dati memorizzati dai browser web, come la cronologia di navigazione, i segnalibri e la cache. Questi artefatti sono conservati in cartelle specifiche all'interno del sistema operativo, con posizioni e nomi differenti a seconda del browser, ma generalmente contengono tipi di dati simili.

Ecco un riepilogo dei più comuni artefatti del browser:

- **Navigation History**: Tiene traccia delle visite dell'utente ai siti web, utile per identificare visite a siti malevoli.
- **Autocomplete Data**: Suggerimenti basati sulle ricerche frequenti, che offrono informazioni utili se combinati con la cronologia di navigazione.
- **Bookmarks**: Siti salvati dall'utente per un accesso rapido.
- **Extensions and Add-ons**: Estensioni o add-on del browser installati dall'utente.
- **Cache**: Memorizza contenuti web (es. immagini, file JavaScript) per migliorare i tempi di caricamento dei siti, preziosa per l'analisi forense.
- **Logins**: Credenziali di accesso memorizzate.
- **Favicons**: Icone associate ai siti web, visualizzate nelle tab e nei segnalibri, utili per informazioni aggiuntive sulle visite utente.
- **Browser Sessions**: Dati relativi alle sessioni del browser aperte.
- **Downloads**: Registri dei file scaricati tramite il browser.
- **Form Data**: Informazioni inserite nei form web, salvate per suggerimenti di autofill futuri.
- **Thumbnails**: Immagini di anteprima dei siti web.
- **Custom Dictionary.txt**: Parole aggiunte dall'utente al dizionario del browser.

## Firefox

Firefox organizza i dati utente all'interno di profili, memorizzati in posizioni specifiche a seconda del sistema operativo:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un file `profiles.ini` all'interno di queste directory elenca i profili utente. I dati di ciascun profilo sono memorizzati in una cartella il cui nome è indicato nella variabile `Path` dentro `profiles.ini`, situata nella stessa directory di `profiles.ini`. Se la cartella di un profilo manca, potrebbe essere stata cancellata.

All'interno di ogni cartella del profilo, puoi trovare diversi file importanti:

- **places.sqlite**: Memorizza cronologia, segnalibri e download. Tool come [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) su Windows possono accedere ai dati della cronologia.
- Use specific SQL queries to extract history and downloads information.
- **bookmarkbackups**: Contiene backup dei segnalibri.
- **formhistory.sqlite**: Memorizza i dati dei form web.
- **handlers.json**: Gestisce i protocol handlers.
- **persdict.dat**: Parole del dizionario personalizzato.
- **addons.json** and **extensions.sqlite**: Informazioni su add-on ed estensioni installate.
- **cookies.sqlite**: Memorizzazione dei cookie, con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponibile per l'ispezione su Windows.
- **cache2/entries** or **startupCache**: Dati di cache, accessibili tramite tool come [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Memorizza i favicons.
- **prefs.js**: Impostazioni e preferenze utente.
- **downloads.sqlite**: Vecchio database dei download, ora integrato in places.sqlite.
- **thumbnails**: Thumbnails dei siti web.
- **logins.json**: Informazioni di login criptate.
- **key4.db** o **key3.db**: Memorizzano le chiavi di cifratura per proteggere le informazioni sensibili.

Inoltre, per controllare le impostazioni anti-phishing del browser è possibile cercare voci `browser.safebrowsing` in `prefs.js`, che indicano se le funzionalità di safe browsing sono abilitate o disabilitate.

Per provare a decrittare la password principale, puoi usare [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Con il seguente script e la chiamata puoi specificare un file di password per eseguire brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome memorizza i profili utente in posizioni specifiche a seconda del sistema operativo:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

All'interno di queste directory, la maggior parte dei dati utente si trova nelle cartelle **Default/** o **ChromeDefaultData/**. I seguenti file contengono dati importanti:

- **History**: Contiene URL, download e parole chiave di ricerca. Su Windows è possibile usare [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) per leggere la history. La colonna "Transition Type" ha diversi significati, inclusi click dell'utente sui link, URL digitati, invio di form e ricariche della pagina.
- **Cookies**: Memorizza i cookie. Per l'ispezione è disponibile [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene dati in cache. Per ispezionare, gli utenti Windows possono utilizzare [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Le app desktop basate su Electron (es. Discord) usano anch'esse Chromium Simple Cache e lasciano ricchi artefatti su disco. Vedi:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Segnalibri dell'utente.
- **Web Data**: Contiene la cronologia dei form.
- **Favicons**: Memorizza i favicons dei siti.
- **Login Data**: Include credenziali di accesso come username e password.
- **Current Session**/**Current Tabs**: Dati sulla sessione di navigazione corrente e sulle schede aperte.
- **Last Session**/**Last Tabs**: Informazioni sui siti attivi nell'ultima sessione prima della chiusura di Chrome.
- **Extensions**: Directory per le estensioni e gli addon del browser.
- **Thumbnails**: Memorizza le miniature dei siti web.
- **Preferences**: Un file ricco di informazioni, incluse impostazioni per plugin, estensioni, pop-up, notifiche e altro.
- **Browser’s built-in anti-phishing**: Per verificare se la protezione anti-phishing e malware è abilitata, esegui `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Cerca `{"enabled: true,"}` nell'output.

## **SQLite DB Data Recovery**

Come si può osservare nelle sezioni precedenti, sia Chrome che Firefox usano database **SQLite** per memorizzare i dati. È possibile **recuperare voci cancellate usando lo strumento** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestisce i suoi dati e metadati in varie posizioni, facilitando la separazione delle informazioni memorizzate e dei relativi dettagli per un accesso e una gestione più semplici.

### Metadata Storage

I metadati per Internet Explorer sono memorizzati in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (con VX che può essere V01, V16 o V24). Insieme a questo, il file `V01.log` potrebbe mostrare discrepanze nei tempi di modifica rispetto a `WebcacheVX.data`, indicando la necessità di riparazione con `esentutl /r V01 /d`. Questi metadati, contenuti in un database ESE, possono essere recuperati e ispezionati rispettivamente con strumenti come photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Nella tabella **Containers** si possono individuare le tabelle o i container specifici dove è memorizzato ogni segmento di dati, includendo dettagli di cache per altri strumenti Microsoft come Skype.

### Cache Inspection

Lo strumento [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permette l'ispezione della cache, richiedendo la posizione della cartella di estrazione dei dati di cache. I metadati della cache includono nome file, directory, numero di accessi, URL di origine e timestamp che indicano creazione, accesso, modifica e scadenza della cache.

### Cookies Management

I cookie possono essere esplorati usando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadati che comprendono nomi, URL, conteggio accessi e vari dettagli temporali. I cookie persistenti sono memorizzati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mentre i cookie di sessione risiedono in memoria.

### Download Details

I metadati dei download sono accessibili tramite [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), con container specifici che contengono dati come URL, tipo di file e posizione di download. I file fisici possono essere trovati sotto `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Per esaminare la cronologia di navigazione, è possibile usare [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), indicando la posizione dei file di history estratti e configurando lo strumento per Internet Explorer. I metadati includono tempi di modifica e accesso, insieme al conteggio degli accessi. I file di history si trovano in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Gli URL digitati e i tempi del loro utilizzo sono memorizzati nel registro sotto `NTUSER.DAT` in `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`, tracciando gli ultimi 50 URL inseriti dall'utente e i relativi ultimi tempi di input.

## Microsoft Edge

Microsoft Edge memorizza i dati utente in `%userprofile%\Appdata\Local\Packages`. I percorsi per i vari tipi di dati sono:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

I dati di Safari sono memorizzati in `/Users/$User/Library/Safari`. File chiave includono:

- **History.db**: Contiene le tabelle `history_visits` e `history_items` con URL e timestamp delle visite. Usa `sqlite3` per interrogare.
- **Downloads.plist**: Informazioni sui file scaricati.
- **Bookmarks.plist**: Memorizza gli URL preferiti.
- **TopSites.plist**: Siti più visitati.
- **Extensions.plist**: Elenco delle estensioni del browser Safari. Usa `plutil` o `pluginkit` per recuperarne il contenuto.
- **UserNotificationPermissions.plist**: Domini autorizzati a inviare notifiche. Usa `plutil` per il parsing.
- **LastSession.plist**: Schede dall'ultima sessione. Usa `plutil` per il parsing.
- **Browser’s built-in anti-phishing**: Verifica con `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una risposta di 1 indica che la funzionalità è attiva.

## Opera

I dati di Opera risiedono in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e condividono il formato di Chrome per history e download.

- **Browser’s built-in anti-phishing**: Verifica controllando se `fraud_protection_enabled` nel file Preferences è impostato su `true` usando `grep`.

Questi percorsi e comandi sono cruciali per accedere e comprendere i dati di navigazione memorizzati dai diversi web browser.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
