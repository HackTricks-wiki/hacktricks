# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Gli artefatti del browser includono vari tipi di dati memorizzati dai browser web, come la cronologia di navigazione, i segnalibri e i dati della cache. Questi artefatti sono conservati in cartelle specifiche all'interno del sistema operativo, che differiscono per posizione e nome tra i browser, ma generalmente memorizzano tipi di dati simili.

Ecco un riepilogo degli artefatti del browser più comuni:

- **Cronologia di Navigazione**: Tiene traccia delle visite degli utenti ai siti web, utile per identificare le visite a siti malevoli.
- **Dati di Autocompletamento**: Suggerimenti basati su ricerche frequenti, offrendo informazioni quando combinati con la cronologia di navigazione.
- **Segnalibri**: Siti salvati dall'utente per un accesso rapido.
- **Estensioni e Componenti Aggiuntivi**: Estensioni del browser o componenti aggiuntivi installati dall'utente.
- **Cache**: Memorizza contenuti web (ad es., immagini, file JavaScript) per migliorare i tempi di caricamento dei siti web, prezioso per l'analisi forense.
- **Accessi**: Credenziali di accesso memorizzate.
- **Favicons**: Icone associate ai siti web, che appaiono nelle schede e nei segnalibri, utili per ulteriori informazioni sulle visite degli utenti.
- **Sessioni del Browser**: Dati relativi alle sessioni del browser aperte.
- **Download**: Registrazioni dei file scaricati tramite il browser.
- **Dati dei Moduli**: Informazioni inserite nei moduli web, salvate per future suggerimenti di autocompletamento.
- **Miniature**: Immagini di anteprima dei siti web.
- **Custom Dictionary.txt**: Parole aggiunte dall'utente al dizionario del browser.

## Firefox

Firefox organizza i dati degli utenti all'interno dei profili, memorizzati in posizioni specifiche in base al sistema operativo:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un file `profiles.ini` all'interno di queste directory elenca i profili utente. I dati di ciascun profilo sono memorizzati in una cartella nominata nella variabile `Path` all'interno di `profiles.ini`, situata nella stessa directory di `profiles.ini` stesso. Se la cartella di un profilo è mancante, potrebbe essere stata eliminata.

All'interno di ciascuna cartella del profilo, puoi trovare diversi file importanti:

- **places.sqlite**: Memorizza cronologia, segnalibri e download. Strumenti come [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) su Windows possono accedere ai dati della cronologia.
- Usa query SQL specifiche per estrarre informazioni sulla cronologia e sui download.
- **bookmarkbackups**: Contiene backup dei segnalibri.
- **formhistory.sqlite**: Memorizza i dati dei moduli web.
- **handlers.json**: Gestisce i gestori di protocollo.
- **persdict.dat**: Parole del dizionario personalizzato.
- **addons.json** e **extensions.sqlite**: Informazioni su componenti aggiuntivi e estensioni installati.
- **cookies.sqlite**: Memorizzazione dei cookie, con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponibile per l'ispezione su Windows.
- **cache2/entries** o **startupCache**: Dati della cache, accessibili tramite strumenti come [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Memorizza i favicons.
- **prefs.js**: Impostazioni e preferenze dell'utente.
- **downloads.sqlite**: Database dei download più vecchi, ora integrato in places.sqlite.
- **thumbnails**: Miniature dei siti web.
- **logins.json**: Informazioni di accesso crittografate.
- **key4.db** o **key3.db**: Memorizza le chiavi di crittografia per proteggere informazioni sensibili.

Inoltre, controllare le impostazioni anti-phishing del browser può essere fatto cercando le voci `browser.safebrowsing` in `prefs.js`, che indicano se le funzionalità di navigazione sicura sono attivate o disattivate.

Per provare a decrittare la password principale, puoi usare [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Con il seguente script e chiamata puoi specificare un file di password da forzare:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (417).png>)

## Google Chrome

Google Chrome memorizza i profili utente in posizioni specifiche in base al sistema operativo:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

All'interno di queste directory, la maggior parte dei dati utente può essere trovata nelle cartelle **Default/** o **ChromeDefaultData/**. I seguenti file contengono dati significativi:

- **History**: Contiene URL, download e parole chiave di ricerca. Su Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) può essere utilizzato per leggere la cronologia. La colonna "Transition Type" ha vari significati, inclusi i clic dell'utente su link, URL digitati, invii di moduli e ricariche di pagina.
- **Cookies**: Memorizza i cookie. Per l'ispezione, è disponibile [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene dati memorizzati nella cache. Per ispezionare, gli utenti Windows possono utilizzare [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).
- **Bookmarks**: Segnalibri dell'utente.
- **Web Data**: Contiene la cronologia dei moduli.
- **Favicons**: Memorizza le favicon dei siti web.
- **Login Data**: Include le credenziali di accesso come nomi utente e password.
- **Current Session**/**Current Tabs**: Dati sulla sessione di navigazione attuale e sulle schede aperte.
- **Last Session**/**Last Tabs**: Informazioni sui siti attivi durante l'ultima sessione prima che Chrome fosse chiuso.
- **Extensions**: Directory per le estensioni e gli addon del browser.
- **Thumbnails**: Memorizza le miniature dei siti web.
- **Preferences**: Un file ricco di informazioni, incluse le impostazioni per plugin, estensioni, pop-up, notifiche e altro.
- **Browser’s built-in anti-phishing**: Per controllare se la protezione anti-phishing e malware è attivata, eseguire `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Cercare `{"enabled: true,"}` nell'output.

## **Recupero Dati SQLite DB**

Come puoi osservare nelle sezioni precedenti, sia Chrome che Firefox utilizzano database **SQLite** per memorizzare i dati. È possibile **recuperare voci eliminate utilizzando lo strumento** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestisce i propri dati e metadati in diverse posizioni, aiutando a separare le informazioni memorizzate e i relativi dettagli per un facile accesso e gestione.

### Archiviazione dei Metadati

I metadati per Internet Explorer sono memorizzati in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (con VX che può essere V01, V16 o V24). Insieme a questo, il file `V01.log` potrebbe mostrare discrepanze nei tempi di modifica con `WebcacheVX.data`, indicando la necessità di riparazione utilizzando `esentutl /r V01 /d`. Questi metadati, contenuti in un database ESE, possono essere recuperati e ispezionati utilizzando strumenti come photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), rispettivamente. All'interno della tabella **Containers**, è possibile discernere le specifiche tabelle o contenitori in cui è memorizzato ciascun segmento di dati, inclusi i dettagli della cache per altri strumenti Microsoft come Skype.

### Ispezione della Cache

Lo strumento [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) consente l'ispezione della cache, richiedendo la posizione della cartella di estrazione dei dati della cache. I metadati per la cache includono nome del file, directory, conteggio degli accessi, origine URL e timestamp che indicano i tempi di creazione, accesso, modifica e scadenza della cache.

### Gestione dei Cookie

I cookie possono essere esplorati utilizzando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadati che comprendono nomi, URL, conteggi di accesso e vari dettagli temporali. I cookie persistenti sono memorizzati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mentre i cookie di sessione risiedono in memoria.

### Dettagli dei Download

I metadati dei download sono accessibili tramite [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), con contenitori specifici che contengono dati come URL, tipo di file e posizione di download. I file fisici possono essere trovati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Cronologia di Navigazione

Per rivedere la cronologia di navigazione, è possibile utilizzare [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), richiedendo la posizione dei file di cronologia estratti e la configurazione per Internet Explorer. I metadati qui includono i tempi di modifica e accesso, insieme ai conteggi di accesso. I file di cronologia si trovano in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL Digitati

Gli URL digitati e i loro tempi di utilizzo sono memorizzati nel registro sotto `NTUSER.DAT` in `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`, tracciando gli ultimi 50 URL inseriti dall'utente e i loro ultimi tempi di input.

## Microsoft Edge

Microsoft Edge memorizza i dati utente in `%userprofile%\Appdata\Local\Packages`. I percorsi per vari tipi di dati sono:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

I dati di Safari sono memorizzati in `/Users/$User/Library/Safari`. I file chiave includono:

- **History.db**: Contiene le tabelle `history_visits` e `history_items` con URL e timestamp delle visite. Usa `sqlite3` per interrogare.
- **Downloads.plist**: Informazioni sui file scaricati.
- **Bookmarks.plist**: Memorizza gli URL dei segnalibri.
- **TopSites.plist**: Siti più visitati.
- **Extensions.plist**: Elenco delle estensioni del browser Safari. Usa `plutil` o `pluginkit` per recuperare.
- **UserNotificationPermissions.plist**: Domini autorizzati a inviare notifiche. Usa `plutil` per analizzare.
- **LastSession.plist**: Schede dell'ultima sessione. Usa `plutil` per analizzare.
- **Browser’s built-in anti-phishing**: Controlla utilizzando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una risposta di 1 indica che la funzione è attiva.

## Opera

I dati di Opera risiedono in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e condividono il formato di Chrome per cronologia e download.

- **Browser’s built-in anti-phishing**: Verifica controllando se `fraud_protection_enabled` nel file Preferences è impostato su `true` utilizzando `grep`.

Questi percorsi e comandi sono cruciali per accedere e comprendere i dati di navigazione memorizzati dai diversi browser web.

## Riferimenti

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Libro: OS X Incident Response: Scripting and Analysis Di Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}
