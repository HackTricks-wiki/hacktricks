# Artefakti browsera

{{#include ../../../banners/hacktricks-training.md}}

## Artefakti browsera <a href="#id-3def" id="id-3def"></a>

Artefakti browsera obuhvataju različite vrste podataka koje web browseri čuvaju, kao što su istorija navigacije, bookmarks i podaci iz cache-a. Ovi artefakti se čuvaju u određenim folderima unutar operativnog sistema, čija se lokacija i naziv razlikuju među browserima, ali uglavnom sadrže slične vrste podataka.

U nastavku je pregled najčešćih artefakata browsera:

- **Istorija navigacije**: Prati korisnikove posete web sajtovima i korisna je za utvrđivanje poseta malicioznim sajtovima.
- **Autocomplete podaci**: Predlozi zasnovani na čestim pretragama, koji pružaju dodatne uvide kada se kombinuju sa istorijom navigacije.
- **Bookmarks**: Sajtovi koje je korisnik sačuvao radi brzog pristupa.
- **Extensions and Add-ons**: Browser extensions ili add-ons koje je korisnik instalirao.
- **Cache**: Čuva web sadržaj (npr. slike, JavaScript fajlove) radi poboljšanja vremena učitavanja web sajtova i vredan je za forenzičku analizu.
- **Logins**: Sačuvani login podaci.
- **Favicons**: Ikone povezane sa web sajtovima, koje se prikazuju u tabovima i bookmarks, korisne za dodatne informacije o korisnikovim posetama.
- **Browser Sessions**: Podaci povezani sa otvorenim browser sesijama.
- **Downloads**: Evidencija fajlova preuzetih kroz browser.
- **Form Data**: Informacije unete u web forme, sačuvane za buduće predloge za autofill.
- **Thumbnails**: Preview slike web sajtova.
- **Custom Dictionary.txt**: Reči koje je korisnik dodao u dictionary browsera.

## Firefox

Firefox organizuje korisničke podatke unutar profila, koji se čuvaju na određenim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

`profiles.ini` fajl unutar ovih foldera navodi korisničke profile. Podaci svakog profila čuvaju se u folderu čiji je naziv naveden u promenljivoj `Path` unutar fajla `profiles.ini`, koji se nalazi u istom direktorijumu kao i sam `profiles.ini`. Ako folder profila nedostaje, možda je obrisan.

Unutar svakog foldera profila možete pronaći nekoliko važnih fajlova:<sup>[[1]](#references)</sup>

- **places.sqlite**: Čuva istoriju, bookmarks i downloads. Alati kao što je [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windows-u mogu pristupiti podacima istorije.
- Koristite specifične SQL queries za izdvajanje informacija o istoriji i downloads.
- **bookmarkbackups**: Sadrži backup bookmarks.
- **formhistory.sqlite**: Čuva podatke web formi.
- **handlers.json**: Upravlja protocol handlers.
- **persdict.dat**: Reči iz custom dictionary-ja.
- **addons.json** i **extensions.sqlite**: Informacije o instaliranim add-ons i extensions.
- **cookies.sqlite**: Skladište cookies, koje se na Windows-u može pregledati pomoću alata [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ili **startupCache**: Podaci iz cache-a, kojima se može pristupiti pomoću alata kao što je [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Čuva favicons.
- **prefs.js**: Korisnička podešavanja i preferences.
- **downloads.sqlite**: Starija baza downloads, koja je sada integrisana u places.sqlite.
- **thumbnails**: Thumbnails web sajtova.
- **logins.json**: Enkriptovane login informacije.
- **key4.db** ili **key3.db**: Čuva encryption keys za zaštitu osetljivih informacija.

Pored toga, provera anti-phishing podešavanja browsera može se obaviti pretragom unosa `browser.safebrowsing` u fajlu `prefs.js`, što pokazuje da li su funkcije safe browsing-a omogućene ili onemogućene.<sup>[[2]](#references)</sup>

Za pokušaj dešifrovanja master password-a možete koristiti [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Pomoću sledećeg script-a i poziva možete navesti password fajl za brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Artefakti browsera - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome čuva korisničke profile na određenim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Unutar ovih direktorijuma većina korisničkih podataka može se pronaći u fasciklama **Default/** ili **ChromeDefaultData/**. Sledeće datoteke sadrže značajne podatke:<sup>[[1]](#references)</sup>

- **History**: Sadrži URL-ove, preuzimanja i ključne reči pretrage. Na Windows-u se za čitanje istorije može koristiti [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolona "Transition Type" ima različita značenja, uključujući korisničke klikove na linkove, ručno unete URL-ove, slanje obrazaca i ponovno učitavanje stranica.
- **Cookies**: Čuva cookies. Za pregled je dostupan [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Sadrži keširane podatke. Za pregled korisnici Windows-a mogu koristiti [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Desktop aplikacije zasnovane na Electron-u (npr. Discord) takođe koriste Chromium Simple Cache i ostavljaju bogate artefakte na disku. Pogledajte:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Korisnički bookmarks.
- **Web Data**: Sadrži istoriju obrazaca.
- **Favicons**: Čuva favicon-e veb-sajtova.
- **Login Data**: Uključuje pristupne podatke kao što su korisnička imena i lozinke.
- **Current Session**/**Current Tabs**: Podaci o trenutnoj sesiji pregledanja i otvorenim tabovima.
- **Last Session**/**Last Tabs**: Informacije o sajtovima aktivnim tokom poslednje sesije, pre nego što je Chrome zatvoren.
- **Extensions**: Direktorijumi za browser extensions i add-ons.
- **Thumbnails**: Čuva thumbnail-e veb-sajtova.
- **Preferences**: Datoteka bogata informacijama, uključujući podešavanja za plugins, extensions, pop-up prozore, notifications i drugo.
- **Browser’s built-in anti-phishing**: Da biste proverili da li su anti-phishing i zaštita od malware-a omogućeni, pokrenite `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. U izlazu potražite `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Kao što možete videti u prethodnim odeljcima, i Chrome i Firefox koriste **SQLite** baze podataka za čuvanje podataka. Moguće je **oporaviti obrisane unose pomoću alata** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ili** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 upravlja svojim podacima i metapodacima na različitim lokacijama, što pomaže u odvajanju sačuvanih informacija i odgovarajućih detalja radi lakšeg pristupa i upravljanja.

### Čuvanje metapodataka

Metapodaci za Internet Explorer čuvaju se u `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gde VX može biti V01, V16 ili V24). Prateća datoteka `V01.log` može pokazivati odstupanja u vremenu izmene u odnosu na `WebcacheVX.data`, što ukazuje na potrebu za popravkom pomoću `esentutl /r V01 /d`. Ovi metapodaci, smešteni u ESE bazi podataka, mogu se oporaviti i pregledati pomoću alata photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). U tabeli **Containers** mogu se utvrditi konkretne tabele ili kontejneri u kojima je sačuvan svaki segment podataka, uključujući detalje cache-a za druge Microsoft alate kao što je Skype.

### Pregled cache-a

Alat [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) omogućava pregled cache-a i zahteva lokaciju fascikle u koju su podaci cache-a izdvojeni. Metapodaci cache-a obuhvataju naziv datoteke, direktorijum, broj pristupa, poreklo URL-a i vremenske oznake koje ukazuju na vreme kreiranja, pristupa, izmene i isteka cache-a.

### Upravljanje cookies-ima

Cookies se mogu pregledati pomoću [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metapodaci obuhvataju nazive, URL-ove, broj pristupa i različite vremenske podatke. Persistent cookies čuvaju se u `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, dok se session cookies nalaze u memoriji.

### Detalji preuzimanja

Metapodaci preuzimanja dostupni su preko [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), pri čemu određeni kontejneri sadrže podatke kao što su URL, tip datoteke i lokacija preuzimanja. Fizičke datoteke mogu se pronaći u `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Istorija pregledanja

Za pregled istorije pregledanja može se koristiti [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), uz navođenje lokacije izdvojenih datoteka istorije i konfiguraciju za Internet Explorer. Metapodaci ovde obuhvataju vremena izmene i pristupa, kao i broj pristupa. Datoteke istorije nalaze se u `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Ručno uneti URL-ovi

Ručno uneti URL-ovi i vremena njihovog korišćenja čuvaju se u registry-ju, u okviru `NTUSER.DAT`, na lokacijama `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`. Prati se poslednjih 50 URL-ova koje je korisnik uneo i vreme njihovog poslednjeg unosa.

## Microsoft Edge

Microsoft Edge čuva korisničke podatke u `%userprofile%\Appdata\Local\Packages`. Putanje za različite tipove podataka su:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari podaci čuvaju se u `/Users/$User/Library/Safari`. Ključne datoteke uključuju:<sup>[[3]](#references)</sup>

- **History.db**: Sadrži tabele `history_visits` i `history_items` sa URL-ovima i vremenskim oznakama poseta. Za upite koristite `sqlite3`.
- **Downloads.plist**: Informacije o preuzetim datotekama.
- **Bookmarks.plist**: Čuva bookmark-ovane URL-ove.
- **TopSites.plist**: Najčešće posećivani sajtovi.
- **Extensions.plist**: Spisak Safari browser extensions. Za preuzimanje podataka koristite `plutil` ili `pluginkit`.
- **UserNotificationPermissions.plist**: Domeni kojima je dozvoljeno slanje push notifications. Za parsiranje koristite `plutil`.
- **LastSession.plist**: Tabovi iz poslednje sesije. Za parsiranje koristite `plutil`.
- **Browser’s built-in anti-phishing**: Proverite pomoću `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odgovor 1 ukazuje da je funkcija aktivna.<sup>[[2]](#references)</sup>

## Opera

Opera podaci nalaze se u `/Users/$USER/Library/Application Support/com.operasoftware.Opera` i koriste isti format kao Chrome za istoriju i preuzimanja.

- **Browser’s built-in anti-phishing**: Proverite da li je `fraud_protection_enabled` u datoteci Preferences podešen na `true`, koristeći `grep`.<sup>[[2]](#references)</sup>

Ove putanje i komande ključne su za pristup podacima pregledanja koje čuvaju različiti web browseri i njihovo razumevanje.

## References

- [1] [Forenzika web browsera: vodič za sprovođenje forenzičke analize web browsera](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Deo 3: Manipulacija sistemom](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Odgovor na incidente na OS X-u: Scripting i analiza, autor Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
