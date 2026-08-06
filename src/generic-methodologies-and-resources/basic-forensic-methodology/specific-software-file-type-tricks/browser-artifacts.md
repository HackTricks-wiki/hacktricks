# Artefakti pregledača

{{#include ../../../banners/hacktricks-training.md}}

## Artefakti pregledača <a href="#id-3def" id="id-3def"></a>

Artefakti pregledača obuhvataju različite vrste podataka koje web pregledači čuvaju, kao što su istorija navigacije, obeleživači i podaci iz keša. Ovi artefakti se čuvaju u određenim fasciklama unutar operativnog sistema, čija se lokacija i naziv razlikuju u zavisnosti od pregledača, ali uglavnom sadrže slične vrste podataka.

U nastavku je sažetak najčešćih artefakata pregledača:

- **Istorija navigacije**: Prati korisnikove posete web lokacijama i korisna je za identifikovanje poseta zlonamernim lokacijama.
- **Podaci za automatsko dovršavanje**: Predlozi zasnovani na čestim pretragama, koji u kombinaciji sa istorijom navigacije mogu pružiti dodatne uvide.
- **Obeleživači**: Lokacije koje je korisnik sačuvao radi brzog pristupa.
- **Ekstenzije i dodaci**: Ekstenzije ili dodaci pregledača koje je korisnik instalirao.
- **Keš**: Čuva web sadržaj (npr. slike i JavaScript datoteke) radi ubrzavanja učitavanja web lokacija i vredan je za forenzičku analizu.
- **Prijave**: Sačuvani podaci za prijavljivanje.
- **Favicons**: Ikone povezane sa web lokacijama, koje se prikazuju u karticama i obeleživačima, a korisne su za dodatne informacije o korisnikovim posetama.
- **Sesije pregledača**: Podaci povezani sa otvorenim sesijama pregledača.
- **Preuzimanja**: Evidencija datoteka preuzetih kroz pregledač.
- **Podaci obrazaca**: Informacije unete u web obrasce, sačuvane za buduće predloge automatskog popunjavanja.
- **Sličice**: Pregledne slike web lokacija.
- **Custom Dictionary.txt**: Reči koje je korisnik dodao u rečnik pregledača.

## Firefox

Firefox organizuje korisničke podatke unutar profila, koji se čuvaju na određenim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Datoteka `profiles.ini` unutar ovih direktorijuma navodi korisničke profile. Podaci svakog profila čuvaju se u fascikli čiji je naziv naveden u promenljivoj `Path` unutar datoteke `profiles.ini`, u istom direktorijumu u kojem se nalazi i sama datoteka `profiles.ini`. Ako fascikla profila nedostaje, moguće je da je obrisana.

Unutar fascikle svakog profila možete pronaći nekoliko važnih datoteka:<sup>[[1]](#references)</sup>

- **places.sqlite**: Čuva istoriju, obeleživače i preuzimanja. Alati kao što je [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windowsu mogu pristupiti podacima istorije.
- Koristite specifične SQL upite za izdvajanje informacija o istoriji i preuzimanjima.
- **bookmarkbackups**: Sadrži rezervne kopije obeleživača.
- **formhistory.sqlite**: Čuva podatke web obrazaca.
- **handlers.json**: Upravlja rukovaocima protokola.
- **persdict.dat**: Reči iz prilagođenog rečnika.
- **addons.json** i **extensions.sqlite**: Informacije o instaliranim dodacima i ekstenzijama.
- **cookies.sqlite**: Skladište kolačića; na Windowsu se za pregled može koristiti [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ili **startupCache**: Podaci keša, kojima se može pristupiti pomoću alata kao što je [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Čuva favicons.
- **prefs.js**: Korisnička podešavanja i preference.
- **downloads.sqlite**: Starija baza podataka preuzimanja, koja je sada integrisana u places.sqlite.
- **thumbnails**: Sličice web lokacija.
- **logins.json**: Šifrovane informacije za prijavljivanje.
- **key4.db** ili **key3.db**: Čuva ključeve za šifrovanje kojima se štite osetljive informacije.

Pored toga, podešavanja pregledača za zaštitu od phishinga mogu se proveriti pretragom unosa `browser.safebrowsing` u datoteci `prefs.js`, koji pokazuju da li su funkcije bezbednog pregledanja omogućene ili onemogućene.<sup>[[2]](#references)</sup>

Za pokušaj dešifrovanja master password-a možete koristiti [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Pomoću sledeće skripte i poziva možete navesti datoteku sa lozinkama za brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Artefakti pregledača - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome čuva korisničke profile na određenim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

U tim direktorijumima većina korisničkih podataka može se pronaći u fasciklama **Default/** ili **ChromeDefaultData/**. Sledeće datoteke sadrže značajne podatke:<sup>[[1]](#references)</sup>

- **History**: Sadrži URL-ove, preuzimanja i ključne reči pretrage. Na Windows-u se za čitanje istorije može koristiti [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolona "Transition Type" ima različita značenja, uključujući korisničke klikove na linkove, ručno unete URL-ove, slanja obrazaca i ponovno učitavanje stranica.
- **Cookies**: Čuva kolačiće. Za pregled je dostupan [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Sadrži keširane podatke. Korisnici Windows-a mogu koristiti [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) za pregled.

Desktop aplikacije zasnovane na Electron-u (npr. Discord) takođe koriste Chromium Simple Cache i ostavljaju bogate artefakte na disku. Pogledajte:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Korisnički bookmark-ovi.
- **Web Data**: Sadrži istoriju obrazaca.
- **Favicons**: Čuva favicon-e veb-sajtova.
- **Login Data**: Uključuje akreditive za prijavljivanje, kao što su korisnička imena i lozinke.
- **Current Session**/**Current Tabs**: Podaci o trenutnoj sesiji pregledanja i otvorenim karticama.
- **Last Session**/**Last Tabs**: Informacije o sajtovima koji su bili aktivni tokom poslednje sesije pre zatvaranja Chrome-a.
- **Extensions**: Direktorijumi za ekstenzije i dodatke pregledača.
- **Thumbnails**: Čuva sličice veb-sajtova.
- **Preferences**: Datoteka bogata informacijama, uključujući podešavanja dodataka, ekstenzija, iskačućih prozora, obaveštenja i drugo.
- **Ugrađena anti-phishing zaštita pregledača**: Da biste proverili da li su anti-phishing i zaštita od malware-a omogućene, pokrenite `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. U izlazu potražite `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Kao što se može videti u prethodnim odeljcima, i Chrome i Firefox koriste **SQLite** baze podataka za čuvanje podataka. Moguće je **oporaviti obrisane unose pomoću alata** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ili** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 upravlja svojim podacima i metapodacima na različitim lokacijama, čime se omogućava razdvajanje sačuvanih informacija i odgovarajućih detalja radi lakšeg pristupa i upravljanja.

### Čuvanje metapodataka

Metapodaci za Internet Explorer čuvaju se u `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gde VX može biti V01, V16 ili V24). Prateća datoteka `V01.log` može pokazati neslaganja u vremenu izmene sa datotekom `WebcacheVX.data`, što ukazuje na potrebu za popravkom pomoću `esentutl /r V01 /d`. Ovi metapodaci, smešteni u ESE bazi podataka, mogu se oporaviti i pregledati pomoću alata photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). U tabeli **Containers** mogu se utvrditi konkretne tabele ili kontejneri u kojima je sačuvan svaki segment podataka, uključujući detalje keša za druge Microsoft alate, kao što je Skype.

### Pregled keša

Alat [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) omogućava pregled keša i zahteva lokaciju fascikle za izdvajanje podataka keša. Metapodaci keša uključuju naziv datoteke, direktorijum, broj pristupa, poreklo URL-a i vremenske oznake koje označavaju vreme kreiranja, pristupa, izmene i isteka keša.

### Upravljanje kolačićima

Kolačići se mogu pregledati pomoću [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), pri čemu metapodaci obuhvataju nazive, URL-ove, broj pristupa i različite vremenske podatke. Trajni kolačići čuvaju se u `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, dok se sesijski kolačići nalaze u memoriji.

### Detalji preuzimanja

Metapodaci preuzimanja dostupni su putem [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), pri čemu određeni kontejneri sadrže podatke kao što su URL, tip datoteke i lokacija preuzimanja. Fizičke datoteke mogu se pronaći u `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Istorija pregledanja

Za pregled istorije pregledanja može se koristiti [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), uz navođenje lokacije izdvojenih datoteka istorije i konfiguraciju za Internet Explorer. Metapodaci ovde uključuju vremena izmene i pristupa, kao i broj pristupa. Datoteke istorije nalaze se u `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Ručno uneti URL-ovi

Ručno uneti URL-ovi i vremena njihovog korišćenja čuvaju se u registru, u okviru `NTUSER.DAT`, na lokacijama `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`. Prati se poslednjih 50 URL-ova koje je korisnik uneo, kao i vremena njihovog poslednjeg unosa.

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
- **Extensions.plist**: Spisak ekstenzija Safari pregledača. Za preuzimanje koristite `plutil` ili `pluginkit`.
- **UserNotificationPermissions.plist**: Domeni kojima je dozvoljeno slanje push obaveštenja. Za parsiranje koristite `plutil`.
- **LastSession.plist**: Kartice iz poslednje sesije. Za parsiranje koristite `plutil`.
- **Ugrađena anti-phishing zaštita pregledača**: Proverite pomoću `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odgovor 1 označava da je funkcija aktivna.<sup>[[2]](#references)</sup>

## Opera

Operini podaci nalaze se u `/Users/$USER/Library/Application Support/com.operasoftware.Opera` i koriste isti format kao Chrome za istoriju i preuzimanja.

- **Ugrađena anti-phishing zaštita pregledača**: Proverite da li je `fraud_protection_enabled` u datoteci Preferences postavljeno na `true` pomoću `grep` komande.<sup>[[2]](#references)</sup>

Ove putanje i komande ključne su za pristup podacima o pregledanju koje čuvaju različiti veb-pregledači i njihovo razumevanje.

## Reference

- [1] [Forenzika veb-pregledača: Vodič za sprovođenje forenzičke analize veb-pregledača](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
