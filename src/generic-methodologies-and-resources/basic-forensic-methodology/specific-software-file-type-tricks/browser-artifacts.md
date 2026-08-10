# Artefakti pregledača

## Artefakti pregledača <a href="#id-3def" id="id-3def"></a>

Artefakti pregledača obuhvataju različite vrste podataka koje čuvaju web pregledači, kao što su istorija navigacije, obeleživači i podaci iz keša. Ovi artefakti se čuvaju u određenim fasciklama unutar operativnog sistema, pri čemu se njihova lokacija i naziv razlikuju između pregledača, ali uglavnom sadrže slične vrste podataka.

U nastavku je sažetak najčešćih artefakata pregledača:

- **Istorija navigacije**: Beleži korisnikove posete web lokacijama i korisna je za utvrđivanje poseta malicious web lokacijama.
- **Podaci automatskog dovršavanja**: Predlozi zasnovani na čestim pretragama, koji pružaju dodatne uvide kada se kombinuju sa istorijom navigacije.
- **Obeleživači**: Lokacije koje je korisnik sačuvao radi brzog pristupa.
- **Extensions and Add-ons**: Browser extensions ili add-ons koje je korisnik instalirao.
- **Keš**: Čuva web sadržaj (npr. slike i JavaScript datoteke) radi ubrzavanja učitavanja web lokacija i vredan je za forenzičku analizu.
- **Prijave**: Sačuvani podaci za prijavljivanje.
- **Favicons**: Ikone povezane sa web lokacijama, koje se prikazuju na karticama i u obeleživačima, a korisne su za dodatne informacije o korisnikovim posetama.
- **Sesije pregledača**: Podaci povezani sa otvorenim sesijama pregledača.
- **Preuzimanja**: Evidencija datoteka preuzetih kroz pregledač.
- **Podaci obrazaca**: Informacije unete u web obrasce, sačuvane radi budućih predloga za automatsko popunjavanje.
- **Sličice**: Pregledne slike web lokacija.
- **Custom Dictionary.txt**: Reči koje je korisnik dodao u rečnik pregledača.

## Firefox

Firefox organizuje korisničke podatke unutar profila, koji se čuvaju na određenim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Datoteka `profiles.ini` u ovim direktorijumima navodi korisničke profile. Podaci svakog profila čuvaju se u fascikli čiji je naziv naveden u promenljivoj `Path` unutar datoteke `profiles.ini`, koja se nalazi u istom direktorijumu kao i sama datoteka `profiles.ini`. Ako fascikla profila nedostaje, moguće je da je obrisana.

U svakoj fascikli profila možete pronaći nekoliko važnih datoteka:<sup>[[1]](#references)</sup>

- **places.sqlite**: Čuva istoriju, obeleživače i preuzimanja. Alati kao što je [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windows-u mogu pristupiti podacima istorije.
- Koristite određene SQL upite za izdvajanje informacija o istoriji i preuzimanjima.
- **bookmarkbackups**: Sadrži rezervne kopije obeleživača.
- **formhistory.sqlite**: Čuva podatke web obrazaca.
- **handlers.json**: Upravlja rukovaocima protokola.
- **persdict.dat**: Reči iz prilagođenog rečnika.
- **addons.json** i **extensions.sqlite**: Informacije o instaliranim add-ons i extensions.
- **cookies.sqlite**: Skladište cookies, koje se na Windows-u može pregledati pomoću alata [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ili **startupCache**: Podaci keša, dostupni pomoću alata kao što je [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Čuva favicons.
- **prefs.js**: Korisnička podešavanja i preference.
- **downloads.sqlite**: Starija baza podataka preuzimanja, koja je sada integrisana u places.sqlite.
- **thumbnails**: Sličice web lokacija.
- **logins.json**: Šifrovane informacije za prijavljivanje.
- **key4.db** ili **key3.db**: Čuva encryption keys za zaštitu osetljivih informacija.

Pored toga, provera anti-phishing podešavanja pregledača može se obaviti pretragom unosa `browser.safebrowsing` u datoteci `prefs.js`, što pokazuje da li su funkcije bezbednog pregledanja omogućene ili onemogućene.<sup>[[2]](#references)</sup>

Da biste pokušali da dešifrujete master password, možete koristiti [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
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
![Artefakti browsera - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome skladišti korisničke profile na određenim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

U ovim direktorijumima većina korisničkih podataka može se pronaći u fasciklama **Default/** ili **ChromeDefaultData/**. Sledeće datoteke sadrže značajne podatke:<sup>[[1]](#references)</sup>

- **History**: Sadrži URL-ove, preuzimanja i ključne reči pretrage. Na Windowsu se za čitanje istorije može koristiti [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolona "Transition Type" ima različita značenja, uključujući korisničke klikove na linkove, ručno unete URL-ove, slanje obrazaca i ponovno učitavanje stranica.
- **Cookies**: Skladišti cookies. Za pregled je dostupan [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Sadrži keširane podatke. Za pregled korisnici Windowsa mogu koristiti [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Desktop aplikacije zasnovane na Electronu (npr. Discord) takođe koriste Chromium Simple Cache i ostavljaju bogate artefakte na disku. Pogledajte:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Korisnički bookmarks.
- **Web Data**: Sadrži istoriju obrazaca.
- **Favicons**: Skladišti favicone veb-sajtova.
- **Login Data**: Sadrži podatke za prijavljivanje, kao što su korisnička imena i lozinke.
- **Current Session**/**Current Tabs**: Podaci o trenutnoj sesiji pretraživanja i otvorenim tabovima.
- **Last Session**/**Last Tabs**: Informacije o sajtovima aktivnim tokom poslednje sesije pre nego što je Chrome zatvoren.
- **Extensions**: Direktorijumi za ekstenzije i dodatke browsera.
- **Thumbnails**: Skladišti sličice veb-sajtova.
- **Preferences**: Datoteka bogata informacijama, uključujući podešavanja za pluginove, ekstenzije, iskačuće prozore, obaveštenja i drugo.
- **Browser’s built-in anti-phishing**: Da biste proverili da li su anti-phishing i zaštita od malware-a omogućeni, pokrenite `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. U izlazu potražite `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Kao što možete videti u prethodnim odeljcima, i Chrome i Firefox koriste **SQLite** baze podataka za skladištenje podataka. Moguće je **oporaviti obrisane unose pomoću alata** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ili** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 upravlja svojim podacima i metapodacima na različitim lokacijama, što pomaže u razdvajanju uskladištenih informacija i odgovarajućih detalja radi jednostavnog pristupa i upravljanja.

### Skladištenje metapodataka

Metapodaci za Internet Explorer skladište se u `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gde VX može biti V01, V16 ili V24). Prateća datoteka `V01.log` može prikazivati razlike u vremenu izmene u odnosu na `WebcacheVX.data`, što ukazuje na potrebu za popravkom pomoću `esentutl /r V01 /d`. Ovi metapodaci, smešteni u ESE bazi podataka, mogu se oporaviti i pregledati pomoću alata photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). U tabeli **Containers** mogu se utvrditi konkretne tabele ili kontejneri u kojima je uskladišten svaki segment podataka, uključujući detalje keša za druge Microsoft alate, kao što je Skype.

### Pregled keša

Alat [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) omogućava pregled keša i zahteva lokaciju fascikle za izdvajanje podataka keša. Metapodaci keša obuhvataju naziv datoteke, direktorijum, broj pristupa, poreklo URL-a i vremenske oznake koje ukazuju na vreme kreiranja, pristupa, izmene i isteka keša.

### Upravljanje cookies

Cookies se mogu pregledati pomoću alata [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metapodaci obuhvataju nazive, URL-ove, broj pristupa i različite vremenske podatke. Persistent cookies se skladište u `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, dok se session cookies nalaze u memoriji.

### Detalji preuzimanja

Metapodaci preuzimanja dostupni su pomoću alata [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), pri čemu određeni kontejneri sadrže podatke kao što su URL, tip datoteke i lokacija preuzimanja. Fizičke datoteke mogu se pronaći u `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Istorija pregledanja

Za pregled istorije pregledanja može se koristiti [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), uz navođenje lokacije izdvojenih datoteka istorije i konfiguraciju za Internet Explorer. Metapodaci ovde obuhvataju vremena izmene i pristupa, kao i broj pristupa. Datoteke istorije nalaze se u `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Ručno uneti URL-ovi

Ručno uneti URL-ovi i vremena njihovog korišćenja skladište se u registru, u okviru `NTUSER.DAT`, na lokacijama `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`. Prate se poslednjih 50 URL-ova koje je korisnik uneo i vremena njihovog poslednjeg unosa.

## Microsoft Edge

Microsoft Edge skladišti korisničke podatke u `%userprofile%\Appdata\Local\Packages`. Putanje za različite tipove podataka su:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari podaci se skladište u `/Users/$User/Library/Safari`. Važne datoteke obuhvataju:<sup>[[3]](#references)</sup>

- **History.db**: Sadrži tabele `history_visits` i `history_items` sa URL-ovima i vremenskim oznakama poseta. Za upite koristite `sqlite3`.
- **Downloads.plist**: Informacije o preuzetim datotekama.
- **Bookmarks.plist**: Skladišti URL-ove sa bookmarks.
- **TopSites.plist**: Najčešće posećivani sajtovi.
- **Extensions.plist**: Spisak ekstenzija Safari browsera. Za preuzimanje koristite `plutil` ili `pluginkit`.
- **UserNotificationPermissions.plist**: Domeni kojima je dozvoljeno slanje push obaveštenja. Za parsiranje koristite `plutil`.
- **LastSession.plist**: Tabovi iz poslednje sesije. Za parsiranje koristite `plutil`.
- **Browser’s built-in anti-phishing**: Proverite pomoću `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odgovor 1 označava da je funkcija aktivna.<sup>[[2]](#references)</sup>

## Opera

Opera podaci se nalaze u `/Users/$USER/Library/Application Support/com.operasoftware.Opera` i koriste isti format kao Chrome za istoriju i preuzimanja.

- **Browser’s built-in anti-phishing**: Proverite da li je `fraud_protection_enabled` u datoteci Preferences postavljen na `true` pomoću `grep`.<sup>[[2]](#references)</sup>

Ove putanje i komande su ključne za pristup podacima o pregledanju koje skladište različiti veb browseri i za njihovo razumevanje.

## References

- [1] [Forenzika veb browsera: vodič za sprovođenje forenzičke analize veb browsera](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Odgovor na incidente na macOS-u | Deo 3: Manipulacija sistemom](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Odgovor na incidente na OS X-u: skriptovanje i analiza, Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
