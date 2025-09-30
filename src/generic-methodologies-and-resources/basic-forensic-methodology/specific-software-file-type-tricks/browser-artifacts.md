# Artefakti pregledača

{{#include ../../../banners/hacktricks-training.md}}

## Artefakti pregledača <a href="#id-3def" id="id-3def"></a>

Artefakti pregledača obuhvataju razne tipove podataka koje čuvaju web pregledači, kao što su istorija navigacije, obeleživači i keš podaci. Ti artefakti se čuvaju u specifičnim folderima unutar operativnog sistema, razlikujući se po lokaciji i nazivu između pregledača, ali generalno beleže slične tipove podataka.

Evo sažetka najčešćih artefakata pregledača:

- **Istorija navigacije**: Prati posete korisnika web sajtovima, korisno za identifikovanje poseta malicioznim sajtovima.
- **Podaci za automatsko popunjavanje**: Sugestije zasnovane na učestalim pretragama, daju dodatne informacije kada se kombinuju sa istorijom navigacije.
- **Obeleživači**: Sajtovi koje je korisnik sačuvao za brz pristup.
- **Extensions and Add-ons**: Ekstenzije ili dodaci instalirani u pregledaču.
- **Keš**: Čuva web sadržaj (npr. slike, JavaScript fajlove) radi bržeg učitavanja sajtova, vredno za forenzičku analizu.
- **Logins**: Sačuvane prijave/akreditive.
- **Favicons**: Ikonice povezane sa sajtovima, pojavljuju se u tabovima i obeleživačima, korisne za dodatne informacije o posetama korisnika.
- **Browser Sessions**: Podaci vezani za otvorene browser sesije.
- **Downloads**: Evidencija fajlova preuzetih preko pregledača.
- **Form Data**: Informacije unesene u web forme, sačuvane za buduće autofill sugestije.
- **Thumbnails**: Pregledne slike sajtova.
- **Custom Dictionary.txt**: Reči koje je korisnik dodao u pregledačev rečnik.

## Firefox

Firefox organizuje korisničke podatke unutar profila, koji se čuvaju na specifičnim lokacijama u zavisnosti od operativnog sistema:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Datoteka `profiles.ini` u ovim direktorijumima navodi korisničke profile. Podaci svakog profila se čuvaju u folderu naznačenom u varijabli `Path` unutar `profiles.ini`, koji se nalazi u istom direktorijumu kao i `profiles.ini` sam. Ako folder profila nedostaje, možda je izbrisan.

Unutar svakog profila možete pronaći nekoliko važnih fajlova:

- **places.sqlite**: Čuva istoriju, obeleživače i preuzimanja. Alati poput [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windows mogu pristupiti podacima istorije.
- Koristite specifične SQL upite za ekstrakciju informacija o istoriji i preuzimanjima.
- **bookmarkbackups**: Sadržava backup-ove obeleživača.
- **formhistory.sqlite**: Čuva podatke iz web formi.
- **handlers.json**: Upravljanje protocol handler-ima.
- **persdict.dat**: Reči iz prilagođenog rečnika.
- **addons.json** i **extensions.sqlite**: Informacije o instaliranim dodacima i ekstenzijama.
- **cookies.sqlite**: Skladište kolačića, sa [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) dostupnim za inspekciju na Windows.
- **cache2/entries** ili **startupCache**: Keš podaci, dostupni kroz alate poput [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Čuva favicons.
- **prefs.js**: Korisnička podešavanja i preference.
- **downloads.sqlite**: Starija baza za preuzimanja, sada integrisana u places.sqlite.
- **thumbnails**: Pregledne slike sajtova.
- **logins.json**: Enkriptovane informacije o prijavama.
- **key4.db** ili **key3.db**: Čuvaju ključeve za enkripciju osetljivih informacija.

Dodatno, proveru anti-phishing podešavanja pregledača možete izvršiti pretragom unosa `browser.safebrowsing` u `prefs.js`, što ukazuje da li su funkcije za bezbedno pretraživanje uključene ili isključene.

Da biste pokušali da dekriptuјete master lozinku, možete koristiti [https://github.com/unode/firefox_decrypt]\
Sa sledećim skriptom i pozivom možete navesti datoteku lozinki za brute force:
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

Google Chrome čuva korisničke profile na određenim lokacijama u zavisnosti od operativnog sistema:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

U ovim direktorijumima većina korisničkih podataka se nalazi u fasciklama **Default/** ili **ChromeDefaultData/**. Sledeće datoteke sadrže značajne podatke:

- **History**: Sadrži URL-ove, preuzimanja i ključne reči pretrage. Na Windows-u, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) može se koristiti za čitanje istorije. Kolona "Transition Type" ima različita značenja, uključujući kliktanja korisnika na linkove, ukucane URL-ove, slanje formi i ponovno učitavanje stranice.
- **Cookies**: Čuva cookies. Za inspekciju je dostupan [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Sadrži keširane podatke. Za inspekciju Windows korisnici mogu koristiti [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Desktop aplikacije zasnovane na Electron-u (npr. Discord) takođe koriste Chromium Simple Cache i ostavljaju bogate artefakte na disku. Vidi:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Korisničke bookmarke.
- **Web Data**: Sadrži istoriju formi.
- **Favicons**: Čuva favikone sajtova.
- **Login Data**: Sadrži kredencijale za prijavu kao što su korisnička imena i lozinke.
- **Current Session**/**Current Tabs**: Podaci o trenutnoj sesiji pregledača i otvorenim tabovima.
- **Last Session**/**Last Tabs**: Informacije o sajtovima aktivnim tokom poslednje sesije pre nego što je Chrome zatvoren.
- **Extensions**: Direktorijumi za ekstenzije i dodatke.
- **Thumbnails**: Čuva sličice veb sajtova.
- **Preferences**: Datoteka bogata informacijama, uključujući podešavanja za pluginove, ekstenzije, pop-upove, notifikacije i više.
- **Browser’s built-in anti-phishing**: Da biste proverili da li su anti-phishing i zaštita od malvera uključeni, pokrenite `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Potražite `{"enabled: true,"}` u izlazu.

## **SQLite DB Data Recovery**

Kao što se može primetiti u prethodnim sekcijama, i Chrome i Firefox koriste **SQLite** baze podataka za čuvanje podataka. Moguće je **oporaviti izbrisane unose koristeći alat** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ili** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 raspoređuje svoje podatke i metapodatke na različitim lokacijama, što pomaže u odvajanju sačuvanih informacija i pripadajućih detalja radi lakšeg pristupa i upravljanja.

### Metadata Storage

Metapodaci za Internet Explorer se čuvaju u %userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data (gde je VX V01, V16 ili V24). Uz to, fajl `V01.log` može pokazati razlike u vremenu izmene u odnosu na `WebcacheVX.data`, što ukazuje na potrebu za popravkom korišćenjem `esentutl /r V01 /d`. Ovi metapodaci, smešteni u ESE bazi podataka, mogu se oporaviti i pregledati korišćenjem alata poput photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). U tabeli **Containers** moguće je razaznati specifične tabele ili kontejnere u kojima je svaki deo podataka smešten, uključujući detalje keša za druge Microsoft alate kao što je Skype.

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) alat omogućava inspekciju keša, i zahteva lokaciju fascikle za ekstrakciju keš podataka. Metapodaci keša uključuju ime fajla, direktorijum, broj pristupa, URL poreklo i vremenske oznake koje označavaju kreiranje, pristup, modifikaciju i isteka keša.

### Cookies Management

Cookies se mogu istražiti koristeći [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metapodaci obuhvataju imena, URL-ove, broj pristupa i razne vremenske detalje. Perzistentni cookies se čuvaju u %userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies, dok session cookies borave u memoriji.

### Download Details

Metapodaci preuzimanja su dostupni preko [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), pri čemu specifični kontejneri sadrže podatke kao što su URL, tip fajla i lokacija preuzimanja. Fizički fajlovi se mogu naći pod %userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory.

### Browsing History

Za pregled istorije pretraživanja može se koristiti [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), potrebno je navesti lokaciju ekstrahovanih fajlova istorije i konfiguraciju za Internet Explorer. Metapodaci ovde uključuju vremena modifikacije i pristupa, zajedno sa brojem pristupa. Fajlovi istorije se nalaze u %userprofile%\Appdata\Local\Microsoft\Windows\History.

### Typed URLs

Ukucani URL-ovi i vremena njihove upotrebe se čuvaju u registru pod NTUSER.DAT na Software\Microsoft\InternetExplorer\TypedURLs i Software\Microsoft\InternetExplorer\TypedURLsTime, prateći poslednjih 50 URL-ova koje je korisnik uneo i vreme njihovog poslednjeg unosa.

## Microsoft Edge

Microsoft Edge čuva korisničke podatke u %userprofile%\Appdata\Local\Packages. Putanje za razne tipove podataka su:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Podaci Safari-ja se čuvaju u /Users/$User/Library/Safari. Ključni fajlovi uključuju:

- **History.db**: Sadrži tabele `history_visits` i `history_items` sa URL-ovima i vremenskim pečatima poseta. Koristite `sqlite3` za upite.
- **Downloads.plist**: Informacije o preuzetim fajlovima.
- **Bookmarks.plist**: Čuva bookmarkovane URL-ove.
- **TopSites.plist**: Najčešće posećeni sajtovi.
- **Extensions.plist**: Lista Safari ekstenzija. Koristite `plutil` ili `pluginkit` za dobijanje.
- **UserNotificationPermissions.plist**: Domeni kojima je dozvoljeno slanje notifikacija. Koristite `plutil` za parsiranje.
- **LastSession.plist**: Tabovi iz poslednje sesije. Koristite `plutil` za parsiranje.
- **Browser’s built-in anti-phishing**: Proverite koristeći `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odgovor 1 označava da je funkcija aktivna.

## Opera

Podaci Opera-e se nalaze u /Users/$USER/Library/Application Support/com.operasoftware.Opera i dele Chrome format za istoriju i preuzimanja.

- **Browser’s built-in anti-phishing**: Proverite tako što ćete u Preferences fajlu proveriti da li je `fraud_protection_enabled` postavljeno na `true` koristeći `grep`.

Ove putanje i komande su ključne za pristup i razumevanje podataka o pretraživanju koje čuvaju različiti web pregledači.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Knjiga: OS X Incident Response: Scripting and Analysis By Jaron Bradley str 123**


{{#include ../../../banners/hacktricks-training.md}}
