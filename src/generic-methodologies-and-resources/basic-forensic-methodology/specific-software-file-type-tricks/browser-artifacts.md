# Artefakti pregledača

{{#include ../../../banners/hacktricks-training.md}}

## Artefakti pregledača <a href="#id-3def" id="id-3def"></a>

Artefakti pregledača obuhvataju različite vrste podataka koje čuvaju web pregledači, kao što su istorija navigacije, obeleživači i podaci iz keša. Ti artefakti se čuvaju u određenim fasciklama operativnog sistema, koje se razlikuju po lokaciji i nazivu u zavisnosti od pregledača, ali uglavnom sadrže slične tipove podataka.

Sledi pregled najčešćih artefakata pregledača:

- **Istorija navigacije**: Beleži korisnikove posete web sajtovima i korisna je za utvrđivanje poseta zlonamernim sajtovima.
- **Podaci za automatsko dovršavanje**: Predlozi zasnovani na čestim pretragama, koji u kombinaciji sa istorijom navigacije pružaju dodatne uvide.
- **Obeleživači**: Sajtovi koje je korisnik sačuvao radi brzog pristupa.
- **Proširenja i dodaci**: Proširenja ili dodaci pregledača koje je korisnik instalirao.
- **Keš**: Čuva web sadržaj (npr. slike, JavaScript datoteke) radi bržeg učitavanja sajtova i koristan je za forenzičku analizu.
- **Prijave**: Sačuvani podaci za prijavu.
- **Favikone**: Ikone povezane sa web sajtovima koje se prikazuju na karticama i u obeleživačima, korisne za dodatne informacije o posetama korisnika.
- **Sesije pregledača**: Podaci povezani sa otvorenim sesijama pregledača.
- **Preuzimanja**: Evidencija datoteka preuzetih putem pregledača.
- **Podaci obrazaca**: Informacije unete u web obrasce, sačuvane za buduće predloge automatskog popunjavanja.
- **Sličice**: Slike za pregled web sajtova.
- **Custom Dictionary.txt**: Reči koje je korisnik dodao u rečnik pregledača.

## Firefox

Firefox organizuje korisničke podatke u profilima, koji se čuvaju na određenim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Datoteka `profiles.ini` u tim fasciklama sadrži spisak korisničkih profila. Podaci svakog profila čuvaju se u fascikli čiji je naziv naveden u promenljivoj `Path` u datoteci `profiles.ini`, koja se nalazi u istoj fascikli kao i sama datoteka `profiles.ini`. Ako fascikla profila nedostaje, možda je izbrisana.

U svakoj fascikli profila nalaze se važne datoteke:<sup>[[1]](#references)</sup>

- **places.sqlite**: Čuva istoriju, obeleživače i preuzimanja. Alati poput [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) u operativnom sistemu Windows mogu da pristupe podacima istorije.
  - Koristite određene SQL upite da biste izdvojili informacije o istoriji i preuzimanjima.
- **bookmarkbackups**: Sadrži rezervne kopije obeleživača.
- **formhistory.sqlite**: Čuva podatke web obrazaca.
- **handlers.json**: Upravljanje rukovaocima protokola.
- **persdict.dat**: Reči iz prilagođenog rečnika.
- **addons.json** i **extensions.sqlite**: Informacije o instaliranim dodacima i proširenjima.
- **cookies.sqlite**: Čuva kolačiće; za pregled u operativnom sistemu Windows dostupan je [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ili **startupCache**: Podaci iz keša, kojima se može pristupiti pomoću alata poput [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Čuva favikone.
- **prefs.js**: Korisnička podešavanja i preference.
- **downloads.sqlite**: Starija baza podataka o preuzimanjima, koja je sada integrisana u places.sqlite.
- **thumbnails**: Sličice web sajtova.
- **logins.json**: Šifrovane informacije za prijavu.
- **key4.db** ili **key3.db**: Čuva ključeve za šifrovanje kojima se štite osetljive informacije.

Pored toga, podešavanja zaštite pregledača od phishing napada mogu se proveriti pretragom unosa `browser.safebrowsing` u datoteci `prefs.js`, koji pokazuju da li su funkcije bezbednog pregledanja omogućene ili onemogućene.<sup>[[2]](#references)</sup>

Da biste dešifrovali sačuvane podatke za prijavu iz dostupnog profila, morate uneti ili zasebno oporaviti [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), ako je podešena; profil ne otkriva tu lozinku. Proverite da li se oporavljeni podaci za prijavu mogu koristiti za prijavu na odgovarajući web nalog. Za root pristup u Unix sistemu potreban je zaseban dokaz da se ti podaci prihvataju i za Unix autentifikaciju korisnika root. Sačuvane podatke za prijavu možete pregledati pomoću alata [firefox_decrypt](https://github.com/unode/firefox_decrypt). Sledeći primer proverava moguće Primary Password lozinke iz datoteke sa lozinkama:

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

Google Chrome čuva korisničke profile na određenim lokacijama, u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

U ovim direktorijumima većinu korisničkih podataka možete pronaći u fasciklama **Default/** ili **ChromeDefaultData/**. Sledeće datoteke sadrže značajne podatke:<sup>[[1]](#references)</sup>

- **History**: Sadrži URL-ove, preuzimanja i ključne reči za pretragu. U Windows-u se za pregled istorije može koristiti [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolona „Transition Type” ima različita značenja, uključujući korisničke klikove na linkove, ručno unete URL-ove, slanje obrazaca i ponovno učitavanje stranica.
- **Cookies**: Čuva kolačiće. Za pregled je dostupan [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Sadrži keširane podatke. Korisnici Windows-a mogu da koriste [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) za pregled.

  Desktop aplikacije zasnovane na Electron-u (npr. Discord) takođe koriste Chromium Simple Cache i ostavljaju bogate artefakte na disku. Pogledajte:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Korisnički obeleživači.
- **Web Data**: Sadrži istoriju obrazaca.
- **Favicons**: Čuva favicone veb-sajtova.
- **Login Data**: Sadrži podatke za prijavljivanje, kao što su korisnička imena i lozinke.
- **Current Session**/**Current Tabs**: Podaci o trenutnoj sesiji pregledanja i otvorenim karticama.
- **Last Session**/**Last Tabs**: Podaci o sajtovima koji su bili aktivni tokom poslednje sesije pre zatvaranja Chrome-a.
- **Extensions**: Direktorijumi za dodatke i ekstenzije pregledača.
- **Thumbnails**: Čuva sličice veb-sajtova.
- **Preferences**: Datoteka sa mnogo informacija, uključujući podešavanja za dodatke, ekstenzije, iskačuće prozore, obaveštenja i drugo.
- **Browser’s built-in anti-phishing**: Da biste proverili da li su zaštita od phishinga i zaštita od zlonamernog softvera omogućene, pokrenite `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. U izlazu potražite `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Direktorijum `Local Extension Settings/<extension-id>/` u Chromium profilu može da sadrži lokalno stanje ekstenzije, uključujući ključni materijal upravljača lozinkama. Na primer, [Passbolt navodi da se njegov šifrovani privatni ključ čuva u lokalnom skladištu ekstenzije pregledača](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), a [ID njegove Chrome ekstenzije](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) identifikuje odgovarajući direktorijum. Samo postojanje direktorijuma ne dokazuje da je ključ prisutan niti otključava trezor: korisnik mora imati pristup podacima profila, upotrebljiv privatni ključ i lozinku, kao i ovlašćen način oporavka/autentifikacije na serveru. Za stavku trezora koja sadrži lozinku naloga operativnog sistema potrebno je zasebno proveriti ponovnu upotrebu naloga. Rutinsko nabrajanje treba da navede samo putanju do skladišta, bez ispisivanja njegovih LevelDB datoteka ili tajnih vrednosti.

## **Oporavak podataka SQLite DB**

Kao što možete videti u prethodnim odeljcima, i Chrome i Firefox koriste baze podataka **SQLite** za čuvanje podataka. **Izbrisane unose moguće je oporaviti pomoću alata** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ili** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 upravlja svojim podacima i metapodacima na različitim lokacijama, čime se olakšava razdvajanje sačuvanih informacija i odgovarajućih detalja radi lakšeg pristupa i upravljanja.

### Skladištenje metapodataka

Metapodaci za Internet Explorer čuvaju se u `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gde je VX V01, V16 ili V24). Prateća datoteka `V01.log` može pokazivati neslaganje vremena izmene u odnosu na `WebcacheVX.data`, što ukazuje na potrebu za popravkom pomoću komande `esentutl /r V01 /d`. Ovi metapodaci, smešteni u ESE bazi podataka, mogu se oporaviti i pregledati pomoću alata kao što su photorec, odnosno [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). U tabeli **Containers** mogu se utvrditi konkretne tabele ili kontejneri u kojima se čuva svaki segment podataka, uključujući detalje keša za druge Microsoft alate, kao što je Skype.

### Pregled keša

Alat [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) omogućava pregled keša i zahteva lokaciju fascikle u koju su izdvojeni podaci keša. Metapodaci keša obuhvataju ime datoteke, direktorijum, broj pristupa, izvorni URL i vremenske oznake kreiranja, pristupa, izmene i isteka keša.

### Upravljanje kolačićima

Kolačiće možete pregledati pomoću [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Metapodaci obuhvataju imena, URL-ove, broj pristupa i razne vremenske podatke. Trajni kolačići čuvaju se u `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, dok se kolačići sesije nalaze u memoriji.

### Detalji o preuzimanjima

Metapodacima o preuzimanjima možete pristupiti pomoću [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), a određeni kontejneri sadrže podatke kao što su URL, tip datoteke i lokacija preuzimanja. Fizičke datoteke nalaze se u `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Istorija pregledanja

Za pregled istorije pregledanja može se koristiti [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html). Potrebno je navesti lokaciju izdvojenih datoteka istorije i podesiti alat za Internet Explorer. Metapodaci obuhvataju vreme izmene i pristupa, kao i broj pristupa. Datoteke istorije nalaze se u `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Ručno uneti URL-ovi

Ručno uneti URL-ovi i vreme njihovog korišćenja čuvaju se u registru pod `NTUSER.DAT`, u ključevima `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`. Tu se beleži poslednjih 50 URL-ova koje je korisnik uneo i vreme njihovog poslednjeg unosa.

## Microsoft Edge

Microsoft Edge čuva korisničke podatke u `%userprofile%\Appdata\Local\Packages`. Putanje za različite tipove podataka su:<sup>[[1]](#references)</sup>

- **Putanja profila**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Istorija, kolačići i preuzimanja**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Podešavanja, obeleživači i lista za čitanje**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Keš**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Poslednje aktivne sesije**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari podaci čuvaju se u `/Users/$User/Library/Safari`. Važne datoteke uključuju:<sup>[[3]](#references)</sup>

- **History.db**: Sadrži tabele `history_visits` i `history_items` sa URL-ovima i vremenskim oznakama poseta. Za upite koristite `sqlite3`.
- **Downloads.plist**: Informacije o preuzetim datotekama.
- **Bookmarks.plist**: Čuva obeležene URL-ove.
- **TopSites.plist**: Najčešće posećeni sajtovi.
- **Extensions.plist**: Spisak ekstenzija pregledača Safari. Za pregled koristite `plutil` ili `pluginkit`.
- **UserNotificationPermissions.plist**: Domeni kojima je dozvoljeno slanje push obaveštenja. Za parsiranje koristite `plutil`.
- **LastSession.plist**: Kartice iz poslednje sesije. Za parsiranje koristite `plutil`.
- **Browser’s built-in anti-phishing**: Proverite pomoću komande `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odgovor 1 znači da je ova funkcija aktivna.<sup>[[2]](#references)</sup>

## Opera

Podaci pregledača Opera nalaze se u `/Users/$USER/Library/Application Support/com.operasoftware.Opera`, a istorija i preuzimanja koriste isti format kao u Chrome-u.

- **Browser’s built-in anti-phishing**: Proverite da li je `fraud_protection_enabled` u datoteci Preferences podešen na `true`, pomoću komande `grep`.<sup>[[2]](#references)</sup>

Ove putanje i komande su ključne za pristup podacima o pregledanju koje čuvaju različiti veb-pregledači i njihovo razumevanje.

## References

- [1] [Forenzika veb-pregledača: vodič za forenzičku analizu veb-pregledača](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Odgovor na incidente u macOS-u | Deo 3: Manipulacija sistemom](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Odgovor na incidente u OS X-u: skriptovanje i analiza, Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
