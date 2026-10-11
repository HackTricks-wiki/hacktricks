# Artefakti pregledača

{{#include ../../../banners/hacktricks-training.md}}

## Artefakti pregledača <a href="#id-3def" id="id-3def"></a>

Artefakti pregledača obuhvataju različite vrste podataka koje čuvaju veb-pregledači, kao što su istorija pregledanja, obeleživači i keširani podaci. Ovi artefakti čuvaju se u posebnim fasciklama operativnog sistema, čija se lokacija i naziv razlikuju među pregledačima, ali uglavnom sadrže slične vrste podataka.

Sledi pregled najčešćih artefakata pregledača:

- **Istorija pregledanja**: Prati korisnikove posete veb-sajtovima i može pomoći u otkrivanju poseta zlonamernim sajtovima.
- **Podaci za automatsko dovršavanje**: Predlozi zasnovani na čestim pretragama, koji pružaju uvid kada se kombinuju sa istorijom pregledanja.
- **Obeleživači**: Sajtovi koje je korisnik sačuvao radi brzog pristupa.
- **Proširenja i dodaci**: Proširenja ili dodaci pregledača koje je korisnik instalirao.
- **Keš**: Čuva veb-sadržaj (npr. slike i JavaScript datoteke) radi bržeg učitavanja veb-sajtova i koristan je za forenzičku analizu.
- **Prijave**: Sačuvani podaci za prijavu.
- **Favikone**: Ikone povezane sa veb-sajtovima, koje se prikazuju na karticama i u obeleživačima i mogu pružiti dodatne informacije o posetama korisnika.
- **Sesije pregledača**: Podaci povezani sa otvorenim sesijama pregledača.
- **Preuzimanja**: Evidencija datoteka preuzetih putem pregledača.
- **Podaci iz obrazaca**: Informacije unete u veb-obrasce, sačuvane za buduće predloge automatskog popunjavanja.
- **Sličice**: Slike za pregled veb-sajtova.
- **Custom Dictionary.txt**: Reči koje je korisnik dodao u rečnik pregledača.

## Firefox

Firefox organizuje korisničke podatke u profile, koji se čuvaju na posebnim lokacijama u zavisnosti od operativnog sistema:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Datoteka `profiles.ini` u ovim direktorijumima sadrži spisak korisničkih profila. Podaci svakog profila čuvaju se u fascikli čiji je naziv naveden u promenljivoj `Path` u datoteci `profiles.ini`, koja se nalazi u istom direktorijumu. Ako fascikla profila nedostaje, možda je obrisana.

U svakoj fascikli profila nalazi se nekoliko važnih datoteka:<sup>[[1]](#references)</sup>

- **places.sqlite**: Čuva istoriju, obeleživače i preuzimanja. Alati poput [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windows-u mogu da pristupe podacima istorije.
  - Koristite određene SQL upite za izdvajanje podataka o istoriji i preuzimanjima.
- **bookmarkbackups**: Sadrži rezervne kopije obeleživača.
- **formhistory.sqlite**: Čuva podatke iz veb-obrazaca.
- **handlers.json**: Upravlja rukovaocima protokola.
- **persdict.dat**: Reči iz prilagođenog rečnika.
- **addons.json** i **extensions.sqlite**: Informacije o instaliranim dodacima i proširenjima.
- **cookies.sqlite**: Čuva kolačiće; za pregled na Windows-u dostupan je [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ili **startupCache**: Keširani podaci, kojima se može pristupiti alatima poput [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Čuva favikone.
- **prefs.js**: Korisnička podešavanja i preference.
- **downloads.sqlite**: Starija baza podataka preuzimanja, koja je sada integrisana u places.sqlite.
- **thumbnails**: Sličice veb-sajtova.
- **logins.json**: Šifrovani podaci za prijavu.
- **key4.db** ili **key3.db**: Čuva ključeve za šifrovanje osetljivih informacija.

Pored toga, podešavanja zaštite pregledača od phishing-a možete proveriti tako što ćete u datoteci `prefs.js` potražiti stavke `browser.safebrowsing`, koje pokazuju da li su funkcije bezbednog pregledanja omogućene ili onemogućene.<sup>[[2]](#references)</sup>

Da biste dešifrovali sačuvane podatke za prijavu iz dostupnog profila, morate navesti ili zasebno povratiti [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), ako je podešena; profil ne otkriva tu lozinku. Potvrdite da se povraćeni podaci za prijavu mogu koristiti za autentifikaciju na veb-nalogu. Root pristup Unix-u zahteva zaseban dokaz da se ti podaci prihvataju i za Unix autentifikaciju kao root. Sačuvane podatke za prijavu možete pregledati pomoću alata [firefox_decrypt](https://github.com/unode/firefox_decrypt). Sledeći primer proverava moguće Primary Password lozinke iz datoteke sa lozinkama:

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

U ovim direktorijumima većina korisničkih podataka nalazi se u fasciklama **Default/** ili **ChromeDefaultData/**. Sledeće datoteke sadrže značajne podatke:<sup>[[1]](#references)</sup>

- **Istorija**: Sadrži URL-ove, preuzimanja i ključne reči za pretragu. U operativnom sistemu Windows, za čitanje istorije može se koristiti [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolona "Transition Type" ima različita značenja, uključujući korisničke klikove na linkove, ručno unete URL-ove, slanje obrazaca i ponovno učitavanje stranica.
- **Kolačići**: Čuva kolačiće. Za pregled je dostupan [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Keš**: Sadrži keširane podatke. Korisnici operativnog sistema Windows mogu ga pregledati pomoću alata [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Desktop aplikacije zasnovane na Electron-u (npr. Discord) takođe koriste Chromium Simple Cache i ostavljaju obilje artefakata na disku. Pogledajte:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Obeleživači**: Korisnički obeleživači.
- **Web Data**: Sadrži istoriju obrazaca.
- **Favicons**: Čuva favicon-e veb-sajtova.
- **Login Data**: Sadrži akreditive za prijavu, kao što su korisnička imena i lozinke.
- **Current Session**/**Current Tabs**: Podaci o trenutnoj sesiji pregledanja i otvorenim karticama.
- **Last Session**/**Last Tabs**: Informacije o sajtovima koji su bili aktivni tokom prethodne sesije, pre nego što je Chrome zatvoren.
- **Extensions**: Direktorijumi za ekstenzije i dodatke pregledača.
- **Thumbnails**: Čuva sličice veb-sajtova.
- **Preferences**: Datoteka sa mnogo informacija, uključujući podešavanja za dodatke, ekstenzije, iskačuće prozore, obaveštenja i drugo.
- **Ugrađena anti-phishing zaštita pregledača**: Da biste proverili da li su omogućene anti-phishing zaštita i zaštita od malvera, pokrenite `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. U izlazu potražite `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Direktorijum `Local Extension Settings/<extension-id>/` u Chromium profilu može da sadrži lokalno stanje ekstenzije, uključujući materijal ključa za password manager. Na primer, [Passbolt navodi da se njegov šifrovani privatni ključ čuva u lokalnom skladištu ekstenzije pregledača](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), a njegov [Chrome extension ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) identifikuje odgovarajući direktorijum. Samo prisustvo direktorijuma ne dokazuje da se u njemu nalazi ključ niti otključava vault: korisnik mora imati pristup podacima profila, upotrebljivom privatnom ključu i lozinci, kao i odobrenom putu za oporavak/autentifikaciju na serveru. Za stavku u vault-u koja sadrži lozinku naloga operativnog sistema potrebno je zasebno proveriti ponovnu upotrebu naloga. Rutinsko popisivanje treba da navede samo putanju skladišta, bez izlistavanja njegovih LevelDB datoteka ili tajnih vrednosti.

## **SQLite oporavak podataka iz baze**

Kao što možete da vidite u prethodnim odeljcima, i Chrome i Firefox koriste **SQLite** baze podataka za čuvanje podataka. **Izbrisani zapisi mogu da se oporave pomoću alata** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ili** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 upravlja podacima i metapodacima na različitim lokacijama, čime razdvaja sačuvane informacije i pripadajuće detalje radi lakšeg pristupa i upravljanja.

### Skladištenje metapodataka

Metapodaci za Internet Explorer čuvaju se u `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gde VX može biti V01, V16 ili V24). Prateća datoteka `V01.log` može prikazivati neslaganja u vremenu izmene u odnosu na `WebcacheVX.data`, što ukazuje na potrebu za popravkom pomoću komande `esentutl /r V01 /d`. Ovi metapodaci, smešteni u ESE bazi podataka, mogu se oporaviti i pregledati pomoću alata kao što su photorec, odnosno [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). U tabeli **Containers** mogu se prepoznati konkretne tabele ili kontejneri u kojima je sačuvan svaki segment podataka, uključujući detalje o kešu za druge Microsoft alate kao što je Skype.

### Pregled keša

Alat [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) omogućava pregled keša i zahteva lokaciju fascikle u koju su izdvojeni podaci keša. Metapodaci keša obuhvataju ime datoteke, direktorijum, broj pristupa, URL porekla i vremenske oznake koje ukazuju na vreme kreiranja, pristupa, izmene i isteka keša.

### Upravljanje kolačićima

Kolačići se mogu pregledati pomoću alata [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metapodaci obuhvataju imena, URL-ove, broj pristupa i različite vremenske podatke. Trajni kolačići čuvaju se u `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, dok se kolačići sesije nalaze u memoriji.

### Detalji o preuzimanjima

Metapodaci o preuzimanjima dostupni su pomoću alata [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), a određeni kontejneri sadrže podatke kao što su URL, tip datoteke i lokacija preuzimanja. Fizičke datoteke mogu se pronaći u `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Istorija pregledanja

Za pregled istorije pregledanja može se koristiti [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html). Potrebno je navesti lokaciju izdvojenih datoteka istorije i podesiti alat za Internet Explorer. Metapodaci obuhvataju vremena izmene i pristupa, kao i broj pristupa. Datoteke istorije nalaze se u `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Ručno uneti URL-ovi

Ručno uneti URL-ovi i vremena njihovog unosa čuvaju se u registru, u okviru `NTUSER.DAT`, na lokacijama `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`. Tu se prate poslednjih 50 URL-ova koje je korisnik uneo i vreme njihovog poslednjeg unosa.

## Microsoft Edge

Microsoft Edge čuva korisničke podatke u `%userprofile%\Appdata\Local\Packages`. Putanje za različite tipove podataka su:<sup>[[1]](#references)</sup>

- **Putanja profila**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Istorija, kolačići i preuzimanja**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Podešavanja, obeleživači i lista za čitanje**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Keš**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Poslednje aktivne sesije**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari podaci čuvaju se u `/Users/$User/Library/Safari`. Važne datoteke su:<sup>[[3]](#references)</sup>

- **History.db**: Sadrži tabele `history_visits` i `history_items` sa URL-ovima i vremenskim oznakama poseta. Za upite koristite `sqlite3`.
- **Downloads.plist**: Informacije o preuzetim datotekama.
- **Bookmarks.plist**: Čuva URL-ove obeleživača.
- **TopSites.plist**: Najčešće posećivani sajtovi.
- **Extensions.plist**: Spisak Safari ekstenzija pregledača. Za dobijanje podataka koristite `plutil` ili `pluginkit`.
- **UserNotificationPermissions.plist**: Domeni kojima je dozvoljeno slanje push obaveštenja. Za raščlanjivanje koristite `plutil`.
- **LastSession.plist**: Kartice iz poslednje sesije. Za raščlanjivanje koristite `plutil`.
- **Ugrađena anti-phishing zaštita pregledača**: Proverite pomoću komande `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Vrednost 1 znači da je funkcija aktivna.<sup>[[2]](#references)</sup>

## Opera

Podaci Opera pregledača nalaze se u `/Users/$USER/Library/Application Support/com.operasoftware.Opera`, a format za istoriju i preuzimanja isti je kao u Chrome-u.

- **Ugrađena anti-phishing zaštita pregledača**: Proverite da li je `fraud_protection_enabled` u datoteci Preferences podešen na `true` pomoću komande `grep`.<sup>[[2]](#references)</sup>

Ove putanje i komande ključne su za pristup podacima o pregledanju koje čuvaju različiti veb-pregledači i njihovo razumevanje.

## References

- [1] [Forenzika veb-pregledača: vodič za forenzičku analizu veb-pregledača](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Reagovanje na incidente u macOS-u | Deo 3: manipulacija sistemom](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Reagovanje na incidente u OS X-u: skriptovanje i analiza, Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
