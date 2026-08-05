# Bypasses macOS Office Sandbox-a

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass putem Launch Agents

Aplikacija koristi **custom Sandbox** uz entitlement **`com.apple.security.temporary-exception.sbpl`**, a ovaj custom sandbox dozvoljava upisivanje fajlova bilo gde, sve dok naziv fajla počinje sa `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Zbog toga je escaping bio jednostavan kao **upisivanje `plist`** LaunchAgent-a u `~/Library/LaunchAgents/~$escape.plist`.

Pogledajte [**originalni izveštaj ovde**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass putem Login Items i zip-a

Podsetimo se da Word, nakon prvog escape-a, može da upisuje proizvoljne fajlove čiji naziv počinje sa `~$`, iako nakon patch-a prethodnog vulnerability-ja nije bilo moguće upisivati u `/Library/Application Scripts` ili `/Library/LaunchAgents`.

Otkriveno je da je iz sandbox-a moguće kreirati **Login Item** (aplikacije koje će se izvršiti kada se korisnik prijavi). Međutim, ove aplikacije **se neće izvršiti osim ako** nisu **notarized**, a **nije moguće dodati args** (zato nije moguće jednostavno pokrenuti reverse shell koristeći **`bash`**).

Nakon prethodnog Sandbox bypass-a, Microsoft je onemogućio upisivanje fajlova u `~/Library/LaunchAgents`. Međutim, otkriveno je da, ako se **zip fajl postavi kao Login Item**, `Archive Utility` će ga jednostavno **raspakovati** na njegovoj trenutnoj lokaciji. Pošto se folder `LaunchAgents` iz `~/Library` podrazumevano ne kreira, bilo je moguće **zip-ovati plist u `LaunchAgents/~$escape.plist`** i **postaviti** zip fajl u **`~/Library`**, tako da prilikom raspakivanja dospe na odredište za persistence.

Pogledajte [**originalni izveštaj ovde**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass putem Login Items i .zshenv

(Podsetimo se da Word, nakon prvog escape-a, može da upisuje proizvoljne fajlove čiji naziv počinje sa `~$`.)

Međutim, prethodna tehnika je imala ograničenje: ako folder **`~/Library/LaunchAgents`** postoji zato što ga je kreirao neki drugi software, tehnika bi bila neuspešna. Zbog toga je za ovo otkriven drugačiji lanac Login Items-a.

Napadač je mogao da kreira fajlove **`.bash_profile`** i **`.zshenv`** sa payload-om za izvršavanje, a zatim da ih zip-uje i **upiše zip u folder korisnika žrtve**: **`~/~$escape.zip`**.

Zatim bi dodao zip fajl u **Login Items**, a potom i aplikaciju **`Terminal`**. Kada se korisnik ponovo prijavi, zip fajl bi bio raspakovan u korisničkom folderu, pri čemu bi prepisao **`.bash_profile`** i **`.zshenv`**; samim tim, terminal bi izvršio jedan od ovih fajlova (u zavisnosti od toga da li se koristi bash ili zsh).

Pogledajte [**originalni izveštaj ovde**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass pomoću Open-a i env variables

Iz sandbox-ovanih procesa je i dalje moguće pozivati druge procese pomoću utility-ja **`open`**. Štaviše, ovi procesi će se izvršavati **unutar sopstvenog sandbox-a**.

Otkriveno je da utility `open` ima opciju **`--env`** za pokretanje aplikacije sa **specific env** varijablama. Zbog toga je bilo moguće kreirati fajl **`.zshenv`** unutar foldera **u sandbox-u**, a zatim koristiti `open` sa `--env` i postaviti promenljivu **`HOME`** na taj folder, uz otvaranje aplikacije `Terminal`, koja će izvršiti fajl `.zshenv` (iz nekog razloga bilo je potrebno postaviti i promenljivu `__OSINSTALL_ENVIROMENT`).

Pogledajte [**originalni izveštaj ovde**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass pomoću Open-a i stdin-a

Utility **`open`** je takođe podržavao parametar **`--stdin`** (a nakon prethodnog bypass-a više nije bilo moguće koristiti `--env`).

Činjenica je da, iako je **`python`** bio potpisan od strane Apple-a, on **neće izvršiti** script sa atributom **`quarantine`**. Međutim, bilo je moguće proslediti mu script preko stdin-a, čime se izbegava provera da li je bio quarantined ili ne:

1. Drop-ujte fajl **`~$exploit.py`** sa proizvoljnim Python commands-ima.
2. Pokrenite _open_ **`–stdin='~$exploit.py' -a Python`**, čime se Python aplikacija pokreće tako da naš drop-ovani fajl služi kao njen standardni input. Python bez problema izvršava naš code, a pošto je child process od **`launchd`**-a, nije ograničen pravilima Word sandbox-a.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
