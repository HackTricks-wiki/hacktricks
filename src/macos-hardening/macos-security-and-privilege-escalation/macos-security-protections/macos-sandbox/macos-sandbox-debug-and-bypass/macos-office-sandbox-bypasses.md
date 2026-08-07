# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass preko Launch Agents

Aplikacija koristi **custom Sandbox** uz entitlement **`com.apple.security.temporary-exception.sbpl`**, a ovaj custom sandbox omogućava upisivanje fajlova bilo gde, sve dok naziv fajla počinje sa `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Zato je escape bio jednostavan kao **upisivanje `plist`** LaunchAgent-a u `~/Library/LaunchAgents/~$escape.plist`.

Pogledajte [**originalni izveštaj ovde**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass preko Login Items i zip-a

Imajte na umu da od prvog escape-a Word može da upisuje proizvoljne fajlove čiji naziv počinje sa `~$`, iako nakon patch-a prethodnog vuln-a više nije bilo moguće upisivati u `/Library/Application Scripts` ili u `/Library/LaunchAgents`.

Otkriveno je da je iz sandbox-a moguće kreirati **Login Item** (aplikacije koje će biti izvršene kada se korisnik prijavi). Međutim, ove aplikacije **neće biti izvršene osim ako** nisu **notarized**, a **nije moguće dodati args** (zato nije moguće jednostavno pokrenuti reverse shell koristeći **`bash`**).

Nakon prethodnog Sandbox bypass-a, Microsoft je onemogućio upisivanje fajlova u `~/Library/LaunchAgents`. Međutim, otkriveno je da će, ako se **zip fajl postavi kao Login Item**, `Archive Utility` jednostavno **raspakovati** taj fajl na njegovoj trenutnoj lokaciji. Pošto se folder `LaunchAgents` iz `~/Library` podrazumevano ne kreira, bilo je moguće **zip-ovati plist u `LaunchAgents/~$escape.plist`** i **postaviti** zip fajl u **`~/Library`**, tako da prilikom raspakivanja dospe na lokaciju za persistence.

Pogledajte [**originalni izveštaj ovde**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass preko Login Items i .zshenv

(Imajte na umu da od prvog escape-a Word može da upisuje proizvoljne fajlove čiji naziv počinje sa `~$`.)

Međutim, prethodna tehnika je imala ograničenje: ako folder **`~/Library/LaunchAgents`** postoji zato što ga je kreirao neki drugi software, tehnika bi bila neuspešna. Zato je za ovo otkriven drugačiji Login Items chain.

Napadač je mogao da kreira fajlove **`.bash_profile`** i **`.zshenv`** sa payload-om koji treba izvršiti, a zatim da ih zip-uje i **upiše zip u korisnički folder žrtve**: **`~/~$escape.zip`**.

Zatim bi dodao zip fajl u **Login Items**, a nakon toga i aplikaciju **`Terminal`**. Kada bi se korisnik ponovo prijavio, zip fajl bi bio raspakovan u korisnički folder, čime bi se prepisali **`.bash_profile`** i **`.zshenv`**, pa bi terminal izvršio jedan od ovih fajlova (u zavisnosti od toga da li se koristi bash ili zsh).

Pogledajte [**originalni izveštaj ovde**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass pomoću Open-a i env promenljivih

Iz sandbox-ovanih procesa i dalje je moguće pozvati druge procese pomoću **`open`** utility-ja. Štaviše, ovi procesi će se izvršavati **unutar sopstvenog sandbox-a**.

Otkriveno je da `open` utility ima opciju **`--env`** za pokretanje aplikacije sa **specifičnim env** promenljivama. Zato je bilo moguće kreirati fajl **`.zshenv`** unutar foldera **u sandbox-u**, a zatim koristiti `open` sa `--env`, postavljajući promenljivu **`HOME`** na taj folder i otvarajući aplikaciju `Terminal`, koja će izvršiti fajl `.zshenv` (iz nekog razloga je bilo potrebno postaviti i promenljivu `__OSINSTALL_ENVIROMENT`).

Pogledajte [**originalni izveštaj ovde**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass pomoću Open-a i stdin-a

Utility **`open`** je takođe podržavao parametar **`--stdin`** (a nakon prethodnog bypass-a više nije bilo moguće koristiti `--env`).

Stvar je u tome da, iako je **`python`** bio potpisan od strane Apple-a, **neće izvršiti** skriptu sa atributom **`quarantine`**. Međutim, bilo je moguće proslediti mu skriptu preko stdin-a, pa neće proveravati da li je ona bila quarantined:

1. Drop-ujte fajl **`~$exploit.py`** sa proizvoljnim Python komandama.
2. Pokrenite _open_ **`–stdin='~$exploit.py' -a Python`**, čime se Python aplikacija pokreće tako da naš drop-ovani fajl služi kao njen standardni input. Python bez problema izvršava naš kod, a pošto je child process od **`launchd`**, nije ograničen pravilima Word-ovog sandbox-a.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
