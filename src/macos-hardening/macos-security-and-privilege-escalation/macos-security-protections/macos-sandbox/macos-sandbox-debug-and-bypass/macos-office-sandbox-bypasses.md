# Word Sandbox bypasses na macOS-u

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass putem Launch Agents

Aplikacija koristi **custom Sandbox** pomoću entitlement-a **`com.apple.security.temporary-exception.sbpl`**, a ovaj custom sandbox omogućava upisivanje fajlova bilo gde pod uslovom da naziv fajla počinje sa `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Zato je escape bio jednostavan kao **upisivanje `plist`** LaunchAgent-a u `~/Library/LaunchAgents/~$escape.plist`.

Pogledajte [**originalni izveštaj ovde**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[1]</sup>

### Word Sandbox bypass putem Login Items i zip-a

Imajte na umu da Word, nakon prvog escape-a, može da upisuje proizvoljne fajlove čiji nazivi počinju sa `~$`, iako nakon patch-a prethodnog vulnerability-ja više nije bilo moguće upisivati u `/Library/Application Scripts` ili u `/Library/LaunchAgents`.

Otkriveno je da je iz sandbox-a moguće kreirati **Login Item** (aplikacije koje se izvršavaju kada se korisnik prijavi). Međutim, ove aplikacije **se neće izvršiti osim ako** nisu **notarizovane**, a **nije moguće dodati argumente** (zato nije moguće jednostavno pokrenuti reverse shell koristeći **`bash`**).

Microsoft je, nakon prethodnog Sandbox bypass-a, onemogućio opciju upisivanja fajlova u `~/Library/LaunchAgents`. Međutim, otkriveno je da, ako postavite **zip fajl kao Login Item**, `Archive Utility` će ga jednostavno **raspakovati** na trenutnoj lokaciji. Pošto se folder `LaunchAgents` iz `~/Library` podrazumevano ne kreira, bilo je moguće **zip-ovati plist u `LaunchAgents/~$escape.plist`** i **postaviti** zip fajl u **`~/Library`**, tako da se prilikom raspakivanja stigne do destinacije za persistence.

Pogledajte [**originalni izveštaj ovde**](https://objective-see.org/blog/blog_0x4B.html).<sup>[2]</sup>

### Word Sandbox bypass putem Login Items i .zshenv

(Imajte na umu da Word, nakon prvog escape-a, može da upisuje proizvoljne fajlove čiji nazivi počinju sa `~$`.)

Međutim, prethodna tehnika je imala ograničenje: ako folder **`~/Library/LaunchAgents`** postoji zato što ga je kreirao neki drugi software, tehnika ne bi uspela. Zato je za ovo otkriven drugačiji lanac Login Items.

Napadač je mogao da kreira fajlove **`.bash_profile`** i **`.zshenv`** sa payload-om za izvršavanje, zatim da ih zip-uje i **upiše zip u korisnički** folder žrtve: **`~/~$escape.zip`**.

Zatim bi dodao zip fajl u **Login Items**, a potom i aplikaciju **`Terminal`**. Kada se korisnik ponovo prijavi, zip fajl bi se raspakovao u korisnički folder, prepisujući **`.bash_profile`** i **`.zshenv`**, pa bi Terminal izvršio jedan od tih fajlova (u zavisnosti od toga da li se koristi bash ili zsh).

Pogledajte [**originalni izveštaj ovde**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[3]</sup>

### Word Sandbox Bypass pomoću Open i env promenljivih

Iz sandbox-ovanih procesa i dalje je moguće pozivati druge procese pomoću utility-ja **`open`**. Štaviše, ti procesi će se izvršavati **unutar sopstvenog sandbox-a**.

Otkriveno je da utility `open` ima opciju **`--env`** za pokretanje aplikacije sa **specifičnim env** promenljivama. Zato je bilo moguće kreirati fajl **`.zshenv`** unutar foldera **u sandbox-u**, a zatim koristiti `open` sa opcijom `--env`, postavljajući promenljivu **`HOME`** na taj folder i otvarajući aplikaciju `Terminal`, koja će izvršiti fajl `.zshenv` (iz nekog razloga bilo je potrebno postaviti i promenljivu `__OSINSTALL_ENVIROMENT`).

Pogledajte [**originalni izveštaj ovde**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[4]</sup>

### Word Sandbox Bypass pomoću Open i stdin-a

Utility **`open`** je takođe podržavao parametar **`--stdin`** (a nakon prethodnog bypass-a više nije bilo moguće koristiti `--env`).

Problem je u tome što, iako je **`python`** bio potpisan od strane Apple-a, **neće izvršiti** script sa atributom **`quarantine`**. Međutim, bilo je moguće proslediti mu script preko stdin-a, pa neće proveravati da li je fajl bio u karantinu:

1. Drop-ujte fajl **`~$exploit.py`** sa proizvoljnim Python komandama.
2. Pokrenite _open_ **`–stdin='~$exploit.py' -a Python`**, čime se Python aplikacija pokreće tako da naš drop-ovani fajl služi kao njen standardni ulaz. Python bez problema izvršava naš code, a pošto je child process od _launchd_-a, nije ograničen Word-ovim sandbox pravilima.

## Reference

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
