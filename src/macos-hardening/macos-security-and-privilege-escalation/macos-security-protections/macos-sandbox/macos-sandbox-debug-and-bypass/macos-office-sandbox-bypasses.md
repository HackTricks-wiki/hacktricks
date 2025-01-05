# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Aplikacija koristi **prilagođeni Sandbox** koristeći ovlašćenje **`com.apple.security.temporary-exception.sbpl`** i ovaj prilagođeni sandbox omogućava pisanje fajlova bilo gde sve dok ime fajla počinje sa `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Stoga, bekstvo je bilo lako kao **pisanje `plist`** LaunchAgent u `~/Library/LaunchAgents/~$escape.plist`.

Proverite [**originalni izveštaj ovde**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

Zapamtite da iz prvog bekstva, Word može pisati proizvoljne fajlove čije ime počinje sa `~$` iako nakon zakrpe prethodne ranjivosti nije bilo moguće pisati u `/Library/Application Scripts` ili u `/Library/LaunchAgents`.

Otkriveno je da iz sandbox-a može da se kreira **Login Item** (aplikacije koje će se izvršavati kada se korisnik prijavi). Međutim, ove aplikacije **neće se izvršiti osim ako** nisu **notarizovane** i **nije moguće dodati argumente** (tako da ne možete samo pokrenuti reverznu ljusku koristeći **`bash`**).

Iz prethodnog Sandbox zaobilaženja, Microsoft je onemogućio opciju pisanja fajlova u `~/Library/LaunchAgents`. Međutim, otkriveno je da ako stavite **zip fajl kao Login Item**, `Archive Utility` će jednostavno **dekompresovati** ga na trenutnoj lokaciji. Dakle, pošto po defaultu folder `LaunchAgents` iz `~/Library` nije kreiran, bilo je moguće **zipovati plist u `LaunchAgents/~$escape.plist`** i **staviti** zip fajl u **`~/Library`** tako da kada se dekompresuje, doći će do odredišta za postojanost.

Proverite [**originalni izveštaj ovde**](https://objective-see.org/blog/blog_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(Zapamtite da iz prvog bekstva, Word može pisati proizvoljne fajlove čije ime počinje sa `~$`).

Međutim, prethodna tehnika je imala ograničenje, ako folder **`~/Library/LaunchAgents`** postoji jer ga je neka druga aplikacija kreirala, to bi propalo. Tako je otkrivena drugačija lanac Login Items za ovo.

Napadač bi mogao da kreira fajlove **`.bash_profile`** i **`.zshenv`** sa teretom za izvršavanje i zatim ih zipuje i **piše zip u korisnički** folder žrtve: **`~/~$escape.zip`**.

Zatim, dodajte zip fajl u **Login Items** i zatim aplikaciju **`Terminal`**. Kada se korisnik ponovo prijavi, zip fajl bi bio dekompresovan u korisničkom folderu, prepisujući **`.bash_profile`** i **`.zshenv`** i stoga će terminal izvršiti jedan od ovih fajlova (u zavisnosti od toga da li se koristi bash ili zsh).

Proverite [**originalni izveštaj ovde**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

Iz sandboxovanih procesa još uvek je moguće pozvati druge procese koristeći **`open`** alat. Štaviše, ovi procesi će se izvršavati **unutar svog vlastitog sandbox-a**.

Otkriveno je da open alat ima **`--env`** opciju za pokretanje aplikacije sa **specifičnim env** varijablama. Stoga, bilo je moguće kreirati **`.zshenv` fajl** unutar foldera **unutar** **sandbox-a** i koristiti `open` sa `--env` postavljajući **`HOME` varijablu** na taj folder otvarajući tu `Terminal` aplikaciju, koja će izvršiti `.zshenv` fajl (iz nekog razloga takođe je bilo potrebno postaviti varijablu `__OSINSTALL_ENVIROMENT`).

Proverite [**originalni izveštaj ovde**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

**`open`** alat takođe podržava **`--stdin`** parametar (i nakon prethodnog zaobilaženja više nije bilo moguće koristiti `--env`).

Stvar je u tome da čak i ako je **`python`** potpisan od strane Apple-a, on **neće izvršiti** skriptu sa **`quarantine`** atributom. Međutim, bilo je moguće proslediti mu skriptu iz stdin-a tako da neće proveravati da li je bila u karantinu ili ne:

1. Postavite **`~$exploit.py`** fajl sa proizvoljnim Python komandama.
2. Pokrenite _open_ **`–stdin='~$exploit.py' -a Python`**, što pokreće Python aplikaciju sa našim postavljenim fajlom kao njenim standardnim ulazom. Python rado izvršava naš kod, a pošto je to podproces _launchd_, nije vezan za pravila Word-ovog sandbox-a.

{{#include ../../../../../banners/hacktricks-training.md}}
