# Zaobilaženja macOS Office Sandbox-a

{{#include ../../../../../banners/hacktricks-training.md}}

U nastavku su navedeni **istorijski načini za izlazak iz Microsoft Office for Mac sandbox-a**. Oni dokumentuju ponovljive greške na granici poverenja, ali ne treba pretpostaviti da su zakrpljene kombinacije Office/macOS ranjive bez reprodukovanja tačne verzije i politike.

### Zaobilaženje Word sandbox-a putem LaunchAgents-a

Pogođena aplikacija koristila je prilagođeno sandbox pravilo kroz `com.apple.security.temporary-exception.sbpl`. Ono je dozvoljavalo regularne datoteke čiji je basename počinjao sa `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Zato je izlazak bio jednostavan kao **upisivanje `plist`** LaunchAgent-a u `~/Library/LaunchAgents/~$escape.plist`.

Pogledajte [**originalni izveštaj ovde**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Zaobilaženje Word Sandbox-a putem Login Items-a i zip-a

Imajte na umu da Word, nakon prvog izlaska, može da upisuje proizvoljne datoteke čiji naziv počinje sa `~$`, iako nakon zakrpe prethodne ranjivosti više nije bilo moguće upisivati u `/Library/Application Scripts` ili `/Library/LaunchAgents`.

Pogođeni sandbox je dozvoljavao kreiranje **Login Item-a**, koji se pokreće kada se korisnik prijavi. Demonstrirana putanja zahtevala je prihvatljivu potpisanu/notarizovanu aplikaciju i nije dozvoljavala proizvoljne argumente, pa dodavanje `bash`-a sa reverse-shell argumentom nije bilo dovoljno.<sup>[[2]](#references)</sup>

Nakon prethodnog Sandbox bypass-a, Microsoft je onemogućio opciju upisivanja datoteka u `~/Library/LaunchAgents`. Međutim, otkriveno je da će, ako stavite **zip datoteku kao Login Item**, `Archive Utility` jednostavno **raspakovati** na njenoj trenutnoj lokaciji. Pošto se folder `LaunchAgents` iz `~/Library` podrazumevano ne kreira, bilo je moguće **zip-ovati plist u `LaunchAgents/~$escape.plist`** i **postaviti** zip datoteku u **`~/Library`**, tako da prilikom raspakivanja stigne do odredišta za persistence.

Pogledajte [**originalni izveštaj ovde**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Zaobilaženje Word Sandbox-a putem Login Items-a i .zshenv-a

(Imajte na umu da Word, nakon prvog izlaska, može da upisuje proizvoljne datoteke čiji naziv počinje sa `~$`.)

Međutim, prethodna tehnika imala je ograničenje: ako folder **`~/Library/LaunchAgents`** postoji zato što ga je kreirao neki drugi softver, tehnika bi bila neuspešna. Zbog toga je otkriven drugačiji lanac Login Items-a.

Napadač je mogao da kreira **`.bash_profile`** i **`.zshenv`** koji sadrže payload, da ih arhivira i upiše ZIP u home direktorijum **žrtve** kao **`~/~$escape.zip`**.

Zatim bi ZIP i **Terminal** bili dodati kao Login Items. Prilikom sledeće prijave, Archive Utility izvlači dotfiles u korisnikov home direktorijum, a shell aplikacije Terminal-a izvršava odgovarajuću startup datoteku (`.bash_profile` za demonstriranu Bash putanju ili `.zshenv` za Zsh).<sup>[[3]](#references)</sup>

Pogledajte [**originalni izveštaj ovde**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass sa Open i env promenljivama

Sandbox-ovani procesi su i dalje mogli da zahtevaju pokretanje aplikacija putem **`open`**. Pokrenuta aplikacija radila je u sopstvenom bezbednosnom kontekstu, umesto da nasledi tačan sandbox profil Word-a.<sup>[[4]](#references)</sup>

Pogođeni `open` utility imao je opciju **`--env`** za prosleđivanje environment promenljivih. Exploit je kreirao `.zshenv` unutar sandbox-a, postavio `HOME` na taj direktorijum i pokrenuo Terminal, tako da ga Zsh izvrši. Prijavljeni lanac je takođe postavljao pogrešno napisanu privatnu promenljivu `__OSINSTALL_ENVIROMENT`; sačuvajte upravo takvo pisanje prilikom reprodukcije istorijskog PoC-a.<sup>[[4]](#references)</sup>

Pogledajte [**originalni izveštaj ovde**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass sa Open i stdin

Utility **`open`** je takođe podržavao parametar **`--stdin`** (a nakon prethodnog bypass-a više nije bilo moguće koristiti `--env`).

Iako bi Apple-ova Python aplikacija odbila quarantined script datoteku, ranjivi workflow je mogao da prosledi istu skriptu putem standardnog ulaza, čime se zaobilazila provera quarantine-a zasnovana na datoteci:<sup>[[5]](#references)</sup>

1. Ostavite datoteku **`~$exploit.py`** sa proizvoljnim Python komandama.
2. Pokrenite `open --stdin='~$exploit.py' -a Python`. Pokrenuta Python aplikacija prima ostavljeni kod preko standardnog ulaza i, u ranjivim verzijama, izvršava se izvan Word sandbox-a zato što je LaunchServices kreira pod `launchd`-om.<sup>[[5]](#references)</sup>

## References

- [1] [Izlazak iz Sandbox-a – Microsoft Office na macOS-u](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office drama na macOS-u](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS izlazak iz Sandbox-a](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Tehnička analiza CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Otkrivanje ranjivosti za izlazak iz macOS App Sandbox-a: Detaljna analiza CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
