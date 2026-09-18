# Injection ya Shell Applications za macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash inapoanza bila mwingiliano wa mtumiaji ili kuendesha script au amri ya `-c`, hupanua thamani ya `BASH_ENV` na kusource faili linalopatikana kabla ya kutekeleza amri iliyoombwa. Bash haitumii `PATH` kutafuta faili hili. Kwa hivyo, process inayoanzisha Bash bila mwingiliano wa mtumiaji ikiwa na environment variables zinazodhibitiwa na attacker inaweza kulazimishwa kutekeleza kwanza shell payload inayoweza kusomeka.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook huendeshwa tu wakati target inapoanzisha Bash; `/bin/sh` kwenye platform nyingine au program inayotekeleza command bila shell si lazima iheshimu hook hiyo. Bash katika privileged mode hupuuza `BASH_ENV`. Wakati effective na real user/group IDs zinapotofautiana, Bash pia huruka startup files na kuweka upya effective IDs isipokuwa `-p` itolewe; kwa `-p`, privileged mode hubaki imewezeshwa na `BASH_ENV` bado hupuuzwa.<sup>[[1]](#references)[[2]](#references)</sup>

Kwenye macOS, `launchd` jobs zinaweza kufafanua inherited au per-job environment variables, kwa hiyo kagua plists na launch contexts zinazoingiza taarifa kwenye privileged scripts. Usitegemee SIP pekee kusafisha interpreter variables: tumia minimal environment (`env -i`), unset `BASH_ENV` kwa uwazi, invoke interpreter inayokusudiwa kwa absolute path, na epuka startup files zinazoweza kuandikwa.

## zsh `ZDOTDIR`

zsh husoma `$ZDOTDIR/.zshenv` kwa kila shell ya kawaida, ikijumuisha non-interactive shells; ikiwa `ZDOTDIR` haijawekwa, hutumia `HOME`. Kuelekeza `ZDOTDIR` kwenye directory inayoweza kuandikwa kwa hiyo huendesha `.zshenv` yake kabla ya command ya `zsh -c` au script.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` huondoa chaguo la `RCS` na kuruka faili hili la kuanzisha la mtumiaji. `/etc/zshenv` ya global bado husomwa, kwa hivyo lazima iendelee kuwa trusted na ndogo.

## fish `XDG_CONFIG_HOME`

fish husoma `$XDG_CONFIG_HOME/fish/conf.d/*.fish` na `$XDG_CONFIG_HOME/fish/config.fish` wakati wa kuanza kwa kila shell, si shell za interactive au login pekee. Pia hutekeleza `fish/vendor_conf.d/*.fish` chini ya entries katika `XDG_DATA_DIRS`. Kwa hivyo, attacker anayesimamia mojawapo ya variables hizi na directory inayosomeka anaweza kuendesha code kabla ya fish script au command ya `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Tumia `fish --no-config` kwa invocation inayoaminika na futa variables za XDG zisizoaminika za path.

## bash `PS4` + xtrace (`SHELLOPTS`)

Bash inapoendeshwa ikiwa na option ya **xtrace**, kabla ya kila command inayofuatiliwa hupanua `PS4` na kuichapisha. `PS4` hupanuliwa kama prompt yoyote, hivyo **command substitution** iliyo ndani yake hutekelezwa. Thamani ya `PS4` **na** njia ya kuwezesha xtrace vinaweza kutoka moja kwa moja kwenye environment: ku-export `SHELLOPTS=xtrace` huwezesha xtrace kwa `bash script.sh` ya kawaida (hakuna flag ya `-x` inayohitajika). Hii hubadilisha script yoyote ya Bash anayoendesha victim kuwa code execution.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` pekee haifanyi chochote hadi xtrace iwashwe (kupitia `SHELLOPTS=xtrace`, `set -x`, au `bash -x`). Bash hupuuza `SHELLOPTS` katika **privileged mode** (vitambulisho halisi/tekelezi vinapotofautiana bila ushughulikiaji wa `-p`), kwa hivyo tahadhari zilezile za setuid kama za `BASH_ENV` zinatumika.

## POSIX `ENV`

Shell za mtindo wa POSIX (`/bin/sh`, `dash`, `ksh`) husoma variable ya `ENV`, huipanua na ku-source faili inayotokana wakati zinapoanzisha shell ya **interactive**. Ni counterpart ya POSIX ya `BASH_ENV` (ambayo hutumika kwa Bash *isiyo-interactive*), kwa hivyo udhibiti wa `ENV` hutekeleza code kila mwathiriwa anapoanzisha `sh`/`dash` ya interactive.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Faili za Kuanzisha Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Kuita Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Faili za Kuanzisha/Kuzima zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Faili za Usanidi wa fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Vigeu vya Bash — `PS4` na Builtin ya Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
