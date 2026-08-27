# Uingizaji wa Shell Applications kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash inapoanza bila mwingiliano ili kuendesha script au amri ya `-c`, hupanua thamani ya `BASH_ENV` na kusource file inayotokana kabla ya kutekeleza amri iliyoombwa. Bash haitumii `PATH` kutafuta file hii. Kwa hivyo, process inayoanzisha Bash bila mwingiliano ikiwa na environment variables zinazodhibitiwa na attacker inaweza kulazimishwa kutekeleza kwanza shell payload inayoweza kusomeka.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook huendeshwa tu wakati target inapoanzisha Bash; `/bin/sh` kwenye platform nyingine au program inayotekeleza command bila shell si lazima iheshimu hook hiyo. Bash ikiwa katika privileged mode hupuuza `BASH_ENV`. Wakati effective na real user/group IDs zinatofautiana, Bash pia huruka startup files na huweka upya effective IDs isipokuwa `-p` itolewe; kwa `-p`, privileged mode hubaki imewezeshwa na `BASH_ENV` bado hupuuzwa.<sup>[[1]](#references)[[2]](#references)</sup>

Kwenye macOS, launchd jobs zinaweza kufafanua environment variables zinazorithiwa au za kila job, kwa hivyo kagua plists na launch contexts zinazoendesha privileged scripts. Usitegemee SIP pekee kusafisha interpreter variables: tumia environment ndogo (`env -i`), ondoa waziwazi `BASH_ENV`, iite interpreter iliyokusudiwa kwa absolute path, na epuka startup files zinazoweza kuandikwa.

## zsh `ZDOTDIR`

zsh husoma `$ZDOTDIR/.zshenv` kwa kila shell ya kawaida, ikijumuisha shells zisizo za interactive; ikiwa `ZDOTDIR` haijawekwa, hutumia `HOME`. Kwa hiyo, kuelekeza `ZDOTDIR` kwenye directory inayoweza kuandikwa huendesha `.zshenv` yake kabla ya command ya `zsh -c` au script.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` huondoa chaguo la `RCS` na kuruka faili hili la kuanzisha la mtumiaji. `/etc/zshenv` ya kimataifa bado husomwa, hivyo lazima ibaki ya kuaminika na iwe na maudhui machache.

## fish `XDG_CONFIG_HOME`

fish husoma `$XDG_CONFIG_HOME/fish/conf.d/*.fish` na `$XDG_CONFIG_HOME/fish/config.fish` wakati wa kuanzisha kila shell, si shell za interactive au login pekee. Pia hutekeleza `fish/vendor_conf.d/*.fish` chini ya entries zilizo katika `XDG_DATA_DIRS`. Mshambulizi anayesimamia mojawapo ya variables hizi na directory inayosomeka anaweza kuendesha code kabla ya fish script au amri ya `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Tumia `fish --no-config` kwa invocation inayoaminika na uondoe XDG path variables zisizoaminika.

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
