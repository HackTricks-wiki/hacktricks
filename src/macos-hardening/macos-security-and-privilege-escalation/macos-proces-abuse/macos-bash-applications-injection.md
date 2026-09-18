# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

जब Bash किसी script या `-c` command को चलाने के लिए non-interactively शुरू होता है, तो वह `BASH_ENV` की value को expand करता है और requested command को execute करने से पहले परिणामी file को source करता है। Bash इस file को खोजने के लिए `PATH` का उपयोग नहीं करता। इसलिए, जो process attacker-controlled environment variables के साथ non-interactive Bash लॉन्च करता है, उसे पहले एक readable shell payload execute करने के लिए मजबूर किया जा सकता है।<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
यह hook केवल तभी चलता है जब target वास्तव में Bash शुरू करता है; किसी अन्य platform पर `/bin/sh` या ऐसा program जो shell के बिना command execute करता है, आवश्यक रूप से इसका पालन नहीं करेगा। Bash privileged mode में `BASH_ENV` को अनदेखा करता है। जब effective और real user/group IDs अलग होते हैं, तब Bash startup files को भी छोड़ देता है और effective IDs को reset कर देता है, जब तक कि `-p` न दिया गया हो; `-p` के साथ privileged mode enabled रहता है और `BASH_ENV` फिर भी अनदेखा किया जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

macOS पर `launchd` jobs inherited या per-job environment variables define कर सकती हैं, इसलिए उन plists और launch contexts की जाँच करें जो privileged scripts को feed करते हैं। Interpreter variables को sanitize करने के लिए केवल SIP पर निर्भर न रहें: minimal environment (`env -i`), explicitly unset `BASH_ENV` का उपयोग करें, intended interpreter को absolute path से invoke करें, और writable startup files से बचें।

## zsh `ZDOTDIR`

zsh हर normal shell के लिए `$ZDOTDIR/.zshenv` पढ़ता है, जिसमें non-interactive shells भी शामिल हैं; यदि `ZDOTDIR` unset है, तो यह `HOME` का उपयोग करता है। इसलिए `ZDOTDIR` को किसी writable directory पर redirect करने से `zsh -c` command या script से पहले उसका `.zshenv` execute हो जाता है।<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` `RCS` option को unset करता है और इस user startup file को skip करता है। Global `/etc/zshenv` को अभी भी read किया जाता है, इसलिए इसे trusted और minimal रहना चाहिए।

## fish `XDG_CONFIG_HOME`

fish हर shell के startup पर `$XDG_CONFIG_HOME/fish/conf.d/*.fish` और `$XDG_CONFIG_HOME/fish/config.fish` को read करता है, केवल interactive या login shells के लिए नहीं। यह `XDG_DATA_DIRS` में मौजूद entries के नीचे `fish/vendor_conf.d/*.fish` को भी execute करता है। इसलिए कोई attacker इनमें से किसी variable और readable directory को control करके fish script या `-c` command से पहले code चला सकता है।<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
विश्वसनीय invocation के लिए `fish --no-config` का उपयोग करें और अविश्वसनीय XDG path variables को साफ़ करें।

## bash `PS4` + xtrace (`SHELLOPTS`)

जब Bash **xtrace** option के साथ चलता है, तो हर traced command से पहले यह `PS4` को expand करके उसे print करता है। `PS4` किसी भी prompt की तरह expand होता है, इसलिए इसके अंदर मौजूद **command substitution** execute किया जाता है। **PS4** की value **और** xtrace को enable करने का तरीका, दोनों पूरी तरह environment से आ सकते हैं: `SHELLOPTS=xtrace` export करने से सामान्य `bash script.sh` में xtrace चालू हो जाता है (किसी `-x` flag की आवश्यकता नहीं होती)। इससे victim द्वारा चलाया जाने वाला कोई भी Bash script code execution में बदल जाता है।<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` अकेले कुछ नहीं करता जब तक xtrace सक्षम न हो (via `SHELLOPTS=xtrace`, `set -x`, या `bash -x`)। Bash **privileged mode** में `SHELLOPTS` को अनदेखा करता है (बिना `-p` handling के अलग real/effective IDs होने पर), इसलिए `BASH_ENV` जैसी ही setuid सावधानियाँ लागू होती हैं।

## POSIX `ENV`

POSIX-style shells (`/bin/sh`, `dash`, `ksh`) `ENV` variable को पढ़ते हैं, उसका विस्तार करते हैं और **interactive** shell शुरू होने पर परिणामी file को source करते हैं। यह `BASH_ENV` का POSIX counterpart है (`BASH_ENV` *non-interactive* Bash के लिए सक्रिय होता है), इसलिए `ENV` पर नियंत्रण होने पर victim जब भी interactive `sh`/`dash` spawn करता है, code execute हो जाता है।
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bash की Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash को Invoke करना](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh की Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish की Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash Variables — `PS4` और Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
