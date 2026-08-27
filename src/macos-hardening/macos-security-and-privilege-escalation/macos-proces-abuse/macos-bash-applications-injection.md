# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

जब Bash किसी script या `-c` command को चलाने के लिए non-interactively शुरू होता है, तो वह `BASH_ENV` की value को expand करता है और requested command को execute करने से पहले resulting file को source करता है। Bash इस file को खोजने के लिए `PATH` का उपयोग नहीं करता। इसलिए, attacker-controlled environment variables के साथ non-interactive Bash लॉन्च करने वाली process को पहले एक readable shell payload execute करने के लिए मजबूर किया जा सकता है।<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook केवल तभी चलता है जब target वास्तव में Bash शुरू करता है; किसी अन्य platform पर `/bin/sh` या ऐसा program जो बिना shell के command execute करता है, इसे आवश्यक रूप से honor नहीं करेगा। Bash privileged mode में `BASH_ENV` को ignore करता है। जब effective और real user/group IDs अलग होते हैं, तो Bash startup files को भी skip करता है और effective IDs को reset कर देता है, जब तक कि `-p` न दिया गया हो; `-p` के साथ privileged mode enabled रहता है और `BASH_ENV` फिर भी ignored रहता है।<sup>[[1]](#references)[[2]](#references)</sup>

macOS पर `launchd` jobs inherited या per-job environment variables define कर सकती हैं, इसलिए उन plists और launch contexts का निरीक्षण करें जो privileged scripts को feed करते हैं। Interpreter variables को sanitize करने के लिए केवल SIP पर निर्भर न रहें: minimal environment (`env -i`) का उपयोग करें, `BASH_ENV` को explicitly unset करें, intended interpreter को absolute path से invoke करें और writable startup files से बचें।

## zsh `ZDOTDIR`

zsh प्रत्येक normal shell के लिए `$ZDOTDIR/.zshenv` पढ़ता है, जिसमें non-interactive shells भी शामिल हैं; यदि `ZDOTDIR` unset है, तो यह `HOME` का उपयोग करता है। इसलिए `ZDOTDIR` को किसी writable directory पर redirect करने से `zsh -c` command या script से पहले उसका `.zshenv` execute हो जाता है।<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` `RCS` option को unset करता है और इस user startup file को skip करता है। Global `/etc/zshenv` अभी भी read की जाती है, इसलिए इसे trusted और minimal रहना चाहिए।

## fish `XDG_CONFIG_HOME`

fish हर shell के startup पर `$XDG_CONFIG_HOME/fish/conf.d/*.fish` और `$XDG_CONFIG_HOME/fish/config.fish` को read करता है, केवल interactive या login shells पर नहीं। यह `XDG_DATA_DIRS` में दी गई entries के नीचे `fish/vendor_conf.d/*.fish` को भी execute करता है। इसलिए कोई attacker इनमें से किसी variable और एक readable directory को control करके fish script या `-c` command से पहले code चला सकता है।<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
विश्वसनीय invocation के लिए `fish --no-config` का उपयोग करें और untrusted XDG path variables को clear करें।

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
