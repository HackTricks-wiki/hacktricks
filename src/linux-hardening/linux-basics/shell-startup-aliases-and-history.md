# Shell स्टार्टअप, aliases और history

{{#include ../../banners/hacktricks-training.md}}

अगर कोई alias, function, startup file या environment variable किसी command के चलने का तरीका बदलता है, तो shell command उसी नाम के executable से अलग व्यवहार कर सकती है। किसी command के output पर भरोसा करने या यह मानने से पहले कि कोई script interactive session जैसा ही PATH इस्तेमाल करती है, इनकी जाँच करें।

## मौजूदा shell की जाँच करें

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` और `command -V` बताते हैं कि कोई नाम alias, function, builtin या file के रूप में resolve होता है या नहीं। `command -v` और `which` aliases और functions के लिए एक जैसी जानकारी नहीं दे सकते। Shell history में commands या credentials उजागर हो सकते हैं, लेकिन यह अधूरी हो सकती है, disabled हो सकती है, या session बंद होने तक memory में रखी जा सकती है।

बदली हुई `.bashrc` एक `sudo` alias define कर सकती है, जो password prompt की नकल करता है, जवाब रिकॉर्ड करता है और उसे असली command तक पहुंचाता है। इससे `sudo` executable या `PATH` बदले बिना credentials को intercept करना छिपाया जा सकता है।<sup>[[5]](#references)</sup> Shell को बदली हुई startup file पढ़नी और alias का विस्तार करना होगा।<sup>[[7]](#references)</sup> Default रूप से, non-interactive Bash aliases का विस्तार नहीं करता, जब तक `expand_aliases` enabled न हो।<sup>[[6]](#references)</sup>

## Startup और history files की समीक्षा करें

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

उपयोगकर्ता द्वारा लिखी जा सकने वाली startup फ़ाइल, भविष्य में shell शुरू होने पर commands चला सकती है। सिस्टम-व्यापी startup फ़ाइल या किसी अधिक विशेषाधिकार वाले उपयोगकर्ता की startup फ़ाइल अधिक संवेदनशील होती है, यदि कम विशेषाधिकार वाला खाता उसे बदल सकता हो। Non-interactive Bash, `BASH_ENV` द्वारा नामित फ़ाइल भी पढ़ सकता है; [environment variables](linux-environment-variables.md#bash_env--env) पेज इस व्यवहार और अन्य interpreter hooks की व्याख्या करता है। किसी persistence path का दावा करने से पहले सत्यापित करें कि login, interactive और non-interactive sessions के लिए वास्तविक shell कौन-सी फ़ाइलें पढ़ता है।

Global startup फ़ाइल द्वारा sourced फ़ाइलों का भी निरीक्षण करें। उदाहरण के लिए, `/etc/bash.bashrc` में मौजूद शाब्दिक `source /opt/app/venv/bin/activate` activation फ़ाइल को shell code के रूप में चलाता है, जब shell वास्तव में उस startup फ़ाइल को पढ़ता है। Activation फ़ाइल, symlink और parent-directory permissions तथा ACLs की समीक्षा करें; कम विशेषाधिकार वाला लेखक किसी privileged shell को तभी प्रभावित कर सकता है, जब वह shell या कोई privileged task बाद में उस फ़ाइल को source करे। यदि write access `sudoedit` पर निर्भर है, तो पहले सटीक sudoers rule और installed vendor-patched sudo package सत्यापित करें; केवल upstream version string से [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) स्थापित नहीं होता।

[users and sessions](../user-information/user-and-session-triage.md) में बताए अनुसार secrets के लिए history, dotfiles और backups जाँचें। यदि कोई privileged script नाम के आधार पर commands खोजती है, तो इस समीक्षा के साथ [PATH hijacking guidance](linux-environment-variables.md#path) भी अपनाएँ।

## Zsh startup redirection और compiled files

Default `RCS` settings के साथ, zsh सामान्य invocations से पहले `$ZDOTDIR/.zshenv` पढ़ता है, जिनमें `zsh -c` और scripts भी शामिल हैं; यदि `ZDOTDIR` unset है, तो वह `$HOME` का उपयोग करता है। जब कोई command runner environment map स्वीकार करता है, तो जाँचें कि क्या वह इनमें से किसी variable को privileged zsh process तक पहुँचाता है। तब writable `.zshenv` उस command body से **पहले** चल सकती है जिसकी runner जाँच करता है या जिसे allowlist में शामिल करता है। इसके लिए privileged process को redirected directory inherit करनी होगी; `zsh -f` user startup files को छोड़ता है, लेकिन global `zshenv` को नहीं (अक्सर `/etc/zshenv`, लेकिन distribution के अनुसार paths अलग होते हैं)। [macOS zsh injection page](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) में `ZDOTDIR` का एक छोटा उदाहरण है।<sup>[[1]](#references)[[2]](#references)</sup>

नया और valid `.zshenv.zwc` या `.zshrc.zwc`, उसकी plaintext startup फ़ाइल के बजाय execute होता है। यदि आप startup directory में लिख सकते हैं, तो किसी बदली हुई फ़ाइल को compile करके और फिर सामान्य दिखने वाली plaintext फ़ाइल बहाल करके, compiled copy में executable code छोड़ा जा सकता है। यह अस्पष्टता है, encryption नहीं। नीचे दिया गया disposable test दिखाता है कि केवल text file का निरीक्षण क्यों पर्याप्त नहीं है; यह किसी वास्तविक home directory को नहीं छूता।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

किसी वास्तविक target के लिए, उसका प्रभावी `ZDOTDIR`/`HOME` निर्धारित करें, text और `.zwc` दोनों files की जाँच करें, और timestamps, ownership तथा writable parent directories की जाँच करें। `.zwc` file को प्राथमिकता पाने के लिए source file से मेल खाना चाहिए और उससे नई होनी चाहिए।<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh startup और shutdown files](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell startup environment injection पर security advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh shell builtins: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [वह .zshrc.zwc जिसे आप जाँचना भूल गए](https://dfir.ch/posts/compiled_zsh/)
- [5] [AI-संचालित जासूसी अभियान ने सरकारी Linux infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash manual: Aliases](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash manual: Bash startup files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
