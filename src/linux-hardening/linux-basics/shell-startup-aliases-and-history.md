# Shell Startup, Aliases और History

{{#include ../../banners/hacktricks-training.md}}

अगर कोई alias, function, startup file या environment variable किसी command के चलने का तरीका बदलता है, तो shell command उसी नाम के executable से अलग व्यवहार कर सकता है। किसी command के output पर भरोसा करने या यह मानने से पहले कि कोई script interactive session जैसा ही PATH इस्तेमाल करती है, इनकी जाँच करें।

## मौजूदा shell का निरीक्षण करें

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` और `command -V` बताते हैं कि कोई नाम alias, function, builtin या file के रूप में resolve होता है या नहीं। Aliases और functions के लिए `command -v` और `which` एक जैसी जानकारी न दें। Shell history में commands या credentials उजागर हो सकते हैं, लेकिन यह अधूरी हो सकती है, disabled हो सकती है या session बंद होने तक memory में रखी जा सकती है।

## Startup और history files की समीक्षा करें

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

उपयोगकर्ता द्वारा लिखी जा सकने वाली स्टार्टअप फ़ाइल, shell के भविष्य में शुरू होने पर commands चला सकती है। सिस्टम-व्यापी स्टार्टअप फ़ाइल या विशेषाधिकार-प्राप्त उपयोगकर्ता की स्टार्टअप फ़ाइल अधिक संवेदनशील होती है, यदि कम विशेषाधिकार वाला account उसे संशोधित कर सके। Non-interactive Bash, `BASH_ENV` द्वारा बताई गई फ़ाइल भी पढ़ सकता है; [environment variables](linux-environment-variables.md#bash_env--env) पेज इस व्यवहार और अन्य interpreter hooks की व्याख्या करता है। Persistence path का दावा करने से पहले जाँचें कि login, interactive और non-interactive sessions के लिए वास्तविक shell कौन-सी फ़ाइलें पढ़ता है।

किसी global startup file द्वारा source की गई फ़ाइलों की भी जाँच करें। उदाहरण के लिए, `/etc/bash.bashrc` में मौजूद literal `source /opt/app/venv/bin/activate`, shell द्वारा वह startup file वास्तव में पढ़े जाने पर activation file को shell code के रूप में चलाता है। Activation file, symlink और parent-directory permissions, तथा ACLs की समीक्षा करें; कम विशेषाधिकार वाला writer किसी विशेषाधिकार-प्राप्त shell को तभी प्रभावित कर सकता है, जब वह shell या कोई privileged task बाद में उस फ़ाइल को source करे। यदि write access `sudoedit` पर निर्भर करती है, तो पहले सटीक sudoers rule और installed vendor-patched sudo package की पुष्टि करें; केवल upstream version string से [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) साबित नहीं होता।

[users and sessions](../user-information/user-and-session-triage.md) में बताए अनुसार, secrets के लिए history, dotfiles और backups भी जाँचें। यदि कोई privileged script नाम के आधार पर commands खोजती है, तो इस समीक्षा के साथ [PATH hijacking मार्गदर्शन](linux-environment-variables.md#path) भी अपनाएँ।

## Zsh स्टार्टअप रीडायरेक्शन और compiled files

अपनी default `RCS` settings के साथ, zsh सामान्य invocations से पहले `$ZDOTDIR/.zshenv` पढ़ता है, जिनमें `zsh -c` और scripts भी शामिल हैं; यदि `ZDOTDIR` unset है, तो वह `$HOME` का उपयोग करता है। जब कोई command runner environment map स्वीकार करता है, तो जाँचें कि क्या वह इनमें से किसी variable को privileged zsh process तक पहुँचाता है। ऐसी स्थिति में writable `.zshenv`, runner द्वारा जाँचे या allowlist किए गए command body से **पहले** चल सकती है। इसके लिए ज़रूरी है कि privileged process redirected directory को inherit करे; `zsh -f` user startup files को छोड़ता है, लेकिन global `zshenv` को नहीं (जो अक्सर `/etc/zshenv` होती है, पर distribution के अनुसार paths अलग होते हैं)। [macOS zsh injection पेज](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) में `ZDOTDIR` का एक न्यूनतम उदाहरण है।<sup>[[1]](#references)[[2]](#references)</sup>

एक नया, valid `.zshenv.zwc` या `.zshrc.zwc` उसकी plaintext startup file के बजाय execute होता है। यदि आप startup directory में लिख सकते हैं, तो संशोधित फ़ाइल को compile करके और फिर सामान्य दिखने वाली plaintext फ़ाइल बहाल करके compiled copy में executable code छोड़ा जा सकता है। यह अस्पष्टता है, encryption नहीं। नीचे दिया गया disposable test दिखाता है कि केवल text file की जाँच पर्याप्त क्यों नहीं है; यह किसी वास्तविक home directory को नहीं छूता।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

किसी वास्तविक target के लिए, उसका प्रभावी `ZDOTDIR`/`HOME` निर्धारित करें, text और `.zwc` दोनों फ़ाइलों की जाँच करें, और timestamps, ownership तथा writable parent directories देखें। `.zwc` फ़ाइल को source file से मेल खाना चाहिए और प्राथमिकता पाने के लिए उसका नया होना ज़रूरी है।<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh की startup और shutdown फ़ाइलें](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell startup environment injection से जुड़ी सलाह](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh shell builtins: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [वह .zshrc.zwc जिसे जाँचना आप भूल गए](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
