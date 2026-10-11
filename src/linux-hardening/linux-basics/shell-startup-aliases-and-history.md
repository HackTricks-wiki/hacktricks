# Shell Startup, Aliases, और History

{{#include ../../banners/hacktricks-training.md}}

यदि कोई alias, function, startup file या environment variable किसी command के चलने के तरीके को बदलता है, तो वह उसी नाम वाले executable से अलग व्यवहार कर सकता है। किसी command के output पर भरोसा करने या यह मानने से पहले कि कोई script interactive session वाले PATH का ही इस्तेमाल करती है, इनकी जाँच करें।

## मौजूदा shell की जाँच करें

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` और `command -V` बताते हैं कि कोई नाम alias, function, builtin या file से resolve होता है या नहीं। `command -v` और `which` aliases और functions के लिए एक जैसी जानकारी नहीं दे सकते। Shell history में commands या credentials उजागर हो सकते हैं, लेकिन यह अधूरी हो सकती है, disabled हो सकती है या session समाप्त होने तक memory में रखी जा सकती है।

## Startup और history files की समीक्षा करें

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

उपयोगकर्ता द्वारा लिखी जा सकने वाली startup फ़ाइल, भविष्य में shell लॉन्च होने पर commands चला सकती है। अगर कम-विशेषाधिकार वाला account, system-wide startup फ़ाइल या किसी विशेषाधिकार-प्राप्त उपयोगकर्ता की startup फ़ाइल को modify कर सकता है, तो वह फ़ाइल अधिक संवेदनशील है। Non-interactive Bash, `BASH_ENV` द्वारा बताई गई फ़ाइल भी पढ़ सकता है; [environment variables](linux-environment-variables.md#bash_env--env) पेज इस व्यवहार और interpreter के अन्य hooks की व्याख्या करता है। Persistence path का दावा करने से पहले जाँचें कि login, interactive और non-interactive sessions के लिए वास्तविक shell कौन-सी फ़ाइलें पढ़ता है।

Global startup फ़ाइल द्वारा source की जाने वाली फ़ाइलों की भी जाँच करें। उदाहरण के लिए, `/etc/bash.bashrc` में मौजूद `source /opt/app/venv/bin/activate` shell के उस startup फ़ाइल को पढ़ने पर activation फ़ाइल को shell code के रूप में चलाता है। Activation फ़ाइल, symlink और parent directory की permissions, तथा ACLs की समीक्षा करें; कम-विशेषाधिकार वाला writer किसी विशेषाधिकार-प्राप्त shell को तभी प्रभावित कर सकता है, जब वह shell या कोई विशेषाधिकार-प्राप्त task बाद में उस फ़ाइल को source करे। अगर write access `sudoedit` पर निर्भर है, तो पहले सटीक sudoers rule और install किए गए vendor-patched sudo package की पुष्टि करें; केवल upstream version string से [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) साबित नहीं होता।

[users and sessions](../user-information/user-and-session-triage.md) में बताए अनुसार secrets के लिए history, dotfiles और backups की जाँच करें। अगर कोई विशेषाधिकार-प्राप्त script नाम के आधार पर commands खोजती है, तो इस समीक्षा के साथ [PATH hijacking guidance](linux-environment-variables.md#path) भी देखें।
{{#include ../../banners/hacktricks-training.md}}
