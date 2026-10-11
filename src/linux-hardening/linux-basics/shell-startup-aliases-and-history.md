# Shell का स्टार्टअप, Aliases और History

{{#include ../../banners/hacktricks-training.md}}

अगर कोई alias, function, startup file या environment variable किसी command के चलने के तरीके को बदलता है, तो shell command उसी नाम के executable से अलग व्यवहार कर सकती है। किसी command के output पर भरोसा करने या यह मानने से पहले कि कोई script interactive session वाले PATH का ही उपयोग करती है, इनकी जाँच करें।

## मौजूदा shell की जाँच करें

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` और `command -V` बताते हैं कि कोई नाम alias, function, builtin या file से resolve होता है या नहीं। `command -v` और `which` aliases और functions के लिए एक जैसी जानकारी नहीं दे सकते। Shell history में commands या credentials उजागर हो सकते हैं, लेकिन यह अधूरी हो सकती है, disabled हो सकती है, या session समाप्त होने तक memory में रह सकती है।

## Startup और history files की समीक्षा करें

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

उपयोगकर्ता द्वारा लिखी जा सकने वाली startup file, shell के भविष्य में लॉन्च होने पर commands चला सकती है। यदि कम विशेषाधिकार वाले account को system-wide startup file या विशेषाधिकार प्राप्त user की startup file में बदलाव करने की अनुमति हो, तो वह अधिक संवेदनशील होती है। Non-interactive Bash, `BASH_ENV` द्वारा बताई गई file भी पढ़ सकता है; [environment variables](linux-environment-variables.md#bash_env--env) पेज इस व्यवहार और interpreter के अन्य hooks के बारे में बताता है। किसी persistence path का दावा करने से पहले पुष्टि करें कि login, interactive और non-interactive sessions के लिए वास्तविक shell कौन-सी files पढ़ता है।

Global startup file द्वारा sourced की गई files की भी जाँच करें। उदाहरण के लिए, `/etc/bash.bashrc` में मौजूद literal `source /opt/app/venv/bin/activate`, उस activation file को shell code के रूप में चलाता है—लेकिन तभी, जब shell वास्तव में उस startup file को पढ़ता हो। Activation file, symlink और parent-directory की permissions, तथा ACLs की समीक्षा करें; कम विशेषाधिकार वाला writer किसी विशेषाधिकार प्राप्त shell को तभी प्रभावित कर सकता है, जब वह shell या कोई विशेषाधिकार प्राप्त task बाद में उस file को source करे। यदि write access `sudoedit` पर निर्भर करती है, तो पहले सटीक sudoers rule और installed vendor-patched sudo package की पुष्टि करें; केवल upstream version string से [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) साबित नहीं होता।

[users and sessions](../user-information/user-and-session-triage.md) में बताए अनुसार, secrets के लिए history, dotfiles और backups जाँचें। यदि कोई विशेषाधिकार प्राप्त script commands को उनके नाम से खोजता है, तो इस समीक्षा के साथ [PATH hijacking guidance](linux-environment-variables.md#path) भी देखें।
{{#include ../../banners/hacktricks-training.md}}
