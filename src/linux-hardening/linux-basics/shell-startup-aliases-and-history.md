# Shell Startup, Aliases, और History

{{#include ../../banners/hacktricks-training.md}}

यदि कोई alias, function, startup file या environment variable किसी command के चलने के तरीके को बदलता है, तो shell command उसी नाम के executable से अलग व्यवहार कर सकती है। किसी command के output पर भरोसा करने या यह मानने से पहले कि कोई script interactive session जैसा ही PATH इस्तेमाल करती है, इनकी जाँच करें।

## मौजूदा shell की जाँच करें

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` और `command -V` बताते हैं कि कोई नाम alias, function, builtin या file के रूप में resolve होता है या नहीं। `command -v` और `which` aliases और functions के लिए एक जैसी जानकारी नहीं दे सकते। Shell history में commands या credentials उजागर हो सकते हैं, लेकिन यह अधूरी हो सकती है, disabled हो सकती है या session समाप्त होने तक memory में रखी जा सकती है।

## Startup और history files की समीक्षा करें

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

किसी user-writable startup file से अगली बार shell लॉन्च होने पर commands execute हो सकते हैं। यदि कम privileged account किसी system-wide startup file या privileged user की startup file को modify कर सकता है, तो वह अधिक संवेदनशील है। Non-interactive Bash, `BASH_ENV` द्वारा नामित file को भी पढ़ सकता है; [environment variables](linux-environment-variables.md#bash_env--env) पेज इस व्यवहार और interpreter के अन्य hooks को समझाता है। Persistence path का दावा करने से पहले यह verify करें कि login, interactive और non-interactive sessions के लिए actual shell कौन-सी files पढ़ता है।

Global startup file द्वारा sourced की जाने वाली files का भी निरीक्षण करें। उदाहरण के लिए, `/etc/bash.bashrc` में `source /opt/app/venv/bin/activate` होने पर, जब shell वास्तव में वह startup file पढ़ता है, तो activation file shell code के रूप में चलती है। Activation file, symlink और parent-directory permissions, तथा ACLs की समीक्षा करें; कम privileged writer किसी privileged shell को तभी प्रभावित कर सकता है जब वह shell या कोई privileged task बाद में उस file को source करे। यदि write access `sudoedit` पर निर्भर है, तो पहले सटीक sudoers rule और इंस्टॉल किए गए vendor-patched sudo package को verify करें; केवल upstream version string से [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) साबित नहीं होता।

[users and sessions](../user-information/user-and-session-triage.md) में बताए अनुसार secrets के लिए history, dotfiles और backups की जाँच करें। यदि कोई privileged script नाम से commands resolve करती है, तो इस समीक्षा के साथ [PATH hijacking guidance](linux-environment-variables.md#path) भी देखें।
{{#include ../../banners/hacktricks-training.md}}
