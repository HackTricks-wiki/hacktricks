# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Vim की अपनी scripting language (Vimscript), environment variables से **arbitrary Ex commands और shell commands** को startup पर चला सकती है। यदि कोई अधिक privileged process (maintenance/root workflow, कोई `sudo vim …`, किसी अन्य tool द्वारा spawn किया गया editor, `crontab -e`, `visudo`, `git`/`less` द्वारा invoke किया गया editor, …) attacker-influenced environment के साथ Vim/Neovim लॉन्च करता है, तो attacker को उस context में code execution मिल जाता है।

## `VIMINIT`

Initialization के दौरान Vim **`VIMINIT`** में मौजूद Ex commands को पढ़कर execute करता है। Ex commands में `:!cmd` (shell command चलाना) और `:call system(...)` शामिल हैं, इसलिए एक single variable किसी भी file को edit करने से पहले arbitrary execution प्रदान करता है।<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
stdin पर भेजा गया `:qa!` payload के पहले ही run हो जाने के बाद editor को केवल बंद करता है; real scenario में victim Vim को सामान्य रूप से खोलता है।

## `EXINIT`

यदि `VIMINIT` set नहीं है, तो Vim (और `vi`/`ex` compatibility binaries) **`EXINIT`** पर fallback करता है, जिसे उसी तरह execute किया जाता है। यह उसी primitive का classic vi-era variant है।<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Notes and caveats

- **Neovim** `VIMINIT` का भी सम्मान करता है (इसे user `init.vim`/`init.lua` से पहले check किया जाता है)।
- Batch/Ex mode (`vim -es` / `vim -Es`) `VIMINIT`/`EXINIT` को source नहीं करता; variables सामान्य (interactive) startup में run होते हैं, जो common victim scenario है।
- संबंधित file-based vectors प्रति-directory `exrc`/`.nvimrc` "modeline"/local-rc features और `-u <vimrc>` हैं; ऊपर दिया गया environment-variable path किसी writable file की आवश्यकता नहीं रखता।

## Hardening

- Privileged या automated contexts से editors launch करने से पहले environment को sanitize करें (`VIMINIT`/`EXINIT` हटाएँ), और ऐसे `sudo -i`/`env -i` wrappers को प्राथमिकता दें जो environment को reset करते हैं।
- `EDITOR`/`VISUAL` को trusted absolute paths पर set करें और inherited user environment के साथ editors को root के रूप में चलाने से बचें।
- Target के environment पर control को उसके द्वारा spawn किए जाने वाले किसी भी Vim/Neovim के लिए code execution के equivalent मानें।

## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
