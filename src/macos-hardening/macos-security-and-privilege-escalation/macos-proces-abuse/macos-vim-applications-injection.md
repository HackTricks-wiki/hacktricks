# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Vim की अपनी scripting language (Vimscript) environment variables से startup पर **arbitrary Ex commands और shell commands** चला सकती है। यदि कोई अधिक privileged process (maintenance/root workflow, `sudo vim …`, किसी अन्य tool द्वारा spawned editor, `crontab -e`, `visudo`, editor invoke करने वाला `git`/`less`, …) attacker-influenced environment के साथ Vim/Neovim launch करता है, तो attacker को उस context में code execution मिल जाता है।

## `VIMINIT`

Initialization के दौरान Vim **`VIMINIT`** में दिए गए Ex commands को read और execute करता है। Ex commands में `:!cmd` (shell command चलाना) और `:call system(...)` शामिल हैं, इसलिए केवल एक variable किसी भी file को edit करने से पहले arbitrary execution दे सकता है।<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
पहले उदाहरण में stdin पर दिया गया `:qa!` payload चलने के बाद ही editor को बंद करता है; वास्तविक scenario में victim Vim को सामान्य रूप से खोल सकता है।

`VIMINIT` को **एक Ex command line** के रूप में parse किया जाता है। किसी chain को `|` (या literal newline) से अलग करें। इसे user के vimrc और `EXINIT` पर precedence प्राप्त है, इसलिए payload को malicious configuration file की आवश्यकता नहीं होती और यह सामान्य user configuration से पहले चलता है।<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

यदि `VIMINIT` set नहीं है, तो Vim (और `vi`/`ex` compatibility binaries) **`EXINIT`** पर fallback करता है, जिसे उसी तरह execute किया जाता है। यह उसी primitive का classic vi-era variant है।<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Startup suppression और exploitability

यह primitive एक **normal startup** पर निर्भर करता है। `vim -u NONE` / `nvim -u NONE` environment/user initialization (और plugins) को skip करते हैं, जबकि `-u <file>` उसकी जगह उस file का उपयोग करता है। Vim `-es`/`-Es` और Neovim `-es`, `-Es`, या `-l` भी ये initialization steps skip करते हैं। `--headless` को safe mode न समझें: एक सामान्य Neovim headless startup अभी भी `VIMINIT` को process करता है।<sup>[[1]](#references)[[2]](#references)</sup>

इसलिए पूरी launch chain को validate करें: variable को wrapper, `sudo` policy, job runner और editor selection से survive करना चाहिए, और final command को `-u NONE`/`NORC` या batch mode को force नहीं करना चाहिए। एक reliable payload `|qall!` के साथ स्वयं terminate हो सकता है, जिससे ऐसे wrappers की testing भी आसान हो जाती है जो TTY प्रदान नहीं करते।<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

एक अलग Neovim injection primitive उन builds को प्रभावित करता है जिनके Lua `package.path`/`package.cpath` में अभी भी `./?.lua` या `./?.so` जैसे current-directory templates मौजूद हैं। केवल Neovim शुरू करना पर्याप्त नहीं है: किसी config या plugin को `require("name")` call करना चाहिए, और किसी पहले loader को उस name को resolve नहीं करना चाहिए। एक सामान्य trigger **optional dependency check** है, जैसे `pcall(require, "optional_dep")`; attacker-controlled working directory में `optional_dep.lua` रखने पर यह अलग `'exrc'` local-configuration feature enable किए बिना इसे execute कर देता है। Core `vim.*` modules और `'runtimepath'` पर पहले से मिले modules सामान्यतः shadowable नहीं होते, इसलिए names का अनुमान लगाने के बजाय वास्तविक missing/optional `require()` calls enumerate करें।<sup>[[3]](#references)</sup>

निम्न harmless marker के साथ loader primitive को reproduce करता है:<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
केवल version string पर निर्भर रहने के बजाय चल रहे build की जाँच करें:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream सामान्य editor startup के दौरान current-directory fallback को हटाने पर काम कर रहा है, जबकि Lua-script (`nvim -l`) का behavior बरकरार रखा गया है। जब तक installed build इसे expose करना बंद नहीं करता, इसे `init.lua` की **शुरुआत** में रखें (यह जानबूझकर relative current-directory Lua/C module templates को हटा देता है, इसलिए इसे उन workflows पर लागू न करें जिनमें इनकी आवश्यकता होती है):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Notes and caveats

- **Neovim** `VIMINIT` और `EXINIT` fallback दोनों को मानता है, लेकिन इसका सामान्य user configuration `init.vim` या `init.lua` होता है।<sup>[[2]](#references)</sup>
- Environment-variable path के लिए किसी writable file की आवश्यकता नहीं होती। Local rc और current-directory module hijacking अलग-अलग, file-backed primitives हैं।<sup>[[1]](#references)[[3]](#references)</sup>
- Project-local configuration, modelines से अलग surface है। Vim में `'exrc'` enabled होने पर, किसी अन्य user के स्वामित्व वाला local vimrc/exrc `'secure'` restrictions के साथ चलता है; हालांकि, किसी archive को सामान्य रूप से extract करने पर planted file victim के स्वामित्व में आ जाती है और ownership-based protection निष्प्रभावी हो जाती है। `'exrc'` enabled होने पर Neovim `.nvim.lua`, `.nvimrc`, या `.exrc` भी खोजता है—इस opt-in mechanism को ऊपर बताए गए `require()` current-directory fallback के साथ न मिलाएँ।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Editor-selection variables केवल यह चुनते हैं कि कौन-सा program launch किया जाए; वे यह सुनिश्चित नहीं करते कि `VIMINIT` final process तक पहुँचे। Vim/Neovim exec boundary पर exact environment और arguments की जाँच करें।<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- Privileged या automated editor launches से पहले variables को स्पष्ट रूप से हटाएँ: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`। जब caller को हर user startup source को ignore करना हो, तब `-u NONE` महत्वपूर्ण है।<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL` को trusted absolute paths पर set करें, inherited user environment के साथ interactive editors को root के रूप में चलाने से बचें, और सुनिश्चित करें कि wrappers sanitization के बाद `VIMINIT`/`EXINIT` को restore न कर सकें।<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim के लिए ऐसे build पर update करें जो editor mode के दौरान current-directory Lua/C search templates को हटा देता हो, या plugins load करने से पहले उन्हें strip करें। Untrusted repositories खोलते समय optional `pcall(require, ...)` calls के लिए plugin code का audit करें।<sup>[[3]](#references)</sup>
- Target के editor environment, working directory, या startup configuration पर control को editor के security context में संभावित code-execution primitive मानें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim documentation — startup और initialization](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()` में current-directory fallback](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
