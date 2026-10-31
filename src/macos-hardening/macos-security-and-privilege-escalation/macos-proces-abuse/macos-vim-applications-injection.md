# macOS Vim/Neovim अनुप्रयोगों में Injection

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

Vim की अपनी scripting language (Vimscript) environment variables से **startup पर arbitrary Ex commands और shell commands चला सकती है**। अगर कोई अधिक privileged process (maintenance/root workflow, `sudo vim …`, किसी दूसरे tool द्वारा शुरू किया गया editor, `crontab -e`, `visudo`, editor को invoke करने वाला `git`/`less`, …) attacker के नियंत्रण वाले environment के साथ Vim/Neovim launch करता है, तो attacker को उस context में code execution मिल जाता है।

## `VIMINIT`

Initialization के दौरान Vim **`VIMINIT`** में मौजूद Ex commands को पढ़ता और चलाता है। Ex commands में `:!cmd` (shell command चलाना) और `:call system(...)` शामिल हैं, इसलिए एक ही variable से किसी भी file को edit करने से पहले arbitrary execution हो सकता है।<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

पहले उदाहरण में stdin पर दिया गया `:qa!` payload चलने के बाद ही editor को बंद करता है; वास्तविक परिदृश्य में victim सामान्य रूप से Vim खोल सकता है।

`VIMINIT` को **एक Ex command line** के रूप में parse किया जाता है। कमांड की शृंखला को `|` (या literal newline) से अलग करें। इसे उपयोगकर्ता के vimrc और `EXINIT` पर प्राथमिकता मिलती है, इसलिए payload को malicious configuration file की ज़रूरत नहीं होती और यह सामान्य user configuration से पहले चलता है।<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

यदि `VIMINIT` सेट नहीं है, तो Vim (और `vi`/`ex` compatibility binaries) **`EXINIT`** पर fallback करता है, जिसे उसी तरह execute किया जाता है। यह उसी primitive का classic vi-era variant है।<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Vim `exrc` के साथ प्रोजेक्ट-लोकल rc

यह `VIMINIT` का फ़ाइल-आधारित विकल्प है। यदि victim ने अपने user configuration में `set exrc` सक्षम किया है, तो Vim संपादित की जा रही फ़ाइल की directory से ही नहीं, बल्कि अपनी **working directory** से भी `.vimrc` (फिर `_vimrc` या `.exrc`) source करता है। एक प्रोजेक्ट-लोकल `.vimrc` रखें और victim से उस प्रोजेक्ट से Vim शुरू करवाएँ। Unix पर, Vim किसी अन्य व्यक्ति के स्वामित्व वाले local rc पर `secure` प्रतिबंध लागू करता है, लेकिन victim द्वारा extract किए गए archive में रखी गई फ़ाइल का स्वामित्व आम तौर पर victim के पास होता है, जिससे यह जाँच टल जाती है।<sup>[[1]](#references)</sup>

यह isolated marker, real user configuration में बदलाव किए बिना startup trigger दिखाता है:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim अलग है: मौजूदा builds में project-local `.nvim.lua`, `.nvimrc`, या `.exrc` को चलाने से पहले trusted करना ज़रूरी है। Trust, फ़ाइल के content hash से जुड़ा होता है, इसलिए पहले से trusted फ़ाइल में बदलाव करने पर फिर से trust का निर्णय लेना पड़ता है। अगर कोई attacker सिर्फ़ repository में फ़ाइल रख सकता है, तो वह `exrc` के ज़रिए बिना किसी संकेत के execution मानकर नहीं चल सकता; इस opt-in, trust-gated तरीके को नीचे दिए गए current-directory Lua `require()` तरीके से अलग समझें।<sup>[[4]](#references)[[5]](#references)</sup>

Project-local vimrc के बजाय writable **user** vimrc के लिए, [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration) देखें।

## Startup को रोकना और exploitability

यह primitive **normal startup** पर निर्भर करता है। `vim -u NONE` / `nvim -u NONE` environment/user initialization (और plugins) को छोड़ देते हैं, जबकि `-u <file>` उस फ़ाइल का इस्तेमाल करता है। Vim के `-es`/`-Es` और Neovim के `-es`, `-Es`, या `-l` भी ये initialization steps छोड़ देते हैं। `--headless` को safe mode न समझें: Neovim का normal headless startup अब भी `VIMINIT` को process करता है।<sup>[[1]](#references)[[2]](#references)</sup>

इसलिए पूरी launch chain को validate करें: variable को wrapper, `sudo` policy, job runner, और editor selection से गुज़रना चाहिए, और अंतिम command में `-u NONE`/`NORC` या batch mode ज़बरदस्ती चालू नहीं होना चाहिए। एक भरोसेमंद payload `|qall!` के साथ खुद को terminate कर सकता है, जिससे ऐसे wrappers की testing भी आसान हो जाती है जो TTY नहीं देते।<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

एक अलग Neovim injection primitive उन builds को प्रभावित करता है जिनके Lua `package.path`/`package.cpath` में अब भी `./?.lua` या `./?.so` जैसे current-directory templates शामिल हैं। सिर्फ़ Neovim शुरू करना काफ़ी नहीं है: किसी config या plugin को `require("name")` call करना होगा, और इससे पहले कोई loader उस नाम को resolve न कर पाया हो। आम trigger एक **optional dependency check** है, जैसे `pcall(require, "optional_dep")`; attacker के control वाले working directory में `optional_dep.lua` रखने पर, अलग `'exrc'` local-configuration feature चालू किए बिना ही वह execute हो जाती है। Core `vim.*` modules और `'runtimepath'` पर पहले से मिल जाने वाले modules को आम तौर पर shadow नहीं किया जा सकता, इसलिए नामों का अंदाज़ा लगाने के बजाय वास्तविक missing/optional `require()` calls की सूची बनाएँ।<sup>[[3]](#references)</sup>

निम्न उदाहरण एक harmless marker के साथ loader primitive को दोहराता है:<sup>[[3]](#references)</sup>

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

Upstream सामान्य editor startup के दौरान current-directory fallback को हटाने पर काम कर रहा है, जबकि Lua-script (`nvim -l`) व्यवहार बरकरार रहेगा। जब तक installed build में यह सुविधा उपलब्ध है, इसे `init.lua` की **शुरुआत** में रखें (यह जानबूझकर relative current-directory Lua/C module templates हटाता है, इसलिए इसे उन workflows पर लागू न करें जिन्हें इनकी ज़रूरत है):<sup>[[3]](#references)</sup>

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

## नोट्स और सावधानियां

- **Neovim** `VIMINIT` और `EXINIT` fallback, दोनों का सम्मान करता है, लेकिन इसकी सामान्य user configuration `init.vim` या `init.lua` होती है।<sup>[[2]](#references)</sup>
- Environment-variable path के लिए किसी writable file की ज़रूरत नहीं होती। Local rc और current-directory module hijacking अलग file-backed primitives हैं।<sup>[[1]](#references)[[3]](#references)</sup>
- Project-local rc files, modelines और ऊपर बताए गए `require()` current-directory fallback से अलग हैं। Vim और Neovim इनके लिए अलग-अलग checks करते हैं; ऊपर दिया गया project-local `exrc` workflow देखें।<sup>[[1]](#references)[[4]](#references)</sup>
- Editor-selection variables केवल यह चुनते हैं कि कौन-सा program launch होगा; वे यह सुनिश्चित नहीं करते कि `VIMINIT` अंतिम process तक पहुंचे। Vim/Neovim exec boundary पर सटीक environment और arguments की जांच करें।<sup>[[1]](#references)[[2]](#references)</sup>

## सुरक्षा सुदृढ़ीकरण

- Privileged या automated editor launches से पहले variables को स्पष्ट रूप से हटाएं: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. जब caller को हर user startup source को अनदेखा करना हो, तब `-u NONE` महत्वपूर्ण है।<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL` को trusted absolute paths पर सेट करें, inherited user environment के साथ interactive editors को root के रूप में चलाने से बचें, और सुनिश्चित करें कि wrappers sanitization के बाद `VIMINIT`/`EXINIT` को फिर से सेट न कर सकें।<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim के लिए ऐसा build इस्तेमाल करें जो editor mode के दौरान current-directory Lua/C search templates हटाता हो, या plugins load करने से पहले उन्हें strip करें। Untrusted repositories खोलते समय optional `pcall(require, ...)` calls के लिए plugin code का audit करें।<sup>[[3]](#references)</sup>
- Target के editor environment, working directory या startup configuration पर नियंत्रण को editor के security context में संभावित code-execution primitive मानें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim दस्तावेज़ — `starting.txt` (प्रारंभिकरण, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim दस्तावेज़ — startup और प्रारंभिकरण](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()` में current-directory fallback](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim options — project-local `exrc` और trust की आवश्यकता](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim editing — trusted files और `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
