# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Vim'in kendi scripting language'ı (Vimscript), environment variable'lar üzerinden **başlangıçta arbitrary Ex command'ları ve shell command'larını çalıştırabilir**. Daha ayrıcalıklı bir process (maintenance/root workflow'u, bir `sudo vim …`, başka bir tool tarafından başlatılan editor, `crontab -e`, `visudo`, editor çağıran `git`/`less`, …), attacker tarafından etkilenebilen bir environment ile Vim/Neovim başlatırsa attacker bu context içinde code execution elde eder.

## `VIMINIT`

Initialization sırasında Vim, **`VIMINIT`** içindeki Ex command'ları okur ve çalıştırır. Ex command'ları arasında `:!cmd` (bir shell command çalıştırır) ve `:call system(...)` bulunur; bu nedenle tek bir variable, herhangi bir file edit edilmeden önce arbitrary execution sağlar.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
İlk örnekte stdin üzerinden verilen `:qa!`, yalnızca payload çalıştıktan sonra editörü kapatır; gerçek bir senaryoda kurban Vim'i normal şekilde açabilir.

`VIMINIT`, **tek bir Ex command line** olarak ayrıştırılır. Bir zinciri `|` (veya gerçek bir satır sonu) ile ayırın. Kullanıcının vimrc'si ve `EXINIT` üzerinde önceliğe sahiptir; bu nedenle bir payload'ın malicious bir configuration file'a ihtiyacı yoktur ve normal kullanıcı configuration'ından önce çalışır.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

`VIMINIT` ayarlanmamışsa Vim (ve `vi`/`ex` compatibility binaries), aynı şekilde çalıştırılan **`EXINIT`**'e geri döner. Bu, aynı primitive'in klasik vi dönemi varyantıdır.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Startup bastırma ve exploit edilebilirlik

Bu primitive **normal startup** işlemine bağlıdır. `vim -u NONE` / `nvim -u NONE` environment/user initialization işlemlerini (ve plugins) atlar; `-u <file>` ise bunun yerine belirtilen dosyayı kullanır. Vim `-es`/`-Es` ve Neovim `-es`, `-Es` veya `-l` seçenekleri de bu initialization adımlarını atlar. `--headless` seçeneğini güvenli bir mod sanmayın: normal bir Neovim headless startup işlemi yine de `VIMINIT` değerini işler.<sup>[[1]](#references)[[2]](#references)</sup>

Sonuç olarak, complete launch chain'i doğrulayın: variable wrapper, `sudo` policy, job runner ve editor selection süreçlerinden geçebilmelidir; final command ise `-u NONE`/`NORC` veya batch mode zorlamamalıdır. Güvenilir bir payload, `|qall!` ile kendisini sonlandırabilir; bu, TTY sağlamayan wrapper'ların test edilmesini de kolaylaştırır.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

Ayrı bir Neovim injection primitive'i, Lua `package.path`/`package.cpath` değerlerinde hâlâ `./?.lua` veya `./?.so` gibi current-directory template'lerinin bulunduğu build'leri etkiler. Neovim'i tek başına başlatmak yeterli değildir: bir config veya plugin `require("name")` çağırmalıdır ve daha önce çalışan bir loader bu name'i resolve etmemelidir. Yaygın bir trigger, `pcall(require, "optional_dep")` gibi bir **optional dependency check** işlemidir; `optional_dep.lua` dosyasını attacker-controlled bir working directory içine yerleştirmek, ayrı `'exrc'` local-configuration özelliğini etkinleştirmeden bu dosyanın çalıştırılmasını sağlar. Core `vim.*` modülleri ve `'runtimepath'` üzerinde zaten bulunan modüller genellikle shadow edilemez; bu nedenle name'leri tahmin etmek yerine gerçek missing/optional `require()` çağrılarını enumerate edin.<sup>[[3]](#references)</sup>

Aşağıdaki örnek, zararsız bir marker ile loader primitive'ini yeniden üretir:<sup>[[3]](#references)</sup>
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
Sadece bir sürüm dizesine güvenmek yerine çalışan build'i kontrol edin:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream, normal editor startup sırasında current-directory fallback özelliğinin kaldırılmasını takip ederken Lua-script (`nvim -l`) davranışını koruyor. Yüklü build bu özelliği artık sunmayana kadar bunu `init.lua` dosyasının **başına** ekleyin (relative current-directory Lua/C module şablonlarını kasıtlı olarak kaldırır; bu nedenle bunları gerektiren workflow'larda uygulamayın):<sup>[[3]](#references)</sup>
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
## Notlar ve dikkat edilmesi gerekenler

- **Neovim**, hem `VIMINIT` değişkenini hem de `EXINIT` fallback mekanizmasını dikkate alır; ancak normal kullanıcı yapılandırması `init.vim` veya `init.lua` dosyasıdır.<sup>[[2]](#references)</sup>
- Environment-variable yolu yazılabilir bir dosya gerektirmez. Yerel rc ve current-directory module hijacking, dosya tabanlı ayrı primitive'lerdir.<sup>[[1]](#references)[[3]](#references)</sup>
- Proje-yerel yapılandırma, modeline'lerden farklı bir yüzeydir. Vim'de `'exrc'` etkinleştirildiğinde, başka bir kullanıcıya ait yerel vimrc/exrc dosyası `'secure'` kısıtlamalarıyla çalışır; ancak bir archive çıkarıldığında yerleştirilen dosya normalde victim'a ait olur ve ownership tabanlı bu korumayı etkisiz kılar. Neovim ayrıca `'exrc'` etkinleştirildiğinde `.nvim.lua`, `.nvimrc` veya `.exrc` dosyalarını da arar—bu opt-in mekanizmayı yukarıdaki `require()` current-directory fallback mekanizmasıyla karıştırmayın.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Editor-selection değişkenleri yalnızca hangi programın başlatılacağını seçer; `VIMINIT` değişkeninin final process'e ulaşacağını garanti etmez. Vim/Neovim exec boundary'sindeki exact environment ve arguments değerlerini inceleyin.<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- Privileged veya automated editor launch işlemlerinden önce değişkenleri açıkça kaldırın: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. Caller'ın her user startup source'u yok sayması gerektiğinde `-u NONE` önemlidir.<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL` değişkenlerini trusted absolute path'lere ayarlayın, root olarak inherited user environment ile interactive editor çalıştırmaktan kaçının ve wrapper'ların sanitization sonrasında `VIMINIT`/`EXINIT` değişkenlerini geri yükleyememesini sağlayın.<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim için, editor mode sırasında current-directory Lua/C search template'lerini kaldıran bir build'e güncelleyin veya plugin'leri yüklemeden önce bunları strip edin. Untrusted repository'ler açılırken optional `pcall(require, ...)` çağrıları için plugin code'u audit edin.<sup>[[3]](#references)</sup>
- Target'ın editor environment'ı, working directory'si veya startup configuration'ı üzerindeki control'ü, editor'ün security context'inde potansiyel bir code-execution primitive'i olarak değerlendirin.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim documentation — startup and initialization](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()` içinde current-directory fallback](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
