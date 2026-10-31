# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Vim'in kendi scripting language'ı (Vimscript), başlangıçta environment variable'lardan **arbitrary Ex commands ve shell commands** çalıştırabilir. Daha fazla yetkiye sahip bir process (bir maintenance/root workflow, `sudo vim …`, başka bir tool tarafından başlatılan bir editor, `crontab -e`, `visudo`, bir editor çağıran `git`/`less` vb.) saldırganın etkileyebildiği bir environment ile Vim/Neovim başlatırsa, saldırgan bu context'te code execution elde eder.

## `VIMINIT`

Başlatma sırasında Vim, **`VIMINIT`** içindeki Ex commands komutlarını okur ve çalıştırır. Ex commands arasında `:!cmd` (bir shell command çalıştırır) ve `:call system(...)` bulunur; dolayısıyla tek bir variable, herhangi bir dosya düzenlenmeden önce arbitrary execution sağlar.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

İlk örnekte stdin üzerinden verilen `:qa!`, yalnızca payload çalıştıktan sonra editörü kapatır; gerçek bir senaryoda kurban Vim'i normal şekilde açabilir.

`VIMINIT`, **tek bir Ex komut satırı** olarak ayrıştırılır. Komut zincirini `|` (veya gerçek bir yeni satır) ile ayırın. Kullanıcının vimrc dosyasına ve `EXINIT`'e göre önceliği vardır; bu nedenle payload kötü amaçlı bir yapılandırma dosyasına ihtiyaç duymaz ve normal kullanıcı yapılandırmasından önce çalışır.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

`VIMINIT` ayarlanmamışsa Vim (ve `vi`/`ex` uyumluluk binary'leri) aynı şekilde çalıştırılan **`EXINIT`**'e geri döner. Bu, aynı primitive'in vi döneminden kalma klasik varyantıdır.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Vim `exrc` ile projeye özgü rc

Bu, `VIMINIT` için dosya tabanlı bir alternatiftir. Kurban kullanıcı yapılandırmasında `set exrc` etkinleştirmişse Vim, `.vimrc` (ardından `_vimrc` veya `.exrc`) dosyasını yalnızca düzenlenen dosyanın bulunduğu dizinden değil, **çalışma dizininden** de yükler. Projeye özgü bir `.vimrc` yerleştirin ve kurbanın Vim'i bu projeden başlatmasını sağlayın. Unix'te Vim, başka birine ait yerel rc dosyasına `secure` kısıtlamaları uygular; ancak kurban tarafından çıkarılan bir arşiv, yerleştirilen dosyanın sahipliğini normalde kurbana verir ve bu denetimi atlatır.<sup>[[1]](#references)</sup>

Bu yalıtılmış işaretleyici, gerçek kullanıcı yapılandırmasını değiştirmeden başlangıç tetikleyicisini gösterir:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim farklıdır: güncel derlemelerde proje dizinindeki `.nvim.lua`, `.nvimrc` veya `.exrc` dosyalarının çalıştırılmadan önce güvenilir olarak işaretlenmesi gerekir. Güven durumu dosyanın içerik hash’ine bağlıdır; bu nedenle daha önce güvenilir olarak işaretlenmiş bir dosyayı değiştirmek yeni bir güven kararı gerektirir. Yalnızca bir depoya dosya yerleştirebilen bir saldırgan, `exrc` üzerinden sessizce kod çalıştırılacağını varsayamaz; bu isteğe bağlı ve güven onayı gerektiren yolu, aşağıdaki geçerli dizin Lua `require()` yolundan ayırın.<sup>[[4]](#references)[[5]](#references)</sup>

Proje dizinindeki bir dosya yerine yazılabilir bir **kullanıcı** vimrc dosyası söz konusuysa, bkz. [macOS Vim başlangıç yapılandırması](../../macos-auto-start-locations.md#vim-startup-configuration).

## Başlangıcın engellenmesi ve exploit edilebilirlik

Bu primitive **normal bir başlangıca** bağlıdır. `vim -u NONE` / `nvim -u NONE`, ortam/kullanıcı başlatma işlemlerini (ve plugin’leri) atlar; `-u <file>` ise bunun yerine belirtilen dosyayı kullanır. Vim `-es`/`-Es` ve Neovim `-es`, `-Es` veya `-l` seçenekleri de bu başlatma adımlarını atlar. `--headless` seçeneğini güvenli mod sanmayın: normal bir Neovim headless başlangıcı yine de `VIMINIT` değişkenini işler.<sup>[[1]](#references)[[2]](#references)</sup>

Bu nedenle başlatma zincirinin tamamını doğrulayın: değişken wrapper, `sudo` politikası, job runner ve editör seçimi boyunca korunmalı; son komut da `-u NONE`/`NORC` veya batch mode seçeneklerini zorlamamalıdır. Güvenilir bir payload, kendini `|qall!` ile sonlandırabilir; bu, TTY sağlamayan wrapper’larla test yapmayı da kolaylaştırır.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim geçerli dizin Lua modülü hijacking

Ayrı bir Neovim injection primitive’i, Lua `package.path`/`package.cpath` değerlerinde `./?.lua` veya `./?.so` gibi geçerli dizin şablonları bulunan derlemeleri etkiler. Yalnızca Neovim’i başlatmak yeterli değildir: bir config veya plugin `require("name")` çağrısı yapmalı ve daha önce hiçbir loader bu adı çözümlememiş olmalıdır. Yaygın bir tetikleyici, `pcall(require, "optional_dep")` gibi **isteğe bağlı bağımlılık denetimidir**; saldırganın denetimindeki çalışma dizinine `optional_dep.lua` yerleştirmek, ayrı `'exrc'` yerel yapılandırma özelliğini etkinleştirmeden bu dosyayı çalıştırır. Çekirdek `vim.*` modülleri ve `'runtimepath'` üzerinde zaten bulunan modüller genellikle shadow edilemez; bu nedenle isim tahmin etmek yerine gerçekten eksik/isteğe bağlı olan `require()` çağrılarını belirleyin.<sup>[[3]](#references)</sup>

Aşağıdaki örnek, zararsız bir işaretçiyle loader primitive’ini yeniden oluşturur:<sup>[[3]](#references)</sup>

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

Yalnızca sürüm dizesine güvenmek yerine çalışan build'i kontrol edin:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream, normal editor startup sırasında geçerli dizin geri dönüşünün kaldırılmasını izlerken Lua script’i (`nvim -l`) davranışını koruyor. Yüklü derlemede bu özellik kaldırılana kadar bunu `init.lua` dosyasının **başına** ekleyin (göreli geçerli dizin Lua/C modül şablonlarını kasıtlı olarak kaldırır; bu nedenle bunları gerektiren iş akışlarında uygulamayın):<sup>[[3]](#references)</sup>

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

## Notlar ve uyarılar

- **Neovim**, hem `VIMINIT` değişkenini hem de `EXINIT` geri dönüşünü dikkate alır; ancak normal kullanıcı yapılandırma dosyası `init.vim` veya `init.lua`'dır.<sup>[[2]](#references)</sup>
- Ortam değişkeni yolu, yazılabilir bir dosya gerektirmez. Yerel rc dosyası ve geçerli dizinden modül ele geçirme, dosya tabanlı ayrı yöntemlerdir.<sup>[[1]](#references)[[3]](#references)</sup>
- Projeye özel rc dosyaları, modeline'lerden ve yukarıdaki `require()` geçerli dizin geri dönüşünden farklıdır. Vim ve Neovim bunlar için farklı denetimler uygular; yukarıdaki projeye özel `exrc` iş akışına bakın.<sup>[[1]](#references)[[4]](#references)</sup>
- Editör seçimi değişkenleri yalnızca hangi programın başlatılacağını belirler; `VIMINIT` değişkeninin son sürece ulaşacağını garanti etmez. Vim/Neovim `exec` sınırındaki ortamı ve argümanları inceleyin.<sup>[[1]](#references)[[2]](#references)</sup>

## Güvenliği sağlamlaştırma

- Yetkili veya otomatik editör başlatmalarından önce değişkenleri açıkça kaldırın: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. Çağıran tarafın tüm kullanıcı başlangıç kaynaklarını yok sayması gerektiğinde `-u NONE` önemlidir.<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL` değişkenlerini güvenilir mutlak yollara ayarlayın, devralınan kullanıcı ortamıyla etkileşimli editörleri root olarak çalıştırmaktan kaçının ve sarmalayıcıların temizleme sonrasında `VIMINIT`/`EXINIT` değişkenlerini yeniden ayarlayamadığından emin olun.<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim için, editör modundayken geçerli dizin Lua/C arama şablonlarını kaldıran bir derlemeye güncelleyin veya eklentileri yüklemeden önce bu şablonları temizleyin. Güvenilmeyen depolar açılırken isteğe bağlı `pcall(require, ...)` çağrıları için eklenti kodunu denetleyin.<sup>[[3]](#references)</sup>
- Bir hedefin editör ortamını, çalışma dizinini veya başlangıç yapılandırmasını denetleme olanağını, editörün güvenlik bağlamında potansiyel bir kod yürütme yöntemi olarak değerlendirin.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim belgeleri — `starting.txt` (başlatma, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim belgeleri — başlatma ve ilklendirme](https://neovim.io/doc/user/starting/)
- [3] [Neovim sorunu #38966 — `require()` içinde geçerli dizin geri dönüşü](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim seçenekleri — projeye özel `exrc` ve güven gereksinimi](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim düzenleme — güvenilir dosyalar ve `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
