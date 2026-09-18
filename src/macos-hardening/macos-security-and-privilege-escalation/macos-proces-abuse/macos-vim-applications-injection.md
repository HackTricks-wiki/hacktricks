# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Vim'in kendi scripting language'i (Vimscript), **başlangıçta environment variables üzerinden arbitrary Ex commands ve shell commands çalıştırabilir**. Daha ayrıcalıklı bir process (bir maintenance/root workflow, bir `sudo vim …`, başka bir tool tarafından başlatılan bir editor, `crontab -e`, `visudo`, bir editor çağıran `git`/`less`, …) attacker-controlled bir environment ile Vim/Neovim'i başlatırsa attacker, o context içinde code execution elde eder.

## `VIMINIT`

Başlatma sırasında Vim, **`VIMINIT`** içindeki Ex commands'leri okur ve çalıştırır. Ex commands, `:!cmd` (bir shell command çalıştırır) ve `:call system(...)` ifadelerini içerir; dolayısıyla tek bir variable, herhangi bir file edit edilmeden önce arbitrary execution sağlar.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
Stdin üzerinden gönderilen `:qa!`, payload zaten çalıştırıldıktan sonra editor'ü kapatır; gerçek bir senaryoda kurban Vim'i normal şekilde açar.

## `EXINIT`

`VIMINIT` ayarlanmamışsa Vim (ve `vi`/`ex` uyumluluk binary'leri), aynı şekilde çalıştırılan **`EXINIT`** değişkenine geri döner. Bu, aynı primitive'in klasik vi dönemi varyantıdır.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Notlar ve dikkat edilmesi gerekenler

- **Neovim**, `VIMINIT` değişkenini de dikkate alır (kullanıcının `init.vim`/`init.lua` dosyasından önce kontrol edilir).
- Batch/Ex modu (`vim -es` / `vim -Es`), **normal (interactive) startup** sırasında değişkenler çalıştırılırken `VIMINIT`/`EXINIT` kaynaklarını yüklemez; bu, yaygın victim senaryosudur.
- İlgili file-based vector'ler, dizin başına kullanılan `exrc`/`.nvimrc` "modeline"/local-rc özellikleri ve `-u <vimrc>` seçenekleridir; yukarıdaki environment-variable yolu hiç writable file gerektirmez.

## Hardening

- Privileged veya automated context'lerden editor başlatmadan önce environment'ı sanitize edin (`VIMINIT`/`EXINIT` değişkenlerini kaldırın) ve environment'ı sıfırlayan `sudo -i`/`env -i` wrapper'larını tercih edin.
- `EDITOR`/`VISUAL` değişkenlerini trusted absolute path'lere ayarlayın ve inherited user environment ile editor'leri root olarak çalıştırmaktan kaçının.
- Bir target'ın environment'ını kontrol etmeyi, onun başlattığı herhangi bir Vim/Neovim için code execution'a eşdeğer kabul edin.

## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
