# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` ve `PERL5LIB` env variable üzerinden

**`PERL5OPT`** env variable'ını kullanarak, interpreter başlatıldığında **Perl**'ün rastgele komutlar çalıştırmasını sağlamak mümkündür (hedef script'in ilk satırı parse edilmeden **önce** bile).
Örneğin, bu script'i oluşturun:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Şimdi **env değişkenini dışa aktarın** ve **perl** script'ini çalıştırın:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Diğer bir seçenek, bir Perl modülü (ör. `/tmp/pmod.pm`) oluşturmaktır:
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Ardından, modülün otomatik olarak bulunup yüklenmesi için env değişkenlerini kullanın:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Diğer ilginç environment variables

* **`PERL5DB`** – interpreter **`-d`** (debugger) flag'iyle başlatıldığında, `PERL5DB` içeriği debugger context'i *içinde* Perl code olarak execute edilir.
Hem environment'ı hem de privileged Perl process'in command-line flag'lerini etkileyebiliyorsanız şuna benzer bir şey yapabilirsiniz:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # script execute edilmeden önce bir shell açar
```

* **`PERL5SHELL`** – Windows'ta bu variable, Perl'in bir shell spawn etmesi gerektiğinde hangi shell executable'ını kullanacağını kontrol eder. Burada yalnızca eksiksizlik amacıyla belirtilmiştir; macOS ile ilgili değildir.

`PERL5DB` **`-d`** switch'ini gerektirse de, verbose troubleshooting için bu flag etkinleştirilerek *root* olarak execute edilen maintenance veya installer script'lerine sıkça rastlanır. Bu da variable'ı geçerli bir escalation vector'ü hâline getirir.

## Dependencies üzerinden (@INC abuse)

Perl'in arayacağı include path'i (**`@INC`**) şu şekilde listelemek mümkündür:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14'te tipik çıktı şu şekilde görünür:
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
Döndürülen klasörlerin bazıları hiç mevcut değil; ancak **`/Library/Perl/5.30`** mevcut, SIP tarafından korunmuyor ve SIP korumalı klasörlerden önce geliyor. Bu nedenle *root* olarak yazabiliyorsanız, ayrıcalıklı bir script tarafından bu modülü import eden her işlem tarafından *öncelikli olarak* yüklenecek kötü amaçlı bir modül (ör. `File/Basename.pm`) bırakabilirsiniz.

> [!WARNING]
> `/Library/Perl` içine yazmak için yine de **root** yetkisine ihtiyacınız vardır ve macOS, yazma işlemini gerçekleştiren işlem için *Full Disk Access* isteyen bir **TCC** prompt'u gösterir.

Örneğin bir script **`use File::Basename;`** import ediyorsa, saldırgan kontrollü kod içeren `/Library/Perl/5.30/File/Basename.pm` dosyasını oluşturmak mümkün olurdu.

## Migration Assistant üzerinden SIP bypass (CVE-2023-32369 “Migraine”)

Mayıs 2023'te Microsoft, **CVE-2023-32369** adlı ve **Migraine** olarak adlandırılan, *root* saldırganın **System Integrity Protection (SIP)** özelliğini tamamen **bypass** etmesine olanak tanıyan bir post-exploitation tekniğini açıkladı.
Güvenlik açığı bulunan bileşen, **`com.apple.rootless.install.heritable`** entitlement'ına sahip bir daemon olan **`systemmigrationd`**'dir. Bu daemon tarafından spawn edilen tüm child process'ler entitlement'ı devralır ve bu nedenle SIP kısıtlamalarının **dışında** çalışır.<sup>[1]</sup>

Araştırmacılar tarafından tespit edilen child process'ler arasında Apple tarafından imzalanmış interpreter da bulunur:<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perl `PERL5OPT` değişkenine (ve Bash `BASH_ENV` değişkenine) uyduğu için, daemon’ın *environment*’ını zehirlemek SIP’siz bir bağlamda arbitrary execution elde etmek için yeterlidir:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC` çalıştığında, `/usr/bin/perl` kötü amaçlı `PERL5OPT` ile başlar ve SIP yeniden etkinleştirilmeden önce `/private/tmp/migraine.sh` dosyasını çalıştırır. Bu script üzerinden, örneğin **`/System/Library/LaunchDaemons`** içine bir payload kopyalayabilir veya bir dosyayı **silinemez** hâle getirmek için `com.apple.rootless` extended attribute'ını atayabilirsiniz.

Apple bu sorunu macOS **Ventura 13.4**, **Monterey 12.6.6** ve **Big Sur 11.7.7** sürümlerinde düzeltti; ancak daha eski veya patch uygulanmamış sistemler hâlâ exploit edilebilir durumdadır.<sup>[1]</sup>

## Hardening önerileri

1. **Tehlikeli değişkenleri temizleyin** – privileged launchdaemon'lar veya cron job'ları temiz bir environment ile başlatılmalıdır (`launchctl unsetenv PERL5OPT`, `env -i` vb.).
2. **Interpreter'ları root olarak çalıştırmaktan kaçının** – kesinlikle gerekli olmadıkça compiled binary'ler kullanın veya privilege'ları erken aşamada düşürün.
3. **Script'leri `-T` (taint mode) ile vendor edin** – taint checking etkinleştirildiğinde Perl, `PERL5OPT` ve diğer güvenli olmayan switch'leri yok sayar.
4. **macOS'u güncel tutun** – “Migraine” güncel sürümlerde tamamen patch'lenmiştir.

## References

- [1] [Microsoft Security Blog – Yeni macOS açığı Migraine, System Integrity Protection'ı atlayabilir (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
