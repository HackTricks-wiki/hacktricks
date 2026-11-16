# Посилення безпеки Linux

{{#include ../banners/hacktricks-training.md}}

Використовуйте цей розділ для дослідження хостів Linux, розуміння меж привілеїв і перевірки засобів контролю, що обмежують локальний доступ. Для загальної оцінки почніть із [основ Linux](linux-basics/README.md) і [контрольного списку підвищення привілеїв](main-system-information/linux-privilege-escalation-checklist.md), а потім перейдіть до відповідної теми нижче.

- [Основи Linux](linux-basics/README.md): методологія підвищення привілеїв, корисні команди, змінні середовища та обходи обмежень.
- [Основна інформація про систему](main-system-information/README.md): ядро, модулі, sudo, поведінка файлової системи, jail-середовища та контрольний список підвищення привілеїв.
- [Інформація про користувачів](user-information/README.md): ідентифікаційні дані користувачів Linux, групи, пересилання SSH agent і інтеграція з Active Directory.
- [Цікаві файли та дозволи](interesting-files-permissions/README.md): шляхи з правом запису, capabilities, поведінка SUID, NFS, розгортання шаблонів і SELinux.
- [Інформація про мережу](network-information/README.md): локальні служби, сокети та приклади експлуатації, пов’язаної з мережею.
- [Інформація про програмне забезпечення](software-information/README.md): модулі автентифікації та специфічні для застосунків поверхні атак.
- [Процеси, crontab, systemd і D-Bus](processes-crontab-systemd-dbus/README.md): заплановане виконання та міжпроцесна взаємодія.
- [Контейнери та простори імен](containers-namespaces/README.md): середовища виконання, межі ізоляції та посилення безпеки контейнерів.
- [Зловживання файлами керування політиками AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): перевірте, чи може привілейований helper записувати у файл керування AppArmor, відкритий локальним користувачем.
- [Post-exploitation](post-exploitation/README.md): пошук облікових даних, закріплення в системі та подальші методи на рівні хоста.

У вразливих ядрах відкриття непривілейованим користувачем файла керування політиками AppArmor у securityfs може бути успішним, хоча прямий запис заборонено. Якщо привілейований helper успадкує цей файл як stdout, його запис може змінити завантажену політику; це окремий шлях локальної атаки, не пов’язаний із простим виявленням слабкого профілю контейнера. Перш ніж тестувати це, перевірте виправлення від постачальника для ядра та helper.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Технічний бюлетень Qualys про CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [База знань Ubuntu про вразливість CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
