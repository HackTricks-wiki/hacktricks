# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Перевірте оригінальний пост для [всієї інформації про цю техніку](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Як **резюме**: якщо ви можете записувати в атрибут **msDS-KeyCredentialLink** користувача/комп'ютера, ви можете отримати **NT hash цього об'єкта**.

У пості описано метод налаштування **аутентифікаційних облікових даних з публічним-приватним ключем** для отримання унікального **Service Ticket**, який містить NTLM hash цілі. Цей процес включає зашифрований NTLM_SUPPLEMENTAL_CREDENTIAL у Сертифікаті Атрибутів Привілеїв (PAC), який можна розшифрувати.

### Requirements

Щоб застосувати цю техніку, необхідно виконати певні умови:

- Потрібен принаймні один контролер домену Windows Server 2016.
- Контролер домену повинен мати встановлений цифровий сертифікат для аутентифікації сервера.
- Active Directory повинна бути на функціональному рівні Windows Server 2016.
- Потрібен обліковий запис з делегованими правами для зміни атрибута msDS-KeyCredentialLink цільового об'єкта.

## Abuse

Зловживання Key Trust для комп'ютерних об'єктів охоплює кроки, що виходять за межі отримання квитка на отримання квитка (TGT) та NTLM hash. Варіанти включають:

1. Створення **RC4 silver ticket** для дій від імені привілейованих користувачів на цільовому хості.
2. Використання TGT з **S4U2Self** для імперсонації **привілейованих користувачів**, що вимагає змін до Service Ticket для додавання класу служби до імені служби.

Значною перевагою зловживання Key Trust є його обмеження лише на приватний ключ, згенерований атакуючим, що уникає делегування потенційно вразливим обліковим записам і не вимагає створення облікового запису комп'ютера, що може бути складно видалити.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Цей інструмент базується на DSInternals, надаючи інтерфейс C# для цієї атаки. Whisker та його Python-еквівалент, **pyWhisker**, дозволяють маніпулювати атрибутом `msDS-KeyCredentialLink`, щоб отримати контроль над обліковими записами Active Directory. Ці інструменти підтримують різні операції, такі як додавання, перерахування, видалення та очищення облікових даних ключів з цільового об'єкта.

**Функції Whisker** включають:

- **Add**: Генерує пару ключів і додає облікові дані ключа.
- **List**: Відображає всі записи облікових даних ключа.
- **Remove**: Видаляє вказані облікові дані ключа.
- **Clear**: Стирає всі облікові дані ключів, потенційно порушуючи законне використання WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Він розширює функціональність Whisker для **систем на базі UNIX**, використовуючи Impacket та PyDSInternals для всебічних можливостей експлуатації, включаючи перелік, додавання та видалення KeyCredentials, а також імпорт та експорт їх у форматі JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray має на меті **використати дозволи GenericWrite/GenericAll, які можуть мати широкі групи користувачів над об'єктами домену**, щоб широко застосувати ShadowCredentials. Це передбачає вхід до домену, перевірку функціонального рівня домену, перерахування об'єктів домену та спробу додати KeyCredentials для отримання TGT та розкриття NT hash. Варіанти очищення та рекурсивні тактики експлуатації підвищують його корисність.

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
