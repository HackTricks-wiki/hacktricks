# Uwierzytelnianie Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź świetny wpis na:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## TL;DR dla atakujących
- Kerberos jest domyślnym protokołem uwierzytelniania AD; większość łańcuchów lateral movement będzie miała z nim styczność.
- Myśl o **trzech fazach operacyjnych**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → użycie hasła/hashu/certyfikatu do uzyskania **TGT**. To tutaj występują **AS-REP roasting**, **over-pass-the-hash / pass-the-key** oraz **PKINIT**.
- **TGS-REQ / TGS-REP** → użycie TGT do uzyskania **service tickets**. To tutaj istotne są **Kerberoasting**, **S4U abuse**, **delegation abuse** oraz większość technik **ticket-forging**.
- **AP-REQ / AP-REP** → przedstawienie ticketu usłudze. To tutaj odbywa się **pass-the-ticket** oraz właściwy dla danej usługi lateral movement.
- Cheatsheety dotyczące praktycznego wykorzystania (AS-REP/Kerberoasting, ticket forgery, delegation abuse itd.) znajdziesz tutaj:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Używaj tej strony jako **przeglądu / indeksu „co ostatnio się zmieniło”**, a następnie przechodź do dedykowanych stron dotyczących [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) lub [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Najnowsze informacje o atakach (2024-2026)
- **Hardening RC4 zmienił domyślne ustawienia, a nie sam Kerberos** – współczesny hardening DC koncentruje się na **domyślnie przyjmowanych typach szyfrowania** dla kont, które nie ustawiają jawnie `msDS-SupportedEncryptionTypes`. Po wdrożeniu zmian w 2026 roku konta te coraz częściej domyślnie używają wyłącznie **AES** na załatanych DC, więc założenia dotyczące ślepego użycia `/rc4` w Kerberoast częściej zawodzą. Jednak **konta usług jawnie obsługujące RC4 nadal są doskonałymi celami do offline crackingu**.<sup>[[1]](#references)</sup>
- **Wymuszanie walidacji PAC ma znaczenie dla forged tickets** – hardening podpisów PAC z 2024 roku oznacza, że nadużycia w stylu **golden/diamond/sapphire/extraSID** wymagają bardziej realistycznych danych PAC oraz właściwego kontekstu podpisywania. Niezałatane domeny lub domeny pozostawione w trybie zgodności/audytu są mniej odporne.<sup>[[2]](#references)</sup>
- **Kerberos oparte na certyfikatach zmieniło się dwukrotnie**:<sup>[[2]](#references)</sup>
- **Strong certificate binding** (oś czasu KB5014754) sprawia, że nieprecyzyjne mapowania certyfikatów do kont są mniej niezawodne w środowiskach z pełnym wymuszaniem.
- **CVE-2025-26647** dodał kolejną warstwę hardeningu wokół mapowań certyfikatów **altSecID / SKI**. Jeśli DC są niezałatane, nadal działają w trybie audytu lub jawnie pomijają walidację NTAuth, dalsze nadużycia pass-the-certificate / shadow-credential pozostają bardziej praktyczne.
- **Nadużycia delegacji między domenami / lasami nadal są bardzo aktualne** – Windows obsługuje współczesne międzyobszarowe przepływy **S4U2Self/S4U2Proxy**, dlatego zapisywalne atrybuty delegacji w innej domenie nadal są wartościowe. Przeszkodą jest zwykle zgodność narzędzi oraz szczegóły trust/policy, a nie obsługa protokołu.
- **Rekursywne RBCD w wielu domenach ma znaczenie operacyjne** – w lasach z 3+ domenami **S4U2Self/S4U2Proxy** może rekursywnie przechodzić przez referrals trustów, a nadużycie **SPN-less** może wymagać końcowego kroku **`S4U2Self+U2U`** oraz obsługi ticketów zależnej od RC4. Zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 wprowadził nową powierzchnię ataku powiązaną z Kerberos** poprzez logikę migracji **dMSA**. Jeśli w domenie 2025 zauważysz delegowane uprawnienia do OU lub obiektów kont usług, sprawdź dedykowaną [stronę BadSuccessor](acl-persistence-abuse/BadSuccessor.md), zamiast traktować to jako „kolejne gMSA”.

## Szybkie kontrole operatora we współczesnych domenach

Przed wyborem ścieżki ataku Kerberos szybko odpowiedz na cztery pytania:

1. **Które konta nadal są przyjazne dla RC4?**
2. **Którzy użytkownicy nie wymagają pre-auth?**
3. **Które obiekty ujawniają możliwości delegation abuse?**
4. **Które części domeny są wystarczająco nowe, aby wymuszać najnowszy hardening?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Praktyczna interpretacja:
- Jeśli **interesujące konta SPN jawnie obsługują RC4**, Kerberoasting pozostaje tani i szybki.
- Jeśli większość kont usług nie ma **jawnej konfiguracji etype**, na zaktualizowanych kontrolerach domeny z 2026 roku oczekuj zachowania **tylko AES** i zaplanuj wolniejsze łamanie offline lub inną ścieżkę.
- Jeśli występuje **RBCD / KCD / unconstrained delegation**, S4U często jest skuteczniejsze niż brute-force.
- Jeśli używane jest **certificate auth**, pamiętaj, że nieudana ścieżka PKINIT **nie zawsze** oznacza, że certyfikat jest bezużyteczny; w wielu środowiskach ten sam certyfikat nadal działa w ataku typu **Schannel/LDAPS** (zobacz [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Typowe błędy Kerberos, które zmieniają plan ataku
- **`KDC_ERR_ETYPE_NOTSUPP`** → Konto docelowe / kontroler domeny nie użyje żądanego typu szyfrowania. Przestań ponawiać próby wyłącznie z RC4; dostarcz **klucze AES** lub zażądaj materiału roast dla **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Prawdopodobnie masz **nieprawidłowy klucz usługi**, **nieprawidłowy SPN** albo sfałszowany bilet, który nie pasuje do faktycznego konta usługi odszyfrowującego bilet.
- **`KRB_AP_ERR_SKEW`** → Twój czas jest nieprawidłowy. Zsynchronizuj go z kontrolerem domeny, zanim zaczniesz debugować cokolwiek innego.
- **`KDC_ERR_BADOPTION`** podczas przepływów S4U / delegation → często oznacza **użytkowników wrażliwych / niepodlegających delegacji**, niewłaściwy model delegacji albo próbę użycia **classic KCD** w sytuacji, gdy tylko **RBCD** zaakceptowałoby bilet S4U2Self bez możliwości forwardowania.

## Referencje
- [1] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
