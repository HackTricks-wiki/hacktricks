# Uwierzytelnianie Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź świetny post na stronie:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR dla attackerów
- Kerberos jest domyślnym protokołem uwierzytelniania AD; większość łańcuchów lateral movement będzie miała z nim styczność.
- Myśl o **trzech fazach operacyjnych**:
- **AS-REQ / AS-REP** → hasło/hash/certificate umożliwiające uzyskanie **TGT**. To tutaj występują **AS-REP roasting**, **over-pass-the-hash / pass-the-key** oraz **PKINIT**.
- **TGS-REQ / TGS-REP** → użycie TGT do uzyskania **service tickets**. To tutaj istotne stają się **Kerberoasting**, **S4U abuse**, **delegation abuse** oraz większość technik **ticket-forging**.
- **AP-REQ / AP-REP** → przedstawienie biletu usłudze. To tutaj występują **pass-the-ticket** oraz lateral movement zależny od konkretnej usługi.
- Cheatsheety dotyczące praktycznego wykorzystania (AS-REP/Kerberoasting, ticket forgery, delegation abuse itd.) znajdziesz tutaj:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Użyj tej strony jako indeksu **przeglądowego / „co ostatnio się zmieniło”**, a następnie przejdź do dedykowanych stron dotyczących [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [certyfikatów AD / PKINIT abuse](ad-certificates.md) lub [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Najnowsze informacje o attackach (2024-2026)
- **Wzmocnienie RC4 zmieniło ustawienia domyślne, a nie sam Kerberos** – współczesne hardening DC koncentruje się na **domyślnie zakładanych typach szyfrowania** dla kont, które nie ustawiają jawnie `msDS-SupportedEncryptionTypes`. Po wdrożeniu zmian w 2026 roku konta te coraz częściej domyślnie używają wyłącznie **AES** na załatanych DC, dlatego założenia dotyczące blind `/rc4` Kerberoast częściej zawodzą. Jednak **jawnie włączone konta usługowe RC4 nadal są doskonałymi celami do offline crackingu**.
- **Wymuszanie walidacji PAC ma znaczenie dla forged tickets** – hardening podpisów PAC z 2024 roku oznacza, że **golden/diamond/sapphire/extraSID-style abuses** wymagają bardziej realistycznych danych PAC oraz poprawnego kontekstu podpisywania. Niezałatane domeny lub domeny pozostawione w trybie zgodności/audytu pozostają łatwiejszymi celami.
- **Kerberos oparte na certyfikatach zmieniło się dwukrotnie**:
- **Strong certificate binding** (oś czasu KB5014754) sprawia, że niedokładne mapowania certyfikatu do konta są mniej niezawodne w środowiskach z pełnym enforcementem.
- **CVE-2025-26647** dodało kolejną warstwę hardeningu wokół mapowań certyfikatów **altSecID / SKI**. Jeśli DC są niezałatane, nadal działają w trybie audytu lub jawnie pomijają walidację NTAuth, dalsze wykorzystanie **pass-the-certificate / shadow-credential** pozostaje bardziej praktyczne.
- **Delegation abuse między domenami / lasami nadal jest bardzo aktualne** – Windows obsługuje nowoczesne międzyrealmowe przepływy **S4U2Self/S4U2Proxy**, dlatego zapisywalne atrybuty delegowania w innej domenie nadal są wartościowe. Przeszkodą jest zazwyczaj wierność narzędzi oraz szczegóły trust/policy, a nie brak obsługi protokołu.
- **Rekursywne RBCD w wielu domenach ma znaczenie operacyjne** – w lasach z co najmniej 3 domenami **S4U2Self/S4U2Proxy** może przechodzić rekursywnie przez trust referrals, a **SPN-less** abuse może wymagać końcowego kroku **`S4U2Self+U2U`** oraz obsługi biletów zależnej od RC4. Zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 wprowadził nową powierzchnię attack surface powiązaną z Kerberos** poprzez logikę migracji **dMSA**. Jeśli widzisz delegated rights względem OU lub obiektów kont usługowych w domenie 2025, sprawdź dedykowaną [stronę BadSuccessor](acl-persistence-abuse/BadSuccessor.md), zamiast traktować to jak „kolejne gMSA”.

## Szybkie kontrole operatora w nowoczesnych domenach

Przed wyborem ścieżki attacku Kerberos szybko odpowiedz na cztery pytania:

1. **Które konta nadal są przyjazne dla RC4?**
2. **Którzy użytkownicy nie wymagają pre-auth?**
3. **Które obiekty umożliwiają delegation abuse?**
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
- Jeśli większość kont usług nie ma **jawnej konfiguracji etype**, na zaktualizowanych kontrolerach domeny z 2026 r. oczekuj zachowania **tylko AES** i zaplanuj wolniejsze łamanie offline lub inną ścieżkę.
- Jeśli występuje **RBCD / KCD / unconstrained delegation**, S4U często jest skuteczniejsze niż brute-force.
- Jeśli wykorzystywane jest **certificate auth**, pamiętaj, że nieudana ścieżka PKINIT **nie zawsze** oznacza, że certyfikat jest bezużyteczny; w wielu środowiskach ten sam certyfikat nadal działa w przypadku nadużycia **Schannel/LDAPS** (zobacz [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Typowe błędy Kerberos zmieniające plan ataku
- **`KDC_ERR_ETYPE_NOTSUPP`** → Konto docelowe / DC nie użyje żądanego przez Ciebie typu szyfrowania. Przestań ponawiać próby wyłącznie z RC4; dostarcz **klucze AES** lub zamiast tego żądaj materiału do roastingu **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Prawdopodobnie masz **nieprawidłowy klucz usługi**, **nieprawidłowy SPN** albo sfałszowany ticket, który nie pasuje do konta usługi faktycznie go odszyfrowującego.
- **`KRB_AP_ERR_SKEW`** → Twój czas jest nieprawidłowy. Zsynchronizuj go z DC, zanim zaczniesz debugować cokolwiek innego.
- **`KDC_ERR_BADOPTION`** podczas przepływów S4U / delegation → często oznacza **użytkowników wrażliwych / niepodlegających delegowaniu**, niewłaściwy model delegowania albo próbę użycia **classic KCD**, gdy tylko **RBCD** zaakceptowałoby ticket S4U2Self bez możliwości forwardowania.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
