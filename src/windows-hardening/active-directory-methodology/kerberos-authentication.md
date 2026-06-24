# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź świetny post od:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR dla attackers
- Kerberos to domyślny protokół auth w AD; większość łańcuchów lateral-movement będzie go dotykać.
- Myśl w **trzech fazach operatora**:
- **AS-REQ / AS-REP** → password/hash/certificate do uzyskania **TGT**. To tutaj są **AS-REP roasting**, **over-pass-the-hash / pass-the-key** i **PKINIT**.
- **TGS-REQ / TGS-REP** → użyj TGT do uzyskania **service tickets**. To tutaj stają się istotne **Kerberoasting**, **S4U abuse**, **delegation abuse** i większość **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → przedstaw ticket usłudze. To tutaj dzieją się **pass-the-ticket** i lateral movement specyficzny dla danej usługi.
- Dla praktycznych cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse, itd.) zobacz:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Użyj tej strony jako indeksu **przeglądowego / „co zmieniło się ostatnio”**, a potem przejdź do dedykowanych stron: [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) lub [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening zmienił domyślne ustawienia, nie sam Kerberos** – nowoczesne hardening DC skupia się na **domyślnie zakładanych typach szyfrowania** dla kont, które **nie** ustawiają explicite `msDS-SupportedEncryptionTypes`. Po rollout 2026 te konta coraz częściej domyślnie przechodzą na **AES-only** na spatchowanych DC, więc ślepe założenia `/rc4` dla Kerberoast częściej zawodzą. Jednak **jawnie RC4-włączone konta usługowe nadal są świetnymi celami do offline crack**.
- **PAC validation enforcement ma znaczenie dla forged tickets** – hardening sygnatur PAC z 2024 oznacza, że **golden/diamond/sapphire/extraSID-style abuses** wymagają bardziej realistycznych danych PAC i właściwego context podpisywania. Niezałatane domeny lub domeny pozostawione w trybie compatibility/audit-style nadal są słabszym celem.
- **Certificate-based Kerberos changed twice**:
- **Strong certificate binding** (timeline KB5014754) sprawia, że niechlujne mapowania certificate-to-account są mniej niezawodne w środowiskach z pełnym enforcement.
- **CVE-2025-26647** dodał kolejną warstwę hardening wokół **altSecID / SKI certificate mappings**. Jeśli DC są niezałatane, nadal w audycie albo explicite omijają weryfikację NTAuth, pass-the-certificate / shadow-credential follow-on abuse pozostaje bardziej praktyczne.
- **Cross-domain / cross-forest delegation abuse nadal ma się bardzo dobrze** – Windows wspiera nowoczesne cross-realm flow **S4U2Self/S4U2Proxy**, więc modyfikowalne atrybuty delegation w innej domenie nadal są wartościowe. Blokadą zwykle jest fidelity tooling i szczegóły trust/policy, a nie wsparcie protokołu.
- **Windows Server 2025 wprowadził nową powierzchnię ataku związaną z Kerberos** przez logikę migracji **dMSA**. Jeśli widzisz delegated rights nad OU albo obiektami service-account w domenie 2025, sprawdź dedykowaną [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) zamiast traktować to jako „po prostu kolejny gMSA”.

## Fast operator checks in modern domains

Zanim wybierzesz ścieżkę ataku Kerberos, szybko odpowiedz na cztery pytania:

1. **Które konta nadal są przyjazne dla RC4?**
2. **Którzy użytkownicy nie wymagają pre-auth?**
3. **Które obiekty ujawniają delegation abuse?**
4. **Które części domeny są wystarczająco nowe, aby wymuszać recent hardening?**
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
- Jeśli **interesujące konta SPN są jawnie zgodne z RC4**, Kerberoasting pozostaje tani i szybki.
- Jeśli większość kont usługowych **nie ma jawnej konfiguracji etype**, spodziewaj się zachowania **tylko AES** na zaktualizowanych DC z 2026 i planuj wolniejsze offline cracking albo inną ścieżkę.
- Jeśli występuje **RBCD / KCD / unconstrained delegation**, S4U często wygrywa z brute-force.
- Jeśli używane jest **certificate auth**, pamiętaj, że nieudana ścieżka PKINIT **nie zawsze** oznacza, że cert jest bezużyteczny; w wielu środowiskach ten sam cert nadal działa do nadużyć **Schannel/LDAPS** (zobacz [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Konto docelowe / DC nie użyje typu szyfrowania, o który prosisz. Przestań ponawiać tylko z RC4; podaj **klucze AES** albo poproś o materiał roast **AES** zamiast tego.
- **`KRB_AP_ERR_MODIFIED`** → Prawdopodobnie masz **zły service key**, **zły SPN** albo podrobiony ticket, który nie pasuje do konta usługi faktycznie go deszyfrującego.
- **`KRB_AP_ERR_SKEW`** → Masz złą godzinę. Zsynchronizuj się z DC, zanim zaczniesz debugować cokolwiek innego.
- **`KDC_ERR_BADOPTION`** podczas flow S4U / delegation → często oznacza **wrażliwych / niedelegowalnych użytkowników**, zły model delegation albo to, że próbujesz wykonać **classic KCD**, podczas gdy tylko **RBCD** zaakceptowałoby nieprzekazywalny ticket S4U2Self.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
