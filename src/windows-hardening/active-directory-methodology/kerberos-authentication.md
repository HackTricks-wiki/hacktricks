# Uwierzytelnianie Kerberos

{{#include ../../banners/hacktricks-training.md}}

Opis wymian na poziomie protokołu, podsumowanych poniżej, znajduje się w artykule Tarlogic dotyczącym Kerberos.<sup>[[3]](#references)</sup>

## TL;DR dla attackerów
- Kerberos to domyślny protokół uwierzytelniania AD; większość łańcuchów lateral movement będzie go dotykać.
- Myśl o tym w **trzech fazach operacyjnych**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → użycie hasła/hashu/certyfikatu do uzyskania **TGT**. W tym miejscu występują **AS-REP roasting**, **over-pass-the-hash / pass-the-key** oraz **PKINIT**.
- **TGS-REQ / TGS-REP** → użycie TGT do uzyskania **service tickets**. W tym miejscu istotne są **Kerberoasting**, **S4U abuse**, **delegation abuse** oraz większość technik **ticket-forging**.
- **AP-REQ / AP-REP** → przedstawienie biletu usłudze. W tym miejscu występują **pass-the-ticket** oraz lateral movement zależny od konkretnej usługi.
- Praktyczne cheatsheety dotyczące (AS-REP/Kerberoasting, ticket forgery, delegation abuse itd.) znajdziesz tutaj:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Użyj tej strony jako indeksu **przeglądowego / „co ostatnio się zmieniło”**, a następnie przejdź do dedykowanych stron dotyczących [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) lub [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Najnowsze informacje dotyczące ataków (2024-2026)
- **Wzmocnienie RC4 zmieniło ustawienia domyślne, a nie sam Kerberos** – współczesne hardening DC koncentruje się na **domyślnie przyjmowanych typach szyfrowania** dla kont, które **nie ustawiają jawnie `msDS-SupportedEncryptionTypes`**. Po wdrożeniu zmian w 2026 roku konta te coraz częściej domyślnie korzystają wyłącznie z **AES** na załatanych DC, dlatego założenia dotyczące ślepego Kerberoast z użyciem `/rc4` częściej zawodzą. Jednak konta usług z **jawnie włączonym RC4** nadal są doskonałymi celami do offline crackingu.<sup>[[1]](#references)</sup>
- **Wymuszanie walidacji PAC ma znaczenie dla forged tickets** – hardening podpisów PAC z 2024 roku oznacza, że nadużycia typu **golden/diamond/sapphire/extraSID** wymagają bardziej realistycznych danych PAC oraz właściwego kontekstu podpisywania. Niezałatane domeny lub domeny pozostawione w trybie zgodności/audytu pozostają łatwiejszymi celami.<sup>[[2]](#references)</sup>
- **Kerberos oparty na certyfikatach zmienił się dwukrotnie**:
- **Strong certificate binding** (oś czasu KB5014754) sprawia, że niedokładne mapowania certyfikatów na konta są mniej niezawodne w środowiskach z w pełni wymuszonymi zabezpieczeniami.
- **CVE-2025-26647** dodało kolejną warstwę hardeningu dotyczącą mapowań `altSecurityIdentities`, które używają identyfikatora Subject Key Identifier certyfikatu. Podczas oceny pass-the-certificate i powiązanych ścieżek opartych na certyfikatach znaczenie mają więc poziom poprawek, stan wymuszania lub audytu oraz jawna konfiguracja mapowania.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> W przypadku PKINIT KDC weryfikuje również ścieżkę certyfikatu i sprawdza, czy wystawca jest zaufany za pośrednictwem magazynu NTAuth.<sup>[[8]](#references)</sup>
- **Nadużycia delegacji między domenami / lasami nadal są bardzo aktualne** – Windows obsługuje nowoczesne przepływy między realmami **S4U2Self/S4U2Proxy**, dlatego atrybuty delegacji z możliwością zapisu w innej domenie nadal są wartościowe. Przeszkodą są zazwyczaj dokładność narzędzi oraz szczegóły zaufania/polityk, a nie obsługa protokołu.
- **Rekursywne RBCD w wielu domenach ma znaczenie operacyjne** – w lasach z co najmniej 3 domenami **S4U2Self/S4U2Proxy** może rekursywnie przechodzić przez referrals zaufania, a nadużycie **SPN-less** może wymagać końcowego skoku **`S4U2Self+U2U`** oraz obsługi biletów zależnej od RC4. Zobacz [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 wprowadził delegated Managed Service Accounts (dMSAs)** oraz logikę ich migracji. Jeśli w domenie z 2025 roku zauważysz delegowane uprawnienia do OU lub obiektów kont usług, sprawdź dedykowaną [stronę BadSuccessor](acl-persistence-abuse/BadSuccessor.md), zamiast traktować to jako „kolejny gMSA”.<sup>[[7]](#references)</sup>

## Szybkie kontrole operatora we współczesnych domenach

Przed wyborem ścieżki ataku Kerberos szybko odpowiedz na cztery pytania:

1. **Które konta nadal są przyjazne dla RC4?**
2. **Którzy użytkownicy nie wymagają pre-auth?**
3. **Które obiekty ujawniają możliwość delegation abuse?**
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
- Jeśli większość kont usług nie ma **jawnej konfiguracji etype**, na zaktualizowanych kontrolerach domeny z 2026 r. oczekuj zachowania **wyłącznie AES** i przygotuj się na wolniejsze łamanie offline lub inną ścieżkę.
- Jeśli występuje **RBCD / KCD / unconstrained delegation**, S4U często jest skuteczniejsze niż brute-force.
- Jeśli wykorzystywane jest **uwierzytelnianie certyfikatowe**, pamiętaj, że nieudana ścieżka PKINIT **nie zawsze** oznacza, że certyfikat jest bezużyteczny; w wielu środowiskach ten sam certyfikat nadal działa w przypadku abuse **Schannel/LDAPS** (zobacz [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Konto docelowe / DC nie użyje typu szyfrowania, o który poproszono. Przestań ponawiać próby wyłącznie z RC4; dostarcz **klucze AES** lub zażądaj materiału do roastingu **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Prawdopodobnie masz **niewłaściwy klucz usługi**, **niewłaściwy SPN** albo podrobiony ticket, który nie pasuje do konta usługi faktycznie odszyfrowującego ticket.
- **`KRB_AP_ERR_SKEW`** → Zegar jest niezsynchronizowany. Zsynchronizuj czas z DC, zanim zaczniesz debugować cokolwiek innego.
- **`KDC_ERR_BADOPTION`** podczas przepływów S4U / delegation → często oznacza **wrażliwych użytkowników / użytkowników, których nie można delegować**, niewłaściwy model delegacji lub próbę użycia **classic KCD** w sytuacji, gdy tylko **RBCD** zaakceptowałoby ticket S4U2Self bez możliwości forwardowania.

## References
- [1] [Microsoft Learn - Wykrywanie i usuwanie użycia RC4 w Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Najnowsze wytyczne dotyczące hardeningu Windows i kluczowe daty](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Jak działa Kerberos? – teoria](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Zmiany w uwierzytelnianiu opartym na certyfikatach w KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - Podatność w mapowaniu certyfikatów Kerberos CVE-2025-26647](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Omówienie Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Wymagania dotyczące certyfikatów kart inteligentnych i walidacja KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
