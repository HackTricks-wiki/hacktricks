# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Managed Service Accounts to principal domenowe przeznaczone do uruchamiania usług bez konieczności obsługiwania przez administratora długotrwałego hasła:

1. **gMSA** (group Managed Service Account) może być używane przez komputery autoryzowane za pośrednictwem `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) wprowadzono w **Windows Server 2025**. Powiązuje ono standardowe uwierzytelnianie z tożsamościami autoryzowanych maszyn i może zastąpić starsze konto usługowe w ramach workflow migracji.

Nie należy mylić **Golden dMSA** z **BadSuccessor**. Golden dMSA wymaga przejęcia materiału klucza głównego KDS i wyprowadza klucze kont zarządzanych; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) wykorzystuje natomiast kontrolę nad obiektem dMSA i jego atrybutami migracji.

DC nie przechowuje niezależnie wygenerowanego hasła w postaci jawnego tekstu dla każdego gMSA. Wyprowadza hasło konta z **klucza głównego KDS**, indeksowanego czasowo klucza Group Key Distribution Protocol (GKDI) oraz SID konta. Obiekty kluczy głównych to obiekty `msKds-ProvRootKey` znajdujące się poniżej `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; wrażliwą wartością jest `msKds-RootKeyData`. `msDS-ManagedPasswordId` **nie jest identyfikatorem GUID**: to binarny identyfikator klucza zawierający GUID klucza głównego KDS, indeksy GKDI `L0`/`L1`/`L2` oraz metadane domeny/lasu. DC stosuje KDF z etykietą `GMSA PASSWORD` i binarnym SID-em jako kontekstem, a następnie udostępnia `MSDS-MANAGEDPASSWORD_BLOB` wyłącznie principalom autoryzowanym do pobierania hasła gMSA.<sup>[[2]](#references)</sup>

dMSA zazwyczaj różni się pod względem operacyjnym: jego sekret powinien pozostać na DC, a KDC wydaje poświadczenia autoryzowanej maszynie. dMSA wykorzystuje jednak ponownie bazowe wyprowadzanie haseł KDS/GKDI. Golden dMSA odtwarza ten sekret bezpośrednio, omijając w ten sposób zamierzony przepływ powiązany z maszyną oraz Credential Guard na hoście usługi.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Po wyodrębnieniu klucza głównego KDS attacker może wyprowadzać hasła dla kont powiązanych z tym kluczem bez odczytywania `msDS-ManagedPassword`. Omija to ACL pobierania haseł poszczególnych kont i przetrwa zwykłe rotacje haseł zarządzanych, dopóki przejęty klucz główny pozostaje w użyciu. W przypadku gMSA możliwy do odczytu `msDS-ManagedPasswordId` zwykle dostarcza dokładny identyfikator klucza. W przypadku dMSA z ograniczeniami ACL Golden dMSA redukuje brakujący identyfikator do zaledwie **1,024 kandydatów**.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

* Odpowiedni obiekt klucza głównego KDS, zwykle uzyskiwany za pomocą uprawnień Enterprise Admin / Domain Admin w lesie głównym, `SYSTEM` na DC albo z ujawnionej bazy danych DC lub backupu.<sup>[[1]](#references)[[2]](#references)</sup>
* SID konta docelowego, domena DNS, nazwa lasu oraz `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* W przypadku bezpośredniego obliczania gMSA — zakodowany w base64 `msDS-ManagedPasswordId`; w przypadku Golden dMSA można go zamiast tego odgadnąć.<sup>[[1]](#references)[[2]](#references)</sup>
* Host Windows x64 z .NET Framework 4.7.2 dla [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Phase 1 - Extract the KDS root key

`GoldenDMSA` i [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) eksportują pola obiektu klucza głównego jako blob base64. Bez argumentu domeny narzędzia odpytują las główny i wymagają odpowiedniego uprzywilejowanego dostępu do katalogu. Z argumentem domeny/lasu `SYSTEM` na DC może odpytać lokalną replikę kontekstu nazewnictwa Configuration tego DC.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Zapisz zarówno identyfikator GUID klucza głównego, jak i zakodowany w base64 blob klucza głównego. Eksport gałęzi rejestru `SECURITY`/`SYSTEM` nie jest sam w sobie kluczem głównym KDS: autorytatywne dane znajdują się na partycji konfiguracji AD.<sup>[[1]](#references)[[2]](#references)</sup>

### Faza 2 - Enumeruj obiekty gMSA / dMSA

W przypadku gMSA uzyskaj `sAMAccountName`, `objectSid` oraz binarny `msDS-ManagedPasswordId`. Ta ostatnia wartość jest zwykle możliwa do odczytania, nawet gdy wywołujący nie ma uprawnień do pobierania `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
Domyślna lista ACL dMSA może uniemożliwiać użytkownikom o niskich uprawnieniach enumerację LDAP. `GoldenDMSA info` może odpytywać LDAP lub wyliczać kandydujące RID-y i rozwiązywać SID-y za pośrednictwem `LsaLookupSids` przez `\PIPE\lsarpc`, a następnie rozróżniać dMSA, konta komputerów i gMSA.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Faza 3 — Odtworzenie lub odgadnięcie `msDS-ManagedPasswordId`

Identyfikator klucza zawiera `L0Index`, `L1Index` i `L2Index`, a nie znacznik czasu utworzenia konta wraz z losowymi bitami. Semperis ustaliło, że ścieżka generowania hasła nie wykorzystuje kandydującego `L0Index`, podczas gdy `L1Index` i `L2Index` są ograniczone do wartości `0..31`. W związku z tym atakujący, który zna GUID klucza głównego, domenę, las i SID, może skonstruować wszystkie `32 * 32 = 1,024` kandydujących identyfikatorów.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Pochodne są obliczane offline, ale identyfikacja aktywnego kandydata zwykle wymaga prób uwierzytelnienia. Może to spowodować serię nieudanych prób wstępnego uwierzytelniania Kerberos lub walidacji NTLM, zanim zostanie znaleziony prawidłowy klucz. W przypadku kluczy AES Kerberos sól konta zarządzanego używana przez narzędzie to `UPPERCASE.DNS.DOMAIN` + `host` + nazwa UPN konta zapisana małymi literami, bez końcowego `$` (na przykład `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Faza 4 - Oblicz i użyj hasła

Jeśli znany jest dokładny identyfikator, oblicz 256-bajtowy bufor hasła i przekonwertuj go na materiał NTLM/AES. Wartość base64 wyświetlana przez te narzędzia to zakodowany bufor hasła, **a nie sam obiekt LDAP `MSDS-MANAGEDPASSWORD_BLOB`**.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Wynik NTLM może być używany tam, gdzie akceptowany jest NTLM; klucz AES może być używany do overpass-the-hash / żądań TGT, gdy managed account obsługuje wyłącznie AES. Zapewnia to uprawnienia, SPN-y, konfigurację delegowania i dostęp do zasobów skompromitowanego managed service account bez dodawania maszyny atakującego do `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Nadużycie partycji Configuration między domenami

Obiekty kluczy głównych KDS znajdują się w kontekście nazewnictwa Configuration lasu, który jest replikowany do kontrolerów domeny w domenach podrzędnych. W konsekwencji `SYSTEM` na kontrolerze domeny podrzędnej może odczytać materiał KDS lasu nadrzędnego z lokalnej repliki kontrolera podrzędnego, mimo że Domain Admins domeny podrzędnej nie mogą bezpośrednio odczytać tego obiektu z kontrolera domeny lasu nadrzędnego. Jeśli atakujący może również odczytać `msDS-ManagedPasswordId` gMSA domeny nadrzędnej, GoldenGMSA może obliczyć hasło tego konta; filtrowanie SID nie zapobiega temu atakowi kryptograficznemu.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Wykrywanie, powstrzymywanie i odzyskiwanie

* Skonfiguruj SACL na kontenerze **Master Root Keys**, dziedziczony przez obiekty `msKds-ProvRootKey`, dla pomyślnych odczytów `msKds-RootKeyData`. Przy włączonym audytowaniu dostępu do usług katalogowych ekstrakcja online generuje zdarzenie Security **4662**; zbadaj podmioty, które nie są oczekiwanymi kontrolerami domeny ani operatorami Tier-0. Audytuj również zmiany tych SACL-i oraz list ACL obiektów kluczy głównych.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Atak child-to-parent odczytuje obiekt KDS z lokalnej repliki przejętego kontrolera domeny child, więc domena forest-root może nie zarejestrować tego odczytu. W domenie nadrzędnej audytuj pomyślne odczyty `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) na obiektach `msDS-GroupManagedServiceAccount` i badaj odczyty wykonywane przez principals z innej domeny.<sup>[[5]](#references)</sup>
* Koreluj dostęp do obiektów KDS z nietypowymi logowaniami kont zarządzanych oraz seriami błędów Kerberos/NTLM dla kont usługowych zakończonych znakiem `$`. Obliczenia offline po wcześniejszej kradzieży bazy danych lub backupu nie są widoczne dla działającego kontrolera domeny.<sup>[[1]](#references)[[3]](#references)</sup>
* Zwykła rotacja haseł nie wystarcza po ujawnieniu klucza głównego. Aktualna procedura odzyskiwania firmy Microsoft tworzy nowy klucz główny KDS, restartuje KDS na wszystkich odpowiednich kontrolerach domeny i przenosi dotknięte konta do tego klucza. Jeśli zakres lub czas ujawnienia są nieznane, a oczekiwanie na bezpieczną rotację jest nieakceptowalne, zastąp każdą gMSA, która używała przejętego klucza; jeśli zakres jest znany, Microsoft opisuje workflow authoritative-restore wymuszający bezpieczną rotację. Przed usunięciem starego klucza sprawdź GUID nowego klucza w `msDS-ManagedPasswordId`.<sup>[[4]](#references)</sup>
* Traktuj dostęp do baz danych kontrolerów domeny i backupów, replikację partycji Configuration oraz administrację głównymi kluczami KDS jako Tier-0. Zmniejszenie `ManagedPasswordIntervalInDays` ogranicza niektóre okna odzyskiwania, ale nie unieważnia już przejętego klucza głównego.<sup>[[4]](#references)</sup>

## Narzędzia

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - enumeracja dMSA/gMSA, generowanie identyfikatorów, walidacja 1,024 kandydatów, obliczanie haseł oraz konwersja NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - enumeracja gMSA/KDS oraz obliczanie haseł online, offline i cross-domain.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) i [`Impacket`](https://github.com/fortra/impacket) - używaj lub waliduj wyprowadzone klucze NTLM/AES podczas autoryzowanych testów.



## References

- [1] [Golden dMSA - obejście uwierzytelniania dla delegowanych kont Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Ataki gMSA Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Repozytorium GoldenDMSA na GitHub](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Jak odzyskać środowisko po ataku Golden gMSA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [Filtr SID jako granica bezpieczeństwa między domenami? Część 5 - atak Golden gMSA na zaufanie](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
