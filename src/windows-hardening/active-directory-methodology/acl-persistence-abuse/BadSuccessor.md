# Nadużywanie ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Delegowane Konta Usług Zarządzanych (**dMSA**) to nowy typ obiektu AD wprowadzony w **Windows Server 2025**. Zostały zaprojektowane, aby zastąpić przestarzałe konta usług, umożliwiając jednoczesną „migrację”, która automatycznie kopiuje nazwy głównych usług (SPN), członkostwa w grupach, ustawienia delegacji, a nawet klucze kryptograficzne do nowego dMSA, co zapewnia aplikacjom płynne przejście i eliminuje ryzyko Kerberoasting.

Badacze z Akamai odkryli, że jeden atrybut — **`msDS‑ManagedAccountPrecededByLink`** — informuje KDC, które przestarzałe konto „sukcesuje” dMSA. Jeśli atakujący może zapisać ten atrybut (i przełączyć **`msDS‑DelegatedMSAState` → 2**), KDC z radością zbuduje PAC, który **dziedziczy każdy SID wybranej ofiary**, co skutecznie pozwala dMSA na podszywanie się pod dowolnego użytkownika, w tym Administratorów Domeny.

## Czym dokładnie jest dMSA?

* Zbudowane na technologii **gMSA**, ale przechowywane jako nowa klasa AD **`msDS‑DelegatedManagedServiceAccount`**.
* Wspiera **migrację na zasadzie opt-in**: wywołanie `Start‑ADServiceAccountMigration` łączy dMSA z przestarzałym kontem, przyznaje przestarzałemu kontu dostęp do zapisu do `msDS‑GroupMSAMembership` i zmienia `msDS‑DelegatedMSAState` = 1.
* Po `Complete‑ADServiceAccountMigration`, przestarzałe konto jest dezaktywowane, a dMSA staje się w pełni funkcjonalne; każdy host, który wcześniej używał przestarzałego konta, jest automatycznie uprawniony do pobrania hasła dMSA.
* Podczas uwierzytelniania KDC osadza wskazówkę **KERB‑SUPERSEDED‑BY‑USER**, dzięki czemu klienci Windows 11/24H2 automatycznie próbują ponownie z dMSA.

## Wymagania do ataku
1. **Co najmniej jeden kontroler domeny Windows Server 2025**, aby klasa LDAP dMSA i logika KDC istniały.
2. **Jakiekolwiek prawa do tworzenia obiektów lub zapisu atrybutów w OU** (dowolne OU) – np. `Create msDS‑DelegatedManagedServiceAccount` lub po prostu **Create All Child Objects**. Akamai odkryło, że 91% rzeczywistych najemców przyznaje takie „nieszkodliwe” uprawnienia OU nie-administratorom.
3. Możliwość uruchomienia narzędzi (PowerShell/Rubeus) z dowolnego hosta dołączonego do domeny, aby żądać biletów Kerberos.
*Nie jest wymagane kontrolowanie użytkownika ofiary; atak nigdy nie dotyka bezpośrednio docelowego konta.*

## Krok po kroku: BadSuccessor* eskalacja uprawnień

1. **Zlokalizuj lub utwórz dMSA, którym zarządzasz**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Ponieważ utworzyłeś obiekt w OU, do którego możesz pisać, automatycznie posiadasz wszystkie jego atrybuty.

2. **Symuluj „zakończoną migrację” w dwóch zapisach LDAP**:
- Ustaw `msDS‑ManagedAccountPrecededByLink = DN` dowolnej ofiary (np. `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Ustaw `msDS‑DelegatedMSAState = 2` (migracja zakończona).

Narzędzia takie jak **Set‑ADComputer, ldapmodify** lub nawet **ADSI Edit** działają; nie są potrzebne prawa administratora domeny.

3. **Zażądaj TGT dla dMSA** — Rubeus wspiera flagę `/dmsa`:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Zwrócony PAC teraz zawiera SID 500 (Administrator) oraz grupy Administratorów Domeny/Administratorów Enterprise.

## Zbierz hasła wszystkich użytkowników

Podczas legalnych migracji KDC musi pozwolić nowemu dMSA na odszyfrowanie **biletów wydanych do starego konta przed przełączeniem**. Aby uniknąć przerwania aktywnych sesji, umieszcza zarówno klucze bieżące, jak i klucze poprzednie w nowym obiekcie ASN.1 zwanym **`KERB‑DMSA‑KEY‑PACKAGE`**.

Ponieważ nasza fałszywa migracja twierdzi, że dMSA sukcesuje ofiarę, KDC sumiennie kopiuje klucz RC4-HMAC ofiary do listy **poprzednich kluczy** – nawet jeśli dMSA nigdy nie miało „poprzedniego” hasła. Ten klucz RC4 jest niesolony, więc jest w zasadzie hashem NT ofiary, dając atakującemu **możliwość łamania offline lub „pass-the-hash”**.

Dlatego masowe łączenie tysięcy użytkowników pozwala atakującemu na zrzucenie hashy „na dużą skalę”, przekształcając **BadSuccessor w zarówno prymityw eskalacji uprawnień, jak i kompromitacji poświadczeń**.

## Narzędzia

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Odniesienia

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
