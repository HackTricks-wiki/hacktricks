# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Główne Keychainy

- **User Keychain** (`~/Library/Keychains/login.keychain-db`) służy do przechowywania **poświadczeń użytkownika**, takich jak hasła aplikacji, hasła internetowe, certyfikaty utworzone przez użytkownika, hasła sieciowe oraz utworzone przez użytkownika klucze publiczne/prywatne.
- **System Keychain** (`/Library/Keychains/System.keychain`) przechowuje **poświadczenia systemowe**, takie jak hasła Wi-Fi, systemowe certyfikaty główne, systemowe klucze prywatne oraz hasła aplikacji systemowych.<sup>[[1]](#references)</sup>
  - Inne komponenty, takie jak certyfikaty, można znaleźć w `/System/Library/Keychains/*`
- Keychain **data protection** przypisany do użytkownika jest widoczny w Keychain Access jako **Local Items** lub **iCloud**. Jest oddzielony od `login.keychain-db` i obejmuje zarówno elementy przechowywane wyłącznie lokalnie, jak i synchronizowane; narzędzie `security` służy przede wszystkim do obsługi keychainów opartych na plikach, więc krótki wynik `dump-keychain` nie wyklucza obecności poświadczeń w tym miejscu.<sup>[[5]](#references)</sup>
- W **iOS** istnieje tylko jeden **Keychain**, znajdujący się w `/private/var/Keychains/`. Ten folder zawiera również bazy danych `TrustStore`, urzędów certyfikacji (`caissuercache`) i wpisów OSCP (`ocspache`).
  - Dostęp aplikacji do keychaina jest ograniczony do ich prywatnego obszaru na podstawie identyfikatora aplikacji.

### Dostęp do Keychain z hasłem

Skopiowany keychain **oparty na pliku** nie zawiera jawnego tekstu. Do odszyfrowania chronionych elementów offline potrzebne jest hasło keychaina lub równoważny materiał kluczowy; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) obsługuje ten format.<sup>[[1]](#references)</sup> Różni się to od odczytu na żywo w odblokowanej sesji użytkownika, w której kontrola dostępu do elementu może zezwolić na odczyt lub wywołać monit bez ponownego podawania hasła logowania. Keychain data protection ma inny model ochrony i grup dostępu.<sup>[[5]](#references)</sup>

## Ochrona wpisów Keychain

### ACL-e keychainów opartych na plikach

Reguły `SecAccess` ACL i partition-list opisane poniżej dotyczą keychainów **opartych na plikach**. Elementy keychaina data protection korzystają natomiast z grup dostępu opartych na podpisywaniu kodu i opcjonalnych warunków `SecAccessControl`; nie należy wnioskować o ich dostępności na podstawie zrzutu ACL keychaina opartego na pliku.<sup>[[5]](#references)</sup>

Każdy wpis w keychainie opartym na pliku podlega **listom kontroli dostępu (ACL)**, które określają, kto może wykonywać różne działania na wpisie keychaina, w tym:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Umożliwia posiadaczowi uzyskanie sekretu w postaci jawnego tekstu.
- **`kSecACLAuthorizationExportWrapped`**: Umożliwia posiadaczowi uzyskanie jawnego tekstu zaszyfrowanego przy użyciu innego, podanego hasła.
- **`kSecACLAuthorizationAny`**: Umożliwia posiadaczowi wykonanie dowolnej czynności.

ACL-om towarzyszy **lista zaufanych aplikacji**, które mogą wykonywać te działania bez wyświetlania monitu. Lista może być:<sup>[[1]](#references)</sup>

- **N`il`** (autoryzacja nie jest wymagana, **zaufani są wszyscy**)
- **Pusta** (**nikt** nie jest zaufany)
- **Listą** konkretnych **aplikacji**.

Wpis może również zawierać klucz **`kSecACLAuthorizationPartitionID`,** używany do identyfikacji **teamid, apple** i **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Jeśli podano **teamid**, aplikacja musi mieć **ten sam teamid**, aby **uzyskać dostęp do wartości wpisu** bez wyświetlania **monitu**.
- Jeśli podano **apple**, aplikacja musi być **podpisana** przez **Apple**.
- Jeśli wskazano **cdhash**, **aplikacja** musi mieć określony **cdhash**.

### Tworzenie wpisu w keychainie opartym na pliku

Podczas tworzenia **nowego** **wpisu** za pomocą **`Keychain Access.app`** obowiązują następujące reguły:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- **Żadna aplikacja** nie może eksportować/odszyfrowywać bez wyświetlenia monitu użytkownikowi.
- Wszystkie aplikacje mogą odczytać kontrolę integralności.
- Żadna aplikacja nie może zmieniać ACL-i.
- **partitionID** ma wartość **`apple`**.

Gdy **aplikacja tworzy wpis w keychainie**, obowiązują nieco inne reguły:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- Tylko **aplikacja tworząca wpis** (lub inne jawnie dodane aplikacje) może eksportować/odszyfrowywać bez wyświetlenia monitu użytkownikowi.
- Wszystkie aplikacje mogą odczytać kontrolę integralności.
- Żadna aplikacja nie może zmieniać ACL-i.
- **partitionID** ma wartość **`teamid:[teamID here]`**.

## Uzyskiwanie dostępu do Keychain

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` ustawia listę partycji elementu, a `-k` podaje bieżące hasło Keychain wymagane do wprowadzenia tej zmiany; flaga pobierająca hasło jest przestarzała.<sup>[[4]](#references)</sup> Pomyślna aktualizacja nie dowodzi, że późniejszy odczyt nie wyświetli monitu: zaobserwowano, że wyłączony prototyp nadal wyświetlał monit o potwierdzenie, gdy odpytywał element za pośrednictwem `Security.framework`. Pasujący identyfikator partycji to tylko jeden z elementów kontroli ACL i zaufanych aplikacji opisanych powyżej, dlatego zweryfikuj rzeczywistą ścieżkę odczytu.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> **Enumerację Keychain i zrzut** sekretów, które **nie wywołują monitu**, można wykonać za pomocą narzędzia [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Inne punkty końcowe API można znaleźć w kodzie źródłowym [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Wyświetlaj listę i pobieraj **informacje** o każdym wpisie Keychain za pomocą **Security Framework** albo sprawdź otwartoźródłowe narzędzie CLI firmy Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Przykłady API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** zwraca informacje o każdym wpisie i umożliwia ustawienie następujących atrybutów:
  - **`kSecReturnData`**: Jeśli ma wartość true, API spróbuje odszyfrować dane (ustaw wartość false, aby uniknąć potencjalnych wyskakujących okienek)
  - **`kSecReturnRef`**: Zwraca referencję do obiektu reprezentującego klucz, certyfikat lub tożsamość; elementy z hasłami nie mają takiej reprezentacji obiektu. Użyj `kSecReturnPersistentRef`, aby zidentyfikować hasło na potrzeby późniejszego, ukierunkowanego zapytania.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Zwraca metadane wpisów
  - **`kSecMatchLimit`**: Określa liczbę zwracanych wyników
  - **`kSecClass`**: Określa typ wpisu Keychain

Pobierz **ACL-e** każdego wpisu:<sup>[[1]](#references)</sup>

- Za pomocą API **`SecAccessCopyACLList`** można pobrać **ACL elementu Keychain**. Zwraca ono listę ACL-i (takich jak `kSecACLAuthorizationExportClear` i inne wspomniane wcześniej), z których każdy zawiera:<sup>[[1]](#references)[[2]](#references)</sup>
  - Opis
  - **Listę zaufanych aplikacji**. Może to być:
    - Aplikacja: /Applications/Slack.app
    - Plik binarny: /usr/libexec/airportd
    - Grupa: group://AirPort

Eksportuj dane:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** pobiera tekst jawny
- API **`SecItemExport`** eksportuje klucze i certyfikaty, ale do eksportowania zaszyfrowanej zawartości może być konieczne ustawienie haseł

Oto **wymagania** umożliwiające **wyeksportowanie sekretu bez monitu**:<sup>[[1]](#references)</sup>

- Jeśli na liście znajduje się co najmniej jedna zaufana aplikacja:
  - Wymagane są odpowiednie **uprawnienia** (**`Nil`** albo przynależność do listy aplikacji dopuszczonych w ramach uprawnienia dostępu do poufnych informacji)
  - Podpis kodu musi być zgodny z **PartitionID**
  - Podpis kodu musi być zgodny z podpisem jednej **zaufanej aplikacji** (albo aplikacja musi należeć do właściwej KeychainAccessGroup)
- Jeśli zaufane są **wszystkie aplikacje**:
  - Wymagane są odpowiednie **uprawnienia**
  - Podpis kodu musi być zgodny z **PartitionID**
    - Jeśli **PartitionID** nie ma, ten warunek nie jest wymagany

> [!CAUTION]
> Dlatego, jeśli na liście znajduje się **jedna aplikacja**, musisz **wstrzyknąć kod do tej aplikacji**.
>
> Jeśli w **partitionID** widnieje **apple**, dostęp do niego można uzyskać za pomocą **`osascript`**; dotyczy to więc wszystkiego, co ufa wszystkim aplikacjom z wartością apple w partitionID. Można też użyć **`Python`**.

### Dwa dodatkowe atrybuty

- **Invisible**: Flaga logiczna służąca do **ukrywania** wpisu w aplikacji Keychain **UI**<sup>[[1]](#references)</sup>
- **General**: Służy do przechowywania **metadanych** (czyli NIE SĄ SZYFROWANE)<sup>[[1]](#references)</sup>
  - Microsoft przechowywał w postaci zwykłego tekstu wszystkie tokeny odświeżania używane do uzyskiwania dostępu do poufnego endpointu.<sup>[[1]](#references)</sup>

### Keychain ochrony danych: enumeracja, a następnie zapytanie o jeden element

Uruchom `SecItemCopyMatching` z poziomu **podpisanej aplikacji działającej w kontekście logowania docelowego użytkownika**, ustawiając `kSecUseDataProtectionKeychain: true`; nie zakładaj, że `security dump-keychain` ani domyślne zapytanie SecItem przeszukiwało ten magazyn. Wywołujący widzi tylko grupy dostępu, do których ma uprawnienia.<sup>[[5]](#references)</sup>

Jeśli kod testowy działa wewnątrz innego procesu, dostęp do jego Keychain ochrony danych zależy od uprawnień pliku wykonywalnego procesu hosta. Sprawdź rzeczywiste podpisane uprawnienia za pomocą `codesign -d --entitlements - /path/to/Target.app` i zobacz [uprawnienia podpisywania kodu w macOS](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md), aby poznać powiązane kontrole.<sup>[[7]](#references)</sup>

Najpierw zażądaj **wyłącznie atrybutów** dla jednej klasy elementów. `kSecAttrSynchronizableAny` obejmuje wyniki zarówno lokalne, jak i synchronizowane z iCloud; pominięcie tego atrybutu wyklucza elementy synchronizowane.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` zapobiega wyświetlaniu interfejsu uwierzytelniania podczas szerokiej enumeracji, ale pomija chronione wyniki.<sup>[[9]](#references)</sup> W razie potrzeby powtórz zapytanie z `kSecClassInternetPassword`.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

W przypadku dozwolonego odczytu sekretu utwórz **nowe**, wąskie zapytanie dotyczące wybranego elementu (na przykład klasy, usługi i konta), ustaw `kSecReturnData: true` oraz `kSecMatchLimit: kSecMatchLimitOne` i oczekuj uwierzytelnienia wymaganego dla danego elementu lub błędu. Nie łącz `kSecReturnData` z `kSecMatchLimitAll` w przypadku elementów typu hasło.<sup>[[10]](#references)</sup> Wynik `errSecItemNotFound` może również wskazywać na niewłaściwy magazyn, filtr synchronizacji lub brak uprawnienia access-group, a nie na brak poświadczenia.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: „Wytrych do pęku kluczy macOS” — Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist — Nowa wersja stealera MacSync dla macOS atakuje entuzjastów kryptowalut i programistów](https://securelist.com/macsync-new-version/121383/)
- [4] [Kopia strony podręcznika Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Interfejsy API i implementacje pęku kluczy na Macu](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: podstawy](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: pułapki i najlepsze praktyki](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Dostęp do elementów pęku kluczy za pomocą Face ID lub Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
