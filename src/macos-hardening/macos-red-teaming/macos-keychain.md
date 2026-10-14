# Pęk kluczy macOS

{{#include ../../banners/hacktricks-training.md}}

## Główne pęki kluczy

- **Pęk kluczy użytkownika** (`~/Library/Keychains/login.keychain-db`), w którym przechowywane są **dane uwierzytelniające konkretnego użytkownika**, takie jak hasła aplikacji i do internetu, certyfikaty utworzone przez użytkownika, hasła sieciowe oraz utworzone przez użytkownika klucze publiczne/prywatne.
- **Pęk kluczy systemu** (`/Library/Keychains/System.keychain`), w którym przechowywane są **dane uwierzytelniające dostępne w całym systemie**, takie jak hasła Wi-Fi, główne certyfikaty systemowe, klucze prywatne systemu i hasła aplikacji systemowych.<sup>[[1]](#references)</sup>
  - Inne składniki, takie jak certyfikaty, można znaleźć w `/System/Library/Keychains/*`
- W **iOS** jest tylko jeden **pęk kluczy**, znajdujący się w `/private/var/Keychains/`. Ten folder zawiera również bazy danych `TrustStore`, urzędów certyfikacji (`caissuercache`) i wpisów OSCP (`ocspache`).
  - Aplikacje mają dostęp w pęku kluczy wyłącznie do swojego prywatnego obszaru, określonego na podstawie identyfikatora aplikacji.

### Dostęp do pęku kluczy za pomocą hasła

Pliki te nie są domyślnie chronione i można je **pobrać**, ale są zaszyfrowane, a do ich odszyfrowania wymagane jest **hasło użytkownika w postaci jawnej**. Do odszyfrowania można użyć narzędzia takiego jak [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Zabezpieczenia wpisów w pęku kluczy

### ACL

Każdy wpis w pęku kluczy podlega **listom kontroli dostępu (ACL)**, które określają, kto może wykonywać różne działania na danym wpisie, w tym:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Zezwala posiadaczowi na uzyskanie sekretu w postaci jawnej.
- **`kSecACLAuthorizationExportWrapped`**: Zezwala posiadaczowi na uzyskanie sekretu zaszyfrowanego innym, podanym hasłem.
- **`kSecACLAuthorizationAny`**: Zezwala posiadaczowi na wykonanie dowolnego działania.

ACL uzupełnia **lista zaufanych aplikacji**, które mogą wykonywać te działania bez wyświetlania monitu. Lista może być:<sup>[[1]](#references)</sup>

- **N`il`** (autoryzacja nie jest wymagana, **wszyscy są zaufani**)
- **Pusta** (**nikt** nie jest zaufany)
- **Listą** określonych **aplikacji**.

Wpis może również zawierać klucz **`kSecACLAuthorizationPartitionID`,** służący do identyfikacji **teamid, apple** i **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Jeśli określono **teamid**, aplikacja musi mieć **ten sam teamid**, aby **uzyskać dostęp do wartości wpisu** bez **monitu**.
- Jeśli określono **apple**, aplikacja musi być **podpisana** przez **Apple**.
- Jeśli określono **cdhash**, **aplikacja** musi mieć określony **cdhash**.

### Tworzenie wpisu w pęku kluczy

Podczas tworzenia **nowego** **wpisu** za pomocą **`Keychain Access.app`** obowiązują następujące zasady:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- **Żadna aplikacja** nie może eksportować/odszyfrowywać danych (bez monitu do użytkownika).
- Wszystkie aplikacje mogą sprawdzać kontrolę integralności.
- Żadna aplikacja nie może zmieniać ACL.
- **partitionID** ma wartość **`apple`**.

Podczas tworzenia wpisu w pęku kluczy przez **aplikację** obowiązują nieco inne zasady:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- Tylko **aplikacja tworząca wpis** (lub inne jawnie dodane aplikacje) może eksportować/odszyfrowywać dane (bez monitu do użytkownika).
- Wszystkie aplikacje mogą sprawdzać kontrolę integralności.
- Żadna aplikacja nie może zmieniać ACL.
- **partitionID** ma wartość **`teamid:[teamID here]`**.

## Dostęp do pęku kluczy

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

`-S` ustawia listę partycji elementu, a `-k` podaje bieżące hasło Keychain wymagane do wprowadzenia tej zmiany; flaga przyjmująca hasło jest przestarzała.<sup>[[4]](#references)</sup> Pomyślna aktualizacja nie dowodzi, że późniejszy odczyt odbędzie się bez monitu: zaobserwowany, wyłączony prototyp nadal wyświetlał monit o potwierdzenie, gdy odpytywał element za pośrednictwem `Security.framework`. Zgodny identyfikator partycji to tylko jeden z elementów kontroli ACL i zaufanych aplikacji opisanych powyżej, dlatego zweryfikuj rzeczywistą ścieżkę odczytu.<sup>[[3]](#references)</sup>

### API

> [!TIP]
> **Wyliczanie elementów Keychain i zrzucanie** sekretów, które **nie wywołują monitu**, można wykonać za pomocą narzędzia [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Inne punkty końcowe API można znaleźć w kodzie źródłowym [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Wyświetl i pobierz **informacje** o każdym wpisie Keychain za pomocą **Security Framework** albo sprawdź narzędzie CLI open source Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Przykłady API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** udostępnia informacje o każdym wpisie; podczas jego używania można ustawić kilka atrybutów:
  - **`kSecReturnData`**: Jeśli ma wartość true, API spróbuje odszyfrować dane (ustaw wartość false, aby uniknąć potencjalnych wyskakujących okienek)
  - **`kSecReturnRef`**: Pobierz również referencję do elementu Keychain (ustaw wartość true na wypadek, gdyby później okazało się, że można go odszyfrować bez wyskakującego okienka)
  - **`kSecReturnAttributes`**: Pobierz metadane wpisów
  - **`kSecMatchLimit`**: Liczba wyników do zwrócenia
  - **`kSecClass`**: Rodzaj wpisu Keychain

Pobierz **ACL-e** poszczególnych wpisów:<sup>[[1]](#references)</sup>

- Za pomocą API **`SecAccessCopyACLList`** można pobrać **ACL elementu Keychain**. Zwraca ono listę ACL-i (takich jak `kSecACLAuthorizationExportClear` i pozostałe wymienione wcześniej), z których każdy zawiera:<sup>[[1]](#references)[[2]](#references)</sup>
  - Opis
  - **Lista zaufanych aplikacji**. Mogą to być:
    - Aplikacja: /Applications/Slack.app
    - Plik binarny: /usr/libexec/airportd
    - Grupa: group://AirPort

Eksportuj dane:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** pobiera tekst jawny
- API **`SecItemExport`** eksportuje klucze i certyfikaty, ale eksport zaszyfrowanej zawartości może wymagać ustawienia haseł

Oto **wymagania**, które należy spełnić, aby **wyeksportować sekret bez monitu**:<sup>[[1]](#references)</sup>

- Jeśli na liście znajduje się co najmniej jedna zaufana aplikacja:
  - Wymagane są odpowiednie **uprawnienia** (**`Nil`** lub przynależność do **dozwolonej listy** aplikacji określonej w uprawnieniu do dostępu do poufnych informacji)
  - Podpis kodu musi być zgodny z **PartitionID**
  - Podpis kodu musi odpowiadać podpisowi jednej **zaufanej aplikacji** (lub aplikacja musi należeć do właściwej grupy KeychainAccessGroup)
- Jeśli zaufane są **wszystkie aplikacje**:
  - Wymagane są odpowiednie **uprawnienia**
  - Podpis kodu musi być zgodny z **PartitionID**
    - Jeśli **brak PartitionID**, ten warunek nie jest wymagany

> [!CAUTION]
> Dlatego jeśli na liście znajduje się **jedna aplikacja**, trzeba **wstrzyknąć kod do tej aplikacji**.
>
> Jeśli w **partitionID** znajduje się **apple**, można uzyskać dostęp za pomocą **`osascript`** — dotyczy to więc wszystkiego, co ufa wszystkim aplikacjom i ma apple w partitionID. Można też użyć **`Python`**.

### Dwa dodatkowe atrybuty

- **Invisible**: Flaga logiczna służąca do **ukrywania** wpisu w aplikacji Keychain **UI**<sup>[[1]](#references)</sup>
- **General**: Służy do przechowywania **metadanych** (nie są one **SZYFROWANE**)<sup>[[1]](#references)</sup>
  - Microsoft przechowywał jawnym tekstem wszystkie tokeny odświeżania używane do uzyskiwania dostępu do poufnego punktu końcowego.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: „Wytrychowanie macOS Keychain” — Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist — Nowa wersja złodzieja danych MacSync na macOS atakuje entuzjastów kryptowalut i programistów](https://securelist.com/macsync-new-version/121383/)
- [4] [Kopia strony podręcznika man Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
