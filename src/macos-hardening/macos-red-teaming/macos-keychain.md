# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Główne pęki kluczy

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), który służy do przechowywania **poświadczeń użytkownika**, takich jak hasła aplikacji, hasła internetowe, certyfikaty wygenerowane przez użytkownika, hasła sieciowe oraz wygenerowane przez użytkownika klucze publiczne/prywatne.
- **System Keychain** (`/Library/Keychains/System.keychain`), który przechowuje **poświadczenia systemowe**, takie jak hasła WiFi, systemowe certyfikaty główne, systemowe klucze prywatne oraz hasła aplikacji systemowych.<sup>[[1]](#references)</sup>
- Możliwe jest znalezienie innych komponentów, takich jak certyfikaty, w `/System/Library/Keychains/*`
- W **iOS** istnieje tylko jeden **Keychain**, znajdujący się w `/private/var/Keychains/`. Folder ten zawiera również bazy danych dla `TrustStore`, urzędów certyfikacji (`caissuercache`) oraz wpisów OSCP (`ocspache`).
- Aplikacje będą miały dostęp w keychainie wyłącznie do swojego prywatnego obszaru, określonego na podstawie ich identyfikatora aplikacji.

### Dostęp do Keychain za pomocą hasła

Pliki te, mimo że nie mają wbudowanej ochrony i mogą zostać **pobrane**, są zaszyfrowane i do ich odszyfrowania wymagają **hasła użytkownika w postaci plaintext**. Do odszyfrowania można użyć narzędzia takiego jak [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Ochrona wpisów Keychain

### ACL

Każdy wpis w keychainie podlega **Listom kontroli dostępu (ACL)**, które określają, kto może wykonywać różne działania na wpisie keychaina, w tym:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Umożliwia posiadaczowi uzyskanie sekretu w postaci jawnego tekstu.
- **ACLAuhtorizationExportWrapped**: Umożliwia posiadaczowi uzyskanie jawnego tekstu zaszyfrowanego za pomocą innego podanego hasła.
- **ACLAuhtorizationAny**: Umożliwia posiadaczowi wykonanie dowolnej czynności.

ACL są dodatkowo uzupełnione **listą zaufanych aplikacji**, które mogą wykonywać te działania bez wyświetlania monitu. Może to być:<sup>[[1]](#references)</sup>

- **N`il`** (autoryzacja nie jest wymagana, **wszyscy są zaufani**)
- Pusta **lista** (**nikt** nie jest zaufany)
- **Lista** konkretnych **aplikacji**.

Wpis może również zawierać klucz **`ACLAuthorizationPartitionID`,** który służy do identyfikowania **teamid, apple** oraz **cdhash**.<sup>[[1]](#references)</sup>

- Jeśli określono **teamid**, aplikacja używana do **uzyskania dostępu do wartości wpisu** **bez monitu** musi mieć takie samo **teamid**.
- Jeśli określono **apple**, aplikacja musi być **podpisana** przez **Apple**.
- Jeśli wskazano **cdhash**, **aplikacja** musi mieć określony **cdhash**.

### Tworzenie wpisu Keychain

Podczas tworzenia **nowego** **wpisu** za pomocą **`Keychain Access.app`** obowiązują następujące zasady:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- **Żadne aplikacje** nie mogą eksportować/odszyfrowywać (bez wyświetlenia monitu użytkownikowi).
- Wszystkie aplikacje mogą wyświetlać kontrolę integralności.
- Żadne aplikacje nie mogą zmieniać ACL.
- **partitionID** jest ustawiony na **`apple`**.

Gdy **aplikacja tworzy wpis w keychainie**, zasady są nieco inne:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- Tylko **aplikacja tworząca** (lub inne jawnie dodane aplikacje) może eksportować/odszyfrowywać (bez wyświetlenia monitu użytkownikowi).
- Wszystkie aplikacje mogą wyświetlać kontrolę integralności.
- Żadne aplikacje nie mogą zmieniać ACL.
- **partitionID** jest ustawiony na **`teamid:[teamID here]`**.

## Uzyskiwanie dostępu do Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Enumerację i dumping** sekretów keychain, które **nie generują promptu**, można przeprowadzić za pomocą narzędzia [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Inne endpointy API można znaleźć w kodzie źródłowym [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Wyświetl i pobierz **informacje** o każdym wpisie keychain za pomocą **Security Framework**. Możesz również sprawdzić open source'owe narzędzie CLI firmy Apple — [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Przykłady API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** dostarcza informacji o każdym wpisie. Podczas jego używania można ustawić następujące atrybuty:
- **`kSecReturnData`**: Jeśli ustawione na true, API spróbuje odszyfrować dane (ustaw false, aby uniknąć potencjalnych pop-upów)
- **`kSecReturnRef`**: Pobiera również referencję do elementu keychain (ustaw true, jeśli później okaże się, że można go odszyfrować bez pop-upu)
- **`kSecReturnAttributes`**: Pobiera metadane wpisów
- **`kSecMatchLimit`**: Liczba wyników do zwrócenia
- **`kSecClass`**: Rodzaj wpisu keychain

Pobierz **ACL** każdego wpisu:<sup>[[1]](#references)</sup>

- Za pomocą API **`SecAccessCopyACLList`** można pobrać **ACL elementu keychain**. Zwróci ono listę ACL (takich jak `ACLAuhtorizationExportClear` i inne wspomniane wcześniej), gdzie każda lista zawiera:
- Opis
- **Trusted Application List**. Może ona zawierać:
- Aplikację: /Applications/Slack.app
- Binarkę: /usr/libexec/airportd
- Grupę: group://AirPort

Eksport danych:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** pobiera tekst jawny
- API **`SecItemExport`** eksportuje klucze i certyfikaty, ale może wymagać ustawienia haseł w celu eksportu zaszyfrowanej zawartości

Poniżej znajdują się wymagania umożliwiające **eksport sekretu bez promptu**:<sup>[[1]](#references)</sup>

- Jeśli wymieniono **co najmniej 1 trusted** app:
- Potrzebne są odpowiednie **authorizations** (**`Nil`** lub bycie **częścią** dozwolonej listy aplikacji w authorization umożliwiającym dostęp do informacji o sekrecie)
- Sygnatura kodu musi odpowiadać **PartitionID**
- Sygnatura kodu musi odpowiadać sygnaturze jednej **trusted app** (lub trzeba być członkiem właściwego KeychainAccessGroup)
- Jeśli **all applications trusted**:
- Potrzebne są odpowiednie **authorizations**
- Sygnatura kodu musi odpowiadać **PartitionID**
- Jeśli nie ma **PartitionID**, nie jest to wymagane

> [!CAUTION]
> Dlatego jeśli **wymieniona jest 1 aplikacja**, trzeba **wstrzyknąć kod do tej aplikacji**.
>
> Jeśli w **partitionID** znajduje się **apple**, można uzyskać dostęp za pomocą **`osascript`** — dotyczy to więc wszystkiego, co ufa wszystkim aplikacjom mającym apple w partitionID. Można również użyć **`Python`**.

### Dwa dodatkowe atrybuty

- **Invisible**: Jest to flaga logiczna służąca do **ukrycia** wpisu w aplikacji **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Służy do przechowywania **metadanych** (dlatego NIE JEST SZYFROWANY)<sup>[[1]](#references)</sup>
- Microsoft przechowywał w postaci jawnego tekstu wszystkie refresh tokeny umożliwiające dostęp do wrażliwego endpointu.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
