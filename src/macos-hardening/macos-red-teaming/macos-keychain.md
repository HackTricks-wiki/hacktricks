# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Główne Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`) służy do przechowywania **credentials użytkownika**, takich jak hasła aplikacji, hasła internetowe, certyfikaty utworzone przez użytkownika, hasła sieciowe oraz utworzone przez użytkownika klucze publiczne/prywatne.
- **System Keychain** (`/Library/Keychains/System.keychain`) przechowuje **credentials systemowe**, takie jak hasła WiFi, systemowe certyfikaty root, systemowe klucze prywatne oraz hasła aplikacji systemowych.<sup>[[1]](#references)</sup>
- Możliwe jest znalezienie innych komponentów, takich jak certyfikaty, w `/System/Library/Keychains/*`
- W **iOS** istnieje tylko jeden **Keychain**, zlokalizowany w `/private/var/Keychains/`. Ten folder zawiera również bazy danych dla `TrustStore`, urzędów certyfikacji (`caissuercache`) oraz wpisów OSCP (`ocspache`).
- Aplikacje mają dostęp w keychainie wyłącznie do swojego prywatnego obszaru na podstawie identyfikatora aplikacji.

### Dostęp do Password Keychain

Te pliki, mimo że nie mają wbudowanej ochrony i mogą zostać **pobrane**, są zaszyfrowane i do ich odszyfrowania wymagają **hasła użytkownika w plaintext**. Do odszyfrowania można użyć narzędzia takiego jak [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Ochrona wpisów Keychain

### ACLs

Każdy wpis w keychainie jest kontrolowany przez **Access Control Lists (ACLs)**, które określają, kto może wykonywać różne działania na wpisie keychaina, w tym:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Umożliwia posiadaczowi uzyskanie sekretu w clear text.
- **ACLAuhtorizationExportWrapped**: Umożliwia posiadaczowi uzyskanie clear text zaszyfrowanego za pomocą innego podanego hasła.
- **ACLAuhtorizationAny**: Umożliwia posiadaczowi wykonanie dowolnej akcji.

ACLs są dodatkowo powiązane z **listą zaufanych aplikacji**, które mogą wykonywać te działania bez wyświetlania promptu. Może to być:<sup>[[1]](#references)</sup>

- **N`il`** (autoryzacja nie jest wymagana, **wszyscy są zaufani**)
- Pusta **lista** (**nikt** nie jest zaufany)
- **Lista** określonych **aplikacji**.

Wpis może również zawierać klucz **`ACLAuthorizationPartitionID`,** używany do identyfikowania **teamid, apple** oraz **cdhash**.<sup>[[1]](#references)</sup>

- Jeśli określono **teamid**, to aby **uzyskać dostęp do wartości wpisu** **bez promptu**, używana aplikacja musi mieć **ten sam teamid**.
- Jeśli określono **apple**, aplikacja musi być **podpisana** przez **Apple**.
- Jeśli wskazano **cdhash**, **aplikacja** musi mieć określony **cdhash**.

### Tworzenie wpisu Keychain

Gdy tworzony jest **nowy** **wpis** za pomocą **`Keychain Access.app`**, obowiązują następujące zasady:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- **Żadne aplikacje** nie mogą eksportować/odszyfrowywać (bez wyświetlenia promptu użytkownikowi).
- Wszystkie aplikacje mogą zobaczyć kontrolę integralności.
- Żadne aplikacje nie mogą zmieniać ACLs.
- **partitionID** jest ustawiony na **`apple`**.

Gdy **aplikacja tworzy wpis w keychainie**, zasady są nieco inne:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- Tylko **aplikacja tworząca** (lub inne jawnie dodane aplikacje) może eksportować/odszyfrowywać (bez wyświetlenia promptu użytkownikowi).
- Wszystkie aplikacje mogą zobaczyć kontrolę integralności.
- Żadne aplikacje nie mogą zmieniać ACLs.
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
> **Enumerację i zrzucanie** sekretów z **keychain**, które **nie wygenerują prompta**, można wykonać za pomocą narzędzia [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Inne endpointy API można znaleźć w kodzie źródłowym [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Listę i **informacje** o każdym wpisie keychain można uzyskać za pomocą **Security Framework**. Możesz także sprawdzić open source'owe narzędzie CLI firmy Apple, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Przykłady API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** zwraca informacje o każdym wpisie i umożliwia ustawienie kilku atrybutów:
- **`kSecReturnData`**: Jeśli ustawione na true, narzędzie spróbuje odszyfrować dane (ustaw false, aby uniknąć potencjalnych popupów)
- **`kSecReturnRef`**: Pobiera także referencję do elementu keychain (ustaw true, jeśli później okaże się, że można go odszyfrować bez popupa)
- **`kSecReturnAttributes`**: Pobiera metadane wpisów
- **`kSecMatchLimit`**: Określa, ile wyników zwrócić
- **`kSecClass`**: Określa rodzaj wpisu keychain

Pobieranie **ACL** każdego wpisu:<sup>[[1]](#references)</sup>

- Za pomocą API **`SecAccessCopyACLList`** można pobrać **ACL elementu keychain**. API zwróci listę ACL (takich jak `ACLAuhtorizationExportClear` i inne wymienione wcześniej), gdzie każda lista zawiera:
- Opis
- **Trusted Application List**. Może ona zawierać:
- Aplikację: /Applications/Slack.app
- Binarkę: /usr/libexec/airportd
- Grupę: group://AirPort

Eksportowanie danych:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** pobiera dane w postaci tekstu jawnego
- API **`SecItemExport`** eksportuje klucze i certyfikaty, ale do eksportu zaszyfrowanej zawartości może być konieczne ustawienie haseł

Poniżej znajdują się wymagania umożliwiające **eksport sekretu bez prompta**:<sup>[[1]](#references)</sup>

- Jeśli wymieniono **1+ zaufanych** aplikacji:
- Potrzebne są odpowiednie **authorizations** (**`Nil`** lub bycie **częścią** dozwolonej listy aplikacji w authorization umożliwiającym dostęp do informacji o sekrecie)
- Sygnatura kodu musi odpowiadać **PartitionID**
- Sygnatura kodu musi odpowiadać sygnaturze jednej **zaufanej aplikacji** (lub kod musi należeć do właściwego KeychainAccessGroup)
- Jeśli **wszystkie aplikacje są zaufane**:
- Potrzebne są odpowiednie **authorizations**
- Sygnatura kodu musi odpowiadać **PartitionID**
- Jeśli brak **PartitionID**, nie jest to wymagane

> [!CAUTION]
> Dlatego jeśli **wymieniono 1 aplikację**, trzeba **wstrzyknąć kod do tej aplikacji**.
>
> Jeśli w **partitionID** wskazano **apple**, można uzyskać dostęp za pomocą **`osascript`**. Dotyczy to więc wszystkiego, co ufa wszystkim aplikacjom mającym apple w partitionID. Można także użyć do tego **`Python`**.

### Dwa dodatkowe atrybuty

- **Invisible**: To flaga boolean służąca do **ukrycia** wpisu w aplikacji **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Służy do przechowywania **metadanych** (dlatego dane te NIE SĄ ZASZYFROWANE)<sup>[[1]](#references)</sup>
- Microsoft przechowywał w postaci tekstu jawnego wszystkie refresh tokeny umożliwiające dostęp do wrażliwego endpointu.<sup>[[1]](#references)</sup>

## Referencje

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
