# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Główne Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`) służy do przechowywania **danych uwierzytelniających użytkownika**, takich jak hasła aplikacji, hasła internetowe, certyfikaty utworzone przez użytkownika, hasła sieciowe oraz utworzone przez użytkownika klucze publiczne/prywatne.
- **System Keychain** (`/Library/Keychains/System.keychain`) przechowuje **dane uwierzytelniające całego systemu**, takie jak hasła WiFi, systemowe główne certyfikaty, systemowe klucze prywatne oraz hasła aplikacji systemowych.<sup>[[1]](#references)</sup>
- W `/System/Library/Keychains/*` można znaleźć inne komponenty, takie jak certyfikaty.
- W **iOS** istnieje tylko jeden **Keychain**, znajdujący się w `/private/var/Keychains/`. Folder ten zawiera również bazy danych dla `TrustStore`, urzędów certyfikacji (`caissuercache`) oraz wpisów OSCP (`ocspache`).
- Aplikacje będą ograniczone w Keychain wyłącznie do swojego prywatnego obszaru na podstawie identyfikatora aplikacji.

### Dostęp do Keychain za pomocą hasła

Pliki te, mimo że nie mają wbudowanej ochrony i mogą zostać **pobrane**, są zaszyfrowane i do ich odszyfrowania wymagają **hasła użytkownika w postaci jawnego tekstu**. Do odszyfrowania można użyć narzędzia takiego jak [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Ochrona wpisów Keychain

### ACL

Każdy wpis w Keychain jest kontrolowany przez **Access Control Lists (ACLs)**, które określają, kto może wykonywać różne działania na wpisie Keychain, w tym:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Umożliwia posiadaczowi uzyskanie sekretu w postaci jawnego tekstu.
- **ACLAuthorizationExportWrapped**: Umożliwia posiadaczowi uzyskanie jawnego tekstu zaszyfrowanego za pomocą innego podanego hasła.
- **ACLAuthorizationAny**: Umożliwia posiadaczowi wykonanie dowolnego działania.

ACL są dodatkowo powiązane z **listą zaufanych aplikacji**, które mogą wykonywać te działania bez wyświetlania monitu. Może to być:<sup>[[1]](#references)</sup>

- **N`il`** (autoryzacja nie jest wymagana, **wszyscy są zaufani**)
- Pusta lista (**nikt** nie jest zaufany)
- **Lista** określonych **aplikacji**.

Wpis może również zawierać klucz **`ACLAuthorizationPartitionID`,** używany do identyfikowania **teamid, apple** oraz **cdhash**.<sup>[[1]](#references)</sup>

- Jeśli określono **teamid**, aplikacja musi mieć **ten sam teamid**, aby **uzyskać dostęp do wartości wpisu** **bez** wyświetlania **monitu**.
- Jeśli określono **apple**, aplikacja musi być **podpisana** przez **Apple**.
- Jeśli wskazano **cdhash**, **aplikacja** musi mieć określony **cdhash**.

### Tworzenie wpisu Keychain

Podczas tworzenia **nowego** **wpisu** za pomocą **`Keychain Access.app`** obowiązują następujące zasady:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- **Żadne aplikacje** nie mogą eksportować/odszyfrowywać danych (bez wyświetlenia monitu użytkownikowi).
- Wszystkie aplikacje mogą sprawdzać kontrolę integralności.
- Żadne aplikacje nie mogą zmieniać ACL.
- **partitionID** jest ustawiony na **`apple`**.

Gdy **aplikacja tworzy wpis w Keychain**, zasady są nieco inne:<sup>[[1]](#references)</sup>

- Wszystkie aplikacje mogą szyfrować.
- Tylko **aplikacja tworząca** (lub inne jawnie dodane aplikacje) może eksportować/odszyfrowywać dane (bez wyświetlenia monitu użytkownikowi).
- Wszystkie aplikacje mogą sprawdzać kontrolę integralności.
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Enumerację i zrzut** sekretów z **keychain**, które **nie generują promptu**, można wykonać za pomocą narzędzia [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Inne endpointy API można znaleźć w kodzie źródłowym [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Lista i pobieranie **informacji** o każdym wpisie keychain za pomocą **Security Framework** lub narzędzia CLI firmy Apple o otwartym kodzie źródłowym [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Kilka przykładów API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** zwraca informacje o każdym wpisie; podczas jego używania można ustawić następujące atrybuty:
- **`kSecReturnData`**: Jeśli ma wartość true, narzędzie spróbuje odszyfrować dane (ustaw false, aby uniknąć potencjalnych pop-upów)
- **`kSecReturnRef`**: Pobiera również referencję do elementu keychain (ustaw true, jeśli później okaże się, że można go odszyfrować bez pop-upu)
- **`kSecReturnAttributes`**: Pobiera metadane wpisów
- **`kSecMatchLimit`**: Liczba wyników do zwrócenia
- **`kSecClass`**: Rodzaj wpisu keychain

Pobieranie **ACL** każdego wpisu:<sup>[[1]](#references)</sup>

- Za pomocą API **`SecAccessCopyACLList`** można pobrać **ACL elementu keychain**. Zwraca ono listę ACL (takich jak `ACLAuthorizationExportClear` i inne wcześniej wymienione), gdzie każdy wpis zawiera:
- Opis
- **Trusted Application List**. Może zawierać:
- Aplikację: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Grupę: group://AirPort

Eksport danych:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** pobiera dane w postaci plaintext
- API **`SecItemExport`** eksportuje klucze i certyfikaty, ale może wymagać ustawienia haseł w celu eksportu zaszyfrowanej zawartości

Poniżej przedstawiono wymagania umożliwiające **eksport sekretu bez promptu**:<sup>[[1]](#references)</sup>

- Jeśli wymieniono **co najmniej 1 zaufaną** aplikację:
- Wymagane są odpowiednie **autoryzacje** (**`Nil`** lub aplikacja musi być **częścią** dozwolonej listy aplikacji w autoryzacji dostępu do poufnych informacji)
- Sygnatura kodu musi być zgodna z **PartitionID**
- Sygnatura kodu musi odpowiadać sygnaturze jednej **zaufanej aplikacji** (lub aplikacja musi należeć do właściwego KeychainAccessGroup)
- Jeśli **wszystkie aplikacje są zaufane**:
- Wymagane są odpowiednie **autoryzacje**
- Sygnatura kodu musi być zgodna z **PartitionID**
- Jeśli nie ma **PartitionID**, nie jest to wymagane

> [!CAUTION]
> Dlatego jeśli **wymieniono 1 aplikację**, trzeba **wstrzyknąć kod do tej aplikacji**.
>
> Jeśli w **partitionID** wskazano **apple**, można uzyskać dostęp za pomocą **`osascript`**, więc dotyczy to wszystkiego, co ufa wszystkim aplikacjom mającym apple w partitionID. Można również użyć do tego **`Python`**.

### Dwa dodatkowe atrybuty

- **Invisible**: Jest to flaga logiczna służąca do **ukrycia** wpisu w aplikacji **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Służy do przechowywania **metadanych** (więc NIE JEST ZASZYFROWANE)<sup>[[1]](#references)</sup>
- Firma Microsoft przechowywała w plaintext wszystkie refresh tokeny umożliwiające dostęp do wrażliwego endpointu.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
