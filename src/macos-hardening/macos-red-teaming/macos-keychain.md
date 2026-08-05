# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Główne Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), używany do przechowywania **poświadczeń użytkownika**, takich jak hasła aplikacji, hasła internetowe, certyfikaty utworzone przez użytkownika, hasła sieciowe oraz utworzone przez użytkownika klucze publiczne/prywatne.
- **System Keychain** (`/Library/Keychains/System.keychain`), przechowujący **poświadczenia systemowe**, takie jak hasła WiFi, systemowe certyfikaty root, systemowe klucze prywatne oraz hasła aplikacji systemowych.<sup>[1]</sup>
- W `/System/Library/Keychains/*` można znaleźć inne komponenty, takie jak certyfikaty.
- W **iOS** istnieje tylko jeden **Keychain**, zlokalizowany w `/private/var/Keychains/`. Folder ten zawiera również bazy danych dla `TrustStore`, urzędów certyfikacji (`caissuercache`) oraz wpisów OSCP (`ocspache`).
- Aplikacje będą ograniczone w Keychain wyłącznie do swojego prywatnego obszaru na podstawie identyfikatora aplikacji.

### Dostęp do Keychain z użyciem hasła

Pliki te, mimo że nie mają wbudowanej ochrony i mogą zostać **pobrane**, są zaszyfrowane i wymagają **hasła użytkownika w postaci plaintextu do odszyfrowania**. Do odszyfrowania można użyć narzędzia takiego jak [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[1]</sup>

## Zabezpieczenia wpisów Keychain

### ACLs

Każdy wpis w Keychain jest kontrolowany przez **Access Control Lists (ACLs)**, które określają, kto może wykonywać różne działania na wpisie Keychain, w tym:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Umożliwia posiadaczowi uzyskanie sekretu w postaci clear text.
- **ACLAuhtorizationExportWrapped**: Umożliwia posiadaczowi uzyskanie clear text zaszyfrowanego przy użyciu innego podanego hasła.
- **ACLAuhtorizationAny**: Umożliwia posiadaczowi wykonanie dowolnego działania.

ACLs zawierają dodatkowo **listę zaufanych aplikacji**, które mogą wykonywać te działania bez wyświetlania promptu. Może to być:<sup>[1]</sup>

- **N`il`** (autoryzacja nie jest wymagana, **wszyscy są zaufani**)
- Pusta lista (**nikt** nie jest zaufany)
- **Lista** określonych **aplikacji**.

Wpis może również zawierać klucz **`ACLAuthorizationPartitionID`,** używany do identyfikacji **teamid, apple** oraz **cdhash**.<sup>[1]</sup>

- Jeśli określono **teamid**, aplikacja używana do **uzyskania dostępu do wartości wpisu** **bez** **promptu** musi mieć takie samo **teamid**.
- Jeśli określono **apple**, aplikacja musi być **podpisana** przez **Apple**.
- Jeśli wskazano **cdhash**, **aplikacja** musi mieć określony **cdhash**.

### Tworzenie wpisu Keychain

Gdy tworzony jest **nowy** **wpis** przy użyciu **`Keychain Access.app`**, obowiązują następujące zasady:<sup>[1]</sup>

- Wszystkie aplikacje mogą szyfrować.
- **Żadne aplikacje** nie mogą eksportować/odszyfrowywać (bez wyświetlenia promptu użytkownikowi).
- Wszystkie aplikacje mogą zobaczyć kontrolę integralności.
- Żadne aplikacje nie mogą zmieniać ACLs.
- **partitionID** jest ustawiony na **`apple`**.

Gdy **aplikacja tworzy wpis w Keychain**, zasady są nieco inne:<sup>[1]</sup>

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
> **Enumerację i dumpowanie sekretów z keychain**, które **nie wygenerują promptu**, można wykonać za pomocą narzędzia [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Inne endpointy API można znaleźć w kodzie źródłowym [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Listuj i pobieraj **info** o każdym wpisie keychain za pomocą **Security Framework**. Możesz również sprawdzić open source'owe narzędzie CLI firmy Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Przykłady API:<sup>[1]</sup>

- API **`SecItemCopyMatching`** dostarcza info o każdym wpisie i pozwala ustawić podczas użycia kilka atrybutów:
- **`kSecReturnData`**: Jeśli true, spróbuje odszyfrować dane (ustaw false, aby uniknąć potencjalnych pop-upów)
- **`kSecReturnRef`**: Pobiera również referencję do elementu keychain (ustaw true, jeśli później okaże się, że można go odszyfrować bez pop-upu)
- **`kSecReturnAttributes`**: Pobiera metadane wpisów
- **`kSecMatchLimit`**: Liczba wyników do zwrócenia
- **`kSecClass`**: Rodzaj wpisu keychain

Pobieranie **ACL** każdego wpisu:<sup>[1]</sup>

- Za pomocą API **`SecAccessCopyACLList`** można pobrać **ACL elementu keychain**. Zwróci ono listę ACL (takich jak `ACLAuhtorizationExportClear` i inne wspomniane wcześniej), gdzie każda lista zawiera:
- Opis
- **Trusted Application List**. Może to być:
- Aplikacja: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Grupa: group://AirPort

Eksportowanie danych:<sup>[1]</sup>

- API **`SecKeychainItemCopyContent`** pobiera plaintext
- API **`SecItemExport`** eksportuje klucze i certyfikaty, ale może wymagać ustawienia haseł w celu eksportu zaszyfrowanej zawartości

Aby móc **wyeksportować sekret bez promptu**, należy spełnić następujące **wymagania**:<sup>[1]</sup>

- Jeśli wymieniono **1+ trusted** aplikacji:
- Potrzebne są odpowiednie **autoryzacje** (**`Nil`** lub trzeba być **częścią** listy dozwolonych aplikacji w autoryzacji dostępu do informacji o sekrecie)
- Podpis kodu musi odpowiadać **PartitionID**
- Podpis kodu musi odpowiadać podpisowi jednej **trusted app** (lub trzeba być członkiem właściwej KeychainAccessGroup)
- Jeśli **wszystkie aplikacje są trusted**:
- Potrzebne są odpowiednie **autoryzacje**
- Podpis kodu musi odpowiadać **PartitionID**
- Jeśli brak **PartitionID**, nie jest to wymagane

> [!CAUTION]
> Dlatego jeśli wymieniono **1 aplikację**, trzeba **wstrzyknąć kod do tej aplikacji**.
>
> Jeśli w **partitionID** wskazano **apple**, można uzyskać dostęp za pomocą **`osascript`**. Dotyczy to wszystkiego, co ufa wszystkim aplikacjom z apple w partitionID. Można również użyć **`Python`**.

### Dwa dodatkowe atrybuty

- **Invisible**: Jest to flaga logiczna służąca do **ukrycia** wpisu przed aplikacją **UI** Keychain<sup>[1]</sup>
- **General**: Służy do przechowywania **metadanych** (nie jest więc **SZYFROWANE**)<sup>[1]</sup>
- Microsoft przechowywał w plaintext wszystkie refresh tokens umożliwiające dostęp do wrażliwego endpointu.<sup>[1]</sup>

## Referencje

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
