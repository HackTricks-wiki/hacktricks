# Red Teaming w macOS

{{#include ../../banners/hacktricks-training.md}}


## Nadużywanie MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Jeśli uda ci się **przejąć dane uwierzytelniające administratora** umożliwiające dostęp do platformy zarządzania, możesz **potencjalnie przejąć wszystkie komputery**, dystrybuując malware na tych urządzeniach.

W ramach red teamingu w środowiskach MacOS zdecydowanie zaleca się posiadanie pewnej wiedzy na temat działania MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Używanie MDM jako C2

MDM będzie mieć uprawnienia do instalowania, odpytywania lub usuwania profili, instalowania aplikacji, tworzenia lokalnych kont administratorów, ustawiania hasła firmware, zmiany klucza FileVault...

Aby uruchomić własny MDM, musisz mieć **swój CSR podpisany przez vendora**, co możesz spróbować uzyskać za pomocą [**https://mdmcert.download/**](https://mdmcert.download/). Aby uruchomić własny MDM dla urządzeń Apple, możesz użyć [**MicroMDM**](https://github.com/micromdm/micromdm).

Aby jednak zainstalować aplikację na zarejestrowanym urządzeniu, nadal musi ona być podpisana przez konto developera... jednak podczas rejestracji w MDM **urządzenie dodaje certyfikat SSL MDM jako zaufany CA**, więc możesz teraz podpisywać wszystko.<sup>[4]</sup>

Aby zarejestrować urządzenie w MDM, musisz zainstalować plik **`mobileconfig`** jako root. Można go dostarczyć za pomocą pliku **pkg** (możesz skompresować go w zip, a po pobraniu z Safari zostanie rozpakowany).

Agent **Mythic Orthrus** używa tej techniki.

### Nadużywanie JAMF PRO

JAMF może uruchamiać **custom scripts** (skrypty opracowane przez sysadmina), **native payloads** (tworzenie kont lokalnych, ustawianie hasła EFI, monitorowanie plików/procesów...) oraz **MDM** (konfiguracje urządzeń, certyfikaty urządzeń...).<sup>[5]</sup>

#### Samo-rejestracja JAMF

Przejdź na stronę taką jak `https://<company-name>.jamfcloud.com/enroll/`, aby sprawdzić, czy mają włączoną **self-enrolment**. Jeśli tak, strona może **poprosić o dane uwierzytelniające umożliwiające dostęp**.

Możesz użyć skryptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) do przeprowadzenia ataku password spraying.

Ponadto, po znalezieniu prawidłowych danych uwierzytelniających możesz być w stanie przeprowadzić brute-force innych nazw użytkowników za pomocą poniższego formularza:

![Nadużywanie JAMF PRO - self-enrolment JAMF: Ponadto, po znalezieniu prawidłowych danych uwierzytelniających możesz być w stanie przeprowadzić brute-force innych nazw użytkowników za pomocą poniższego formularza](<../../images/image (107).png>)

#### Uwierzytelnianie urządzenia JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Plik binarny **`jamf`** zawierał sekret umożliwiający otwarcie keychaina, który w momencie odkrycia był **współdzielony** przez wszystkich i miał wartość: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
Ponadto jamf **utrwala się** jako **LaunchDaemon** w pliku **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Przejęcie urządzenia JAMF

Adres **URL** **JSS** (Jamf Software Server), którego użyje **`jamf`**, znajduje się w pliku **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ten plik zawiera zasadniczo adres URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Zatem atakujący mógłby umieścić złośliwy pakiet (`pkg`), który podczas instalacji **nadpisuje ten plik**, ustawiając **URL listenera Mythic C2 agenta Typhon**, aby umożliwić wykorzystanie JAMF jako C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Aby **impersonować komunikację** między urządzeniem a JMF, potrzebujesz:

- **UUID** urządzenia: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** z: `/Library/Application\ Support/Jamf/JAMF.keychain`, który zawiera certyfikat urządzenia

Mając te informacje, **utwórz VM** ze **skradzionym** Hardware **UUID** oraz z **wyłączonym SIP**, umieść w niej **JAMF keychain**, wykonaj **hook** na **agencie** Jamf i przechwyć jego informacje.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Możesz również monitorować lokalizację `/Library/Application Support/Jamf/tmp/` pod kątem **custom scripts**, które administratorzy mogą chcieć wykonać za pośrednictwem Jamf, ponieważ są tutaj **umieszczane, wykonywane i usuwane**. Skrypty te **mogą zawierać credentials**.

Jednak **credentials** mogą być przekazywane do tych skryptów jako **parameters**, dlatego konieczne byłoby monitorowanie `ps aux | grep -i jamf` (nawet bez uprawnień root).

Skrypt [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) może nasłuchiwać nowych plików oraz nowych argumentów procesów.

### macOS Remote Access

A także informacje o "specjalnych" **network** **protocols** systemu **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

W niektórych przypadkach okaże się, że **komputer MacOS jest połączony z AD**. W takim scenariuszu spróbuj **enumerate** active directory tak, jak zwykle. Więcej **help** znajdziesz na następujących stronach:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Niektóre **local MacOS tools**, które również mogą Ci pomóc, to `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Dostępne są również narzędzia przygotowane dla MacOS do automatycznego enumerowania AD i pracy z kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound to rozszerzenie narzędzia Bloodhound do audytu, umożliwiające zbieranie i importowanie relacji Active Directory z hostów MacOS.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost to projekt Objective-C zaprojektowany do interakcji z API Heimdal krb5 w systemie macOS. Celem projektu jest umożliwienie dokładniejszego testowania bezpieczeństwa Kerberos na urządzeniach macOS przy użyciu natywnych API, bez konieczności instalowania na celu jakichkolwiek innych frameworków lub pakietów.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Narzędzie JavaScript for Automation (JXA) służące do enumerowania Active Directory.

### Informacje o domenie
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Użytkownicy

Trzy typy użytkowników MacOS to:

- **Użytkownicy lokalni** — Zarządzani przez lokalną usługę OpenDirectory, nie są w żaden sposób połączeni z Active Directory.
- **Użytkownicy sieciowi** — Ulotni użytkownicy Active Directory, którzy do uwierzytelnienia wymagają połączenia z serwerem DC.
- **Użytkownicy mobilni** — Użytkownicy Active Directory z lokalną kopią zapasową swoich poświadczeń i plików.

Lokalne informacje o użytkownikach i grupach są przechowywane w folderze _/var/db/dslocal/nodes/Default._\
Na przykład informacje o użytkowniku o nazwie _mark_ są przechowywane w _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacje o grupie _admin_ znajdują się w _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oprócz używania krawędzi HasSession i AdminTo, **MacHound dodaje trzy nowe krawędzie** do bazy danych Bloodhound:<sup>[2]</sup>

- **CanSSH** — encja, której zezwolono na używanie SSH do hosta
- **CanVNC** — encja, której zezwolono na używanie VNC do hosta
- **CanAE** — encja, której zezwolono na wykonywanie skryptów AppleEvent na hoście
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Więcej informacji na stronie [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Hasło Computer$

Pobieraj hasła za pomocą:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Możliwe jest uzyskanie dostępu do hasła **`Computer$`** w pęku kluczy System.

### Over-Pass-The-Hash

Uzyskaj TGT dla określonego użytkownika i usługi:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Po zebraniu TGT można injectować go do bieżącej sesji za pomocą:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Po uzyskaniu biletów usługowych można próbować uzyskać dostęp do udziałów na innych komputerach:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Uzyskiwanie dostępu do Keychain

Keychain z dużym prawdopodobieństwem zawiera poufne informacje, które po uzyskaniu do nich dostępu bez generowania promptu mogłyby pomóc w dalszym prowadzeniu ćwiczenia red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Usługi zewnętrzne

MacOS Red Teaming różni się od standardowego Windows Red Teaming, ponieważ **MacOS jest zwykle bezpośrednio zintegrowany z kilkoma zewnętrznymi platformami**. Typowa konfiguracja MacOS umożliwia dostęp do komputera przy użyciu **zsynchronizowanych poświadczeń OneLogin oraz dostęp do kilku zewnętrznych usług** (takich jak github, aws...) za pośrednictwem OneLogin.

## Różne techniki Red Team

### Safari

Gdy plik jest pobierany w Safari, jeśli jest „bezpiecznym” plikiem, zostanie **automatycznie otwarty**. Na przykład po **pobraniu pliku zip** zostanie on automatycznie zdekompresowany:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referencje

- [1] [Gone Apple Pickin': Red Teaming w środowiskach MacOS w 2021 roku - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Przedstawiamy MacHound: rozwiązanie do ataków na macOS oparte na Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Polecenia Domain Enumeration (odpowiedniki dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Przejdź na Ciemną Stronę, mamy Apple: zmienianie zarządzania macOS w narzędzie zła](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: „Perspektywa atakującego na konfiguracje Jamf” - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
