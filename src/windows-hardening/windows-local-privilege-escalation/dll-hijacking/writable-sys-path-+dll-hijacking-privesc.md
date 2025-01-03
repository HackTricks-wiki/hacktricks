# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Ako ste otkrili da možete **pisati u folderu System Path** (napomena: ovo neće raditi ako možete pisati u folderu User Path) moguće je da možete **povećati privilegije** u sistemu.

Da biste to uradili, možete zloupotrebiti **Dll Hijacking** gde ćete **oteti biblioteku koja se učitava** od strane servisa ili procesa sa **većim privilegijama** od vaših, i pošto taj servis učitava Dll koji verovatno čak ni ne postoji u celom sistemu, pokušaće da ga učita iz System Path gde možete pisati.

Za više informacija o **onome što je Dll Hijacking** pogledajte:

{{#ref}}
./
{{#endref}}

## Povećanje privilegija sa Dll Hijacking

### Pronalaženje nedostajuće Dll

Prva stvar koju treba da uradite je da **identifikujete proces** koji se izvršava sa **većim privilegijama** od vas i koji pokušava da **učita Dll iz System Path** u koji možete pisati.

Problem u ovim slučajevima je što ti procesi verovatno već rade. Da biste pronašli koje Dll-ove nedostaju uslugama, treba da pokrenete procmon što je pre moguće (pre nego što se procesi učitaju). Dakle, da biste pronašli nedostajuće .dll-ove uradite:

- **Kreirajte** folder `C:\privesc_hijacking` i dodajte putanju `C:\privesc_hijacking` u **System Path env varijablu**. Ovo možete uraditi **ručno** ili sa **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Pokrenite **`procmon`** i idite na **`Options`** --> **`Enable boot logging`** i pritisnite **`OK`** u prozoru.
- Zatim, **ponovo pokrenite**. Kada se računar ponovo pokrene, **`procmon`** će početi da **snima** događaje što je pre moguće.
- Kada se **Windows** **pokrene, ponovo izvršite `procmon`**, reći će vam da je već radio i **pitati vas da li želite da sačuvate** događaje u datoteci. Recite **da** i **sačuvajte događaje u datoteci**.
- **Nakon** što je **datoteka** **generisana**, **zatvorite** otvoreni **`procmon`** prozor i **otvorite datoteku sa događajima**.
- Dodajte ove **filtre** i pronaći ćete sve DLL-ove koje je neki **proces pokušao da učita** iz foldera sa zapisivim sistemskim putem:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Propušteni DLL-ovi

Pokrećući ovo na besplatnoj **virtuelnoj (vmware) Windows 11 mašini** dobio sam ove rezultate:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju .exe su beskorisni, pa ih ignorisite, propušteni DLL-ovi su bili iz:

| Usluga                          | DLL                | CMD linija                                                          |
| ------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Task Scheduler (Raspored)      | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`       |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`             |

Nakon što sam ovo pronašao, našao sam ovaj zanimljiv blog post koji takođe objašnjava kako da [**zloupotrebite WptsExtensions.dll za eskalaciju privilegija**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Što je ono što **sada planiramo da uradimo**.

### Eksploatacija

Dakle, da bismo **eskalirali privilegije**, planiramo da preuzmemo biblioteku **WptsExtensions.dll**. Imajući **putanju** i **ime**, samo treba da **generišemo maliciozni dll**.

Možete [**pokušati da koristite neki od ovih primera**](./#creating-and-compiling-dlls). Možete pokrenuti payload-e kao što su: dobijanje rev shell-a, dodavanje korisnika, izvršavanje beacona...

> [!WARNING]
> Imajte na umu da **nisu sve usluge pokrenute** sa **`NT AUTHORITY\SYSTEM`**, neke se takođe pokreću sa **`NT AUTHORITY\LOCAL SERVICE`** što ima **manje privilegija** i ne **ćete moći da kreirate novog korisnika** zloupotrebom njegovih dozvola.\
> Međutim, taj korisnik ima privilegiju **`seImpersonate`**, tako da možete koristiti [**potato suite za eskalaciju privilegija**](../roguepotato-and-printspoofer.md). Dakle, u ovom slučaju rev shell je bolja opcija nego pokušaj da se kreira korisnik.

U trenutku pisanja, usluga **Task Scheduler** se pokreće sa **Nt AUTHORITY\SYSTEM**.

Nakon što ste **generisali maliciozni DLL** (_u mom slučaju sam koristio x64 rev shell i dobio sam shell nazad, ali ga je defender ubio jer je bio iz msfvenom_), sačuvajte ga u zapisivom sistemskom putu pod imenom **WptsExtensions.dll** i **ponovo pokrenite** računar (ili ponovo pokrenite uslugu ili uradite šta god je potrebno da ponovo pokrenete pogođenu uslugu/program).

Kada se usluga ponovo pokrene, **dll bi trebao biti učitan i izvršen** (možete **ponovo koristiti** **procmon** trik da proverite da li je **biblioteka učitana kako se očekivalo**).

{{#include ../../../banners/hacktricks-training.md}}
