# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Ako otkrijete da možete **write in a System Path folder** (imajte na umu da ovo neće raditi ako možete pisati u **User Path folder**) moguće je da biste mogli **escalate privileges** na sistemu.

Da biste to postigli možete zloupotrebiti **Dll Hijacking** gde ćete preuzeti biblioteku koja se učitava od strane servisa ili procesa sa **više privilegija** od vaših, i pošto taj servis učitava Dll koji verovatno čak i ne postoji u celom sistemu, pokušaće da ga učita iz System Path u kojem možete pisati.

Za više informacija o **what is Dll Hijackig** pogledajte:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

Prva stvar koja vam treba je da **identify a process** koji radi sa **more privileges** od vaših i koji pokušava da **load a Dll from the System Path** u kojem možete pisati.

Problem u ovim slučajevima je što su ti procesi verovatno već pokrenuti. Da biste pronašli koje Dll-ove servisi nemaju, morate pokrenuti procmon što je pre moguće (pre nego što se procesi učitaju). Dakle, da biste pronašli nedostajuće .dll-ove uradite:

- **Kreirajte** folder `C:\privesc_hijacking` i dodajte putanju `C:\privesc_hijacking` u **System Path env variable**. Ovo možete uraditi **ručno** ili sa **PS**:
```bash
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
- Pokrenite **`procmon`** i idite na **`Options`** --> **`Enable boot logging`** i pritisnite **`OK`** u promptu.
- Zatim, **rebootujte**. Kada se računar restartuje, **`procmon`** će početi da **snima** događaje što je pre moguće.
- Kada se **Windows** pokrene, ponovo pokrenite **`procmon`**; obavestiće vas da je već radio i pitaće da li želite da sačuvate događaje u fajl. Recite **da** i **sačuvajte događaje u fajl**.
- **Nakon** što se **fajl** generiše, **zatvorite** otvoreni **`procmon`** prozor i **otvorite fajl sa događajima**.
- Dodajte ove **filtre** i naći ćete sve Dll-ove koje je neki **proces pokušao da učita** iz zapisivog System Path foldera:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Missed Dlls

Pokrenuvši ovo na besplatnoj virtuelnoj (vmware) Windows 11 mašini dobio sam ove rezultate:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju .exe fajlovi su beskorisni pa ih ignorišite, propušteni DLL-ovi su bili iz:

| Servis                          | Dll                | CMD linija                                                            |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nakon što sam ovo pronašao, naišao sam na interesantan blog post koji takođe objašnjava kako **abuse WptsExtensions.dll for privesc** (https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). To je ono što ćemo **sada uraditi**.

### Exploitation

Dakle, da bismo **eskalirali privilegije** plan je da hijack-ujemo biblioteku **WptsExtensions.dll**. Imajući **path** i **ime**, treba samo da **generišemo maliciozni dll**.

Možete [**pokušati da koristite bilo koji od ovih primera**](#creating-and-compiling-dlls). Možete izvršiti payload-e kao što su: dobijanje rev shell-a, dodavanje korisnika, izvršavanje beacon-a...

> [!WARNING]
> Imajte na umu da **nisu svi servisi pokrenuti** sa **`NT AUTHORITY\SYSTEM`**; neki se takođe pokreću sa **`NT AUTHORITY\LOCAL SERVICE`**, koji ima **manje privilegija** i **nećete moći da kreirate novog korisnika** zloupotrebom njegovih permisija.\
> Međutim, taj nalog ima privilegiju **`seImpersonate`**, pa možete koristiti [**potato suite da eskalirate privilegije**](../roguepotato-and-printspoofer.md). Dakle, u ovom slučaju rev shell je bolja opcija od pokušaja kreiranja korisnika.

U trenutku pisanja, servis **Task Scheduler** se pokreće sa **Nt AUTHORITY\SYSTEM**.

Kada ste **generisali maliciozni Dll** (_u mom slučaju sam koristio x64 rev shell i dobio sam shell nazad ali ga je Defender ubio jer je bio iz msfvenom_), sačuvajte ga u zapisivi System Path pod imenom **WptsExtensions.dll** i **restartujte** računar (ili restartujte servis ili uradite šta god treba da se pokrene pogođeni servis/program ponovo).

Kada se servis ponovo pokrene, **dll bi trebalo da se učita i izvrši** (možete ponovo iskoristiti **procmon** trik da proverite da li je **biblioteka učitana kao što se očekivalo**).

{{#include ../../../banners/hacktricks-training.md}}
