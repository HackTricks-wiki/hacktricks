# Writable Sys Path +DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Ako možete da **pišete u direktorijum u sistemskom `PATH`-u** (ne samo u svom korisničkom `PATH`-u), možda ćete moći da **eskalirate privilegije** na sistemu.

Ovo se može zloupotrebiti kroz **DLL hijacking** kada privilegovaniji servis ili proces pokuša da učita DLL koji ne postoji na ranijim lokacijama za pretragu i na kraju pretraži direktorijum sistemskog `PATH`-a u koji je moguće pisati.

Za više informacija o **DLL hijacking-u**, pogledajte:


{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Pronalaženje DLL-a koji nedostaje

Prvo **identifikujte proces** koji se izvršava sa **većim privilegijama** i pokušava da **učita DLL iz direktorijuma sistemskog `PATH`-a u koji je moguće pisati**.

Imajte na umu da ova tehnika zavisi od stavke u **Machine/System PATH**, a ne samo od vašeg **User PATH**-a. Zato, pre nego što utrošite vreme na Procmon, vredi izlistati stavke **Machine PATH**-a i proveriti u koje je moguće pisati:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Problem u ovim slučajevima je to što su ti procesi verovatno već pokrenuti. Da biste identifikovali DLL-ove koje servisi pokušavaju, ali ne uspevaju da učitaju, pokrenite Procmon što je ranije moguće (pre pokretanja procesa), a zatim:

- **Kreirajte** folder `C:\privesc_hijacking` i dodajte putanju `C:\privesc_hijacking` u **System Path env variable**. To možete uraditi **ručno** ili pomoću **PS**:
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
- Pokrenite **`procmon`** i idite na **`Options`** --> **`Enable boot logging`**, zatim pritisnite **`OK`** u prozoru za potvrdu.
- Zatim **restartujte računar**. Kada se računar ponovo pokrene, **`procmon`** će odmah početi da **snima** događaje.
- Kada se **Windows** **pokrene, ponovo izvršite `procmon`**. Program će vas obavestiti da je već radio i **pitati da li želite da sačuvate** događaje u datoteku. Izaberite **yes** i **sačuvajte događaje u datoteku**.
- **Nakon** što se **datoteka** **generiše**, zatvorite otvoreni prozor programa **`procmon`** i **otvorite datoteku sa događajima**.
- Dodajte sledeće **filtere** da biste pronašli sve DLL-ove koje je neki **proces pokušao da učita** iz foldera writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** je potreban samo za servise koji se pokreću **previše rano** da bi se inače posmatrali. Ako možete **pokrenuti ciljani servis/program na zahtev** (na primer, interakcijom sa njegovim COM interfejsom, ponovnim pokretanjem servisa ili ponovnim pokretanjem scheduled task-a), obično je brže zadržati normalno Procmon snimanje sa filterima kao što su **`Path contains .dll`**, **`Result is NAME NOT FOUND`** i **`Path begins with <writable_machine_path>`**.

### Propušteni DLL-ovi

Pokretanjem ovoga na besplatnoj **virtuelnoj (vmware) Windows 11 mašini** dobio sam sledeće rezultate:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju zanemarite rezultate za `.exe`. Probe za DLL-ove koji nedostaju potekle su od:

| Servis                         | Dll                | CMD linija                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Sledeći primer koristi tehniku opisanu u ovom članku o [**zloupotrebi `WptsExtensions.dll` za escalation privilegija**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Drugi kandidati vredni trijaže

`WptsExtensions.dll` je dobar primer, ali nije jedini recurring **phantom DLL** koji se pojavljuje u privilegovanim servisima. Savremena hunting pravila i javni hijack katalozi i dalje prate nazive kao što su:<sup>[[2]](#references)</sup>

| Servis / Scenario | DLL koji nedostaje | Napomene |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasičan **SYSTEM** kandidat na client sistemima. Dobar je kada se writable direktorijum nalazi u **Machine PATH** promenljivoj i servis proverava DLL tokom pokretanja. |
| NetMan na Windows Server-u | `wlanhlp.dll` / `wlanapi.dll` | Zanimljivo na **server izdanjima** zato što servis radi kao **SYSTEM** i u nekim buildovima ga **normalan korisnik može pokrenuti na zahtev**, što ga čini boljim od slučajeva koji zahtevaju samo restart. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Obično prvo daje **`NT AUTHORITY\LOCAL SERVICE`**. To je često i dalje dovoljno zato što token ima **`SeImpersonatePrivilege`**, pa ga možete ulančati sa [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Ove nazive posmatrajte kao **smernice za trijažu**, a ne kao garantovane rezultate: zavise od **SKU-a/build-a**, a Microsoft može promeniti ponašanje između izdanja. Najvažnije je tražiti **DLL-ove koji nedostaju u privilegovanim servisima koji prolaze kroz Machine PATH**, naročito ako se servis može **ponovo pokrenuti bez restarta računara**.

### Exploitation

Da biste **eskalirali privilegije**, hijack-ujte **`WptsExtensions.dll`**. Kada su **putanja** i **naziv** poznati, generišite malicious DLL.

Možete [**pokušati da koristite neki od ovih primera**](#creating-and-compiling-dlls). Možete pokretati payload-e kao što su: dobavljanje rev shell-a, dodavanje korisnika, izvršavanje beacon-a...

> [!WARNING]
> Imajte na umu da svi servisi **ne rade** kao **`NT AUTHORITY\SYSTEM`**. Neki rade kao **`NT AUTHORITY\LOCAL SERVICE`**, koji ima **manje privilegija**, pa vam zloupotreba jednog od ovih servisa možda neće omogućiti kreiranje novog korisnika.\
> Međutim, taj nalog ima korisničko pravo **`SeImpersonatePrivilege`**, pa možete koristiti [**Potato suite za eskalaciju privilegija**](../roguepotato-and-printspoofer.md). U ovom slučaju, reverse shell je bolja opcija od pokušaja kreiranja korisnika.

U trenutku pisanja ovog teksta servis **Task Scheduler** radi sa **Nt AUTHORITY\SYSTEM**.

Nakon što ste **generisali malicious Dll** (_u mom slučaju koristio sam x64 rev shell i dobio shell nazad, ali ga je defender prekinuo zato što je poticao iz msfvenom-a_), sačuvajte ga u writable System Path sa nazivom **WptsExtensions.dll** i **restartujte** računar (ili restartujte servis, odnosno uradite sve što je potrebno da se pogođeni servis/program ponovo pokrene).

Kada se servis ponovo pokrene, **dll bi trebalo da bude učitan i izvršen** (možete **ponovo upotrebiti** trik sa **procmon** da proverite da li je **biblioteka učitana kako se očekuje**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Sumnjivi DLL učitan za Persistence ili Eskalaciju privilegija](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Eskalacija privilegija](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
