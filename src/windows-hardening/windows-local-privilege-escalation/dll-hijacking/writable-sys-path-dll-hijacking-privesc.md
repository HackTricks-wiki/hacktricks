# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Ako možete da **pišete u direktorijum u sistemskom `PATH`-u** (ne samo u korisnički `PATH`), možda ćete moći da **eskalirate privilegije** na sistemu.

Ovo se može zloupotrebiti putem **DLL hijacking-a** kada privilegovaniji servis ili proces pokuša da učita DLL koji ne postoji na ranijim lokacijama pretrage i na kraju pretraži upisivi direktorijum sistemskog `PATH`-a.

Za više informacija o **DLL hijacking-u** pogledajte:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Pronalaženje DLL-a koji nedostaje

Prvo, **identifikujte proces** koji se izvršava sa **višim privilegijama** i pokušava da **učita DLL iz upisivog direktorijuma sistemskog `PATH`-a**.

Imajte na umu da ova tehnika zavisi od unosa u **Machine/System PATH**, a ne samo od vašeg **User PATH**. Zato, pre nego što utrošite vreme na Procmon, vredi enumerisati unose **Machine PATH**-a i proveriti koji od njih imaju omogućeno pisanje:<sup>[[1]](#references)</sup>
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
Problem u ovim slučajevima je to što su ti procesi verovatno već pokrenuti. Da biste identifikovali DLL-ove koje servisi pokušavaju da učitaju, ali u tome ne uspevaju, pokrenite Procmon što je ranije moguće (pre pokretanja procesa), a zatim:

- **Kreirajte** fasciklu `C:\privesc_hijacking` i dodajte putanju `C:\privesc_hijacking` u **System Path env variable**. To možete uraditi **ručno** ili pomoću **PS**:
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
- Pokrenite **`procmon`** i idite na **`Options`** --> **`Enable boot logging`**, zatim pritisnite **`OK`** u upitu.
- Zatim **restartujte računar**. Kada se računar ponovo pokrene, **`procmon`** će odmah početi da **snima** događaje.
- Kada se **Windows** **pokrene, izvršite `procmon`** ponovo. Program će vas obavestiti da je već radio i **pitati da li želite da sačuvate** događaje u datoteci. Izaberite **yes** i **sačuvajte događaje u datoteci**.
- **Nakon** što je **datoteka** **generisana**, zatvorite otvoreni prozor **`procmon`** i **otvorite datoteku sa događajima**.
- Dodajte sledeće **filtere** da biste pronašli sve DLL-ove koje je neki **process pokušao da učita** iz writable System Path foldera:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** je potreban samo za servise koji se pokreću **suviše rano** da bi se inače posmatrali. Ako možete **pokrenuti ciljani servis/program na zahtev** (na primer, interakcijom sa njegovim COM interfejsom, ponovnim pokretanjem servisa ili ponovnim pokretanjem scheduled task-a), obično je brže zadržati normalno Procmon snimanje sa filterima kao što su **`Path contains .dll`**, **`Result is NAME NOT FOUND`** i **`Path begins with <writable_machine_path>`**.

### Propušteni DLL-ovi

Pokretanjem ovoga na besplatnoj **virtualnoj (vmware) Windows 11 mašini** dobio sam sledeće rezultate:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju zanemarite rezultate za `.exe`. Probe za DLL-ove koji nedostaju potekle su iz:

| Servis                         | Dll                | CMD linija                                                           |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)      | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                            | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Sledeći primer koristi tehniku opisanu u ovom članku o [**zloupotrebi `WptsExtensions.dll` za privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Drugi kandidati vredni trijaže

`WptsExtensions.dll` je dobar primer, ali nije jedini recurring **phantom DLL** koji se pojavljuje u privilegovanim servisima. Savremena hunting pravila i javni katalozi hijack-ova i dalje prate nazive kao što su:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasičan **SYSTEM** kandidat na klijentskim sistemima. Dobar je kada se writable direktorijum nalazi u **Machine PATH**-u, a servis proverava DLL tokom pokretanja. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Zanimljiv na **server editions** zato što servis radi kao **SYSTEM** i u nekim buildovima može da ga **pokrene na zahtev običan user**, što ga čini boljim od slučajeva koji zahtevaju samo restart. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Obično prvo daje **`NT AUTHORITY\LOCAL SERVICE`**. To je često i dalje dovoljno zato što token ima **`SeImpersonatePrivilege`**, pa se može povezati sa [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Ove nazive posmatrajte kao **smernice za trijažu**, a ne kao garantovane dobitke: zavise od **SKU-a/build-a**, a Microsoft može promeniti ponašanje između izdanja. Važno je tražiti **DLL-ove koji nedostaju u privilegovanim servisima koji prolaze kroz Machine PATH**, naročito ako se servis može **ponovo pokrenuti bez restarta računara**.

### Exploitation

Da biste **eskalirali privilegije**, hijack-ujte **`WptsExtensions.dll`**. Kada su **path** i **name** poznati, generišite malicious DLL.

Možete [**pokušati da koristite neki od ovih primera**](#creating-and-compiling-dlls). Možete pokrenuti payload-e kao što su: dobavljanje rev shell-a, dodavanje user-a, izvršavanje beacon-a...

> [!WARNING]
> Imajte na umu da **ne rade svi servisi** kao **`NT AUTHORITY\SYSTEM`**. Neki rade kao **`NT AUTHORITY\LOCAL SERVICE`**, koji ima **manje privilegija**, pa zloupotreba nekog od ovih servisa možda neće omogućiti kreiranje novog user-a.\
> Međutim, taj account ima korisničko pravo **`SeImpersonatePrivilege`**, pa možete koristiti [**Potato suite za privilege escalation**](../roguepotato-and-printspoofer.md). U ovom slučaju, reverse shell je bolja opcija od pokušaja kreiranja user-a.

U trenutku pisanja, servis **Task Scheduler** radi sa **Nt AUTHORITY\SYSTEM**.

Nakon što ste **generisali malicious Dll** (_u mom slučaju koristio sam x64 rev shell i dobio shell nazad, ali ga je defender prekinuo zato što je poticao iz msfvenom-a_), sačuvajte ga u writable System Path-u pod nazivom **WptsExtensions.dll** i **restartujte** računar (ili restartujte servis, odnosno uradite sve što je potrebno da se pogođeni servis/program ponovo pokrene).

Kada se servis ponovo pokrene, **dll bi trebalo da bude učitan i izvršen** (možete **ponovo upotrebiti** trik sa **procmon** da proverite da li je **library učitan očekivano**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
