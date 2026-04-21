# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Ako ste otkrili da možete da **pišete u folderu System Path** (napomena: ovo neće raditi ako možete da pišete u folderu User Path), moguće je da možete da **eskalirate privilegije** u sistemu.

Da biste to uradili, možete zloupotrebiti **Dll Hijacking** tako što ćete **oteti biblioteku koja se učitava** od strane servisa ili procesa sa **više privilegija** nego što ih imate, i pošto taj servis učitava Dll koji verovatno ne postoji ni u celom sistemu, pokušaće da ga učita iz System Path u koji vi možete da pišete.

Za više informacija o **šta je Dll Hijackig** pogledajte:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

Prva stvar koja vam je potrebna jeste da **identifikujete proces** koji radi sa **više privilegija** nego vi i pokušava da **učita Dll iz System Path** u koji možete da pišete.

Zapamtite da ova tehnika zavisi od **Machine/System PATH** stavke, a ne samo od vašeg **User PATH**. Zato, pre nego što potrošite vreme na Procmon, vredi nabrojati **Machine PATH** stavke i proveriti koje su upisive:
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
Problem u ovim slučajevima je što ti procesi verovatno već rade. Da bi pronašao koje Dll-ove servisima nedostaju, treba da pokreneš procmon što je pre moguće (pre nego što se procesi učitaju). Dakle, da bi pronašao nedostajuće .dll fajlove, uradi:

- **Create** folder `C:\privesc_hijacking` i dodaj putanju `C:\privesc_hijacking` u **System Path env variable**. To možeš da uradiš **manually** ili pomoću **PS**:
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
- Pokreni **`procmon`** i idi na **`Options`** --> **`Enable boot logging`** i pritisni **`OK`** u promptu.
- Zatim, **restartuj**. Kada se računar restartuje, **`procmon`** će početi da **snima** događaje ASAP.
- Kada se **Windows** **podigne, ponovo pokreni `procmon`**, on će ti reći da je već radio i **pitaće te da li želiš da sačuvaš** događaje u fajl. Reci **yes** i **sačuvaj događaje u fajl**.
- **Nakon** što se **fajl** **generiše**, **zatvori** otvoreni prozor **`procmon`** i **otvori events fajl**.
- Dodaj ove **filtere** i pronaći ćeš sve Dll-ove koje je neki **proccess pokušao da učita** iz writable System Path foldera:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** je potreban samo za servise koji startuju previše rano da bi se drugačije posmatrali. Ako možeš da **okineš target service/program na zahtev** (na primer, interakcijom sa njegovim COM interfejsom, restartovanjem servisa ili ponovnim pokretanjem scheduled task-a), obično je brže da držiš normalan Procmon capture sa filterima kao što su **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, i **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Pokretanjem ovoga na slobodnoj **virtual (vmware) Windows 11 mašini** dobio sam ove rezultate:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju .exe su beskorisni pa ih ignoriši, propušteni DLL-ovi su bili od:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nakon što sam ovo pronašao, naleteo sam na ovaj zanimljiv blog post koji takođe objašnjava kako da [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Što je upravo ono što **ćemo sada da uradimo**.

### Other candidates worth triaging

`WptsExtensions.dll` je dobar primer, ali nije jedini ponavljajući **phantom DLL** koji se pojavljuje u privilegovanim servisima. Moderna hunting pravila i javni hijack katalozi i dalje prate nazive kao što su:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasičan **SYSTEM** kandidat na client sistemima. Dobar kada je writable direktorijum u **Machine PATH** i servis proverava DLL tokom startovanja. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Zanimljivo na **server editions** jer servis radi kao **SYSTEM** i može da se **okine na zahtev od strane normalnog user-a** u nekim build-ovima, što ga čini boljim od slučajeva koji zahtevaju samo reboot. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Obično prvo daje **`NT AUTHORITY\LOCAL SERVICE`**. To je često i dalje dovoljno jer token ima **`SeImpersonatePrivilege`**, pa možeš da ga lančano iskoristiš sa [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Ove nazive tretiraj kao **triage hintove**, ne kao garantovane pobede: oni zavise od **SKU/build** verzije, i Microsoft može da promeni ponašanje između izdanja. Važna poenta je da tražiš **missing DLL-ove u privilegovanim servisima koji prolaze kroz Machine PATH**, posebno ako servis može da se **ponovo okine bez rebootovanja**.

### Exploitation

Dakle, da bismo **eskalirali privilegije**, hijackovaćemo biblioteku **WptsExtensions.dll**. Imajući **putanju** i **naziv**, treba nam samo da **generišemo malicious dll**.

Možeš da [**pokušaš da koristiš bilo koji od ovih primera**](#creating-and-compiling-dlls). Možeš da pokrećeš payload-ove kao što su: get a rev shell, dodaj user-a, izvrši beacon...

> [!WARNING]
> Napomena da **nisu svi servisi pokrenuti** sa **`NT AUTHORITY\SYSTEM`** neki se takođe pokreću kao **`NT AUTHORITY\LOCAL SERVICE`** koji ima **manje privilegija** i **nećeš moći da kreiraš novog user-a** da zloupotrebiš njegove dozvole.\
> Međutim, taj user ima **`seImpersonate`** privilegiju, pa možeš da koristiš[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Dakle, u ovom slučaju je rev shell bolja opcija nego pokušaj da kreiraš user-a.

U trenutku pisanja, servis **Task Scheduler** radi kao **Nt AUTHORITY\SYSTEM**.

Nakon što si **generisao malicious Dll** (_u mom slučaju sam koristio x64 rev shell i dobio shell nazad, ali ga je defender ubio zato što je bio iz msfvenom_), sačuvaj ga u writable System Path pod imenom **WptsExtensions.dll** i **restartuj** računar (ili restartuj servis ili uradi šta god treba da bi se pogođeni servis/program ponovo pokrenuo).

Kada se servis ponovo startuje, **dll bi trebalo da bude učitan i izvršen** (možeš da **ponovo iskoristiš** trik sa **procmon** da proveriš da li je **library učitana kako treba**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
