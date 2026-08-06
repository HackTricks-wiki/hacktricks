# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Ako ste otkrili da možete da **pišete u folder System Path** (imajte na umu da ovo neće raditi ako možete da pišete u folder User Path), moguće je da biste mogli da **eskalirate privilegije** na sistemu.

Da biste to uradili, možete zloupotrebiti **Dll Hijacking**, pri čemu ćete **oteti biblioteku koja se učitava** od strane servisa ili procesa sa **većim privilegijama** od vaših. Pošto taj servis učitava Dll koji verovatno čak ni ne postoji u celom sistemu, pokušaće da ga učita iz foldera System Path u koji možete da pišete.

Za više informacija o tome **šta je Dll Hijackig**, pogledajte:


{{#ref}}
./
{{#endref}}

## Privesc sa Dll Hijacking

### Pronalaženje Dll-a koji nedostaje

Prvo što vam je potrebno jeste da **identifikujete proces** koji radi sa **većim privilegijama** od vaših i koji pokušava da **učita Dll iz foldera System Path** u koji možete da pišete.

Imajte na umu da ova tehnika zavisi od stavke **Machine/System PATH**, a ne samo od vašeg **User PATH**. Zato, pre nego što potrošite vreme na Procmon, vredi enumerisati stavke **Machine PATH** i proveriti u koje od njih može da se piše:<sup>[[1]](#references)</sup>
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
Problem u ovim slučajevima je što su ti procesi verovatno već pokrenuti. Da biste otkrili koji DLL-ovi nedostaju servisima, morate pokrenuti procmon što je pre moguće (pre učitavanja procesa). Dakle, da biste pronašli DLL-ove koji nedostaju, uradite sledeće:

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
- Pokrenite **`procmon`** i idite na **`Options`** --> **`Enable boot logging`**, zatim pritisnite **`OK`** u promptu.
- Zatim **restartujte računar**. Kada se računar ponovo pokrene, **`procmon`** će početi da **snima** događaje čim pre.
- Kada se **Windows** **pokrene, izvršite `procmon`** ponovo. On će vas obavestiti da je već radio i **pitati da li želite da sačuvate** događaje u datoteku. Izaberite **yes** i **sačuvajte događaje u datoteku**.
- **Nakon** što je **datoteka** **generisana**, zatvorite otvoreni prozor **`procmon`** i **otvorite datoteku sa događajima**.
- Dodajte ove **filtere** i pronaći ćete sve DLL-ove koje je neki **proces pokušao da učita** iz foldera upisivog System Path-a:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** je potreban samo za servise koji se pokreću **prerano** da bi se inače posmatrali. Ako možete **pokrenuti ciljni servis/program po potrebi** (na primer, interakcijom sa njegovim COM interfejsom, ponovnim pokretanjem servisa ili ponovnim pokretanjem scheduled task-a), obično je brže da koristite normalno Procmon snimanje sa filterima kao što su **`Path contains .dll`**, **`Result is NAME NOT FOUND`** i **`Path begins with <writable_machine_path>`**.

### Propušteni DLL-ovi

Pokretanjem ovoga na besplatnoj **virtuelnoj (vmware) Windows 11 mašini** dobio sam sledeće rezultate:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju .exe datoteke su beskorisne, pa ih ignorišite. Propušteni DLL-ovi poticali su od:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nakon što sam ovo pronašao, našao sam zanimljiv blog post koji takođe objašnjava kako da [**zloupotrebite WptsExtensions.dll za privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Upravo to ćemo **sada uraditi**.<sup>[[3]](#references)</sup>

### Drugi kandidati vredni triage-a

`WptsExtensions.dll` je dobar primer, ali nije jedini recurring **phantom DLL** koji se pojavljuje u privilegovanim servisima. Savremena hunting pravila i javni hijack katalozi i dalje prate imena kao što su:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasičan **SYSTEM** kandidat na klijentskim sistemima. Dobar je kada se upisivi direktorijum nalazi u **Machine PATH-u**, a servis proverava DLL tokom pokretanja. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Zanimljiv je na **server izdanjima** zato što servis radi kao **SYSTEM** i u nekim build-ovima može biti **pokrenut po potrebi od strane običnog korisnika**, što ga čini boljim od slučajeva koji zahtevaju samo restart računara. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Obično prvo daje **`NT AUTHORITY\LOCAL SERVICE`**. To je često i dalje dovoljno zato što token poseduje **`SeImpersonatePrivilege`**, pa ga možete ulančati sa [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Ova imena posmatrajte kao **triage smernice**, a ne kao garantovane rezultate: zavise od **SKU-a/build-a**, a Microsoft može promeniti ponašanje između izdanja. Najvažnije je tražiti **nedostajuće DLL-ove u privilegovanim servisima koji prolaze kroz Machine PATH**, naročito ako se servis može **ponovo pokrenuti bez restartovanja računara**.

### Exploitation

Dakle, da bismo **eskalirali privilegije**, hijackovaćemo biblioteku **WptsExtensions.dll**. Pošto imamo **putanju** i **ime**, potrebno je samo da **generišemo malicious DLL**.

Možete [**pokušati da koristite neki od ovih primera**](#creating-and-compiling-dlls). Možete pokrenuti payload-e kao što su: dobavljanje rev shell-a, dodavanje korisnika, izvršavanje beacon-a...

> [!WARNING]
> Imajte na umu da se **ne pokreću svi servisi** sa **`NT AUTHORITY\SYSTEM`**; neki se pokreću i sa **`NT AUTHORITY\LOCAL SERVICE`**, koji ima **manje privilegija**, pa **nećete moći da kreirate novog korisnika** niti da zloupotrebite njegove dozvole.\
> Međutim, taj korisnik ima privilegiju **`seImpersonate`**, pa možete koristiti [ **potato suite za eskalaciju privilegija**](../roguepotato-and-printspoofer.md). Zato je u ovom slučaju rev shell bolja opcija od pokušaja kreiranja korisnika.

U trenutku pisanja ovog teksta, servis **Task Scheduler** radi sa **Nt AUTHORITY\SYSTEM**.

Nakon što ste **generisali malicious DLL** (_u mom slučaju koristio sam x64 rev shell i dobio shell nazad, ali ga je defender prekinuo zato što je poticao iz msfvenom-a_), sačuvajte ga u upisivi System Path sa imenom **WptsExtensions.dll** i **restartujte** računar (ili restartujte servis, odnosno uradite sve što je potrebno da ponovo pokrenete pogođeni servis/program).

Kada se servis ponovo pokrene, **DLL bi trebalo da bude učitan i izvršen** (možete **ponovo iskoristiti** trik sa **procmon** da proverite da li je **biblioteka učitana kao što je očekivano**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
