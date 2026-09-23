# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Ako možete da **pišete u direktorijum u sistemskom `PATH`-u** (ne samo u korisničkom `PATH`-u), možda ćete moći da **eskalirate privilegije** na sistemu.

Ovo se može zloupotrebiti putem **DLL hijacking-a** kada servis ili proces sa većim privilegijama pokuša da učita DLL koji ne postoji na ranijim lokacijama pretrage i na kraju pretraži upisiv direktorijum sistemskog `PATH`-a.

Upisiv unos u Machine `PATH` predstavlja samo **primitivu**, a ne dokaz izvršavanja koda. Kod nepakovane aplikacije koja koristi standardni redosled pretrage, `PATH` se proverava nakon redirekcije, API setova, SxS-a, liste učitanih modula, KnownDLLs-a, direktorijuma aplikacije i Windows-a, kao i trenutnog direktorijuma. Puna putanja ili pravila `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` mogu u potpunosti isključiti `PATH`.<sup>[[4]](#references)</sup>

Za više informacija o **DLL hijacking-u**, pogledajte:

{{#ref}}
./
{{#endref}}

## Privesc uz DLL Hijacking

### Pronalaženje DLL-a koji nedostaje

Prvo, **identifikujte proces** koji se izvršava sa **većim privilegijama** i pokušava da **učita DLL iz upisivog direktorijuma sistemskog `PATH`-a**.

Imajte na umu da ova tehnika zavisi od unosa u Machine/System PATH, a ne samo od vašeg **User PATH**-a. Zato, pre nego što potrošite vreme na Procmon, vredi izlistati unose u **Machine PATH**-u i proveriti koji su od njih upisivi:<sup>[[1]](#references)</sup>
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
ACL tekst može da bude obmanjujući jer članstvo u grupama, deny ACE-ovi i nasleđene dozvole utiču na rezultat. U okviru autorizovanog testa, create/delete probe proverava **efektivni pristup trenutnog tokena** (intruzivan je i može generisati upozorenja):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Potvrdite efektivni `PATH` cilja

Machine `PATH` pročitan iz registra predstavlja konfiguracione podatke; loader koristi environment block **target process**-a. Svaki proces poseduje environment block, a child obično nasleđuje kopiju environment-a svog parent-a. Zbog toga long-running service može zadržati stariju vrednost, a service pokrenut sa custom environment-om može da se razlikuje od vrednosti vidljive u vašem shell-u. Posmatrani Procmon probe tačnog direktorijuma od strane target PID-a tretirajte kao ground truth; nakon promene `PATH`-a u labu, restartujte relevantno process tree ili rebootujte sistem pre nego što zaključite da se lookup ne dešava.<sup>[[5]](#references)</sup>

Problem u ovim slučajevima jeste to što su ti procesi verovatno već pokrenuti. Da biste identifikovali DLLs koje services pokušavaju, ali ne uspevaju da učitaju, pokrenite Procmon što je ranije moguće (pre pokretanja procesa), a zatim:

> [!WARNING]
> Dodavanje user-writable direktorijuma u Machine `PATH` **stvara ranjivu situaciju**. Ovo radite samo u izolovanoj research VM kako biste otkrili koji privileged processes pristupaju `PATH`-u; na assessed host-u nadgledajte postojeći writable entry bez menjanja system configuration-a.<sup>[[1]](#references)</sup>

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
- Pokrenite **`procmon`** i idite na **`Options`** --> **`Enable boot logging`**, a zatim pritisnite **`OK`** u upitu.
- Zatim izvršite **reboot**. Kada se računar ponovo pokrene, **`procmon`** će odmah početi da **snima** događaje.
- Kada se **Windows** **pokrene, izvršite `procmon`** ponovo. Program će vas obavestiti da je radio i **pitati da li želite da sačuvate** događaje u datoteku. Izaberite **yes** i **sačuvajte događaje u datoteku**.
- **Nakon** što je **datoteka** **generisana**, zatvorite otvoreni prozor **`procmon`** i **otvorite datoteku sa događajima**.
- Dodajte sledeće **filtere** da biste pronašli sve DLL-ove koje je **proces pokušao da učita** iz foldera System Path sa dozvolom upisivanja:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** je potreban samo za servise koji se pokreću **previše rano** da bi se inače posmatrali. Ako možete da **pokrenete ciljni servis/program na zahtev** (na primer, interakcijom sa njegovim COM interfejsom, ponovnim pokretanjem servisa ili ponovnim pokretanjem zakazanog zadatka), obično je brže koristiti normalno Procmon snimanje sa filterima kao što su **`Path contains .dll`**, **`Result is NAME NOT FOUND`** i **`Path begins with <writable_machine_path>`**.

### Propušteni DLL-ovi

Prilikom pokretanja ovoga na besplatnoj **virtuelnoj (vmware) Windows 11 mašini** dobio sam sledeće rezultate:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju zanemarite rezultate za `.exe`. Probe za DLL-ove koji nedostaju potekle su od:

| Servis                         | Dll                | CMD linija                                                             |
| ------------------------------ | ------------------ | ---------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Sledeći primer koristi tehniku opisanu u ovom članku o [**zloupotrebi `WptsExtensions.dll` za eskalaciju privilegija**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Ostali kandidati vredni trijaže

`WptsExtensions.dll` je dobar primer, ali nije jedini phantom DLL koji se ponavlja u privilegovanim servisima. Savremena hunting pravila i javni katalozi za hijacking i dalje prate imena kao što su:<sup>[[2]](#references)</sup>

| Servis / scenario | DLL koji nedostaje | Napomene |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasičan **SYSTEM** kandidat na klijentskim sistemima. Dobar je kada se direktorijum sa dozvolom upisivanja nalazi u **Machine PATH**-u i servis traži DLL tokom pokretanja. |
| NetMan na Windows Serveru | `wlanhlp.dll` / `wlanapi.dll` | Zanimljivo na **serverskim izdanjima** zato što servis radi kao **SYSTEM** i u nekim buildovima ga **običan korisnik može pokrenuti na zahtev**, zbog čega je bolji od slučajeva koji zahtevaju samo reboot. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Obično prvo daje **`NT AUTHORITY\LOCAL SERVICE`**. To je često i dalje dovoljno zato što token ima **`SeImpersonatePrivilege`**, pa ga možete povezati sa [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Ova imena posmatrajte kao **smernice za trijažu**, a ne kao garantovane rezultate: zavise od **SKU-a/builda**, a Microsoft može promeniti ponašanje između izdanja. Važno je tražiti **DLL-ove koji nedostaju u privilegovanim servisima i prolaze kroz Machine PATH**, naročito ako servis može da se **ponovo pokrene bez reboot-a**.

### Proverite kandidata pre weaponization-a

Sam događaj `NAME NOT FOUND` nije dovoljan. Pre postavljanja payload-a proverite čitav lanac:<sup>[[1]](#references)[[4]](#references)</sup>

1. Događaj pripada očekivanom **PID-u, komandnoj liniji, servisnom nalogu i nivou integriteta**, a putanja koja nedostaje jeste tačan Machine `PATH` direktorijum sa dozvolom upisivanja.
2. Za isti DLL basename nijedan raniji direktorijum ne vraća `SUCCESS`, a modul nije obezbeđen listom učitanih modula, KnownDLLs, redirekcijom ili SxS manifestom.
3. Proba se ponavlja kada korisnik sa niskim privilegijama pokrene predviđeni trigger. Lookup koji se izvršava samo pri boot-u može da se koristi, ali je operativno mnogo lošiji od onog koji se izvršava na zahtev.
4. Arhitektura payload-a odgovara procesu. Ako aplikacija kasnije razrešava export-e, napravite proxy legitimnog DLL-a ili exportujte očekivane simbole; pogledajte [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Najpre koristite bezopasan canary DLL koji beleži PID, identitet i vremensku oznaku. U Procmon-u zahtevajte uspešan **`Load Image`** iz postavljene putanje, umesto da pretpostavite da je prethodna proba datoteke izazvala izvršavanje.

### Exploitation

Da biste **eskalirali privilegije**, hijackujte **`WptsExtensions.dll`**. Kada su **putanja** i **ime** poznati, generišite zlonamerni DLL.

Možete [**pokušati da koristite neki od ovih primera**](README.md#creating-and-compiling-dlls). Možete pokrenuti payload-e kao što su: dobavljanje rev shell-a, dodavanje korisnika, izvršavanje beacon-a...

> [!WARNING]
> Imajte na umu da **ne rade svi servisi** kao **`NT AUTHORITY\SYSTEM`**. Neki rade kao **`NT AUTHORITY\LOCAL SERVICE`**, koji ima **manje privilegija**, pa vam zloupotreba jednog od ovih servisa možda neće omogućiti kreiranje novog korisnika.\
> Međutim, ovaj nalog ima korisničko pravo **`SeImpersonatePrivilege`**, pa možete koristiti [**Potato suite za eskalaciju privilegija**](../roguepotato-and-printspoofer.md). U tom slučaju, reverse shell je bolja opcija od pokušaja kreiranja korisnika.

Servis **Task Scheduler** obično radi kao **`NT AUTHORITY\SYSTEM`**, ali proverite stvarno deployment okruženje i nemojte zaključivati identitet izvršavanja samo na osnovu imena servisa:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Pošto ste **kreirali maliciozni Dll** (_u mom slučaju koristio sam x64 rev shell i dobio shell nazad, ali ga je defender prekinuo jer je poticao iz msfvenom-a_), sačuvajte ga u writable System Path direktorijumu pod imenom **WptsExtensions.dll** i **restartujte** računar (ili restartujte service, odnosno uradite šta god je potrebno da ponovo pokrenete pogođeni service/program).

Kada se service ponovo pokrene, **DLL bi trebalo da bude učitan i izvršen** (možete **ponovo iskoristiti** trik sa **Procmon** alatom da proverite da li je **library učitan kako je očekivano**).

> [!NOTE]
> Planirajte cleanup pre pokretanja. Service može zadržati DLL mapiran i zaključati fajl sve dok se ne zaustavi; za `WptsExtensions.dll`, zaustavljanje Task Scheduler-a zahteva povišene privilegije. Nakon dobijanja željenog konteksta, bezbedno zaustavite cilj, uklonite payload i vratite sve lab-only `PATH` izmene.<sup>[[1]](#references)</sup>

### Remediation / detection

Uklonite slabe write dozvole iz svakog Machine `PATH` direktorijuma i uklonite zastarele unose. Developeri bi trebalo da učitavaju trusted libraries koristeći punu putanju ili da ograniče resolution pomoću `SetDefaultDllDirectories` / `LoadLibraryEx` search flagova. Defenders mogu povezati izmene Machine `PATH` promenljive sa privileged procesima koji učitavaju DLL-ove iz non-system, user-writable direktorijuma.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (Nadam se) razjašnjen](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Sumnjivi DLL učitan radi Persistence-a ili Privilege Escalation-a](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Redosled pretrage dynamic-link library-ja](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
