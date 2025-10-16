# SeManageVolumePrivilege: Accesso raw al volume per lettura arbitraria di file

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Privilegio utente Windows: Perform volume maintenance tasks (costante: SeManageVolumePrivilege).

I possessori possono eseguire operazioni a basso livello sul volume come deframmentazione, creazione/rimozione di volumi e I/O di manutenzione. Criticamente per gli attaccanti, questo privilegio permette di aprire handle di dispositivo del volume raw (e.g., \\.\C:) e inviare I/O diretto al disco che bypassa le ACL di file NTFS. Con l'accesso raw puoi copiare i byte di qualunque file sul volume anche se negato dalla DACL, analizzando offline le strutture del filesystem o sfruttando tool che leggono a livello di blocco/cluster.

Predefinito: Amministratori su server e domain controller.

## Scenari di abuso

- Lettura arbitraria di file bypassando le ACL leggendo il dispositivo disco (e.g., esfiltrare materiale sensibile protetto di sistema come chiavi private macchina sotto %ProgramData%\Microsoft\Crypto\RSA\MachineKeys e %ProgramData%\Microsoft\Crypto\Keys, hive del registro, masterkey DPAPI, SAM, ntds.dit via VSS, ecc.).
- Bypassare percorsi bloccati/privilegiati (C:\Windows\System32\…) copiando byte direttamente dal dispositivo raw.
- Negli ambienti AD CS, esfiltrare il materiale chiave della CA (machine key store) per creare “Golden Certificates” e impersonare qualsiasi principal di dominio via PKINIT. Vedi il link sotto.

Nota: Serve comunque un parser per le strutture NTFS a meno che non ci si affidi a tool di supporto. Molti strumenti off-the-shelf astraono l'accesso raw.

## Tecniche pratiche

- Aprire un handle del volume raw e leggere cluster:

<details>
<summary>Clicca per espandere</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- Usa uno strumento NTFS-aware per recuperare file specifici dal raw volume:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, poi copia il file target dallo snapshot (se puoi creare VSS; spesso richiede admin ma comunemente disponibile agli stessi operatori che detengono SeManageVolumePrivilege)

Percorsi sensibili tipici da prendere di mira:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Se puoi leggere la chiave privata della Enterprise CA dal machine key store, puoi forgiare client‑auth certificates per arbitrary principals e autenticarti via PKINIT/Schannel. Questo è spesso referred to as a Golden Certificate. Vedi:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sezione: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Rilevamento e hardening

- Limitare fortemente l'assegnazione di SeManageVolumePrivilege (Perform volume maintenance tasks) solo ad admin di fiducia.
- Monitorare Sensitive Privilege Use e le aperture di handle di processo verso oggetti device come \\.\C:, \\.\PhysicalDrive0.
- Preferire chiavi CA protette da HSM/TPM o DPAPI-NG in modo che raw file reads non possano recuperare materiale chiave in forma utilizzabile.
- Mantenere percorsi di upload, temp ed estrazione non eseguibili e separati (difesa nel contesto web che spesso si abbina a questa chain post‑exploitation).

## Riferimenti

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
