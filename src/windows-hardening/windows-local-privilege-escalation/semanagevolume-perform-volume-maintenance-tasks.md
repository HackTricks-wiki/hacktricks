# SeManageVolumePrivilege: Accesso raw al volume per lettura arbitraria di file

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Privilegio utente di Windows: Perform volume maintenance tasks (costante: SeManageVolumePrivilege).

I titolari possono eseguire operazioni a basso livello sul volume come deframmentazione, creare/rimuovere volumi e IO di manutenzione. Importante per un attaccante, questo diritto permette di aprire handle su dispositivi volume raw (es., \\.\C:) e inviare I/O diretti su disco che bypassano le ACL dei file NTFS. Con l'accesso raw puoi copiare i byte di qualsiasi file sul volume anche se negato dalla DACL, parsando le strutture del filesystem offline o sfruttando tool che leggono a livello di blocco/cluster.

Predefinito: Administrators su server e domain controller.

## Scenari di abuso

- Lettura arbitraria di file bypassando le ACL leggendo il dispositivo disco (es., exfiltrate materiale sensibile protetto di sistema come le chiavi private macchina sotto %ProgramData%\Microsoft\Crypto\RSA\MachineKeys e %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, ecc.).
- Bypassare percorsi bloccati/privilegiati (C:\Windows\System32\…) copiando i byte direttamente dal dispositivo raw.
- In ambienti AD CS, exfiltrate il materiale chiave della CA (machine key store) per coniare “Golden Certificates” e impersonare qualsiasi principal di dominio via PKINIT. Vedi il link sotto.

Nota: Hai ancora bisogno di un parser per le strutture NTFS a meno che non ti affidi a tool di supporto. Molti strumenti off-the-shelf astraggono l'accesso raw.

## Tecniche pratiche

- Aprire un handle raw del volume e leggere cluster:

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

- Usa uno strumento compatibile con NTFS per recuperare file specifici da un volume grezzo:
- RawCopy/RawCopy64 (copia a livello di settore di file in uso)
- FTK Imager or The Sleuth Kit (imaging in sola lettura, poi carving/estrazione dei file)
- vssadmin/diskshadow + shadow copy, quindi copiare il file target dallo snapshot (se puoi creare VSS; spesso richiede privilegi amministrativi ma è comunemente disponibile agli stessi operatori che possiedono SeManageVolumePrivilege)

Percorsi sensibili tipici da prendere di mira:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Se riesci a leggere la chiave privata della Enterprise CA dall'archivio chiavi della macchina, puoi forgiare certificati client‑auth per soggetti arbitrari e autenticarti tramite PKINIT/Schannel. Questo è spesso chiamato Golden Certificate. Vedi:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sezione: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Rilevamento e hardening

- Limitare fortemente l'assegnazione di SeManageVolumePrivilege (Perform volume maintenance tasks) solo agli amministratori di fiducia.
- Monitorare Sensitive Privilege Use e le aperture di handle di processo su oggetti dispositivo come \\.\C:, \\.\PhysicalDrive0.
- Preferire chiavi CA protette da HSM/TPM o DPAPI-NG in modo che letture raw dei file non possano recuperare materiale della chiave in forma utilizzabile.
- Mantenere i percorsi di upload, temp ed estrazione non eseguibili e separati (difesa nel contesto web che spesso si accompagna a questa catena post‑exploitation).

## Riferimenti

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
