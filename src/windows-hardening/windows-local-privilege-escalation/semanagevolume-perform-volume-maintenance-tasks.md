# SeManageVolumePrivilege: accesso al volume raw per la lettura arbitraria di file

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Diritto utente Windows: Eseguire attività di manutenzione dei volumi (costante: SeManageVolumePrivilege).

I titolari possono eseguire operazioni low-level sui volumi, come la deframmentazione, la creazione/rimozione di volumi e operazioni di manutenzione IO. Per gli attaccanti, questo diritto consente soprattutto di aprire handle ai dispositivi dei volumi raw (ad esempio, \\.\C:) ed eseguire operazioni di I/O dirette sul disco che bypassano le ACL dei file NTFS. Con l'accesso raw è possibile copiare i byte di qualsiasi file presente sul volume anche se l'accesso è negato dalla DACL, analizzando offline le strutture del filesystem o utilizzando tool che leggono a livello di blocco/cluster.

Predefinito: Administrators su server e domain controller.<sup>[[1]](#references)</sup>

## Scenari di abuso

- Lettura arbitraria di file con bypass delle ACL tramite la lettura del dispositivo disco (ad esempio, esfiltrare materiale sensibile protetto dal sistema, come le chiavi private della macchina in %ProgramData%\Microsoft\Crypto\RSA\MachineKeys e %ProgramData%\Microsoft\Crypto\Keys, gli hive del registry, le masterkey DPAPI, SAM, ntds.dit tramite VSS, ecc.).
- Bypass dei percorsi bloccati o privilegiati (C:\Windows\System32\…) copiando direttamente i byte dal dispositivo raw.
- Negli ambienti AD CS, esfiltrare il materiale delle chiavi della CA (machine key store) per creare “Golden Certificates” e impersonare qualsiasi principal del dominio tramite PKINIT. Vedere il link qui sotto.<sup>[[2]](#references)</sup>

Nota: è comunque necessario un parser per le strutture NTFS, a meno che non si faccia affidamento su helper tool. Molti tool off-the-shelf astraggono l'accesso raw.

## Tecniche pratiche

- Aprire un handle a un volume raw e leggere i cluster:

<details>
<summary>Fai clic per espandere</summary>
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

- Usa uno strumento compatibile con NTFS per recuperare file specifici dal volume raw:
- RawCopy/RawCopy64 (copia a livello di settore di file in uso)
- FTK Imager o The Sleuth Kit (creazione di immagini in sola lettura, quindi carving dei file)
- vssadmin/diskshadow + shadow copy, quindi copia del file target dallo snapshot (se puoi creare VSS; spesso richiede privilegi amministrativi, ma generalmente è disponibile agli stessi operatori che dispongono di SeManageVolumePrivilege)

Percorsi sensibili tipici da prendere di mira:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (segreti locali)
- C:\Windows\NTDS\ntds.dit (domain controller – tramite shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificati/CRL della CA; le chiavi private risiedono nel machine key store indicato sopra)

## Integrazione con AD CS: Forging a Golden Certificate

Se puoi leggere la chiave privata della Enterprise CA dal machine key store, puoi creare certificati di autenticazione client per principal arbitrari e autenticarti tramite PKINIT/Schannel. Questa tecnica viene spesso indicata come Golden Certificate.<sup>[[2]](#references)</sup> Vedi:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sezione: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Rilevamento e hardening

- Limita fortemente l'assegnazione di SeManageVolumePrivilege (Perform volume maintenance tasks), concedendola solo ad amministratori di fiducia.
- Monitora Sensitive Privilege Use e l'apertura di handle di processo verso oggetti dispositivo come \\.\C:, \\.\PhysicalDrive0.
- Preferisci chiavi CA protette da HSM/TPM o DPAPI-NG, in modo che la lettura raw dei file non possa recuperare il materiale delle chiavi in una forma utilizzabile.
- Mantieni upload, percorsi temporanei e percorsi di estrazione non eseguibili e separati (una difesa del contesto web spesso associata a questa catena di post-exploitation).

## Riferimenti

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
