# SeManageVolumePrivilege: abuso della manutenzione dei volumi e verifica dell'accesso raw

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Diritti utente di Windows: eseguire attività di manutenzione dei volumi (costante: SeManageVolumePrivilege).

Questo diritto autorizza operazioni di manutenzione dei volumi, come la deframmentazione e la creazione o rimozione di volumi. Microsoft avverte che chi possiede questo diritto potrebbe essere in grado di estendere i file nello spazio di archiviazione contenente altri dati e quindi leggere o modificare i byte acquisiti.<sup>[[1]](#references)</sup>

Non bisogna considerare il possesso di `SeManageVolumePrivilege` come una garanzia di accesso raw al disco. Microsoft documenta che l'apertura di un disco fisico o di un volume tramite `CreateFile` per l'accesso diretto richiede privilegi amministrativi e che continuano ad applicarsi i normali controlli di accesso agli oggetti e ai dispositivi. Su una specifica build o prodotto, verificare se il token, l'ACL del dispositivo, l'accesso richiesto, i flag di condivisione e lo stato del volume consentono di ottenere un handle raw prima di affermare la possibilità di leggere arbitrariamente i file.<sup>[[3]](#references)</sup>

Predefinito: Administrators su server e domain controller.<sup>[[1]](#references)</sup>

## Scenari di abuso

- Se l'account riesce effettivamente a ottenere un handle leggibile del volume raw, un parser consapevole di NTFS può aggirare le ACL dei singoli file e recuperare file protetti o bloccati dai cluster allocati.
- I possibili obiettivi includono contenuti bloccati o protetti da ACL in `C:\Windows\System32`, gli hive del registro, le chiavi master DPAPI, il SAM e, quando è accessibile separatamente tramite uno snapshot o un volume offline, `ntds.dit`.
- Sugli host con certificate services, le posizioni utili delle chiavi software includono `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` e `%ProgramData%\Microsoft\Crypto\Keys`; recuperare un file è utile solo quando il relativo materiale della chiave è esportabile e può anche essere decrittografato.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Su un host AD CS, una chiave privata CA **esportabile/supportata da software** recuperata correttamente può consentire l'abuso di Golden Certificate. I design con chiavi supportate da hardware o non esportabili modificano questo percorso.<sup>[[2]](#references)</sup>

Nota: è comunque necessario un parser per le strutture NTFS, a meno di affidarsi a tool di supporto. Molti tool disponibili sul mercato astraggono l'accesso raw.

## Tecniche pratiche

- Aprire un handle raw del volume e leggere i cluster:

<details>
<summary>Fare clic per espandere</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
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
- RawCopy/RawCopy64 (copia a livello di settore dei file in uso)
- FTK Imager o The Sleuth Kit (acquisizione in sola lettura, quindi file carving)
- vssadmin/diskshadow + shadow copy, quindi copia del file target dallo snapshot (se puoi creare VSS; spesso richiede privilegi amministrativi, ma comunemente è disponibile per gli stessi operatori che possiedono SeManageVolumePrivilege)

Percorsi sensibili tipici da prendere di mira:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (segreti locali)
- C:\Windows\NTDS\ntds.dit (domain controller – tramite shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificati/CRL della CA; le chiavi private si trovano nel machine key store indicato sopra)

## Collegamento con AD CS: Forging a Golden Certificate

Se puoi leggere la chiave privata della Enterprise CA dal machine key store, puoi forgiare certificati per l'autenticazione client per principal arbitrari e autenticarti tramite PKINIT/Schannel. Questo viene spesso definito Golden Certificate.<sup>[[2]](#references)</sup> Vedi:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sezione: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Rilevamento e hardening

- Limita rigorosamente l'assegnazione di SeManageVolumePrivilege (Perform volume maintenance tasks) ai soli amministratori fidati.
- Monitora Sensitive Privilege Use e le aperture di handle dei processi verso oggetti dispositivo come \\.\C:, \\.\PhysicalDrive0.
- Preferisci chiavi CA non esportabili, correttamente configurate e protette da HSM o TPM, in modo che la copia di un file contenitore della chiave non sia sufficiente a recuperare materiale di chiave privata utilizzabile.
- Per i segreti applicativi al di fuori del percorso della chiave CA, DPAPI o DPAPI-NG possono rendere insufficiente la copia di un file di dati, proteggendolo tramite un utente, una macchina, un gruppo o un altro principal autorizzato. Questo non protegge il plaintext già accessibile al principal compromesso.<sup>[[4]](#references)</sup>
- Mantieni i percorsi di upload, temporanei ed estrazione non eseguibili e separati (una difesa del contesto web che spesso si abbina a questa catena post‑exploitation).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
