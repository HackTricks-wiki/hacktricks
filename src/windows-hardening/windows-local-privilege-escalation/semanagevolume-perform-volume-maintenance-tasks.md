# SeManageVolumePrivilege: abuso della manutenzione dei volumi e verifica dell'accesso raw

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Diritto utente di Windows: Eseguire attività di manutenzione dei volumi (costante: SeManageVolumePrivilege).

Il diritto autorizza operazioni di manutenzione dei volumi, come la deframmentazione e la creazione o rimozione di volumi. Microsoft avverte che chi lo detiene potrebbe riuscire a estendere i file nello spazio di archiviazione che contiene altri dati e quindi leggere o modificare i byte acquisiti.<sup>[[1]](#references)</sup>

Non equiparare il possesso di `SeManageVolumePrivilege` all'accesso garantito al disco raw. Microsoft documenta che l'apertura di un disco o volume fisico tramite `CreateFile` per l'accesso diretto richiede privilegi amministrativi e che continuano ad applicarsi i normali controlli di accesso agli oggetti e ai dispositivi. Su una specifica build o prodotto, verifica se il token, la ACL del dispositivo, l'accesso richiesto, i flag di condivisione e lo stato del volume consentono di ottenere un handle raw prima di affermare che sia possibile leggere arbitrariamente i file.<sup>[[3]](#references)</sup>

Impostazione predefinita: Administrators su server e controller di dominio.<sup>[[1]](#references)</sup>

## Scenari di abuso

- Se l'account riesce effettivamente a ottenere un handle leggibile del volume raw, un parser che supporta NTFS può aggirare le ACL per-file e recuperare file protetti o bloccati dai cluster allocati.
- Tra i possibili obiettivi ci sono contenuti bloccati o protetti da ACL in `C:\Windows\System32`, gli hive del registro, le chiavi master DPAPI, il SAM e, se accessibile separatamente tramite uno snapshot o un volume offline, `ntds.dit`.
- Sugli host dei servizi certificati, tra i percorsi utili per le chiavi software ci sono `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` e `%ProgramData%\Microsoft\Crypto\Keys`; recuperare un file è utile solo se il materiale della chiave è esportabile e può anche essere decrittato.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Su un host AD CS, una chiave privata CA **esportabile e basata su software** recuperata correttamente può consentire l'abuso di Golden Certificate. Le chiavi basate su hardware o non esportabili modificano questo percorso.<sup>[[2]](#references)</sup>
- Alcuni strumenti di manutenzione dei volumi usano `FSCTL_SD_GLOBAL_CHANGE` per sostituire le voci ACL del filesystem quando l'operazione è consentita. Questo modifica i controlli di accesso anziché leggere passivamente i blocchi raw, può interessare gran parte di un volume e deve essere verificato rispetto al token effettivo e al comportamento del dispositivo. Il [codice sorgente dello strumento](https://github.com/CsEnox/SeManageVolumeExploit) mostra questo specifico meccanismo; il solo possesso del privilegio non dimostra che l'operazione avrà successo.
- Ottenere accesso ai file modificando le ACL non decritta un file crittografato con EFS. Per ottenere il testo in chiaro è ancora necessaria una chiave privata corrispondente dell'utente o di ripristino. Analogamente, l'esportazione di una chiave CA basata su software con [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) dipende dal fatto che la chiave sia disponibile localmente, esportabile e accessibile.

Nota: serve comunque un parser per le strutture NTFS, a meno che non si usino strumenti ausiliari. Molti strumenti standard astraggono l'accesso raw.

## Tecniche pratiche

- Aprire un handle raw del volume e leggere i cluster:

<details>
<summary>Fai clic per espandere</summary>

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

- Usa uno strumento compatibile con NTFS per recuperare file specifici da un volume raw:
  - RawCopy/RawCopy64 (copia a livello di settore dei file in uso)
  - FTK Imager o The Sleuth Kit (creazione di un’immagine in sola lettura, poi carving dei file)
  - vssadmin/diskshadow + shadow copy, quindi copia del file di destinazione dallo snapshot (se puoi creare VSS; spesso richiede i privilegi di amministratore, ma è comunemente disponibile agli stessi operatori che dispongono di SeManageVolumePrivilege)

Percorsi sensibili tipici da controllare:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (segreti locali)
- C:\Windows\NTDS\ntds.dit (domain controller, tramite shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificati/CRL della CA; le chiavi private si trovano nel machine key store indicato sopra)

## Collegamento con AD CS: creazione di un Golden Certificate

Se riesci a leggere la chiave privata della Enterprise CA dal machine key store, puoi creare certificati di autenticazione client per principal arbitrari e autenticarti tramite PKINIT/Schannel. Questa tecnica è spesso chiamata Golden Certificate.<sup>[[2]](#references)</sup> Vedi:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sezione: “Creazione di certificati con certificati CA sottratti (Golden Certificate) – DPERSIST1”).

## Rilevamento e hardening

- Limita rigorosamente l’assegnazione di SeManageVolumePrivilege (Perform volume maintenance tasks) ai soli amministratori fidati.
- Monitora Sensitive Privilege Use e le aperture di handle di processo verso oggetti device come \\.\C:, \\.\PhysicalDrive0.
- Preferisci chiavi CA non esportabili, supportate da HSM o TPM e configurate correttamente, così che la copia di un file contenitore di chiavi non sia sufficiente per recuperare materiale di chiave privata utilizzabile.
- Per i segreti delle applicazioni al di fuori del percorso delle chiavi CA, DPAPI o DPAPI-NG possono rendere insufficiente la copia di un file di dati, proteggendolo per un utente, una macchina, un gruppo o un altro principal autorizzato. Questo non protegge i dati in chiaro già accessibili al principal compromesso.<sup>[[4]](#references)</sup>
- Mantieni le directory di upload, temporanee ed estrazione non eseguibili e separate (una difesa nel contesto web che spesso si affianca a questa catena post-exploitation).

## References

- [1] [Microsoft – Esegui attività di manutenzione dei volumi (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege usato per leggere la chiave CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` per dischi e volumi fisici](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - API di crittografia: Next Generation e DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
