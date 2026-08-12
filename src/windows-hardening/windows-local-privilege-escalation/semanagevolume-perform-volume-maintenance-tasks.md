# SeManageVolumePrivilege: Matumizi mabaya ya maintenance ya volume na uthibitishaji wa raw-access

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Haki ya mtumiaji wa Windows: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Haki hii inaruhusu shughuli za maintenance ya volume kama vile defragmentation na kuunda au kuondoa volumes. Microsoft inaonya kwamba mwenye haki hii anaweza kuweza kuendeleza files hadi kwenye storage iliyo na data nyingine, kisha kusoma au kurekebisha bytes zilizopatikana.<sup>[[1]](#references)</sup>

Usilinganishe moja kwa moja kuwa na `SeManageVolumePrivilege` na uhakika wa kupata raw-disk access. Microsoft inaeleza kwamba kufungua physical disk au volume kupitia `CreateFile` kwa direct access kunahitaji administrative privileges, na ukaguzi wa kawaida wa object/device access bado hutumika. Kwenye build au product fulani, jaribu kama token, device ACL, requested access, share flags, na volume state zinaruhusu raw handle kabla ya kudai uwezo wa kusoma file lolote.<sup>[[3]](#references)</sup>

Default: Administrators kwenye servers na domain controllers.<sup>[[1]](#references)</sup>

## Abuse scenarios

- Ikiwa account inaweza kweli kupata readable raw-volume handle, parser inayojua NTFS inaweza kupita per-file ACLs na kurejesha files zilizolindwa au zilizofungwa kutoka kwenye allocated clusters.
- Malengo yanayowezekana yanajumuisha content iliyofungwa au kulindwa na ACL chini ya `C:\Windows\System32`, registry hives, DPAPI master keys, SAM, na—pale inapoweza kufikiwa kando kupitia snapshot au offline volume—`ntds.dit`.
- Kwenye certificate services hosts, maeneo muhimu ya software keys yanajumuisha `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` na `%ProgramData%\Microsoft\Crypto\Keys`; kurejesha file kuna manufaa tu wakati key material yake inaweza ku-exportiwa na pia inaweza ku-decryptiwa.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Kwenye AD CS host, CA private key iliyorejeshwa kwa mafanikio na ambayo ni **exportable/software-backed** inaweza kuwezesha Golden Certificate abuse. Miundo ya keys inayotumia hardware au isiyoweza ku-exportiwa hubadilisha njia hii.<sup>[[2]](#references)</sup>

Kumbuka: Bado unahitaji parser ya NTFS structures isipokuwa utegemee helper tools. Zana nyingi zinazopatikana tayari huficha maelezo ya raw access.

## Practical techniques

- Fungua raw volume handle na usome clusters:

<details>
<summary>Bofya ili kupanua</summary>
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

- Tumia zana inayofahamu NTFS kurejesha faili mahususi kutoka kwenye volume ghafi:
- RawCopy/RawCopy64 (kunakili faili zinazotumika kwa kiwango cha sectors)
- FTK Imager au The Sleuth Kit (imaging ya kusoma tu, kisha kuchonga faili)
- vssadmin/diskshadow + shadow copy, kisha nakili faili lengwa kutoka kwenye snapshot (ikiwa unaweza kuunda VSS; mara nyingi huhitaji admin, lakini kwa kawaida hupatikana kwa operators wale wale wenye SeManageVolumePrivilege)

Njia nyeti za kawaida za kulenga:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – kupitia shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys huhifadhiwa kwenye machine key store iliyo hapo juu)

## Muunganisho wa AD CS: Forging a Golden Certificate

Ikiwa unaweza kusoma private key ya Enterprise CA kutoka kwenye machine key store, unaweza kuunda client-auth certificates za principals yoyote na kufanya authentication kupitia PKINIT/Schannel. Hii mara nyingi huitwa Golden Certificate.<sup>[[2]](#references)</sup> Tazama:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sehemu: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Ugunduzi na hardening

- Punguza kwa kiasi kikubwa assignment ya SeManageVolumePrivilege (Perform volume maintenance tasks) na uwape trusted admins pekee.
- Fuatilia Sensitive Privilege Use na process handle opens kwa device objects kama \\.\C:, \\.\PhysicalDrive0.
- Pendelea CA keys zilizosanidiwa ipasavyo, zinazoungwa mkono na HSM au TPM na zisizoweza ku-exportiwa, ili faili iliyonakiliwa ya key-container isitoshe kurejesha private-key material inayoweza kutumika.
- Kwa application secrets zilizo nje ya CA-key path, DPAPI au DPAPI-NG inaweza kufanya faili ya data iliyonakiliwa isiwe ya kutosha kwa kuilinda kwa user, machine, group, au principal mwingine aliyeidhinishwa. Hii hailindi plaintext ambayo tayari inaweza kufikiwa na principal aliyecompromised.<sup>[[4]](#references)</sup>
- Weka uploads, temp, na extraction paths zikiwa non-executable na zimetenganishwa (web context defense ambayo mara nyingi huambatana na chain hii baada ya pentesting).

## References

- [1] [Microsoft – Tekeleza majukumu ya maintenance ya volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege iliyotumika kusoma CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` disks na volumes za physical](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation na DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
