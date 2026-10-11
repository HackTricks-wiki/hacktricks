# SeManageVolumePrivilege: Matumizi mabaya ya matengenezo ya volume na uthibitishaji wa ufikiaji wa raw

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Haki ya mtumiaji ya Windows: Kutekeleza kazi za matengenezo ya volume (constant: SeManageVolumePrivilege).

Haki hii huruhusu shughuli za matengenezo ya volume kama vile kufanya defragmentation na kuunda au kuondoa volumes. Microsoft inaonya kwamba mwenye haki hii anaweza kupanua faili hadi kwenye hifadhi iliyo na data nyingine, kisha kusoma au kurekebisha byte alizopata.<sup>[[1]](#references)</sup>

Usidhani kwamba kuwa na `SeManageVolumePrivilege` kunamaanisha kuwa na ufikiaji wa raw-disk bila kizuizi. Microsoft inaeleza kwamba kufungua diski halisi au volume kupitia `CreateFile` kwa ufikiaji wa moja kwa moja kunahitaji ruhusa za msimamizi, na ukaguzi wa kawaida wa ufikiaji wa object/device bado hutumika. Kwenye build au bidhaa husika, jaribu ikiwa token, device ACL, ufikiaji ulioombwa, share flags na hali ya volume zinaruhusu kupata raw handle kabla ya kudai kwamba unaweza kusoma faili yoyote.<sup>[[3]](#references)</sup>

Chaguomsingi: Wasimamizi kwenye servers na domain controllers.<sup>[[1]](#references)</sup>

## Matukio ya matumizi mabaya

- Ikiwa akaunti inaweza kupata raw-volume handle inayosomeka, parser inayotambua NTFS inaweza kukwepa ACL za kila faili na kurejesha faili zilizolindwa au zilizofungwa kutoka kwenye clusters zilizotengewa nafasi.
- Malengo yanayowezekana ni pamoja na maudhui yaliyofungwa au yanayolindwa na ACL chini ya `C:\Windows\System32`, registry hives, funguo kuu za DPAPI, SAM, na—ikiwa inaweza kufikiwa kando kupitia snapshot au volume isiyo mtandaoni—`ntds.dit`.
- Kwenye hosts za huduma za vyeti, maeneo muhimu ya funguo za software ni `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` na `%ProgramData%\Microsoft\Crypto\Keys`; kurejesha faili kuna manufaa tu ikiwa key material yake inaweza kuhamishwa na pia inaweza kusimbuliwa.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Kwenye host ya AD CS, kurejesha kwa mafanikio ufunguo binafsi wa CA **unaoweza kuhamishwa/unaotegemea software** kunaweza kuwezesha matumizi mabaya ya Golden Certificate. Miundo ya funguo inayotegemea hardware au isiyoweza kuhamishwa hubadilisha njia hii.<sup>[[2]](#references)</sup>
- Baadhi ya zana za matengenezo ya volume hutumia `FSCTL_SD_GLOBAL_CHANGE` kubadilisha maingizo ya ACL za filesystem pale operesheni hiyo inaporuhusiwa. Hii hubadilisha vidhibiti vya ufikiaji badala ya kusoma raw blocks bila kubadilisha chochote, inaweza kuathiri sehemu kubwa ya volume, na lazima ithibitishwe kwa kutumia token na tabia halisi ya kifaa. [Msimbo wa chanzo wa tool](https://github.com/CsEnox/SeManageVolumeExploit) unaonyesha utaratibu huu mahususi; kuwa na haki hii pekee hakuthibitishi kwamba utafanikiwa.
- Kupata ufikiaji wa faili kupitia mabadiliko ya ACL hakusimbui faili iliyosimbwa kwa EFS. Ili kupata maandishi yasiyosimbwa, bado unahitaji ufunguo binafsi unaolingana wa mtumiaji au wa kurejesha. Vivyo hivyo, kuhamisha ufunguo wa CA unaotegemea software kwa kutumia [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) kunategemea ufunguo huo kupatikana kwenye mfumo wa ndani, kuweza kuhamishwa, na kufikiwa.

Kumbuka: Bado unahitaji parser ya miundo ya NTFS isipokuwa utumie zana saidizi. Zana nyingi zinazopatikana tayari huficha ugumu wa ufikiaji wa raw.

## Mbinu za vitendo

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

- Tumia zana inayotambua NTFS ili kurejesha faili mahususi kutoka kwenye volume ghafi:
  - RawCopy/RawCopy64 (nakala ya kiwango cha sekta ya faili zinazotumika)
  - FTK Imager au The Sleuth Kit (utengenezaji wa image ya kusoma pekee, kisha uchimbuaji wa faili)
  - vssadmin/diskshadow + shadow copy, kisha nakili faili lengwa kutoka kwenye snapshot (ikiwa unaweza kuunda VSS; mara nyingi huhitaji admin, lakini kwa kawaida hupatikana kwa operators wale wale wenye SeManageVolumePrivilege)

Njia nyeti za kawaida za kulenga:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (siri za ndani)
- C:\Windows\NTDS\ntds.dit (domain controllers – kupitia shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (vyeti/CRLs za CA; private keys huhifadhiwa kwenye machine key store iliyo hapo juu)

## Uhusiano wa AD CS: Forging a Golden Certificate

Ukiweza kusoma private key ya Enterprise CA kutoka kwenye machine key store, unaweza kughushi vyeti vya client-auth kwa principals wowote na kuthibitisha utambulisho kupitia PKINIT/Schannel. Hii mara nyingi huitwa Golden Certificate.<sup>[[2]](#references)</sup> Tazama:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sehemu: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Ugunduzi na uimarishaji wa usalama

- Weka mipaka mikali kwa ugawaji wa SeManageVolumePrivilege (Perform volume maintenance tasks), na uwape admins wanaoaminika pekee.
- Fuatilia Sensitive Privilege Use na michakato inayofungua handles za device objects kama \\.\C:, \\.\PhysicalDrive0.
- Pendelea CA keys zisizoweza kuhamishwa, zinazotumia HSM au TPM, na zilizosanidiwa ipasavyo ili kunakili faili ya key-container pekee kusitoshe kurejesha nyenzo za private key zinazoweza kutumika.
- Kwa application secrets zilizo nje ya njia ya CA-key, DPAPI au DPAPI-NG zinaweza kufanya faili ya data iliyonakiliwa isitoshe kwa kuilinda kwa user, machine, group, au principal mwingine aliyeidhinishwa. Hii hailindi plaintext ambayo tayari inaweza kufikiwa na principal aliyeathiriwa.<sup>[[4]](#references)</sup>
- Hakikisha njia za uploads, temp, na extraction haziwezi kutekeleza faili na zimetenganishwa (ulinzi wa web context ambao mara nyingi huenda pamoja na mnyororo huu wa post‑exploitation).

## References

- [1] [Microsoft – Tekeleza kazi za matengenezo ya volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege imetumika kusoma CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` kwa physical disks na volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation na DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
