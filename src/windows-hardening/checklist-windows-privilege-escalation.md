# Checklist - Upandishaji wa Haki za Mtumiaji wa Ndani wa Windows

{{#include ../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za kupandisha haki za mtumiaji wa ndani wa Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Taarifa za Mfumo](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pata [**taarifa za mfumo**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tafuta **kernel** [**exploits kwa kutumia scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Tumia **Google kutafuta** **exploits** za kernel
- [ ] Tumia **searchsploit kutafuta** **exploits** za kernel
- [ ] Kuna taarifa muhimu kwenye [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Kuna nywila kwenye [**historia ya PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Kuna taarifa muhimu kwenye [**mipangilio ya Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / matumizi mabaya ya IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Uchunguzi wa Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kagua mipangilio ya [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)na [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Kagua [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kagua kama [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)inafanya kazi
- [ ] [**Ulinzi wa LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credentials zilizo kwenye cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kagua kama kuna [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Sera ya AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Ulinzi wa Admin / upandishaji wa kimyakimya wa UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Uenezaji wa registry ya ufikivu kwenye Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Haki za Mtumiaji**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kagua [**haki za** mtumiaji **wa sasa**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Je, wewe ni [**mwanachama wa kikundi chochote chenye haki maalum**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kagua kama una [tokeni yoyote kati ya hizi zilizowezeshwa](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Kagua kama una [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ya kusoma volumes ghafi na kukwepa ACL za faili
- [ ] [**Vipindi vya Watumiaji**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kagua [**folda za nyumbani za watumiaji**](windows-local-privilege-escalation/index.html#home-folders) (ufikiaji?)
- [ ] Kagua [**Sera ya Nywila**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Kuna nini[ **ndani ya Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Kagua [**taarifa za mtandao** **za sasa**](windows-local-privilege-escalation/index.html#network)
- [ ] Kagua **huduma za ndani zilizofichwa** ambazo ufikiaji wake umewekewa mipaka kutoka nje

### [Processes Zinazoendeshwa](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Ruhusa za faili na folda**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) za binary za processes
- [ ] [**Uchimbaji wa Nywila kwenye Kumbukumbu**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Programu za GUI zisizo salama**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Je, unaweza kuiba credentials kwa kutumia **processes muhimu** kupitia `ProcDump.exe`? (firefox, chrome, n.k. ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Je, unaweza **kurekebisha service yoyote**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Je, unaweza **kurekebisha** **binary** ambayo **inatekelezwa** na **service** yoyote?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Je, unaweza **kurekebisha** **registry** ya **service** yoyote?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Je, unaweza kutumia fursa ya **path** ya binary ya **service isiyonukuliwa**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Vichochezi vya Service: orodhesha na uanzishe services zenye haki maalum](windows-local-privilege-escalation/service-triggers.md)

### [**Programu**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Ruhusa za kuandika** kwenye [**programu zilizosakinishwa**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Programu za Kuanzisha**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers** Zilizo Hatarini](windows-local-privilege-escalation/index.html#drivers)

### [Utekaji wa DLL](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Je, unaweza **kuandika kwenye folda yoyote iliyo ndani ya PATH**?
- [ ] Je, kuna binary yoyote ya service inayojulikana ambayo **inajaribu kupakia DLL isiyokuwepo**?
- [ ] Je, unaweza **kuandika** kwenye **folda yoyote ya binaries**?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Orodhesha mtandao (shares, interfaces, routes, neighbours, ...)
- [ ] Chunguza kwa makini services za mtandao zinazosikiliza kwenye localhost (127.0.0.1)

### [Credentials za Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credentials za [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Kuna credentials za [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) unazoweza kutumia?
- [ ] Kuna [**credentials za DPAPI**](windows-local-privilege-escalation/index.html#dpapi) muhimu?
- [ ] Nywila za [**mitandao ya Wifi**](windows-local-privilege-escalation/index.html#wifi) zilizohifadhiwa?
- [ ] Kuna taarifa muhimu kwenye [**miunganisho ya RDP iliyohifadhiwa**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Nywila kwenye [**amri zilizotekelezwa hivi karibuni**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Nywila za [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe ipo**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Faili na Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credentials**](windows-local-privilege-escalation/index.html#putty-creds) **na** [**funguo za host za SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Funguo za SSH kwenye registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Nywila kwenye [**faili za unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Kuna nakala rudufu yoyote ya [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Ikiwa [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ipo, jaribu kusoma volumes ghafi ili kupata `SAM`, `SYSTEM`, data ya DPAPI na `MachineKeys`
- [ ] [**Credentials za Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Kuna faili ya [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Nywila ya GPP iliyo kwenye cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Kuna nywila kwenye [**faili ya usanidi wa IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Kuna taarifa muhimu kwenye [**logs za** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Je, unataka [**kumwomba mtumiaji credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Kuna [**faili muhimu ndani ya Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Kuna [**registry nyingine yenye credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Kuna nini ndani ya [**data ya Browser**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historia, bookmarks, ...)?
- [ ] [**Utafutaji wa jumla wa nywila**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) kwenye faili na registry
- [ ] [**Zana**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za kutafuta nywila kiotomatiki

### [Handlers Zilizovuja](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Je, unaweza kufikia handler yoyote ya process inayoendeshwa na administrator?

### [Uigaji wa Mteja wa Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kagua kama unaweza kuitumia vibaya

## References

- [1] [Project Zero - Kukwepa Ulinzi wa Administrator kwa Kutumia UI Access Vibaya](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
