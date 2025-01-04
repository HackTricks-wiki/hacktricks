# Orodha - Kuinua Haki za Windows za Mitaa

{{#include ../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za kuinua haki za Windows za ndani:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Taarifa za Mfumo](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pata [**Taarifa za mfumo**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tafuta **kernel** [**exploits kwa kutumia scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Tumia **Google kutafuta** **exploits** za kernel
- [ ] Tumia **searchsploit kutafuta** **exploits** za kernel
- [ ] Taarifa za kuvutia katika [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Nywila katika [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Taarifa za kuvutia katika [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Kuhesabu/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Angalia [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)na [**WEF** ](windows-local-privilege-escalation/index.html#wef)settings
- [ ] Angalia [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Angalia kama [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)iko hai
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Angalia kama kuna [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Angalia [**haki za**] **mtumiaji wa sasa** (windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Je, wewe ni [**mwanachama wa kikundi chochote chenye haki**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Angalia kama una [mifumo hii ya tokens iliyoanzishwa](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sessions za Watumiaji**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Angalia [**nyumba za watumiaji**](windows-local-privilege-escalation/index.html#home-folders) (ufikiaji?)
- [ ] Angalia [**Sera ya Nywila**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Nini kiko [**ndani ya Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Angalia **taarifa za sasa za** [**mtandao**](windows-local-privilege-escalation/index.html#network)
- [ ] Angalia **huduma za ndani zilizofichwa** zilizozuiliwa kwa nje

### [Mchakato unaoendelea](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Mchakato wa binaries [**file na ruhusa za folda**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Kuchimba nywila za kumbukumbu**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Programu za GUI zisizo salama**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Pora nywila na **michakato ya kuvutia** kupitia `ProcDump.exe` ? (firefox, chrome, nk ...)

### [Huduma](windows-local-privilege-escalation/index.html#services)

- [ ] [Je, unaweza **kubadilisha huduma yoyote**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Je, unaweza **kubadilisha** **binary** inayotekelezwa na **huduma yoyote**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Je, unaweza **kubadilisha** **registry** ya **huduma yoyote**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Je, unaweza kunufaika na **path** ya **binary** ya **huduma isiyo na quote**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Programu**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Andika** [**ruhusa kwenye programu zilizowekwa**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Programu za Kuanzisha**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Wasiwasi** [**Madereva**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Je, unaweza **kuandika katika folda yoyote ndani ya PATH**?
- [ ] Je, kuna binary ya huduma inayojulikana ambayo **inajaribu kupakia DLL isiyokuwepo**?
- [ ] Je, unaweza **kuandika** katika **folda za binaries**?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Hesabu mtandao (shares, interfaces, routes, neighbours, ...)
- [ ] Angalia kwa makini huduma za mtandao zinazokisikiliza kwenye localhost (127.0.0.1)

### [Nywila za Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)nywila
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) nywila ambazo unaweza kutumia?
- [ ] Taarifa za kuvutia [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Nywila za mitandao ya [**Wifi zilizohifadhiwa**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Taarifa za kuvutia katika [**RDP Connections zilizohifadhiwa**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Nywila katika [**amri zilizokimbizwa hivi karibuni**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Meneja wa Nywila za Desktop ya KijRemote**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) nywila?
- [ ] [**AppCmd.exe** ipo](windows-local-privilege-escalation/index.html#appcmd-exe)? Nywila?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Faili na Registry (Nywila)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **na** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys katika registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Nywila katika [**faili zisizokuwa na mtu**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Backup yoyote ya [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) faili?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Nywila katika [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Taarifa za kuvutia katika [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Je, unataka [**kuomba nywila**](windows-local-privilege-escalation/index.html#ask-for-credentials) kwa mtumiaji?
- [ ] Taarifa za kuvutia [**ndani ya Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Registry nyingine [**ikiwemo nywila**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Ndani ya [**data za kivinjari**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historia, alama, ...)?
- [ ] [**Utafutaji wa nywila wa jumla**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) katika faili na registry
- [ ] [**Zana**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za kutafuta nywila kiotomatiki

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Je, una ufikiaji wa handler yoyote ya mchakato unaoendeshwa na msimamizi?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Angalia kama unaweza kuitumia

{{#include ../banners/hacktricks-training.md}}
