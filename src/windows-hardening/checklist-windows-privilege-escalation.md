# Kontrol Listesi - Yerel Windows Yetki Yükseltme

{{#include ../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Sistem Bilgileri](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**Sistem bilgilerini**](windows-local-privilege-escalation/index.html#system-info) edinin
- [ ] **Kernel** [**exploitlerini scriptlerle**](windows-local-privilege-escalation/index.html#version-exploits) arayın
- [ ] Kernel **exploitlerini aramak için Google'ı kullanın**
- [ ] Kernel **exploitlerini aramak için searchsploit kullanın**
- [ ] [**Env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgiler var mı?
- [ ] [**PowerShell geçmişinde**](windows-local-privilege-escalation/index.html#powershell-history) parolalar var mı?
- [ ] [**İnternet ayarlarında**](windows-local-privilege-escalation/index.html#internet-settings) ilginç bilgiler var mı?
- [ ] [**Sürücüler**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Üçüncü taraf agent otomatik güncelleyicileri / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV numaralandırması](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)ve [**WEF** ](windows-local-privilege-escalation/index.html#wef)ayarlarını kontrol edin
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) olup olmadığını kontrol edin
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktif mi kontrol edin
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Önbelleğe alınmış kimlik bilgileri**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) olup olmadığını kontrol edin
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess sessiz yükseltme**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop erişilebilirlik kayıt defteri yayılımı (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Kullanıcı ayrıcalıkları**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**Mevcut** kullanıcının **ayrıcalıklarını**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol edin
- [ ] [**Ayrıcalıklı bir grubun üyesi misiniz**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] **Devre dışı** olarak gösterilseler bile [bu ayrıcalıkların mevcut token'da bulunup bulunmadığını](windows-local-privilege-escalation/access-tokens.md) kontrol edin: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Devre dışı bir ayrıcalık yalnızca token'da zaten bulunuyorsa etkinleştirilebilir.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Bir birim bakım hakkı olan [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks) ayrıcalığını kontrol edin. Tek başına ham birim okuma erişimi sağlamaz; disk veya birim açmak için ayrıca erişim izinleri gerekir.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Kullanıcı oturumları**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**Kullanıcı ana dizinlerini**](windows-local-privilege-escalation/index.html#home-folders) kontrol edin (erişim?)
- [ ] [**Parola politikasını**](windows-local-privilege-escalation/index.html#password-policy) kontrol edin
- [ ] [**Panonun içinde**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ne var?

### [Ağ](windows-local-privilege-escalation/index.html#network)

- [ ] **Mevcut** [**ağ** **bilgilerini**](windows-local-privilege-escalation/index.html#network) kontrol edin
- [ ] Dış erişime kapalı **gizli yerel servisleri** kontrol edin

### [Çalışan İşlemler](windows-local-privilege-escalation/index.html#running-processes)

- [ ] İşlem binary'lerinin [**dosya ve klasör izinlerini**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) kontrol edin
- [ ] [**Bellekten parola madenciliği**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Güvenli olmayan GUI uygulamaları**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` aracılığıyla **ilginç işlemlerden** kimlik bilgilerini çalın (firefox, chrome vb.)?

### [Servisler](windows-local-privilege-escalation/index.html#services)

- [ ] [Herhangi bir **servisi değiştirebilir misiniz**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Herhangi bir **servisin** çalıştırdığı **binary'yi değiştirebilir misiniz**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Herhangi bir **servisin** **kayıt defteri** girdisini değiştirebilir misiniz?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Tırnak içine alınmamış herhangi bir **servis binary** **yolundan** yararlanabilir misiniz?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Servis Tetikleyicileri: ayrıcalıklı servisleri numaralandırma ve tetikleme](windows-local-privilege-escalation/service-triggers.md)

### [**Uygulamalar**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Yüklü uygulamalarda** [**yazma izinleri**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Başlangıç uygulamaları**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Güvenlik açığı bulunan** [**sürücüler**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH içindeki herhangi bir klasöre **yazabilir misiniz**?
- [ ] Mevcut olmayan bir DLL'yi **yüklemeye çalışan** bilinen bir servis binary'si var mı?
- [ ] Herhangi bir **binary klasörüne** **yazabilir misiniz**?

### [Ağ](windows-local-privilege-escalation/index.html#network)

- [ ] Ağı numaralandırın (paylaşımlar, arayüzler, rotalar, komşular, ...)
- [ ] Localhost'ta (127.0.0.1) dinleyen ağ servislerini özellikle inceleyin

### [Windows Kimlik Bilgileri](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)kimlik bilgileri
- [ ] Kullanabileceğiniz [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kimlik bilgileri var mı?
- [ ] İlginç [**DPAPI kimlik bilgileri**](windows-local-privilege-escalation/index.html#dpapi) var mı?
- [ ] Kayıtlı [**Wifi ağlarının**](windows-local-privilege-escalation/index.html#wifi) parolaları?
- [ ] [**Kaydedilmiş RDP bağlantılarında**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ilginç bilgiler var mı?
- [ ] [**Yakın zamanda çalıştırılan komutlarda**](windows-local-privilege-escalation/index.html#recently-run-commands) parolalar var mı?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) parolaları?
- [ ] [**AppCmd.exe mevcut mu**](windows-local-privilege-escalation/index.html#appcmd-exe)? Kimlik bilgileri?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) mevcut mu? DLL Side Loading?

### [Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Kimlik bilgileri**](windows-local-privilege-escalation/index.html#putty-creds) **ve** [**SSH host key'leri**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Kayıt defterindeki SSH key'leri**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**Katılımsız kurulum dosyalarında**](windows-local-privilege-escalation/index.html#unattended-files) parolalar var mı?
- [ ] Herhangi bir [**SAM ve SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) yedeği var mı?
- [ ] Okunabilir ham birim handle'ına erişim ayrıca izinliyse `SAM`, `SYSTEM`, DPAPI materyali ve `MachineKeys` öğelerinin açığa çıkma olasılığını değerlendirin; bu erişimin **SeManageVolumePrivilege** ayrıcalığından kaynaklandığını varsaymayın.<sup>[[5]](#references)</sup>
- [ ] [**Cloud kimlik bilgileri**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) dosyası?
- [ ] [**Önbelleğe alınmış GPP parolası**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web yapılandırma dosyasında**](windows-local-privilege-escalation/index.html#iis-web-config) parola var mı?
- [ ] [**Web** **loglarında**](windows-local-privilege-escalation/index.html#logs) ilginç bilgiler var mı?
- [ ] Kullanıcıdan [**kimlik bilgilerini istemek**](windows-local-privilege-escalation/index.html#ask-for-credentials) ister misiniz?
- [ ] [**Geri Dönüşüm Kutusu'ndaki**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) ilginç dosyalar?
- [ ] Kimlik bilgileri içeren başka [**kayıt defteri**](windows-local-privilege-escalation/index.html#inside-the-registry) girdileri var mı?
- [ ] [**Tarayıcı verilerinde**](windows-local-privilege-escalation/index.html#browsers-history) (veritabanları, geçmiş, yer imleri, ...) neler var?
- [ ] Dosyalarda ve kayıt defterinde [**genel parola araması**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] Parolaları otomatik olarak aramak için [**araçlar**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Yönetici tarafından çalıştırılan bir işlemin herhangi bir handler'ına erişiminiz var mı?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kötüye kullanıp kullanamayacağınızı kontrol edin



## References

- [1] [Project Zero - UI Access'i kötüye kullanarak Administrator Protection'ı atlatma](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Ayrıcalıklar](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Token'daki ayrıcalıkları değiştirme](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - Fiziksel diskler ve birimler için CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Dosya sisteminde ayrıcalıkları yönetme](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
