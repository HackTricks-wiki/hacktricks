# Kontrol Listesi - Yerel Windows Yetki Yükseltme

{{#include ../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Sistem Bilgileri](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**Sistem bilgilerini**](windows-local-privilege-escalation/index.html#system-info) edinin
- [ ] **Kernel** [**exploit'lerini script'lerle**](windows-local-privilege-escalation/index.html#version-exploits) arayın
- [ ] Kernel **exploit'lerini aramak için Google'ı** kullanın
- [ ] Kernel **exploit'lerini aramak için searchsploit'i** kullanın
- [ ] [**Ortam değişkenlerinde**](windows-local-privilege-escalation/index.html#environment) ilginç bilgiler var mı?
- [ ] [**PowerShell geçmişinde**](windows-local-privilege-escalation/index.html#powershell-history) parolalar var mı?
- [ ] [**Internet ayarlarında**](windows-local-privilege-escalation/index.html#internet-settings) ilginç bilgiler var mı?
- [ ] [**Sürücüler**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit'i**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Üçüncü taraf agent otomatik güncelleyicilerini / IPC kötüye kullanımını**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Günlükleme/AV sayımı](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) ve [**WEF**](windows-local-privilege-escalation/index.html#wef) ayarlarını kontrol edin
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) durumunu kontrol edin
- [ ] [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) etkin mi kontrol edin
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Önbelleğe alınmış kimlik bilgileri**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) olup olmadığını kontrol edin
- [ ] [**AppLocker ilkesi**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Yönetici koruması / UIAccess sessiz yükseltme**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop erişilebilirlik kayıt defteri yayılımı (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Kullanıcı ayrıcalıkları**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**Mevcut** kullanıcının **ayrıcalıklarını**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol edin
- [ ] [**Ayrıcalıklı bir grubun üyesi**](windows-local-privilege-escalation/index.html#privileged-groups) misiniz?
- [ ] Şu belirteçlerden [herhangi birinin etkin olup olmadığını](windows-local-privilege-escalation/index.html#token-manipulation) kontrol edin: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Ham birimleri okumak ve dosya ACL'lerini atlatmak için [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ayrıcalığınız olup olmadığını kontrol edin
- [ ] [**Kullanıcı oturumları**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**Kullanıcı ana dizinlerini**](windows-local-privilege-escalation/index.html#home-folders) kontrol edin (erişilebiliyor mu?)
- [ ] [**Parola ilkesini**](windows-local-privilege-escalation/index.html#password-policy) kontrol edin
- [ ] [**Panoda**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ne var?

### [Ağ](windows-local-privilege-escalation/index.html#network)

- [ ] **Mevcut** [**ağ** **bilgilerini**](windows-local-privilege-escalation/index.html#network) kontrol edin
- [ ] Dış erişime kapalı **gizli yerel hizmetleri** kontrol edin

### [Çalışan İşlemler](windows-local-privilege-escalation/index.html#running-processes)

- [ ] İşlem ikililerinin [**dosya ve klasör izinleri**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Bellekten parola madenciliği**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Güvenli olmayan GUI uygulamaları**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` aracılığıyla **ilginç işlemlerden** (firefox, chrome, vb.) kimlik bilgilerini çalabilir misiniz?

### [Hizmetler](windows-local-privilege-escalation/index.html#services)

- [ ] [Herhangi bir **hizmeti değiştirebilir** misiniz?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Herhangi bir **hizmetin** **çalıştırdığı** **ikili dosyayı** değiştirebilir misiniz?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Herhangi bir **hizmetin** **kayıt defterini** değiştirebilir misiniz?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Herhangi bir **tırnak içine alınmamış hizmet ikili dosyası yolundan** yararlanabilir misiniz?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Hizmet Tetikleyicileri: ayrıcalıklı hizmetleri numaralandırın ve tetikleyin](windows-local-privilege-escalation/service-triggers.md)

### [**Uygulamalar**](windows-local-privilege-escalation/index.html#applications)

- [ ] [**Yüklü uygulamalarda yazma izinleri**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Başlangıç uygulamaları**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Güvenlik açığı bulunan** [**sürücüler**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH içindeki herhangi bir klasöre yazabilir** misiniz?
- [ ] **Mevcut olmayan bir DLL'i yüklemeye çalışan** bilinen bir hizmet ikilisi var mı?
- [ ] Herhangi bir **ikili dosya klasörüne** yazabilir misiniz?

### [Ağ](windows-local-privilege-escalation/index.html#network)

- [ ] Ağı numaralandırın (paylaşımlar, arabirimler, rotalar, komşular, ...)
- [ ] Localhost'ta (127.0.0.1) dinleyen ağ hizmetlerine özellikle dikkat edin

### [Windows Kimlik Bilgileri](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) kimlik bilgileri
- [ ] Kullanabileceğiniz [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kimlik bilgileri var mı?
- [ ] İlginç [**DPAPI kimlik bilgileri**](windows-local-privilege-escalation/index.html#dpapi) var mı?
- [ ] Kayıtlı [**Wi-Fi ağlarının**](windows-local-privilege-escalation/index.html#wifi) parolaları?
- [ ] [**Kaydedilmiş RDP bağlantılarında**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ilginç bilgiler var mı?
- [ ] [**Yakın zamanda çalıştırılan komutlarda**](windows-local-privilege-escalation/index.html#recently-run-commands) parolalar var mı?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) parolaları?
- [ ] [**AppCmd.exe** mevcut mu](windows-local-privilege-escalation/index.html#appcmd-exe)? Kimlik bilgileri?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) var mı? DLL Side Loading?

### [Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Kimlik bilgileri**](windows-local-privilege-escalation/index.html#putty-creds) **ve** [**SSH host anahtarları**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Kayıt defterindeki SSH anahtarları**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**Gözetimsiz kurulum dosyalarında**](windows-local-privilege-escalation/index.html#unattended-files) parolalar var mı?
- [ ] Herhangi bir [**SAM ve SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) yedeği var mı?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) varsa `SAM`, `SYSTEM`, DPAPI materyali ve `MachineKeys` için ham birim okumalarını deneyin
- [ ] [**Cloud kimlik bilgileri**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) dosyası var mı?
- [ ] [**Önbelleğe alınmış GPP parolası**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web yapılandırma dosyasında**](windows-local-privilege-escalation/index.html#iis-web-config) parola var mı?
- [ ] [**Web** **günlüklerinde**](windows-local-privilege-escalation/index.html#logs) ilginç bilgiler var mı?
- [ ] Kullanıcıdan [**kimlik bilgilerini istemek**](windows-local-privilege-escalation/index.html#ask-for-credentials) ister misiniz?
- [ ] [**Geri Dönüşüm Kutusu'nda**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) ilginç [**dosyalar**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) var mı?
- [ ] Kimlik bilgileri içeren başka [**kayıt defteri anahtarları**](windows-local-privilege-escalation/index.html#inside-the-registry) var mı?
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
{{#include ../banners/hacktricks-training.md}}
