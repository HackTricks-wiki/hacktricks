# Kontrol Listesi - Yerel Windows Yetki Yükseltme

{{#include ../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Sistem Bilgisi](windows-local-privilege-escalation/#system-info)

- [ ] [**Sistem bilgilerini**](windows-local-privilege-escalation/#system-info) elde et
- [ ] **kernel** için [**saldırılar aramak**](windows-local-privilege-escalation/#version-exploits) amacıyla **scriptler** kullan
- [ ] **Google ile kernel** **saldırılarını aramak** için kullan
- [ ] **searchsploit ile kernel** **saldırılarını aramak** için kullan
- [ ] [**env vars**](windows-local-privilege-escalation/#environment) içinde ilginç bilgiler var mı?
- [ ] [**PowerShell geçmişinde**](windows-local-privilege-escalation/#powershell-history) şifreler var mı?
- [ ] [**Internet ayarlarında**](windows-local-privilege-escalation/#internet-settings) ilginç bilgiler var mı?
- [ ] [**Sürücüler**](windows-local-privilege-escalation/#drives)?
- [ ] [**WSUS saldırısı**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Günlükleme/AV sayımı](windows-local-privilege-escalation/#enumeration)

- [ ] [**Denetim**](windows-local-privilege-escalation/#audit-settings) ve [**WEF**](windows-local-privilege-escalation/#wef) ayarlarını kontrol et
- [ ] [**LAPS**](windows-local-privilege-escalation/#laps) kontrol et
- [ ] [**WDigest**](windows-local-privilege-escalation/#wdigest) aktif mi kontrol et
- [ ] [**LSA Koruması**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Önbellekli Kimlik Bilgileri**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) var mı kontrol et
- [ ] [**AppLocker Politikası**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Kullanıcı Yetkileri**](windows-local-privilege-escalation/#users-and-groups)
- [ ] [**mevcut** kullanıcı **yetkilerini**](windows-local-privilege-escalation/#users-and-groups) kontrol et
- [ ] [**herhangi bir ayrıcalıklı grubun**](windows-local-privilege-escalation/#privileged-groups) üyesi misin?
- [ ] [**bu tokenlerden herhangi biri etkin mi**](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Kullanıcı Oturumları**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] [**kullanıcı evlerini**](windows-local-privilege-escalation/#home-folders) kontrol et (erişim?)
- [ ] [**Şifre Politikası**](windows-local-privilege-escalation/#password-policy) kontrol et
- [ ] [**Pano içinde ne var**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Ağ](windows-local-privilege-escalation/#network)

- [ ] **mevcut** [**ağ** **bilgilerini**](windows-local-privilege-escalation/#network) kontrol et
- [ ] **dışarıya kısıtlı gizli yerel hizmetleri** kontrol et

### [Çalışan Süreçler](windows-local-privilege-escalation/#running-processes)

- [ ] Süreçlerin ikili [**dosya ve klasör izinleri**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Bellek Şifre madenciliği**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Güvensiz GUI uygulamaları**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] `ProcDump.exe` aracılığıyla **ilginç süreçlerle** kimlik bilgilerini çal? (firefox, chrome, vb...)

### [Hizmetler](windows-local-privilege-escalation/#services)

- [ ] [Herhangi bir **hizmeti değiştirebilir misin**?](windows-local-privilege-escalation/#permissions)
- [ ] [Herhangi bir **hizmetin** **çalıştırdığı** **ikiliyi** **değiştirebilir misin**?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Herhangi bir **hizmetin** **kayıt defterini** **değiştirebilir misin**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Herhangi bir **belirsiz hizmet** ikili **yolu** üzerinden avantaj sağlayabilir misin?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Uygulamalar**](windows-local-privilege-escalation/#applications)

- [ ] **Yüklenmiş uygulamalar üzerindeki** [**yazma izinleri**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Başlangıç Uygulamaları**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Zayıf** [**Sürücüler**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] **PATH içindeki herhangi bir klasöre yazabilir misin**?
- [ ] **yüklemeye çalışan** bilinen bir hizmet ikilisi var mı **mevcut olmayan DLL**?
- [ ] **herhangi bir** ikili klasöre **yazabilir misin**?

### [Ağ](windows-local-privilege-escalation/#network)

- [ ] Ağı say (paylaşımlar, arayüzler, yollar, komşular, ...)
- [ ] localhost (127.0.0.1) üzerinde dinleyen ağ hizmetlerine özel bir göz at

### [Windows Kimlik Bilgileri](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) kimlik bilgileri
- [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) kullanabileceğin kimlik bilgileri var mı?
- [ ] İlginç [**DPAPI kimlik bilgileri**](windows-local-privilege-escalation/#dpapi)?
- [ ] Kaydedilmiş [**Wifi ağlarının**](windows-local-privilege-escalation/#wifi) şifreleri?
- [ ] [**kaydedilmiş RDP Bağlantılarında**](windows-local-privilege-escalation/#saved-rdp-connections) ilginç bilgiler var mı?
- [ ] [**son çalıştırılan komutlarda**](windows-local-privilege-escalation/#recently-run-commands) şifreler var mı?
- [ ] [**Uzak Masaüstü Kimlik Bilgileri Yöneticisi**](windows-local-privilege-escalation/#remote-desktop-credential-manager) şifreleri?
- [ ] [**AppCmd.exe** mevcut mı](windows-local-privilege-escalation/#appcmd-exe)? Kimlik bilgileri?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Yan Yükleme?

### [Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Kimlik Bilgileri**](windows-local-privilege-escalation/#putty-creds) **ve** [**SSH anahtarları**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**Kayıt defterinde SSH anahtarları**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] [**katılımsız dosyalarda**](windows-local-privilege-escalation/#unattended-files) şifreler var mı?
- [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) yedeği var mı?
- [ ] [**Bulut kimlik bilgileri**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) dosyası?
- [ ] [**Önbellekli GPP Şifresi**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] [**IIS Web yapılandırma dosyasında**](windows-local-privilege-escalation/#iis-web-config) şifre var mı?
- [ ] [**web** **günlüklerinde**](windows-local-privilege-escalation/#logs) ilginç bilgiler var mı?
- [ ] Kullanıcıdan [**kimlik bilgilerini istemek**](windows-local-privilege-escalation/#ask-for-credentials) ister misin?
- [ ] [**Geri Dönüşüm Kutusu içindeki ilginç dosyalar**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] [**kimlik bilgileri içeren diğer**](windows-local-privilege-escalation/#inside-the-registry) kayıt defterleri?
- [ ] [**Tarayıcı verileri içinde**](windows-local-privilege-escalation/#browsers-history) (dbs, geçmiş, yer imleri, ...)?
- [ ] Dosyalar ve kayıt defterinde [**genel şifre araması**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
- [ ] Şifreleri otomatik olarak aramak için [**Araçlar**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [Sızdırılan İşleyiciler](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Yönetici tarafından çalıştırılan bir sürecin herhangi bir işleyicisine erişimin var mı?

### [Pipe İstemci Taklit Etme](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Bunu kötüye kullanıp kullanamayacağını kontrol et

{{#include ../banners/hacktricks-training.md}}
