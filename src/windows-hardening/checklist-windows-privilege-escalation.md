# Kontrol Listesi - Yerel Windows Yetki Yükseltme

{{#include ../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Sistem Bilgisi](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**Sistem bilgilerini**](windows-local-privilege-escalation/index.html#system-info) elde et
- [ ] **kernel** için **saldırılar** [**scriptler kullanarak**](windows-local-privilege-escalation/index.html#version-exploits) ara
- [ ] **Google kullanarak** kernel **saldırılarını** ara
- [ ] **searchsploit kullanarak** kernel **saldırılarını** ara
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment) içinde ilginç bilgiler var mı?
- [ ] [**PowerShell geçmişinde**](windows-local-privilege-escalation/index.html#powershell-history) şifreler var mı?
- [ ] [**Internet ayarlarında**](windows-local-privilege-escalation/index.html#internet-settings) ilginç bilgiler var mı?
- [ ] [**Sürücüler**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS saldırısı**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Günlükleme/AV sayımı](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Denetim**](windows-local-privilege-escalation/index.html#audit-settings) ve [**WEF**](windows-local-privilege-escalation/index.html#wef) ayarlarını kontrol et
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) kontrol et
- [ ] [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) aktif mi kontrol et
- [ ] [**LSA Koruması**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Kimlik Bilgileri Koruması**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Önbelleklenmiş Kimlik Bilgileri**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Herhangi bir [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) kontrol et
- [ ] [**AppLocker Politikası**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Kullanıcı Yetkileri**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**mevcut** kullanıcı **yetkilerini**](windows-local-privilege-escalation/index.html#users-and-groups) kontrol et
- [ ] [**herhangi bir ayrıcalıklı grubun**](windows-local-privilege-escalation/index.html#privileged-groups) üyesi misin?
- [ ] [**bu tokenlerden herhangibiri**](windows-local-privilege-escalation/index.html#token-manipulation) etkin mi: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Kullanıcı Oturumları**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**kullanıcı evlerini**](windows-local-privilege-escalation/index.html#home-folders) kontrol et (erişim?)
- [ ] [**Şifre Politikası**](windows-local-privilege-escalation/index.html#password-policy) kontrol et
- [ ] [**Panoya**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ne var?

### [Ağ](windows-local-privilege-escalation/index.html#network)

- [ ] **mevcut** [**ağ** **bilgilerini**](windows-local-privilege-escalation/index.html#network) kontrol et
- [ ] Dışarıya kısıtlı **gizli yerel hizmetleri** kontrol et

### [Çalışan Süreçler](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Süreçlerin ikili [**dosya ve klasör izinleri**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Bellek Şifre madenciliği**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Güvensiz GUI uygulamaları**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe` aracılığıyla **ilginç süreçlerle** kimlik bilgilerini çal? (firefox, chrome, vb...)

### [Hizmetler](windows-local-privilege-escalation/index.html#services)

- [ ] [Herhangi bir **hizmeti değiştirebilir misin**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Herhangi bir **hizmet** tarafından **çalıştırılan** **ikiliyi** **değiştirebilir misin**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Herhangi bir **hizmetin** **kayıt defterini** **değiştirebilir misin**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Herhangi bir **belirtilmemiş hizmet** ikili **yolu** üzerinden avantaj sağlayabilir misin?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Uygulamalar**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Yüklenmiş uygulamalar üzerindeki** [**yazma**](windows-local-privilege-escalation/index.html#write-permissions) izinleri
- [ ] [**Başlangıç Uygulamaları**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Zayıf** [**Sürücüler**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH içindeki herhangi bir klasöre yazabilir misin**?
- [ ] **yüklenmeye çalışan** herhangi bir bilinen hizmet ikilisi var mı **mevcut olmayan DLL**?
- [ ] **herhangi bir** ikili klasöre **yazabilir misin**?

### [Ağ](windows-local-privilege-escalation/index.html#network)

- [ ] Ağı say (paylaşımlar, arayüzler, yollar, komşular, ...)
- [ ] localhost (127.0.0.1) üzerinde dinleyen ağ hizmetlerine özel bir göz at

### [Windows Kimlik Bilgileri](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) kimlik bilgileri
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kullanabileceğin kimlik bilgileri var mı?
- [ ] İlginç [**DPAPI kimlik bilgileri**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Kaydedilmiş [**Wifi ağlarının**](windows-local-privilege-escalation/index.html#wifi) şifreleri?
- [ ] [**kaydedilmiş RDP Bağlantılarında**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ilginç bilgiler var mı?
- [ ] [**son çalıştırılan komutlarda**](windows-local-privilege-escalation/index.html#recently-run-commands) şifreler var mı?
- [ ] [**Uzak Masaüstü Kimlik Bilgileri Yöneticisi**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) şifreleri?
- [ ] [**AppCmd.exe** mevcut mı](windows-local-privilege-escalation/index.html#appcmd-exe)? Kimlik bilgileri?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Yan Yükleme?

### [Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Kimlik Bilgileri**](windows-local-privilege-escalation/index.html#putty-creds) **ve** [**SSH anahtarları**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Kayıt defterinde SSH anahtarları**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**denetimsiz dosyalarda**](windows-local-privilege-escalation/index.html#unattended-files) şifreler var mı?
- [ ] Herhangi bir [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) yedeği var mı?
- [ ] [**Bulut kimlik bilgileri**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) dosyası?
- [ ] [**Önbelleklenmiş GPP Şifresi**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web yapılandırma dosyasında**](windows-local-privilege-escalation/index.html#iis-web-config) şifre var mı?
- [ ] [**web** **günlüklerinde**](windows-local-privilege-escalation/index.html#logs) ilginç bilgiler var mı?
- [ ] Kullanıcıdan [**kimlik bilgilerini istemek**](windows-local-privilege-escalation/index.html#ask-for-credentials) ister misin?
- [ ] [**Geri Dönüşüm Kutusu içindeki**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) ilginç dosyalar var mı?
- [ ] [**kimlik bilgileri içeren diğer**](windows-local-privilege-escalation/index.html#inside-the-registry) kayıt defterleri var mı?
- [ ] [**Tarayıcı verileri içinde**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, geçmiş, yer imleri, ...)?
- [ ] Dosyalar ve kayıt defterinde [**genel şifre araması**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] Şifreleri otomatik olarak aramak için [**Araçlar**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Sızdırılan İşleyiciler](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Yönetici tarafından çalıştırılan bir sürecin herhangi bir işleyicisine erişimin var mı?

### [Pipe İstemci Taklit Etme](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Bunu kötüye kullanıp kullanamayacağını kontrol et

{{#include ../banners/hacktricks-training.md}}
