# UIAccess ile Admin Koruması Atlama Yöntemleri

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış
- Windows AppInfo, UIAccess süreçleri başlatmak için `RAiLaunchAdminProcess`'i açığa çıkarır (erişilebilirlik amaçlı). UIAccess, User Interface Privilege Isolation (UIPI) mesaj filtrelemesinin çoğunu atlar, böylece erişilebilirlik yazılımları daha yüksek-IL UI'yi kontrol edebilir.
- UIAccess'i doğrudan etkinleştirmek `NtSetInformationToken(TokenUIAccess)` ile **SeTcbPrivilege** gerektirir; bu yüzden düşük-privilege çağırıcılar servise güvenir. Servis, UIAccess ayarlamadan önce hedef ikili üzerinde üç kontrol yapar:
- Gömülü manifest `uiAccess="true"` içerir.
- Local Machine root deposu tarafından güvenilen herhangi bir sertifika ile imzalanmış (EKU/Microsoft gereksinimi yok).
- Sistem sürücüsünde yöneticiye özel bir yolda yer alır (ör. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, belirli yazılabilir alt yollar hariç).
- `RAiLaunchAdminProcess` UIAccess başlatmaları için herhangi bir onay ekranı göstermez (aksi takdirde erişilebilirlik araçları istemi kontrol edemezdi).

## Token şekillendirme ve bütünlük seviyeleri
- Kontroller başarılı olursa, AppInfo **çağırıcı token'ı kopyalar**, UIAccess'i etkinleştirir ve Integrity Level (IL) yükseltir:
- Limited admin user (kullanıcı Administrators grubunda ama filtrelenmiş çalışıyor) ➜ **High IL**.
- Non-admin user ➜ IL **+16 seviye** artırılır, bir **High** sınırına kadar (System IL asla atanmaz).
- Eğer çağırıcı token zaten UIAccess içeriyorsa, IL değiştirilmez.
- “Ratchet” taktiği: bir UIAccess süreci kendi üzerinde UIAccess'i devre dışı bırakıp `RAiLaunchAdminProcess` ile yeniden başlatarak bir +16 IL artışı daha kazanabilir. Medium➜High için 255 yeniden başlatma gerekir (gürültülü ama işe yarar).

## Neden UIAccess bir Admin Koruması kaçağı sağlar
- UIAccess, daha düşük-IL süreçlerin daha yüksek-IL pencerelere pencere mesajları göndermesine izin verir (UIPI filtrelerini atlayarak). Eşit IL'de, `SetWindowsHookEx` gibi klasik UI araçları herhangi bir pencereye sahip sürece kod enjeksiyonu/DLL yükleme izinleri verebilir (COM tarafından kullanılan **message-only windows** dahil).
- Admin Protection, UIAccess sürecini **sınırlı kullanıcının kimliğiyle** ama **High IL** olarak, sessizce başlatır. High-IL UIAccess sürecinde rastgele kod çalıştırıldığında, saldırgan masaüstündeki diğer High-IL süreçlere (farklı kullanıcılara ait olsa bile) enjeksiyon yapabilir ve amaçlanan ayrımı bozar.

## HWND'den süreç tutamacı elde etme ilkelisi (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ üzerinde API Win32k'ya taşındı (`NtUserGetWindowProcessHandle`) ve çağırıcı tarafından sağlanan `DesiredAccess` kullanarak bir süreç tutamacı açabiliyor. Kernel yolu `ObOpenObjectByPointer(..., KernelMode, ...)` kullanır; bu normal kullanıcı modu erişim kontrollerini atlar.
- Pratik önkoşullar: hedef pencerenin aynı desktop'ta olması ve UIPI kontrollerinin geçmesi gerekir. Tarihsel olarak, UIAccess olan bir çağırıcı UIPI başarısızlığını atlayıp yine de kernel-mode tutamacı alabiliyordu (CVE-2023-41772 olarak düzeltildi).
- Etki: bir pencere tanıtıcısı, çağıranın normalde açamayacağı güçlü bir süreç tutamacı elde etmesi için bir **kapasite** haline gelir (genelde `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`). Bu, sandboxlar arası erişimi sağlar ve hedef herhangi bir pencere (message-only pencereler dahil) açıyorsa Protected Process / PPL sınırlarını kırabilir.
- Pratik kötüye kullanım akışı: HWND'leri enumerate etmek veya bulmak (ör. `EnumWindows`/`FindWindowEx`), sahip olan PID'yi çözmek (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` çağırmak ve dönen tutamaç ile bellek okuma/yazma veya kod-hijack primitifleri için kullanmak.
- Düzeltme sonrası davranış: UIAccess artık UIPI başarısızlığında kernel-mode açıkları vermez ve izin verilen erişim hakları legacy hook kümesi ile sınırlandırılır; Windows 11 24H2 süreç-koruma kontrolleri ve feature-flag ile daha güvenli yollar ekler. UIPI'yi sistem çapında devre dışı bırakmak (`EnforceUIPI=0`) bu korumaları zayıflatır.

## Güvenli-dizin doğrulama zayıflıkları (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo sağlanan yolu `GetFinalPathNameByHandle` ile çözümler ve sonra sabitlenmiş kökler/dışlamalara karşı **string allow/deny kontrolleri** uygular. Bu basit doğrulamadan kaynaklanan birkaç atlama sınıfı vardır:
- **Directory named streams**: Hariç tutulan yazılabilir dizinler (ör. `C:\Windows\tracing`) dizinin kendisine ait bir named stream ile atlanabilir, örn. `C:\Windows\tracing:file.exe`. String kontroller `C:\Windows\` görür ve hariç tutulan alt yolu kaçırır.
- **Allowed root içinde yazılabilir dosya/dizin**: `CreateProcessAsUser` bir `.exe` uzantısı gerektirmez. İzin verilen bir root altında yazılabilir herhangi bir dosyanın üzerine çalıştırılabilir payload yazmak işe yarar; ya da imzalı `uiAccess="true"` EXE'yi herhangi bir yazılabilir alt dizine kopyalamak (ör. mevcutsa `Tasks_Migrated` gibi güncelleme kalıntıları) secure-path kontrolünü geçmesini sağlar.
- **MSIX into `C:\Program Files\WindowsApps` (düzeltildi)**: Non-adminler imzalımış MSIX paketleri kurabilir ve bunlar `WindowsApps`'a düşebilirdi; bu yol hariç tutulmamıştı. MSIX içine bir UIAccess ikilisi paketleyip bunu `RAiLaunchAdminProcess` ile başlatmak, **prompt olmadan High-IL UIAccess süreci** veriyordu. Microsoft bu yolu hariç tutarak hafifletti; ayrıca `uiAccess` ile kısıtlı MSIX özelliği zaten admin kurulumu gerektiriyordu.

## Saldırı iş akışı (prompt olmadan High IL)
1. İmzalanmış bir **UIAccess binary** elde edin/oluşturun (manifest `uiAccess="true"`).
2. AppInfo’nin allowlist'inin kabul ettiği bir yere koyun (veya yukarıdaki yol-doğrulama kenar durumunu/yazılabilir artefaktı kullanın).
3. `RAiLaunchAdminProcess` çağırarak onu UIAccess + yükseltilmiş IL ile **sessizce** başlatın.
4. Bu High-IL köprüden, masaüstündeki başka bir High-IL süreci hedefleyin ve **window hooks/DLL injection** veya aynı-IL primitifleri kullanarak yönetici bağlamını tamamen ele geçirin.

## Yazılabilir aday yolların listelenmesi
Seçilen bir token perspektifinden nominal olarak güvenli kökler içinde yazılabilir/üzerine yazılabilir nesneleri keşfetmek için PowerShell yardımcısını çalıştırın:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Genişletilmiş görünürlük için Administrator olarak çalıştırın; `-ProcessId`'i o token'ın erişimini yansıtacak şekilde düşük ayrıcalıklı bir işleme ayarlayın.
- `RAiLaunchAdminProcess` ile adayları kullanmadan önce bilinen yasaklı alt dizinleri hariç tutmak için manuel olarak filtreleyin.

## Referanslar
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
