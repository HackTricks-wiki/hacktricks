# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış
- Windows AppInfo, UIAccess süreçleri başlatmak için `RAiLaunchAdminProcess`'i sunar (erişilebilirlik için tasarlanmıştır). UIAccess, User Interface Privilege Isolation (UIPI) mesaj filtrelemesinin çoğunu atlayarak erişilebilirlik yazılımlarının daha yüksek-IL UI'yi kontrol etmesine izin verir.
- UIAccess'i doğrudan etkinleştirmek `NtSetInformationToken(TokenUIAccess)` ile **SeTcbPrivilege** gerektirdiğinden, düşük ayrıcalıklı çağırıcılar servise güvenir. Servis, UIAccess ayarlamadan önce hedef ikili üzerinde üç kontrol gerçekleştirir:
  - Gömülü manifest `uiAccess="true"` içerir.
  - Local Machine root deposu tarafından güvenilen herhangi bir sertifika ile imzalanmıştır (EKU/Microsoft gereksinimi yok).
  - Sistem sürücüsündeki yalnızca yönetici erişimli bir yolda yer alır (ör. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`; belirli yazılabilir alt yollar hariç).
- `RAiLaunchAdminProcess` UIAccess başlatmaları için herhangi bir consent prompt göstermektedir (aksi halde erişilebilirlik araçları prompt'u kontrol edemezdi).

## Token şekillendirme ve bütünlük seviyeleri
- Kontroller başarılı olursa, AppInfo **çağırıcı token'ı kopyalar**, UIAccess'i etkinleştirir ve Integrity Level (IL) yükseltir:
  - Limited admin user (kullanıcı Administrators grubunda ama filtrelenmiş çalışıyor) ➜ **High IL**.
  - Non-admin user ➜ IL **+16 seviye** artırılır, ancak maksimum **High** ile sınırlandırılır (System IL asla atanmaz).
- Eğer çağırıcı token zaten UIAccess içeriyorsa, IL değişmeden bırakılır.
- “Ratchet” hilesi: bir UIAccess süreç kendisinde UIAccess'i devre dışı bırakıp `RAiLaunchAdminProcess` ile yeniden başlatarak bir başka +16 IL artışı elde edebilir. Medium➜High için 255 yeniden başlatma gerekir (gürültülü ama çalışır).

## Neden UIAccess Admin Protection kaçışına izin verir
- UIAccess, daha düşük-IL bir sürecin daha yüksek-IL pencerelerine pencere mesajları göndermesine izin verir (UIPI filtrelerini atlayarak). Eşit IL'de, `SetWindowsHookEx` gibi klasik UI araçları herhangi bir pencereye sahip sürece (COM tarafından kullanılan message-only pencereler dahil) kod enjeksiyonu/DLL yüklemesine izin verebilir.
- Admin Protection, UIAccess sürecini **limited user kimliğinde** ama **High IL**'de sessizce başlatır. Bir kez High-IL UIAccess sürecinde rastgele kod çalıştırıldığında, saldırgan masaüstündeki diğer High-IL süreçlere (farklı kullanıcılara ait olsalar bile) enjeksiyon yaparak hedeflenen ayrımı bozabilir.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ üzerinde API Win32k'ye taşındı (`NtUserGetWindowProcessHandle`) ve çağırıcı tarafından sağlanan `DesiredAccess` kullanarak bir process handle açabiliyor. Kernel yolu `ObOpenObjectByPointer(..., KernelMode, ...)` kullanır; bu da normal user-mode erişim kontrollerini atlar.
- Pratik önkoşullar: hedef pencere aynı desktop üzerinde olmalı ve UIPI kontrolleri geçmelidir. Tarihsel olarak, UIAccess sahibi bir çağırıcı UIPI başarısızlığını atlayıp yine de kernel-mode handle alabiliyordu (CVE-2023-41772 olarak düzeltildi).
- Etki: bir pencere handle'ı, çağırıcı normalde açamayacağı güçlü bir process handle (genellikle `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) elde etmek için bir yetenek haline gelir. Bu, çapraz-kum havuzu (cross-sandbox) erişimine izin verir ve hedef herhangi bir pencere (message-only pencereler dahil) açıyorsa Protected Process / PPL sınırlarını kırabilir.
- Pratik suistimal akışı: HWND'leri saymak veya bulmak (ör. `EnumWindows`/`FindWindowEx`), sahip PID'yi çözmek (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` çağırmak ve dönen handle'ı bellek okuma/yazma veya kod-hijack primitive'leri için kullanmak.
- Düzeltme sonrası davranış: UIAccess artık UIPI hatasında kernel-mode açılışlara izin vermez ve izin verilen erişim hakları legacy hook set ile sınırlanır; Windows 11 24H2 süreç-koruma kontrolleri ve feature-flag'li daha güvenli yollar ekler. UIPI'yi sistem genelinde devre dışı bırakmak (`EnforceUIPI=0`) bu korumaları zayıflatır.

## Güvenli-dizin doğrulama zayıflıkları (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo sağlanan yolu `GetFinalPathNameByHandle` ile çözer ve sonra hardcoded kökler/istisnalar karşısında **string allow/deny kontrolleri** uygular. Bu basit doğrulamadan kaynaklanan birkaç atlatma sınıfı vardır:
- **Directory named streams**: Hariç tutulmuş yazılabilir dizinler (ör. `C:\Windows\tracing`) dizinin kendisi üzerinde bir named stream ile atlatılabilir, örn. `C:\Windows\tracing:file.exe`. String kontroller `C:\Windows\`'ı görür ve hariç tutulan alt yolu kaçırır.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **bir `.exe` uzantısı gerektirmez**. İzin verilen bir kök altında herhangi bir yazılabilir dosyanın üzerine çalıştırılabilir payload yazarak veya imzalı `uiAccess="true"` EXE'yi herhangi bir yazılabilir alt dizine kopyalayarak (ör. mevcutsa güncelleme artıklarından `Tasks_Migrated` gibi) secure-path kontrolü geçilebilir.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admin'ler imzalı MSIX paketleri yükleyebiliyor ve bunlar `WindowsApps`'e düşüyordu; bu yol hariç tutulmamıştı. MSIX içine bir UIAccess ikilisi paketleyip `RAiLaunchAdminProcess` ile başlatmak bir **prompt'suz High-IL UIAccess süreci** veriyordu. Microsoft bu yolu hariç tutarak hafifletecek; ayrıca `uiAccess` sınırlı MSIX yeteneğinin kendisi zaten admin kurulumu gerektirir.

## Saldırı iş akışı (uyarı olmadan High IL)
1. İmzalı bir UIAccess binary elde edin/oluşturun (manifest `uiAccess="true"`).
2. AppInfo’nin allowlist'inin kabul ettiği bir yere koyun (veya yukarıda belirtilen yol-doğrulama kenar durumu/yazılabilir artefaktı suistimal edin).
3. `RAiLaunchAdminProcess` çağırarak UIAccess + yükseltilmiş IL ile **sessizce** başlatın.
4. Bu High-IL dayanak noktasından, masaüstündeki başka bir High-IL süreci hedefleyerek `window hooks`/DLL enjeksiyonu veya aynı-IL primitive'leri kullanarak admin bağlamını tamamen ele geçirin.

## Yazılabilir aday yolları enumerate etme
Seçilen bir token perspektifinden nominal olarak güvenli kökler içindeki yazılabilir/üstüne yazılabilir nesneleri keşfetmek için PowerShell yardımcıyı çalıştırın:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Daha geniş görünürlük için Administrator olarak çalıştırın; o token'ın erişimini yansıtmak için `-ProcessId` parametresini low-priv bir process'e ayarlayın.
- Adayları `RAiLaunchAdminProcess` ile kullanmadan önce bilinen izin verilmeyen alt dizinleri hariç tutmak için manuel olarak filtreleyin.

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
