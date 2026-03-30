# UIAccess ile Admin Protection Bypass'ları

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış
- Windows AppInfo `RAiLaunchAdminProcess`'i UIAccess süreçleri başlatmak için açığa çıkarır (erişilebilirlik amaçlı). UIAccess, erişilebilirlik yazılımlarının daha yüksek-IL UI'yi kontrol edebilmesi için çoğu User Interface Privilege Isolation (UIPI) mesaj filtrelemesini atlar.
- UIAccess'i doğrudan etkinleştirmek `NtSetInformationToken(TokenUIAccess)` ile **SeTcbPrivilege** gerektirir, bu yüzden düşük ayrıcalıklı çağırıcılar servise güvenir. Servis, UIAccess ayarlamadan önce hedef ikili üzerinde üç kontrol gerçekleştirir:
  - Gömülü manifest `uiAccess="true"` içerir.
  - Local Machine root store tarafından güvenilen herhangi bir sertifika ile imzalanmış (EKU/Microsoft şartı yok).
  - Sistem sürücüsünde yöneticiye özel bir yolun içinde yer alır (ör. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, belirli yazılabilir alt yollar hariç).
- `RAiLaunchAdminProcess` UIAccess başlatmaları için herhangi bir onay istemi göstermez (aksi takdirde erişilebilirlik araçları istemi kontrol edemezdi).

## Token shaping ve integrity seviyeleri
- Kontroller başarılı olursa, AppInfo **çağırıcı token'ı kopyalar**, UIAccess'i etkinleştirir ve Integrity Level (IL) yükseltir:
  - Limited admin user (kullanıcı Administrators grubunda ama filtrelenmiş olarak çalışıyor) ➜ **High IL**.
  - Non-admin user ➜ IL **+16 seviyeye** kadar arttırılır, en fazla **High** ile sınırlandırılır (System IL atanmaz).
- Eğer çağırıcı token zaten UIAccess içeriyorsa, IL değiştirilmez.
- “Ratchet” hilesi: bir UIAccess süreç kendi üzerindeki UIAccess'i devre dışı bırakıp `RAiLaunchAdminProcess` ile tekrar başlatabilir ve başka bir +16 IL artışı elde edebilir. Medium➜High geçişi 255 yeniden başlatma gerektirir (gürültülü, ama çalışır).

## Neden UIAccess Admin Protection kaçışına izin verir
- UIAccess, daha düşük-IL bir sürecin daha yüksek-IL pencerelere pencere mesajı göndermesine izin verir (UIPI filtrelerini atlayarak). Eşit IL'de, `SetWindowsHookEx` gibi klasik UI primitifleri herhangi bir pencereye sahip sürece (COM tarafından kullanılan message-only pencereler dahil) kod enjeksiyonu/DLL yüklemeye izin verir.
- Admin Protection UIAccess sürecini **limited user kimliğiyle** ama **High IL** seviyesinde sessizce başlatır. Bir kez High-IL UIAccess sürecinde rastgele kod çalıştırıldığında, saldırgan masaüstündeki diğer High-IL süreçlere (farklı kullanıcılara ait olanlar dahil) enjeksiyon yapabilir ve tasarlanan ayrımı kırar.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+'te API Win32k'ye (`NtUserGetWindowProcessHandle`) taşındı ve çağırıcı tarafından sağlanan `DesiredAccess` kullanılarak bir process handle açabilir. Kernel yolu `ObOpenObjectByPointer(..., KernelMode, ...)` kullanır; bu normal user-mode erişim kontrollerini atlar.
- Pratik önkoşullar: hedef pencere aynı desktop'ta olmalı ve UIPI kontrolleri geçmelidir. Tarihsel olarak, UIAccess sahibi bir çağırıcı UIPI başarısızlığını atlayabiliyor ve yine de kernel-mode handle elde edebiliyordu (düzeltildi: CVE-2023-41772).
- Etki: bir pencere handle'ı, çağırıcının normalde açamayacağı güçlü bir process handle (genellikle `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) elde etmesi için bir capability haline gelir. Bu çapraz sandbox erişimine izin verir ve hedef herhangi bir pencere (message-only pencereler dahil) açıyorsa Protected Process / PPL sınırlarını zayıflatabilir.
- Pratik kötüye kullanım akışı: HWND'leri listele veya bul (ör. `EnumWindows`/`FindWindowEx`), sahip PID'yi çöz (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` çağır, sonra dönen handle'ı bellek okuma/yazma veya kod ele geçirme primitifleri için kullan.
- Düzeltmeden sonraki davranış: UIAccess artık UIPI başarısızlığında kernel-mode açılışlara izin vermez ve izin verilen erişim hakları legacy hook set ile sınırlanır; Windows 11 24H2 process-protection kontrolleri ve özellik-flag'lenmiş daha güvenli yollar ekler. UIPI'yi sistem çapında devre dışı bırakmak (`EnforceUIPI=0`) bu korumaları zayıflatır.

## Secure-directory validation zayıflıkları (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo verilen yolu `GetFinalPathNameByHandle` ile çözümler ve sonra sabitlenmiş kökler/dışlamalara karşı **string allow/deny kontrolleri** uygular. Bu basit doğrulamadan kaynaklanan birden fazla bypass sınıfı vardır:
- **Directory named streams**: Hariç tutulmuş yazılabilir dizinler (ör. `C:\Windows\tracing`) dizinin kendisinde bir named stream ile atlanabilir, örn. `C:\Windows\tracing:file.exe`. String kontroller `C:\Windows\` kısmını görür ve hariç tutulmuş alt yolu kaçırır.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` bir `.exe` uzantısı gerektirmez. İzin verilen kök altında herhangi bir yazılabilir dosyayı çalıştırılabilir yük ile üstüne yazmak işe yarar, veya imzalı `uiAccess="true"` EXE'yi herhangi bir yazılabilir alt dizine kopyalamak (ör. mevcutsa güncelleme kalıntıları gibi `Tasks_Migrated`) secure-path kontrolünü geçmesini sağlar.
- **MSIX into `C:\Program Files\WindowsApps` (düzeltildi)**: Non-admin'ler imzalı MSIX paketleri kurup `WindowsApps` içine yerleştirebiliyordu; bu yol hariç tutulmamıştı. MSIX içine UIAccess ikili paketleyip `RAiLaunchAdminProcess` ile başlatmak, prompt olmadan High-IL UIAccess süreci elde edilmesine yol açıyordu. Microsoft bu yolu hariç tutarak hafifletti; ayrıca `uiAccess` kısıtlı MSIX capability'si zaten admin kurulumu gerektiriyordu.

## Saldırı iş akışı (Prompt olmadan High IL elde etme)
1. İmzalı bir **UIAccess binary** elde et veya oluştur (manifest `uiAccess="true"`).
2. AppInfo’nun allowlist'inin kabul ettiği bir yere yerleştir (veya yukarıdaki yol-doğrulama kenar durumunu/yazılabilir artefaktı suistimal et).
3. `RAiLaunchAdminProcess` çağırarak onu UIAccess + yükseltilmiş IL ile **sessizce** başlat.
4. Bu High-IL foothold'dan, masaüstündeki başka bir High-IL süreci hedefle ve **window hooks/DLL injection** veya aynı-IL primitifleri ile admin bağlamını tamamen ele geçir.

## Yazılabilir aday yolları listeleme
Belirli bir token perspektifinden nominal olarak güvenli kökler içinde yazılabilir/üzerine yazılabilir nesneleri keşfetmek için PowerShell yardımcısını çalıştır:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Daha geniş görünürlük için Yönetici olarak çalıştırın; `-ProcessId`'i o token'ın erişimini yansıtacak düşük ayrıcalıklı bir sürece ayarlayın.
- Adayları `RAiLaunchAdminProcess` ile kullanmadan önce, bilinen izin verilmeyen alt dizinleri hariç tutmak için elle filtreleyin.

## İlgili

Secure Desktop erişilebilirlik kayıt defteri yayılımı LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referanslar
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
