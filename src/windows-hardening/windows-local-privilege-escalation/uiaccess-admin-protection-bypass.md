# UIAccess üzerinden Admin Protection Bypass'leri

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış
- Windows AppInfo, erişilebilirlik amacıyla UIAccess uygulamalarını başlatmak için kullanılan dahili `RAiLaunchAdminProcess` yolunu dışa açar. UIAccess, User Interface Privilege Isolation (UIPI) sınırları arasındaki belirli etkileşimlere izin verir; her process-security sınırını aşmak için genel bir bypass değildir.<sup>[[1]](#references)[[3]](#references)</sup>
- UIAccess'i doğrudan etkinleştirmek için **SeTcbPrivilege** ile `NtSetInformationToken(TokenUIAccess)` gerekir; bu nedenle düşük yetkili çağıranlar service'e dayanır. Service, UIAccess'i ayarlamadan önce hedef binary üzerinde şu üç kontrolü gerçekleştirir:
- Embedded manifest, `uiAccess="true"` içerir.
- Local Machine root store tarafından trusted olan herhangi bir certificate ile imzalanmıştır (EKU/Microsoft gereksinimi yoktur).
- System drive üzerinde administrator-only bir path'te bulunur (ör. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`; belirli writable subpath'ler hariç).
- `RAiLaunchAdminProcess`, UIAccess launch'ları için consent prompt göstermez (aksi durumda accessibility tooling prompt'u kontrol edemezdi).<sup>[[1]](#references)</sup>

## Token şekillendirme ve integrity level'lar
- Kontroller başarılı olursa AppInfo, **caller token'ını kopyalar**, UIAccess'i etkinleştirir ve Integrity Level'ı (IL) yükseltir:
- Limited admin user (user Administrators grubunda ancak filtered olarak çalışıyor) ➜ **High IL**.
- Non-admin user ➜ IL, **High** sınırına kadar **+16 level** artırılır (System IL hiçbir zaman atanmaz).
- Caller token'ında zaten UIAccess varsa IL değiştirilmez.
- “Ratchet” trick: Bir UIAccess process kendi UIAccess'ini devre dışı bırakabilir, `RAiLaunchAdminProcess` üzerinden yeniden başlatabilir ve bir +16 IL artışı daha elde edebilir. Medium➜High için 255 relaunch gerekir (gürültülüdür, ancak çalışır).<sup>[[1]](#references)</sup>

## UIAccess neden bir Admin Protection escape sağlar?
- UIAccess, daha düşük IL'ye sahip bir process'in daha yüksek IL'ye sahip window'lara window message göndermesine izin verir (UIPI filter'larını bypass eder). **Aynı IL** seviyesinde, `SetWindowsHookEx` gibi klasik UI primitive'leri, bir window'a sahip herhangi bir process'e (**COM tarafından kullanılan message-only window'lar dahil**) code injection/DLL loading yapılmasına **izin verir**.
- Admin Protection, UIAccess process'ini **limited user'ın identity'siyle**, ancak sessizce **High IL** seviyesinde başlatır. Bu High-IL UIAccess process'inin içinde arbitrary code çalıştırıldığında attacker, desktop üzerindeki diğer High-IL process'lere (farklı user'lara ait olanlar dahil) inject olabilir ve amaçlanan ayrımı bozabilir.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ sürümlerinde API Win32k içine taşındı (`NtUserGetWindowProcessHandle`) ve caller tarafından sağlanan `DesiredAccess` değerini kullanarak bir process handle açabilir. Kernel path, normal user-mode access check'lerini bypass eden `ObOpenObjectByPointer(..., KernelMode, ...)` kullanır.<sup>[[2]](#references)</sup>
- Pratikteki ön koşullar: Hedef window aynı desktop üzerinde olmalı ve UIPI check'leri başarılı olmalıdır. Tarihsel olarak UIAccess'e sahip bir caller, UIPI failure'ı bypass edip yine de kernel-mode handle elde edebiliyordu (CVE-2023-41772 ile düzeltildi).
- Tarihsel etki: Bir window handle, caller'ın normalde elde edemeyeceği `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` veya `PROCESS_VM_OPERATION` gibi process access yetkileri için bir **capability** haline geldi. Belgelenen düzeltmelerden önce bu durum, hedefin bir window açığa çıkardığı sandbox ve protected-process sınırlarını aşabiliyordu; buna message-only window da dahildi.<sup>[[2]](#references)</sup>
- Pratik abuse flow: HWND'leri enumerate edin veya bulun (ör. `EnumWindows`/`FindWindowEx`), sahip PID'yi çözümleyin (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` çağrısını yapın, ardından dönen handle'ı memory read/write veya code-hijack primitive'leri için kullanın.
- Post-fix davranışı: UIAccess artık UIPI failure durumunda kernel-mode open işlemlerine izin vermez ve izin verilen access right'lar legacy hook set'iyle sınırlandırılmıştır; Windows 11 24H2, process-protection check'leri ve feature-flag'li daha güvenli path'ler ekler. UIPI'yi system-wide devre dışı bırakmak (`EnforceUIPI=0`) bu korumaları zayıflatır.<sup>[[2]](#references)</sup>

## Secure-directory validation zayıflıkları (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo, sağlanan path'i `GetFinalPathNameByHandle` üzerinden çözümler ve ardından hardcoded root/exclusion'lara karşı **string allow/deny check'leri** uygular. Bu basit validation'dan birden fazla bypass sınıfı kaynaklanır:
- **Directory named stream'leri**: Excluded writable directory'ler (ör. `C:\Windows\tracing`), directory'nin kendisinde named stream kullanılarak bypass edilebilir; ör. `C:\Windows\tracing:file.exe`. String check'leri `C:\Windows\` ifadesini görür ve excluded subpath'i kaçırır.
- **Allowed root içinde writable file/directory**: `CreateProcessAsUser`, `.exe` extension'ı **gerektirmez**. Allowed root altında bulunan herhangi bir writable file'ı executable payload ile overwrite etmek veya signed `uiAccess="true"` EXE'yi herhangi bir writable subdirectory'ye (ör. mevcut olduğunda `Tasks_Migrated` gibi update leftovers) kopyalamak, secure-path check'ini geçmesini sağlar.
- **`C:\Program Files\WindowsApps` içine MSIX (düzeltildi)**: Non-admin'ler, `WindowsApps` içine yerleşen signed MSIX package'ler kurabiliyordu; bu path excluded değildi. MSIX içine bir UIAccess binary package'leyip ardından `RAiLaunchAdminProcess` üzerinden başlatmak, **prompt'suz High-IL UIAccess process** oluşturuyordu. Microsoft bu path'i exclude ederek önlem aldı; `uiAccess` restricted MSIX capability'si zaten admin install gerektirir.<sup>[[1]](#references)</sup>

## Attack workflow (prompt olmadan High IL)
1. **Signed UIAccess binary** edinin/oluşturun (manifest `uiAccess="true"`). Gerçekçi bir assessment için trust material ve path'leri lab için açıkça authorize edilmiş şekilde test edin; production machine'ın Local Machine root store'una attacker certificate eklemeyin.
2. AppInfo allowlist'inin kabul ettiği konuma yerleştirin (veya yukarıdaki gibi bir path-validation edge case'ini/writable artifact'ı abuse edin).
3. UIAccess + elevated IL ile **sessizce** spawn etmek için `RAiLaunchAdminProcess` çağrısını yapın.
4. Bu High-IL foothold'dan, **window hook/DLL injection** veya diğer same-IL primitive'lerini kullanarak desktop üzerindeki başka bir High-IL process'i hedefleyin ve admin context'ini tamamen compromise edin.<sup>[[1]](#references)</sup>

## Candidate writable path'leri enumerate etme
Seçilen bir token perspektifinden nominal olarak secure root'lar içindeki writable/overwritable object'leri keşfetmek için PowerShell helper'ı çalıştırın:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Daha geniş görünürlük için Yönetici olarak çalıştırın; bu token’ın erişimini yansıtmak üzere `-ProcessId` değerini düşük ayrıcalıklı bir process olarak ayarlayın.
- `RAiLaunchAdminProcess` ile adayları kullanmadan önce bilinen izin verilmeyen alt dizinleri manuel olarak hariç tutun.

## İlgili

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [UI Access'i Kötüye Kullanarak Administrator Protection'ı Bypass Etme](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Derinlemesine İnceleme](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess uygulamaları](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
