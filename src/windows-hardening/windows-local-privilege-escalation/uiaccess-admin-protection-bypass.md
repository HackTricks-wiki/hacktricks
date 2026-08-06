# UIAccess üzerinden Admin Protection Bypass'leri

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış
- Windows AppInfo, UIAccess processes oluşturmak için `RAiLaunchAdminProcess` işlevini sunar (erişilebilirlik amacıyla tasarlanmıştır). UIAccess, çoğu User Interface Privilege Isolation (UIPI) mesaj filtrelemesini bypass eder; böylece erişilebilirlik yazılımları daha yüksek IL'ye sahip arayüzleri kontrol edebilir.
- UIAccess'i doğrudan etkinleştirmek için **SeTcbPrivilege** ile `NtSetInformationToken(TokenUIAccess)` gerekir; bu nedenle düşük ayrıcalıklı çağıranlar service'e güvenir. Service, UIAccess'i ayarlamadan önce hedef binary üzerinde üç kontrol gerçekleştirir:
- Embedded manifest `uiAccess="true"` içerir.
- Local Machine root store tarafından güvenilen herhangi bir certificate ile imzalanmıştır (EKU/Microsoft şartı yoktur).
- System drive üzerindeki yalnızca administrator'ların yazabildiği bir path'te bulunur (ör. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`; belirli writable alt path'ler hariç).
- `RAiLaunchAdminProcess`, UIAccess launch'ları için consent prompt göstermez (aksi hâlde accessibility tooling prompt'u kontrol edemezdi).<sup>[[1]](#references)</sup>

## Token şekillendirme ve integrity level'lar
- Kontroller başarılı olursa AppInfo **caller token'ı kopyalar**, UIAccess'i etkinleştirir ve Integrity Level'ı (IL) yükseltir:
- Limited admin user (user Administrators grubunda ancak filtered olarak çalışıyor) ➜ **High IL**.
- Non-admin user ➜ IL, **High** sınırına kadar **+16 level** artırılır (System IL hiçbir zaman atanmaz).
- Caller token'ında zaten UIAccess varsa IL değiştirilmez.
- “Ratchet” trick: Bir UIAccess process, UIAccess'i kendi üzerinde devre dışı bırakabilir, `RAiLaunchAdminProcess` üzerinden yeniden launch edebilir ve bir +16 IL artışı daha kazanabilir. Medium➜High için 255 relaunch gerekir (gürültülüdür ancak çalışır).<sup>[[1]](#references)</sup>

## UIAccess neden Admin Protection escape sağlar?
- UIAccess, daha düşük IL'ye sahip bir process'in daha yüksek IL'ye sahip window'lara window message göndermesine izin verir (UIPI filtrelerini bypass ederek). **Aynı IL** seviyesinde, `SetWindowsHookEx` gibi klasik UI primitive'leri, bir window'a sahip herhangi bir process'e (**message-only windows** kullanan COM dahil) code injection/DLL loading yapılmasına izin verir.
- Admin Protection, UIAccess process'i **limited user'ın identity'siyle** ancak **High IL** seviyesinde, sessizce launch eder. Bu High-IL UIAccess process içinde arbitrary code çalışmaya başladıktan sonra attacker, desktop üzerindeki diğer High-IL process'lere (farklı user'lara ait olanlar dahil) inject olabilir ve amaçlanan ayrımı bozabilir.<sup>[[1]](#references)</sup>

## HWND'den process handle primitive'i (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ sürümlerinde API, Win32k içine taşındı (`NtUserGetWindowProcessHandle`) ve caller-supplied `DesiredAccess` kullanarak bir process handle açabilir. Kernel path, `ObOpenObjectByPointer(..., KernelMode, ...)` kullanır; bu da normal user-mode access check'lerini bypass eder.<sup>[[2]](#references)</sup>
- Pratikte ön koşullar: Hedef window aynı desktop üzerinde olmalı ve UIPI check'leri geçilmelidir. Geçmişte UIAccess sahibi bir caller, UIPI failure'ını bypass ederek yine de kernel-mode handle elde edebiliyordu (CVE-2023-41772 ile düzeltildi).
- Etki: Bir window handle, caller'ın normalde açamayacağı güçlü bir process handle elde etmek için bir **capability** hâline gelir (yaygın olarak `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`). Bu, cross-sandbox access sağlar ve hedef herhangi bir window (message-only windows dahil) expose ederse Protected Process / PPL sınırlarını bozabilir.
- Pratik abuse flow: HWND'leri enumerate edin veya bulun (ör. `EnumWindows`/`FindWindowEx`), sahip PID'yi çözümleyin (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` çağırın ve ardından döndürülen handle'ı memory read/write veya code-hijack primitive'leri için kullanın.
- Fix sonrası davranış: UIAccess artık UIPI failure durumunda kernel-mode open sağlamaz ve izin verilen access right'lar legacy hook set ile sınırlandırılmıştır; Windows 11 24H2 process-protection check'leri ve feature-flag'li daha güvenli path'ler ekler. UIPI'yi system-wide devre dışı bırakmak (`EnforceUIPI=0`) bu korumaları zayıflatır.<sup>[[2]](#references)</sup>

## Secure-directory validation zayıflıkları (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo, sağlanan path'i `GetFinalPathNameByHandle` üzerinden çözümler ve ardından hardcoded root/exclusion'lara karşı **string allow/deny check'leri** uygular. Bu basit validation'dan birden fazla bypass sınıfı ortaya çıkar:
- **Directory named streams**: Excluded writable directory'ler (ör. `C:\Windows\tracing`), directory'nin kendisi üzerinde named stream kullanılarak bypass edilebilir; ör. `C:\Windows\tracing:file.exe`. String check'leri `C:\Windows\` kısmını görür ve excluded subpath'i kaçırır.
- **Allowed root içinde writable file/directory**: `CreateProcessAsUser`, `.exe` extension'ı gerektirmez. Allowed root altında bulunan herhangi bir writable file'ı executable payload ile overwrite etmek veya signed `uiAccess="true"` EXE'yi herhangi bir writable subdirectory'ye (ör. mevcut olduğunda `Tasks_Migrated` gibi update leftovers) kopyalamak, secure-path check'ini geçmesini sağlar.
- **`C:\Program Files\WindowsApps` içine MSIX (düzeltildi)**: Non-admin'ler, `WindowsApps` içine yerleşen signed MSIX package'lar kurabiliyordu; bu path excluded değildi. MSIX içine bir UIAccess binary package'layıp `RAiLaunchAdminProcess` üzerinden launch etmek, **prompt'suz High-IL UIAccess process** elde edilmesini sağlıyordu. Microsoft bu path'i exclude ederek önlem aldı; `uiAccess` restricted MSIX capability'si zaten admin install gerektirir.<sup>[[1]](#references)</sup>

## Attack workflow (prompt olmadan High IL)
1. **Signed UIAccess binary** elde edin/oluşturun (`uiAccess="true"` manifest'i).
2. AppInfo'nun allowlist'inin kabul ettiği bir yere yerleştirin (veya yukarıdaki gibi bir path-validation edge case/writable artifact abuse edin).
3. UIAccess + elevated IL ile **sessizce** spawn etmek için `RAiLaunchAdminProcess` çağırın.
4. Bu High-IL foothold'dan, admin context'i tamamen compromise etmek için desktop üzerindeki başka bir High-IL process'i **window hooks/DLL injection** veya aynı IL seviyesindeki diğer primitive'leri kullanarak hedefleyin.<sup>[[1]](#references)</sup>

## Aday writable path'leri enumerate etme
Seçilen bir token perspektifinden nominal olarak secure root'lar içindeki writable/overwritable object'leri keşfetmek için PowerShell helper'ı çalıştırın:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Daha geniş görünürlük için Administrator olarak çalıştırın; bu token’ın erişimini yansıtmak üzere `-ProcessId` değerini düşük ayrıcalıklı bir process’e ayarlayın.
- `RAiLaunchAdminProcess` ile adayları kullanmadan önce, bilinen izin verilmeyen alt dizinleri manuel olarak hariç tutun.

## İlgili

Secure Desktop erişilebilirlik registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referanslar

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
