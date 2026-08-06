# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows Accessibility özellikleri kullanıcı yapılandırmasını HKCU altında saklar ve bunu oturum başına HKLM konumlarına aktarır. Bir **Secure Desktop** geçişi sırasında (kilit ekranı veya UAC istemi), **SYSTEM** bileşenleri bu değerleri yeniden kopyalar. **Oturum başına HKLM anahtarı kullanıcı tarafından yazılabilir durumdaysa**, bu anahtar ayrıcalıklı bir yazma choke point'ine dönüşür ve **registry symbolic links** ile başka bir hedefe yönlendirilebilir. Böylece **arbitrary SYSTEM registry write** elde edilir.<sup>[[1]](#references)</sup>

RegPwn tekniği, `osk.exe` tarafından kullanılan bir dosya üzerinde **opportunistic lock (oplock)** kullanarak küçük bir race window'ı kararlı hâle getirir ve bu propagation chain'i abuse eder.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Örnek özellik: **On-Screen Keyboard** (`osk`). İlgili konumlar şunlardır:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Secure desktop geçişi sırasında propagation chain (basitleştirilmiş):

1. **User `atbroker.exe`**, `HKCU\...\ATConfig\osk` değerini `HKLM\...\Session<session id>\ATConfig\osk` konumuna kopyalar.
2. **SYSTEM `atbroker.exe`**, `HKLM\...\Session<session id>\ATConfig\osk` değerini `HKU\.DEFAULT\...\ATConfig\osk` konumuna kopyalar.
3. **SYSTEM `osk.exe`**, `HKU\.DEFAULT\...\ATConfig\osk` değerini tekrar `HKLM\...\Session<session id>\ATConfig\osk` konumuna kopyalar.

Session HKLM subtree kullanıcı tarafından yazılabilir durumdaysa, 2/3. adımlar kullanıcının değiştirebileceği bir konum üzerinden SYSTEM write sağlar.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Kullanıcı tarafından yazılabilir per-session key'i, saldırganın seçtiği bir hedefi gösteren bir **registry symbolic link** ile değiştirin. SYSTEM copy gerçekleştiğinde link'i takip eder ve saldırganın kontrolündeki değerleri arbitrary target key'e yazar.

Temel fikir:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Saldırgan bu key'i başka herhangi bir key'e yönlendiren bir **registry link** ile değiştirir.
- SYSTEM copy işlemini gerçekleştirir ve saldırganın seçtiği key'e SYSTEM permissions ile yazar.

Bu, bir **arbitrary SYSTEM registry write** primitive'i sağlar.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

**SYSTEM `osk.exe`** başlatıldıktan sonra per-session key'e yazılana kadar kısa bir timing window bulunur. Bunu güvenilir hâle getirmek için exploit şu dosya üzerinde bir **oplock** oluşturur:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Oplock tetiklendiğinde attacker, oturum başına HKLM key'ini bir registry link ile değiştirir, SYSTEM write işleminin gerçekleşmesini bekler ve ardından link'i kaldırır.<sup>[[1]](#references)</sup>

## Örnek Exploitation Akışı (Yüksek Seviye)

1. Access token'dan mevcut **session ID** değerini alın.
2. Gizli bir `osk.exe` instance'ı başlatın ve kısa süre bekleyin (oplock'in tetikleneceğinden emin olmak için).
3. Attacker-controlled değerleri şu konuma yazın:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** ayarlayın.
5. **Secure Desktop**'ı (`LockWorkstation()`) tetikleyin; bu işlem SYSTEM `atbroker.exe` / `osk.exe` başlatır.
6. Oplock tetiklendiğinde, `HKLM\...\Session<session id>\ATConfig\osk` değerini arbitrary target'a işaret eden bir **registry link** ile değiştirin.
7. SYSTEM copy işleminin tamamlanması için kısa süre bekleyin, ardından link'i kaldırın.<sup>[[1]](#references)</sup>

## Primitive'i SYSTEM Execution'a Dönüştürme

Basit bir chain, bir **service configuration** değerinin (ör. `ImagePath`) üzerine yazmak ve ardından service'i başlatmaktır. RegPwn PoC, **`msiserver`** service'inin `ImagePath` değerinin üzerine yazar ve **MSI COM object**'ini instantiate ederek bunu tetikler; sonuç olarak **SYSTEM** code execution elde edilir.<sup>[[1]](#references)[[2]](#references)</sup>

## İlgili

Diğer Secure Desktop / UIAccess davranışları için bkz.:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
