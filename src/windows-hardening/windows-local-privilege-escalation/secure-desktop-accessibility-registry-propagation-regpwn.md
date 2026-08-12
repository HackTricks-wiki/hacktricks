# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Accessibility özellikleri kullanıcı yapılandırmasını HKCU altında kalıcı hâle getirir ve bunu session başına HKLM konumlarına aktarır. Bir **Secure Desktop** geçişi (kilit ekranı veya UAC prompt'u) sırasında **SYSTEM** bileşenleri bu değerleri yeniden kopyalar. **per-session HKLM key** kullanıcı tarafından yazılabilir durumdaysa, bu key **registry symbolic links** ile yönlendirilebilen ayrıcalıklı bir write choke point'e dönüşür ve **arbitrary SYSTEM registry write** elde edilir.<sup>[[1]](#references)</sup>

RegPwn technique, bu propagation chain'i `osk.exe` tarafından kullanılan bir dosya üzerinde **opportunistic lock (oplock)** ile stabilize edilen küçük bir race window kullanarak istismar eder.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Örnek feature: **On-Screen Keyboard** (`osk`). İlgili konumlar şunlardır:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Bir secure desktop transition sırasında propagation (basitleştirilmiş):

1. **User `atbroker.exe`**, `HKCU\...\ATConfig\osk` değerini `HKLM\...\Session<session id>\ATConfig\osk` konumuna kopyalar.
2. **SYSTEM `atbroker.exe`**, `HKLM\...\Session<session id>\ATConfig\osk` değerini `HKU\.DEFAULT\...\ATConfig\osk` konumuna kopyalar.
3. **SYSTEM `osk.exe`**, `HKU\.DEFAULT\...\ATConfig\osk` değerini tekrar `HKLM\...\Session<session id>\ATConfig\osk` konumuna kopyalar.

Session HKLM subtree kullanıcı tarafından yazılabilir durumdaysa, 2/3. adımlar kullanıcının replace edebileceği bir konum üzerinden SYSTEM write sağlar.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

User-writable per-session key'i attacker tarafından seçilen bir destination'a işaret eden **registry symbolic link** ile değiştirin. SYSTEM copy gerçekleştiğinde link takip edilir ve attacker-controlled değerler arbitrary target key içine yazılır.

Temel fikir:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker bu key'i başka herhangi bir key'e yönlendiren bir **registry link** ile değiştirir.
- SYSTEM copy işlemini gerçekleştirir ve attacker tarafından seçilen key'e SYSTEM permissions ile yazar.

Bu, bir **arbitrary SYSTEM registry write** primitive'i sağlar.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

**SYSTEM `osk.exe`** başladıktan sonra per-session key'e write gerçekleştirmeden önce kısa bir timing window bulunur. Bunu reliable hâle getirmek için exploit şu konuma bir **oplock** yerleştirir:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Oplock tetiklendiğinde saldırgan, oturum başına HKLM anahtarını bir registry link ile değiştirir, SYSTEM tarafından yapılan yazma işleminin gerçekleşmesini bekler ve ardından linki kaldırır.<sup>[[1]](#references)</sup>

## Örnek Exploitation Akışı (Yüksek Düzey)

1. Access token'dan mevcut **session ID** değerini alın.
2. Gizli bir `osk.exe` örneği başlatın ve kısa süre bekleyin (oplock'un tetiklenmesini sağlayın).
3. Saldırgan tarafından kontrol edilen değerleri şuraya yazın:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** ayarlayın.
5. **Secure Desktop**'u (`LockWorkstation()`) tetikleyin; bu işlem SYSTEM yetkileriyle `atbroker.exe` / `osk.exe` başlatır.
6. Oplock tetiklendiğinde `HKLM\...\Session<session id>\ATConfig\osk` anahtarını, rastgele bir hedefe işaret eden bir **registry link** ile değiştirin.
7. SYSTEM tarafından yapılan kopyalama işleminin tamamlanması için kısa süre bekleyin, ardından linki kaldırın.<sup>[[1]](#references)</sup>

## Primitive'i SYSTEM Execution'a Dönüştürme

Basit bir zincir, bir **service configuration** değerinin (ör. `ImagePath`) üzerine yazmak ve ardından servisi başlatmaktır. RegPwn PoC, **`msiserver`** servisinin `ImagePath` değerinin üzerine yazar ve servisi **MSI COM object** örneği oluşturarak tetikler; bunun sonucunda **SYSTEM** code execution elde edilir.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## İlgili

Diğer Secure Desktop / UIAccess davranışları için bkz.:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
