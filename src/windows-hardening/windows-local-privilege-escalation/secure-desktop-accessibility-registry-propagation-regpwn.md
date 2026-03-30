# Secure Desktop Erişilebilirlik Kayıt Defteri Yayılımı LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Windows Accessibility özellikleri kullanıcı yapılandırmasını HKCU altında saklar ve bunu oturum başına HKLM konumlarına yayar. Bir **Secure Desktop** geçişi (kilit ekranı veya UAC istemi) sırasında **SYSTEM** bileşenleri bu değerleri yeniden kopyalar. Eğer **oturum başına HKLM anahtarı kullanıcı tarafından yazılabilirse**, bu, kullanıcı tarafından yönlendirilebilen ayrıcalıklı bir yazma darboğazı haline gelir; bu da **registry symbolic links** ile yönlendirilebilir ve sonuçta bir **arbitrary SYSTEM registry write** oluşur.

RegPwn tekniği, bu yayılım zincirini `osk.exe` tarafından kullanılan bir dosyada bir **opportunistic lock (oplock)** ile stabilize edilen küçük bir yarış penceresiyle suistimal eder.

## Kayıt Defteri Yayılım Zinciri (Accessibility -> Secure Desktop)

Örnek özellik: **On-Screen Keyboard** (`osk`). İlgili konumlar:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Güvenli masaüstü geçişi sırasında yayılma (basitleştirilmiş):

1. **Kullanıcı `atbroker.exe`** `HKCU\...\ATConfig\osk` öğesini `HKLM\...\Session<session id>\ATConfig\osk` konumuna kopyalar.
2. **SYSTEM `atbroker.exe`** `HKLM\...\Session<session id>\ATConfig\osk` öğesini `HKU\.DEFAULT\...\ATConfig\osk` konumuna kopyalar.
3. **SYSTEM `osk.exe`** `HKU\.DEFAULT\...\ATConfig\osk` öğesini tekrar `HKLM\...\Session<session id>\ATConfig\osk` konumuna kopyalar.

Eğer oturum HKLM alt ağacı kullanıcı tarafından yazılabilirse, adım 2/3 kullanıcı tarafından değiştirilebilen bir konum üzerinden SYSTEM yazması sağlar.

## Temel: Kayıt Defteri Bağlantıları ile Rastgele SYSTEM Kayıt Defteri Yazma

Kullanıcı tarafından yazılabilir oturum anahtarını, saldırganın seçtiği hedefe işaret eden bir **registry symbolic link** ile değiştirin. SYSTEM kopyalaması gerçekleştiğinde, bağlantıyı takip eder ve saldırganın kontrolündeki değerleri keyfi hedef anahtara yazar.

Ana fikir:

- Kurbandaki yazma hedefi (kullanıcı tarafından yazılabilir):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Saldırgan bu anahtarı herhangi bir başka anahtara işaret eden bir **registry link** ile değiştirir.
- SYSTEM kopyalamayı gerçekleştirir ve SYSTEM izinleriyle saldırganın seçtiği anahtara yazar.

Bu, bir **arbitrary SYSTEM registry write** ilkelini sağlar.

## Oplocks ile Yarış Penceresini Kazanma

**SYSTEM `osk.exe`**'nin başlaması ile oturum anahtarını yazması arasında kısa bir zaman penceresi vardır. Bunu güvenilir hale getirmek için exploit şu dosya üzerinde bir **oplock** yerleştirir:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
When the oplock triggers, saldırgan per-session HKLM anahtarını bir registry link ile değiştirir, SYSTEM'in yazmasına izin verir ve ardından linki kaldırır.

## Example Exploitation Flow (High Level)

1. access token'dan mevcut **session ID**'yi al.
2. Gizli bir `osk.exe` örneği başlat ve kısa süre bekle (oplock'ın tetikleneceğinden emin ol).
3. Saldırgan kontrollü değerleri şu anahtara yaz:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** ayarla.
5. **Secure Desktop**'ı (`LockWorkstation()`) tetikle; bu, SYSTEM `atbroker.exe` / `osk.exe`'in başlamasına neden olur.
6. Oplock tetiklendiğinde, `HKLM\...\Session<session id>\ATConfig\osk`'u rastgele bir hedefe işaret eden bir **registry link** ile değiştir.
7. SYSTEM kopyasının tamamlanmasını kısa süre bekle, sonra linki kaldır.

## Converting the Primitive to SYSTEM Execution

Basit bir yol, bir **service configuration** değerini (ör. `ImagePath`) üzerine yazmak ve ardından servisi başlatmaktır. RegPwn PoC, **`msiserver`**'in `ImagePath`'ini değiştirir ve **MSI COM object**'i örnekleyerek tetikler; sonuç olarak **SYSTEM** kod yürütülür.

## Related

Diğer Secure Desktop / UIAccess davranışları için bkz:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
