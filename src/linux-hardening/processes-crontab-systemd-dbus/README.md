# Süreçler, Crontab, Systemd ve D-Bus

{{#include ../../banners/hacktricks-training.md}}

Zamanlanmış işler ve süreçler arası iletişim, çağıranınkinden farklı ayrıcalıklara sahip kodları başlatabilir. Bir servisi veya işi test etmeden önce sahibini, komutunu ve yazılabilir girdilerini inceleyin.

- [Süreç numaralandırması ve servis yolları](process-enumeration-and-service-paths.md), süreç ağaçlarını, çalışma zamanı dosyalarını ve systemd yürütme zincirlerini ele alır.
- [Cron işleri ve systemd zamanlayıcıları](cron-and-systemd-timers.md), zamanlanmış görevlerin keşfini ve yazılabilir girdileri ele alır.
- [D-Bus numaralandırması ve command injection privilege escalation](d-bus-enumeration-and-command-injection-privilege-escalation.md), mesaj veri yolunu ve ayrıcalıklı servis metotlarını ele alır.
- [Çalıştırılacak Payloads](payloads-to-execute.md), bir yürütme yolu belirlendiğinde kullanılabilecek payload'ları bir araya getirir.

Cron işleri ve systemd servislerini daha kapsamlı incelemek için [Linux privilege escalation kontrol listesi](../main-system-information/linux-privilege-escalation-checklist.md)'ni kullanın.
{{#include ../../banners/hacktricks-training.md}}
