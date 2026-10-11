# Processes, Crontab, Systemd ve D-Bus

{{#include ../../banners/hacktricks-training.md}}

Zamanlanmış işler ve süreçler arası iletişim, çağırandan farklı ayrıcalıklara sahip kodları çalıştırabilir. Bir servisi veya işi test etmeden önce sahibini, komutunu ve yazılabilir girdilerini inceleyin.

- [Process numaralandırması ve servis yolları](process-enumeration-and-service-paths.md), süreç ağaçlarını, çalışma zamanı dosyalarını ve systemd yürütme zincirlerini kapsar.
- [Cron işleri ve systemd zamanlayıcıları](cron-and-systemd-timers.md), zamanlanmış görevlerin keşfini ve yazılabilir girdileri kapsar.
- [D-Bus numaralandırması ve komut enjeksiyonu ile privilege escalation](d-bus-enumeration-and-command-injection-privilege-escalation.md), mesaj veriyolunu ve ayrıcalıklı servis metotlarını kapsar.
- [Çalıştırılacak payload'lar](payloads-to-execute.md), bir yürütme yolu belirlendiğinde kullanılabilecek payload'ları derler.

Cron işlerini ve systemd servislerini daha kapsamlı incelemek için [Linux privilege escalation kontrol listesini](../main-system-information/linux-privilege-escalation-checklist.md) kullanın.
{{#include ../../banners/hacktricks-training.md}}
