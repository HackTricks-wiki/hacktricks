# Ağ Bilgileri

{{#include ../../banners/hacktricks-training.md}}

Yerel dinleyiciler, Unix socket'leri ve ağa açık yazılımlar, dış taramalarda görünmeyen yolları açığa çıkarabilir. Önce ana makinenin dinleme yapan servislerini ve her uç noktaya sahip olan süreci inceleyin.

- [Trafik yakalama, güvenlik duvarı ve dış bağlantı triyajı](traffic-capture-and-firewall-egress.md) paket yakalama, filtreleme, proxy'ler ve bağlantı testlerini kapsar.
- [Yerel ağ ve socket triyajı](local-network-and-socket-triage.md) loopback servislerini, Unix socket'lerini ve container ağlarını kapsar.
- [Socket command injection](socket-command-injection.md) açık yerel socket'ler üzerinden kabul edilen komutları kapsar.
- Cisco SD-WAN Manager cihazlarına erişim sağlamak için [vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md) sayfasına bakın; ConfD CLI, REST API ve root tarafından sahip olunan içe aktarma yolları, genel socket triyajından farklıdır.
{{#include ../../banners/hacktricks-training.md}}
