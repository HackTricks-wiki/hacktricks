{{#include ../../banners/hacktricks-training.md}}

There are several blogs in the Internet which **highlight the dangers of leaving printers configured with LDAP with default/weak** logon credentials.\
This is because an attacker could **trick the printer to authenticate against a rouge LDAP server** (typically a `nc -vv -l -p 444` is enough) and to capture the printer **credentials on clear-text**.

Also, several printers will contains **logs with usernames** or could even be able to **download all usernames** from the Domain Controller.

All this **sensitive information** and the common **lack of security** makes printers very interesting for attackers.

Some blogs about the topic:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Printer Configuration

- **Location**: The LDAP server list is found at: `Network > LDAP Setting > Setting Up LDAP`.
- **Behavior**: The interface allows LDAP server modifications without re-entering credentials, aiming for user convenience but posing security risks.
- **Exploit**: The exploit involves redirecting the LDAP server address to a controlled machine and leveraging the "Test Connection" feature to capture credentials.

## Capturing Credentials

**For more detailed steps, refer to the original [source](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Method 1: Netcat Listener

A simple netcat listener might suffice:

```bash
sudo nc -k -v -l -p 386
```

However, this method's success varies.

### Method 2: Full LDAP Server with Slapd

A more reliable approach involves setting up a full LDAP server because the printer performs a null bind followed by a query before attempting credential binding.

1. **LDAP Server Setup**: The guide follows steps from [this source](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Key Steps**:
   - Install OpenLDAP.
   - Configure admin password.
   - Import basic schemas.
   - Set domain name on LDAP DB.
   - Configure LDAP TLS.
3. **LDAP Service Execution**: Once set up, the LDAP service can be run using:

```bash
slapd -d 2
```

## References

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}



