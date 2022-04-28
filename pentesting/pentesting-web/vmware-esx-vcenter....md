# VMWare \(ESX, VCenter...\)

## Enumeration

```text
nmap -sV --script "http-vmware-path-vuln or vmware-version" -p <PORT> <IP>
msf> use auxiliary/scanner/vmware/esx_fingerprint
msf> use auxiliary/scanner/http/ms15_034_http_sys_memory_dump 
```

## Bruteforce

```text
msf> auxiliary/scanner/vmware/vmware_http_login
```

If you find valid credentials, you can use more metasploit scanner modules to obtain information.

