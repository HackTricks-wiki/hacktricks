# PowerUp

## Invoke

```text
powershell -ep bypass
. .\powerup.ps
Invoke-AllChecks
```

## Checks

_03/2019_

* [x] Current privileges
* [x] Unquoted service paths
* [x] Service executable permissions
* [x] Service permissions
* [x] %PATH% for hijackable DLL locations
* [x] AlwaysInstallElevated registry key
* [x] Autologon credentials in registry
* [x] Modifidable registry autoruns and configs
* [x] Modifiable schtask files/configs
* [x] Unattended install files
* [x] Encrypted web.config strings
* [x] Encrypted application pool and virtual directory passwords
* [x] Plaintext passwords in McAfee SiteList.xml
* [x] Cached Group Policy Preferences .xml files

