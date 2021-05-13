# Interesting Windows Registry Keys

## **Windows system info**

### Version

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Windows version, Service Pack, Installation time and the registered owner

### Hostname

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Hostname

### Timezone

* **`System\ControlSet001\Control\TimeZoneInformation`**: TimeZone

### Last Access Time

* **`System\ControlSet001\Control \Filesystem`**: Last time access \(by default it's disabled with `NtfsDisableLastAccessUpdate=1`, if `0`, then, it's enabled\).
  * To enable it: `fsutil behavior set disablelastaccess 0`

### Shutdown Time

* `System\ControlSet001\Control\Windows`: Shutdown time
* `System\ControlSet001\Control\Watchdog\Display`: Shutdown count \(only XP\)

### Network Information

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Network interfaces
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: First and last time a network connection was performed and connections through VPN
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` \(for XP\) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Network type \(0x47-wireless, 0x06-cable, 0x17-3G\) an category \(0-Public, 1-Private/Home, 2-Domain/Work\) and last connections

### Shared Folders

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Share folders and their configurations. If **Client Side Caching** \(CSCFLAGS\) is enabled, then, a copy of the shared files will be saved in the clients in `C:\Windows\CSC` \(there are different options\)

### AutoStart programs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` 
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce` 
* `Software\Microsoft\Windows\CurrentVersion\Runonce` 
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` 
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Explorer Searches

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: What the user searched for using explorer/helper. The item with `MRU=0` is the last one.

### Typed Paths

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Paths types in the explorer \(only W10\)

### Recent Docs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: Recent documents opened by the user
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU`:Recent office docs. Versions:
  * 14.0 Office 2010
  * 12.0 Office 2007
  * 11.0 Office 2003
  * 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU`: Recent office docs. Versions:
  * 15.0 office 2013
  * 16.0 Office 2016

### MRUs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

Indicates the path from where the executable was executed

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` \(XP\)
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

Indicates files opened inside an opened Window

### Last Run Commands

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### User AssistKey

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

The GUID is the id of the application. Data saved:

* Last Run Time
* Run Count
* GUI application name \(this contains the abs path and more information\)
* Focus time and Focus name

## Shellbags

When you open a directory Windows saves data about how to visualize the directory in the registry. These entries are known as Shellbags.

Explorer Access: 

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Desktop Access:

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

To analyze the Shellbags you can use [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) ****and you will be able to find the **MAC time of the folder** and also the **creation date and modified date of the shellba**g which are related with the f**irst time the folder was accessed and the last time**.



