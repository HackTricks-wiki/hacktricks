# Interesting Windows Registry Keys

## Interesting Windows Registry Keys

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Windows system info**

### Version

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Windows version, Service Pack, Installation time and the registered owner

### Hostname

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Hostname

### Timezone

* **`System\ControlSet001\Control\TimeZoneInformation`**: TimeZone

### Last Access Time

* **`System\ControlSet001\Control\Filesystem`**: Last time access (by default it's disabled with `NtfsDisableLastAccessUpdate=1`, if `0`, then, it's enabled).
  * To enable it: `fsutil behavior set disablelastaccess 0`

### Shutdown Time

* `System\ControlSet001\Control\Windows`: Shutdown time
* `System\ControlSet001\Control\Watchdog\Display`: Shutdown count (only XP)

### Network Information

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Network interfaces
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: First and last time a network connection was performed and connections through VPN
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (for XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Network type (0x47-wireless, 0x06-cable, 0x17-3G) an category (0-Public, 1-Private/Home, 2-Domain/Work) and last connections

### Shared Folders

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Share folders and their configurations. If **Client Side Caching** (CSCFLAGS) is enabled, then, a copy of the shared files will be saved in the clients and server in `C:\Windows\CSC`
  * CSCFlag=0 -> By default the user needs to indicate the files that he wants to cache
  * CSCFlag=16 -> Automatic caching documents. “All files and programs that users open from the shared folder are automatically available offline” with the “optimize for performance" unticked.
  * CSCFlag=32 -> Like the previous options by “optimize for performance” is ticked
  * CSCFlag=48 -> Cache is disabled.
  * CSCFlag=2048: This setting is only on Win 7 & 8 and is the default setting until you disable “Simple file sharing” or use the “advanced” sharing option. It also appears to be the default setting for the “Homegroup”
  * CSCFlag=768 -> This setting was only seen on shared Print devices.

### AutoStart programs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Explorer Searches

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: What the user searched for using explorer/helper. The item with `MRU=0` is the last one.

### Typed Paths

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Paths types in the explorer (only W10)

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

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
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
* GUI application name (this contains the abs path and more information)
* Focus time and Focus name

## Shellbags

When you open a directory Windows saves data about how to visualize the directory in the registry. These entries are known as Shellbags.

Explorer Access:

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Desktop Access:

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

To analyze the Shellbags you can use [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) and you will be able to find the\*\* MAC time of the folder **and also the** creation date and modified date of the shellbag which are related to the\*\* first time and the last time\*\* the folder was accessed.

Note 2 things from the following image:

1. We know the **name of the folders of the USB** that was inserted in **E:**
2. We know when the **shellbag was created and modified** and when the folder was created and accessed

![](<../../../.gitbook/assets/image (475).png>)

## USB information

### Device Info

The registry `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR` monitors each USB device that has been connected to the PC.\
Within this registry it's possible to find:

* The manufacturer's name
* The product name and version
* The Device Class ID
* The volume name (in the following images the volume name is the highlighted subkey)

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

Moreover, by checking the registry `HKLM\SYSTEM\ControlSet001\Enum\USB` and comparing the values of the sub-keys it's possible to find the VID value.

![](<../../../.gitbook/assets/image (478).png>)

With the previous information the registry `SOFTWARE\Microsoft\Windows Portable Devices\Devices` can be used to obtain the **`{GUID}`**:

![](<../../../.gitbook/assets/image (480).png>)

### User that used the device

Having the **{GUID}** of the device it's now possible to **check all the NTUDER.DAT hives of all the users**, searching for the GUID until you find it in one of them (`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`).

![](<../../../.gitbook/assets/image (481).png>)

### Last mounted

Checking the registry `System\MoutedDevices` it's possible to find out **which device was the last one mounted**. In the following image check how the last device mounted in `E:` is the Toshiba one (using the tool Registry Explorer).

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### Volume Serial Number

In `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` you can find the volume serial number. **Knowing the volume name and the volume serial number you can correlate the information** from LNK files that uses that information.

Note that when a USB device is formatted:

* A new volume name is created
* A new volume serial number is created
* The physical serial number is kept

### Timestamps

In `System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\` you can find the first and last time the device was connected:

* 0064 -- First connection
* 0066 -- Last connection
* 0067 -- Disconnection

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
