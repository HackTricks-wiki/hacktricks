# Interesting Windows Registry Keys

### Interesting Windows Registry Keys

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


### **Windows Version and Owner Info**
- Located at **`Software\Microsoft\Windows NT\CurrentVersion`**, you'll find the Windows version, Service Pack, installation time, and the registered owner's name in a straightforward manner.

### **Computer Name**
- The hostname is found under **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Time Zone Setting**
- The system's time zone is stored in **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Access Time Tracking**
- By default, the last access time tracking is turned off (**`NtfsDisableLastAccessUpdate=1`**). To enable it, use:
  `fsutil behavior set disablelastaccess 0`

### Windows Versions and Service Packs
- The **Windows version** indicates the edition (e.g., Home, Pro) and its release (e.g., Windows 10, Windows 11), while **Service Packs** are updates that include fixes and, sometimes, new features.

### Enabling Last Access Time
- Enabling last access time tracking allows you to see when files were last opened, which can be critical for forensic analysis or system monitoring.

### Network Information Details
- The registry holds extensive data on network configurations, including **types of networks (wireless, cable, 3G)** and **network categories (Public, Private/Home, Domain/Work)**, which are vital for understanding network security settings and permissions.

### Client Side Caching (CSC)
- **CSC** enhances offline file access by caching copies of shared files. Different **CSCFlags** settings control how and what files are cached, affecting performance and user experience, especially in environments with intermittent connectivity.

### AutoStart Programs
- Programs listed in various `Run` and `RunOnce` registry keys are automatically launched at startup, affecting system boot time and potentially being points of interest for identifying malware or unwanted software.

### Shellbags
- **Shellbags** not only store preferences for folder views but also provide forensic evidence of folder access even if the folder no longer exists. They are invaluable for investigations, revealing user activity that isn't obvious through other means.

### USB Information and Forensics
- The details stored in the registry about USB devices can help trace which devices were connected to a computer, potentially linking a device to sensitive file transfers or unauthorized access incidents.

### Volume Serial Number
- The **Volume Serial Number** can be crucial for tracking the specific instance of a file system, useful in forensic scenarios where file origin needs to be established across different devices.

### **Shutdown Details**
- Shutdown time and count (the latter only for XP) are kept in **`System\ControlSet001\Control\Windows`** and **`System\ControlSet001\Control\Watchdog\Display`**.

### **Network Configuration**
- For detailed network interface info, refer to **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- First and last network connection times, including VPN connections, are logged under various paths in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Shared Folders**
- Shared folders and settings are under **`System\ControlSet001\Services\lanmanserver\Shares`**. The Client Side Caching (CSC) settings dictate offline file availability.

### **Programs that Start Automatically**
- Paths like **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** and similar entries under `Software\Microsoft\Windows\CurrentVersion` detail programs set to run at startup.

### **Searches and Typed Paths**
- Explorer searches and typed paths are tracked in the registry under **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** for WordwheelQuery and TypedPaths, respectively.

### **Recent Documents and Office Files**
- Recent documents and Office files accessed are noted in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` and specific Office version paths.

### **Most Recently Used (MRU) Items**
- MRU lists, indicating recent file paths and commands, are stored in various `ComDlg32` and `Explorer` subkeys under `NTUSER.DAT`.

### **User Activity Tracking**
- The User Assist feature logs detailed application usage stats, including run count and last run time, at **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Shellbags Analysis**
- Shellbags, revealing folder access details, are stored in `USRCLASS.DAT` and `NTUSER.DAT` under `Software\Microsoft\Windows\Shell`. Use **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** for analysis.

### **USB Device History**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** and **`HKLM\SYSTEM\ControlSet001\Enum\USB`** contain rich details on connected USB devices, including manufacturer, product name, and connection timestamps.
- The user associated with a specific USB device can be pinpointed by searching `NTUSER.DAT` hives for the device's **{GUID}**.
- The last mounted device and its volume serial number can be traced through `System\MountedDevices` and `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, respectively.

This guide condenses the crucial paths and methods for accessing detailed system, network, and user activity information on Windows systems, aiming for clarity and usability.



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

