# Windows Forensics

## Windows 10 Notifications

In the path `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` you can find the database `appdb.dat` \(before Windows anniversary\)  or `wpndatabase.db` \(after Windows Anniversary\).

Inside this SQLite database you can find the `Notification` table with all the notifications \(in xml format\) that may contain interesting data.

## Timeline

Timeline is a Windows characteristic that provides **chronological history** of web pages visited, edited documents, executed applications...  
The database resides in the path `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`  
This database can be open with a SQLite tool or with the tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) ****which generates 2 files that can be opened with the tool [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

## Windows RecentAPPs

Inside the registry `NTUSER.DAT` in the path `Software\Microsoft\Current Version\Search\RecentApps` you can subkeys with information about the **application executed**, **last time** it was executed, and **number of times** it was launched.

## BAM

You can open the `SYSTEM` file with a registry editor and inside the path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` you can find the information about the **applications executed by each user** \(note the `{SID}` in the path\) and at **what time** they were executed \(the time is inside the Data value of the registry\).

## Windows Mail App

This application saves the emails in HTML or text. You can find the emails inside subfolders inside `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. The emails are saved with `.dat` extension.

The **metadata** of the emails and the **contacts** can be found inside the **EDB database**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Change the extension** of the file from `.vol` to `.edb` and you can use the tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) to open it. Inside the `Message` table you can see the emails.

## Plug and Play Cleanup

The 'Plug and Play Cleanup' scheduled task is responsible for **clearing** legacy versions of drivers. It would appear \(based upon reports online\) that it also picks up **drivers which have not been used in 30 days**, despite its description stating that "the most current version of each driver package will be kept". As such, **removable devices which have not been connected for 30 days may have their drivers removed**.   
The scheduled task itself is located at ‘C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup’, and its content is displayed below:

![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

The task references 'pnpclean.dll' which is responsible for performing the cleanup activity additionally we see that the ‘UseUnifiedSchedulingEngine’ field is set to ‘TRUE’ which specifies that the generic task scheduling engine is used to manage the task. The ‘Period’ and ‘Deadline’ values of 'P1M' and 'P2M' within ‘MaintenanceSettings’ instruct Task Scheduler to execute the task once every month during regular Automatic maintenance and if it fails for 2 consecutive months, to start attempting the task during.  
**This section was copied from** [**here**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**.**

## **Windows Store**

The installed applications can be found in `\ProgramData\Microsoft\Windows\AppRepository\`  
This repository has a **log** with **each application installed** in the system inside the database **`StateRepository-Machine.srd`**.

Inside the Application table of this database it's possible to find the columns: "Application ID", "PackageNumber", and "Display Name". This columns have information about pre-installed and installed applications and it can be found if some applications were uninstalled because the IDs of installed applications should be sequential.

It's also possible to **find installed application** inside the registry path: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`  
And **uninstalled** **applications** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

