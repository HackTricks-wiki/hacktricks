Standard system enumeration relies heavily on native binaries (`systeminfo.exe`, `net.exe`, `tasklist.exe`) or high-level PowerShell cmdlets (`Get-LocalUser`, `Get-WmiObject`).  While effective, these traditional methods can be conspicuous depending on the testing environment. For example spawning native executables triggers **Event ID 4688 (Process Creation)**,  exposing suspicious CLI arguments to EDRs, etc.

An alternative is to bypass these and directly interact with underlying **.NET Framework classes** from within an existing PowerShell session . By calling classes like `[System.Environment]` or `[System.Net.NetworkInformation]`, it's possible to perform comprehensive system reconnaissance entirely in-memory. This method avoids creating unnecessary child processes, evades standard CLI argument monitoring, and provides a critical living-off-the-land approach to mapping out the host with minimal forensic footprints.
# Core Enumeration Techniques
## System and Environment Reconnaissance
It's possible to directly query the `[System.Environment]` class to extract details about the host, domain context, and file system instead of calling `Get-WmiObject Win32_OperatingSystem` or `systeminfo.exe`
```
[System.Environment]::OSVersion.VersionString # Get Operating System version
[System.Environment]::MachineName # Get Machine Name 
[System.Environment]::UserDomainName # Get Domain Name
[System.Environment]::GetLogicalDrives() # Identify logical drives (useful for locating sensitive files)
[System.Environment]::GetEnvironmentVariables() # Map all environment variables (may reveal credentials or paths)
```
## Network and Port Enumeration
As an alternative to `netstat -ano` or `Get-NetTCPConnection` its possible to stay completely in-memory, by leveraging the `System.Net.NetworkInformation` namespace.
```
$ipProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
$ipProperties.GetActiveTcpConnections() | Where-Object { $_.State -eq 'Established' } | Select-Object LocalEndPoint, RemoteEndPoint # Enumerate Active TCP Connections (Established)
$ipProperties.GetActiveTcpListeners() | Select-Object Address, Port # Enumerate Listening Ports (Find local hidden services for LPE)
```
## Service Enumeration
Enumerate the vulnerable services using `System.ServiceProcess.ServiceController`. This is an alternative to `Get-Service` cmdlet.
```
[System.ServiceProcess.ServiceController]::GetServices() | Where-Object { $_.Status -eq 'Running' } | Select-Object ServiceName, DisplayName, ServiceType # List all Running services

[System.ServiceProcess.ServiceController]::GetServices() | Where-Object { $_.Status -eq 'Stopped' } | Select-Object ServiceName, DisplayName # List all Stopped services
```
## Process Mapping
Identifying high-privileged processes or security agents usually requires `tasklist.exe` or `Get-Process`. As an alternative, possible to use `System.Diagnostics.Process` class for a quieter approach.
```
# List running processes, PIDs, and session IDs
[System.Diagnostics.Process]::GetProcesses() | Select-Object ProcessName, Id, SessionId, StartTime | Sort-Object ProcessName 
```
## Account and Group Enumeration
Querying the local SAM database is typically done through `net user` or `net localgroup`. It is possible to do this programmatically by loading the `System.DirectoryServices.AccountManagement` assembly.
```
Add-Type -AssemblyName System.DirectoryServices.AccountManagement # Load the required .NET assembly into the current runspace
$context = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Machine) # # Bind to the local machine context (SAM database)

# Enumerate All Local Users
$userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::new($context)
$searcher = [System.DirectoryServices.AccountManagement.PrincipalSearcher]::new($userPrincipal)
$searcher.FindAll() | Select-Object Name, Description, Enabled, LastLogon

# Enumerate Members of the Local Administrators Group
$group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context, "Administrators")
if ($null -ne $group) {
    $group.GetMembers() | Select-Object Name, PrincipalSource
}
```
## Security Context and Privileges
It's possible to retrieve the current token privileges using the `WindowsIdentity` and `WindowsPrincipal` classes as an instead of `whoami /all`
```
# Get the current user identity
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)

# Display Username and SID 
$identity.Name 
$identity.User.Value

# Check whether the current token has the enabled Administrators role (not a full integrity-level check)
$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

# Dump all group SIDs the current user belongs to (useful for token impersonation mapping) 
$identity.Groups.Value
```

# Detection and Defensive Considerations
Using .NET classes within an existing PowerShell process avoids additional child-process creation for these calls, but does not prevent logging of the PowerShell process or script activity. Modern defenses can also detect in-memory enumeration.
## PowerShell Script Block Logging (Event ID 4104)
If **Event ID 4104 (Deep Script Block Logging)** has been enabled within the `Microsoft-Windows-PowerShell/Operational` event log, the raw .NET classes will be recorded in plain text as they're loaded.

While script obfuscation can hide these calls, modern PowerShell implementations automatically log the deobfuscated just before execution if it detects possibly malicious patterns.

On the defensive side, rules should be monitoring Event ID 4104 for unexpected administrative assemblies being loaded (e.g., `System.DirectoryServices.AccountManagement`) by standard users.
## Anti-Malware Scan Interface (AMSI)
AMSI is an interface between the scripting engine (PowerShell, VBScript, etc.) and the host antivirus/EDR solutions. Before executing script blocks, their contents are sent to to AMSI for inspection.

If the EDR behavioral signatures identifying a dense cluster of enumeration-focused .NET classes(e.g. chaining `WindowsIdentity` with `ServiceController`) AMSI could block the execution and flag activity

These techniques may be detected or blocked by AMSI; using .NET classes does not guarantee evasion.
## Event Tracing for Windows (ETW)
EDR solutions do not rely on PowerShell logging alone as they can hook directly into ETW. The .NET Common Language Runtime (CLR) has its own ETW provider (`Microsoft-Windows-DotNETRuntime`).

ETW provides deep visibility into **Assembly Loads**, **Method Executions**, and **Interop calls** living in-memory.

Even if the enumeration is done using a custom C# loader (like Cobalt Strike's `execute-assembly`) to bypass `powershell.exe` entirely, ETW telemetry can still expose the malicious process loading `System.DirectoryServices` or querying `NetworkInformation`.
