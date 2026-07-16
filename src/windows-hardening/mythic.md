# Mythic

{{#include ../banners/hacktricks-training.md}}

## What is Mythic?

Mythic is an open-source, modular, collaborative command and control (C2) framework designed for red teaming. It allows operators to manage and deploy agents (payloads) across different operating systems, including Windows, Linux, and macOS. Mythic provides a browser UI for multi-operator tasking, file handling, SOCKS/rpfwd management, and payload generation.

Unlike monolithic frameworks, the Mythic repository itself does **not** ship payload types or C2 profiles. Agents, wrappers, and C2 profiles are typically installed as external components and can be updated independently from Mythic core.

### Installation

To install Mythic, follow the instructions on the official **[Mythic repo](https://github.com/its-a-feature/Mythic)**. A common bootstrap from the Mythic directory is:

```bash
sudo make
sudo ./mythic-cli start
```

If Mythic is already running, you can normally add a new agent or profile with `./mythic-cli install github ...` and then either restart Mythic or just start the new component directly.

### Agents

Mythic supports multiple agents, which are the **payloads that perform tasks on the compromised systems**. Each agent can be tailored to specific needs and can run on different operating systems.

By default Mythic doesn't have any agents installed. The open-source community agents live in [**https://github.com/MythicAgents**](https://github.com/MythicAgents), and the [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) is useful to quickly check supported operating systems, payload formats, wrappers, and C2 profiles.

To install an agent from that org you can run:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

The `sudo -E` form is useful when you are installing from a non-root environment. You can add new agents with the previous command even if Mythic is already running.

### C2 Profiles

C2 profiles in Mythic define **how agents communicate with the Mythic server**. They specify the communication protocol, encryption methods, and other settings. You can create and manage C2 profiles through the Mythic web interface.

By default Mythic is installed with no profiles, however, it's possible to download some profiles from the repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) running:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Current platform notes

- Many public agents and profiles now install with pre-built remote container images.
  If you fork a component or patch it locally and Mythic keeps using the old
  behavior, inspect the generated `.env` entries for `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT`, and `*_USE_VOLUME`; enabling
  `*_USE_BUILD_CONTEXT="true"` is usually what makes Mythic rebuild from your
  local Docker context instead of silently reusing the remote image.
- Browser scripts are one of Mythic's highest-value quality-of-life features
  for operators: they can turn raw command output into tables, screenshot
  viewers, download links, and buttons that issue follow-on tasking directly
  from the UI. This is especially useful for repetitive `ls`, `ps`, triage,
  and file-browser workflows.
- Newer Mythic builds also support interactive tasking and Push C2 patterns
  that reduce the need for `sleep 0` polling during PTY/SOCKS/rpfwd-heavy
  operations. When an agent/profile supports it, this is usually lower-overhead
  than hammering the server with constant check-ins just to keep an interactive
  channel usable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Current build/profile notes

- Apollo can currently emit `WinExe`, `Shellcode`, `Service`, and `Source` payloads.
- The commonly used Apollo profiles are `http`, `httpx`, `smb`, `tcp`, and `websocket`.
- `httpx` is usually the more flexible option when you need domain rotation, proxy support, custom message placement, and message transforms instead of the older static `http` profile.
- Apollo supports wrapper payloads such as `service_wrapper` and `scarecrow_wrapper`.
- `register_file` and `register_assembly` are the staging primitives for `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, and `powerpick`. In current Apollo builds, those staged artifacts are cached client-side as DPAPI-protected AES256 blobs.
- `ls` and `ps` results integrate especially well with Mythic's browser scripts and file/process browser, which makes operator triage noticeably faster in collaborative operations.
- Apollo's fork-and-run jobs inherit their sacrificial process settings from
  `spawnto_x86` / `spawnto_x64`, inherit parent selection from `ppid`, and
  then use the currently selected injection primitive. In practice, this means
  your OPSEC tuning for one command often affects `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, and `spawn` at the
  same time.
- Current documented Apollo injection backends include `CreateRemoteThread`,
  `QueueUserAPC` (early-bird style), and `NtCreateThreadEx` via syscalls. Use
  `get_injection_techniques` before noisy post-exploitation and
  `set_injection_technique` if you need to swap away from a primitive that
  clashes with the target or the command you want to run.
- `blockdlls` only affects sacrificial processes created for post-exploitation
  jobs. Combined with a less suspicious `spawnto_x64` target than the default
  bare `rundll32.exe`, this is one of the easiest Apollo-side changes to make
  before running assembly/PowerShell-heavy tasking.

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: Print the contents of a file
- `cd`: Change the current working directory
- `cp`: Copy a file from one location to another
- `ls`: List files and directories in the current directory or specified path
- `ifconfig`: Get network adapters and interfaces
- `netstat`: Get TCP and UDP connection information
- `pwd`: Print the current working directory
- `ps`: List running processes on the target system (with added info)
- `jobs`: List all running jobs associated with long-running tasking
- `download`: Download a file from the target system to the local machine
- `upload`: Upload a file from the local machine to the target system
- `reg_query`: Query registry keys and values on the target system
- `reg_write_value`: Write a new value to a specified registry key
- `sleep`: Change the agent's sleep interval, which determines how often it checks in with the Mythic server
- And many others, use `help` to see the full list of available commands.

### Privilege escalation

- `getprivs`: Enable as many privileges as possible on the current thread token
- `getsystem`: Open a handle to winlogon and duplicate the token, effectively escalating privileges to SYSTEM level
- `make_token`: Create a new logon session and apply it to the agent, allowing for impersonation of another user
- `steal_token`: Steal a primary token from another process, allowing the agent to impersonate that process's user
- `pth`: Pass-the-Hash attack, allowing the agent to authenticate as a user using their NTLM hash without needing the plaintext password
- `mimikatz`: Run Mimikatz commands to extract credentials, hashes, and other sensitive information from memory or the SAM database
- `rev2self`: Revert the agent's token to its primary token, effectively dropping privileges back to the original level
- `ppid`: Change the parent process for post-exploitation jobs by specifying a new parent process ID, allowing for better control over job execution context
- `printspoofer`: Execute PrintSpoofer commands to bypass print spooler security measures, allowing for privilege escalation or code execution
- `dcsync`: Sync a user's Kerberos keys to the local machine, allowing for offline password cracking or further attacks
- `ticket_cache_add`: Add a Kerberos ticket to the current logon session or a specified one, allowing for ticket reuse or impersonation

### Process execution

- `assembly_inject`: Allows to inject a .NET assembly loader into a remote process
- `blockdlls`: Block non-Microsoft signed DLLs from loading into post-exploitation jobs
- `execute_assembly`: Executes a .NET assembly in the context of the agent
- `execute_coff`: Executes a COFF file in memory, allowing for in-memory execution of compiled code
- `execute_pe`: Executes an unmanaged executable (PE)
- `keylog_inject`: Injects a keylogger into another process and streams keystrokes back into Mythic's keylog view
- `screenshot` / `screenshot_inject`: Capture the current desktop directly or
  by injecting a screenshot assembly into a target process/session
- `get_injection_techniques`: Show available injection techniques and the currently selected one
- `inline_assembly`: Executes a .NET assembly in a disposable AppDomain, allowing for temporary execution of code without affecting the agent's main process
- `register_assembly`: Register a .NET assembly for later execution
- `register_file`: Register a file in the agent cache for later `execute_*` or PowerShell tasking
- `run`: Executes a binary on the target system, using the system's PATH to find the executable
- `set_injection_technique`: Change the injection primitive used by post-exploitation jobs
- `shinject`: Injects shellcode into a remote process, allowing for in-memory execution of arbitrary code
- `inject`: Injects agent shellcode into a remote process, allowing for in-memory execution of the agent's code
- `spawn`: Spawns a new agent session in the specified executable, allowing for the execution of shellcode in a new process
- `spawnto_x64` and `spawnto_x86`: Change the default binary used in post-exploitation jobs to a specified path instead of using `rundll32.exe` without params which is very noisy.

### Mythic Forge

This allows to **load COFF/BOF** files from the Mythic Forge, which is a repository of pre-compiled payloads and tools that can be executed on the target system. With all the commands that can be loaded it'll be possible to perform common actions executing them in the current agent process as BOFs (usually with better OPSEC than spawning a separate process).

Start installing them with:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Then, use `forge_collections` to show the COFF/BOF modules from the Mythic Forge to be able to select and load them into the agent's memory for execution. By default, the following 2 collections are added in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

After one module is loaded, it'll appear in the list as another command like `forge_bof_sa-whoami` or `forge_bof_sa-netuser`.

For BOFs, remember that Forge does **not** just pass one flat argument string
 to Apollo. It maps BOF parameters into Mythic's typed-array format and then
 forwards them into Apollo's `execute_coff` flow. If a Forge-loaded BOF behaves
 strangely, check the expected BOF argument types / entrypoint rather than only
 the command line you typed.

### PowerShell & scripting execution

- `powershell_import`: Imports a new PowerShell script (.ps1) into the agent cache for later execution
- `powershell`: Executes a PowerShell command in the context of the agent, allowing for advanced scripting and automation
- `powerpick`: Injects a PowerShell loader assembly into a sacrificial process and executes a PowerShell command (without powershell logging).
- `psinject`: Executes PowerShell in a specified process, allowing for targeted execution of scripts in the context of another process
- `shell`: Executes a shell command in the context of the agent, similar to running a command in cmd.exe

### Lateral Movement

- `jump_psexec`: Uses the PsExec technique to move laterally to a new host by first copying over the Apollo agent executable (apollo.exe) and executing it.
- `jump_wmi`: Uses the WMI technique to move laterally to a new host by first copying over the Apollo agent executable (apollo.exe) and executing it.
- `link` and `unlink`: Create and tear down P2P links (for example over SMB/TCP) between callbacks.
- `wmiexecute`: Executes a command on the local or specified remote system using WMI, with optional credentials for impersonation.
- `net_dclist`: Retrieves a list of domain controllers for the specified domain, useful for identifying potential targets for lateral movement.
- `net_localgroup`: Lists local groups on the specified computer, defaulting to localhost if no computer is specified.
- `net_localgroup_member`: Retrieves local group membership for a specified group on the local or remote computer, allowing for enumeration of users in specific groups.
- `net_shares`: Lists remote shares and their accessibility on the specified computer, useful for identifying potential targets for lateral movement.
- `socks`: Enables a SOCKS 5 compliant proxy on the target network, allowing for tunneling of traffic through the compromised host. Compatible with tools like proxychains.
- `rpfwd`: Starts listening on a specified port on the target host and forwards traffic through Mythic to a remote IP and port, allowing for remote access to services on the target network.
- `listpipes`: Lists all named pipes on the local system, which can be useful for lateral movement or privilege escalation by interacting with IPC mechanisms.

For the lower-level WMI execution primitives used underneath `jump_wmi` or `wmiexecute`, check [WmiExec](lateral-movement/wmiexec.md). For broader pivoting patterns, check [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Displays detailed information about specific commands or general information about all available commands in the agent.
- `clear`: Marks tasks as 'cleared' so they can't be picked up by agents. You can specify `all` to clear all tasks or `task Num` to clear a specific task.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is a Golang agent that compiles into **Linux and macOS** executables.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.
- `pty` is one of the most useful newer-quality-of-life commands for Linux/macOS
  operations because it opens an interactive PTY and can expose a Mythic-side
  port for fuller terminal interaction without resorting to the older `sleep 0`
  + SOCKS workaround.
- Poseidon's current docs are especially interesting for macOS-heavy
  tradecraft: `jxa` executes JavaScript for Automation in-memory,
  `screencapture` grabs the logged-in desktop, `clipboard_monitor` streams
  pasteboard changes, `execute_library` loads a local dylib and calls a
  function from it, and `libinject` forces a remote process to load an on-disk
  dylib.
- For long-running jobs, remember that Poseidon executes post-exploitation work
  in goroutines/threads that are cooperative rather than hard-killable. The
  docs also explicitly note that there is currently no built-in agent
  obfuscation, so build/profile-level tradecraft matters more than with heavily
  obfuscated commercial implants.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: Print the contents of a file
- `cd`: Change the current working directory
- `chmod`: Change the permissions of a file
- `config`: View current config and host information
- `cp`: Copy a file from one location to another
- `curl`: Execute a single web request with optional headers and method
- `upload`: Upload a file to the target
- `download`: Download a file from the target system to the local machine
- And many more

### Search Sensitive Information

- `triagedirectory`: Find interesting files within a directory on a host, such as sensitive files or credentials.
- `getenv`: Get all of the current environment variables.

### macOS-specific tradecraft

- `jxa`: Execute JavaScript for Automation in-memory via `OSAScript`, which is
  useful for native macOS post-exploitation without dropping separate script
  files.
- `clipboard_monitor`: Poll the pasteboard and report changes back to Mythic,
  which is handy for credential/token theft workflows that rely on copy/paste.
- `screencapture`: Capture the user's desktop on macOS.
- `execute_library`: Load a dylib from disk and call a specific exported function.
- `libinject`: Inject a shellcode stub that forces another macOS process to load a dylib from disk.
- `persist_launchd`: Create LaunchAgent / LaunchDaemon persistence directly from the agent.

### Move laterally

- `ssh`: SSH to host using the designated credentials and open a PTY without spawning ssh.
- `sshauth`: SSH to specified host(s) using the designated credentials. You can also use this to execute a specific command on the remote hosts via SSH or use it to SCP files.
- `link_tcp`: Link to another agent over TCP, allowing for direct communication between agents.
- `link_webshell`: Link to an agent using the webshell P2P profile, allowing for remote access to the agent's web interface.
- `rpfwd`: Start or Stop a Reverse Port Forward, allowing for remote access to services on the target network.
- `socks`: Start or Stop a SOCKS5 proxy on the target network, allowing for tunneling of traffic through the compromised host. Compatible with tools like proxychains.
- `portscan`: Scan host(s) for open ports, useful for identifying potential targets for lateral movement or further attacks.

### Process execution

- `shell`: Execute a single shell command via /bin/sh, allowing for direct execution of commands on the target system.
- `run`: Execute a command from disk with arguments, allowing for the execution of binaries or scripts on the target system.
- `pty`: Open up an interactive PTY, allowing for direct interaction with the shell on the target system.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
