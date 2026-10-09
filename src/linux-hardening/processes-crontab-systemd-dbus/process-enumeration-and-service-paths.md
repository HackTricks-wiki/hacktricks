# Process Enumeration and Service Paths

{{#include ../../banners/hacktricks-training.md}}

The useful question is which privileged process consumes data or code that a lower-privileged user can influence. Inspect the process tree, live environment, open files, and the unit or script that launched each candidate.

## Map processes and ownership

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

A cross-user parent-child relationship can be normal, but an unexpected transition warrants review of the parent command, arguments, executable, working directory, and referenced files. Use [users and sessions](../user-information/user-and-session-triage.md) to interpret the owner and login context.

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Deleted executables and deleted-but-open files remain referenced until their last descriptor closes. They can preserve evidence or accessible secrets. Process environments and memory may contain credentials, but reading another process is constrained by ownership, `/proc` mount options, Yama ptrace policy, and other security controls. See [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) and [post-exploitation credential hunting](../post-exploitation/README.md) for related techniques.

## Privileged office automation sockets

LibreOffice and OpenOffice can expose their UNO API through an `--accept=socket,host=<host>,port=<port>;urp;` argument. A root-owned office process with a reachable endpoint may let a lower-privileged local user invoke API services in that process's security context. The `SystemShellExecute` service includes an operation for launching a system command. Binding to loopback limits remote reachability but still leaves the socket reachable to local users unless another control prevents access.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Correlate the process owner, exact `--accept` argument, and current listening address and port. A configured acceptor that failed to bind is only a lead; do not connect to or invoke the API during passive enumeration. Avoid starting a privileged office instance merely to test this condition.

## System V shared memory consumed by privileged processes

A root-owned helper can create a System V shared-memory segment that another user can write. If the helper later trusts data from that segment in a shell command or another sensitive operation, the segment crosses a privilege boundary even when the executable and its files are protected. `shmget()` takes access permissions from the low nine bits of its flags; mode `0666` permits other users to write, whereas an `IPC_CREAT` flag does not narrow those permissions. Inspect active segments passively with `ipcs -m` and correlate their owner, mode, and lifetime with the privileged process and its input handling. A world-writable segment alone does not establish command execution.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments are distinct from POSIX shared-memory files under `/dev/shm`. A segment created for only a moment may be absent from a single `ipcs` snapshot, so empty output does not clear a helper that uses shared memory. Review its source or binary behavior and any `sudo` rule that launches it; do not invoke the privileged helper just to make a segment appear during enumeration. The [IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) explains how namespaces affect visibility.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul can run script health checks with the operating-system identity of its agent. If an agent runs as root, enables `enable_script_checks`, and permits a lower-privileged user to register a service with a script check through the local HTTP API, that user may cause root-run commands. Binding the API only to `127.0.0.1` still permits local users to reach it. The `enable_local_script_checks` setting is narrower: it excludes script checks submitted through HTTP API registrations. When Consul ACLs are enabled, service registration requires `service:write`; an `acl.default_policy=allow` line by itself does not prove that an anonymous caller can register. Review the actual agent identity, loaded settings, API binding, and authorization together.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Follow the running agent's `-config-dir` and `-config-file` arguments to the relevant configuration, and inspect only the script-check and ACL field names and settings. Configuration files may also contain gossip keys or tokens; avoid pasting them into shared logs. Do not register a service or run a health check merely to enumerate this condition.

## Follow the service execution chain

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Check the unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories, and socket activation. A root-owned unit can still be unsafe if it reads a user-writable config or script. The [arbitrary file write](../interesting-files-permissions/write-to-root.md) page covers common service and unit abuse paths. Monitor short-lived jobs with [pspy](https://github.com/DominicBreuker/pspy) or audit/process telemetry when a one-time `ps` listing misses them.

An empty but writable `/etc/systemd/system/<unit>.service.d` directory matters even when the unit file and every existing drop-in are protected: the user may create a new `.conf` override. Check that the directory is writable and searchable by the current identity, the unit is loaded and runs as root, and whether a daemon reload followed by a restart will occur. A reload or restart permission, timer, or later boot can make the change effective; directory write access alone does not execute it immediately.

For running services, follow literal `EnvironmentFile=` paths from the unit's `[Service]` section, including files whose names do not start with `.env`. If a low-privilege user can read one, list credential-like key names such as `API_TOKEN` or `APP_SECRET_KEY` without printing the values into shared logs. Check drop-in overrides and optional `-` prefixes when assessing the effective unit. Readability is a credential-exposure lead; the value must still be valid for a privileged action to yield escalation.

## Xvfb framebuffer files

`Xvfb -fbdir <directory>` uses memory-mapped files named `Xvfb_screen<n>` for its virtual screens. If another user's running Xvfb process names a directory whose screen files are readable by the current user, the framebuffer may expose that user's desktop content. Confirm the process, file ownership and permissions together; a readable file by itself does not prove that useful content is on the screen. Inspect paths and metadata first, without copying image data into shared enumeration output. The [Xvfb manual](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) documents the `-fbdir` behavior.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` manual](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` manual](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` manual](https://man.openbsd.org/ipcs.1)
4. [Consul agent configuration: script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent service registration API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL configuration](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice help: opening a socket for external API clients](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
