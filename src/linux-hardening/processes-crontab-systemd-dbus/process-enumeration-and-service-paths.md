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

A locally reachable web interface can execute code with its service account even when the first shell cannot access that account's files. For example, CVE-2023-0297 affected pyLoad's `/flash/addcrypted2` handling when untrusted JavaScript reached Js2Py with Python imports enabled; the [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) disabled `pyimport`. Correlate the running process owner, listening address, endpoint exposure, and installed patch or vendor backport before treating a pyLoad process as an escalation path. A process name, open port, or package version alone does not prove exposure; passive enumeration should not send an execution payload.

### Privileged login shells sharing a terminal

A privileged interactive shell that runs `su --login <user>` without an independent pseudo-terminal may leave its terminal shared with the lower-privileged login shell. If that user's startup file is controllable and code in it can use `TIOCSTI` to inject terminal input, the input may reach the privileged shell when it resumes. [The util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) describes the shared-terminal risk and recommends `su --pty`/`-P` for interactive use; `su -c` starts a separate session without a controlling terminal. The risk requires the actual parent shell, terminal relationship, target startup file, and kernel policy. A process name or `su -l` argument alone is only a review lead.

Inspect the observed process tree and TTY columns, then the readable launcher and startup-file ownership/permissions. On Linux, `/proc/sys/dev/tty/legacy_tiocsti` can help interpret the policy when present; its absence is not proof of safety. [The Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) notes that since Linux 6.2 the operation may require `CAP_SYS_ADMIN` when this sysctl is false. Do not invoke the ioctl merely to enumerate the host.

A database account can sometimes alter the target user's startup file without direct filesystem write access. PostgreSQL server-side `COPY ... TO 'filename'` writes as the database server's OS account, but [PostgreSQL limits](https://www.postgresql.org/docs/current/sql-copy.html) this file form to database superusers or roles such as `pg_write_server_files`. Confirm both the database role and server OS file permissions; an application connection string alone does not grant file-write authority. Keep the privileged launcher and the database account's capabilities separate when assessing the chain.

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Deleted executables and deleted-but-open files remain referenced until their last descriptor closes. They can preserve evidence or accessible secrets. Process environments and memory may contain credentials, but reading another process is constrained by ownership, `/proc` mount options, Yama ptrace policy, and other security controls. See [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) and [post-exploitation credential hunting](../post-exploitation/README.md) for related techniques.

Saved syscall traces are another file-permission boundary. [`strace` records syscall arguments to an output file](https://man7.org/linux/man-pages/man1/strace.1.html), so a readable trace of [`execve` arguments](https://man7.org/linux/man-pages/man2/execve.2.html) may expose a password that a privileged job passed on its command line. First establish that the current user can read the particular trace and that the argument really contains a credential; a later Unix-account transition requires separate proof that the credential is accepted there. File metadata is a useful passive lead without scanning every trace or printing its contents during routine enumeration.

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

A separate local-file path exists when a lower-privileged user can **write and search** the directory named by a root-run agent's `-config-dir`: a new `.hcl` or `.json` service definition may be loaded from that directory. Directory search and write can permit adding a file even when listing the directory is denied. For root command execution, confirm the agent actually loads that directory, its **effective** script-check setting permits local definitions, the definition is loaded, and the agent keeps root privileges. [Consul documents](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) which settings and health-check definitions can reload; enabling script checks itself may require a restart, so verify the installed version's behavior. When ACLs protect the agent, [`consul reload` requires `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); KV write permission alone does not supply it. Treat writable directory metadata as a review cue, not proof of an authorized reload, restart, or command execution. Inspect paths, permissions, and policy without writing configuration or calling the API.

## Follow the service execution chain

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Check the unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories, and socket activation. A root-owned unit can still be unsafe if it reads a user-writable config or script. The [arbitrary file write](../interesting-files-permissions/write-to-root.md) page covers common service and unit abuse paths. Monitor short-lived jobs with [pspy](https://github.com/DominicBreuker/pspy) or audit/process telemetry when a one-time `ps` listing misses them.

For a custom **xinetd** service, correlate the enabled stanza's `server`, `user`, and access controls with the live listener and exact executable. The [`user` setting](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) chooses the spawned process identity, while a set-user-ID bit on the executable can separately change its effective identity if [`execve` permits that transition](https://man7.org/linux/man-pages/man2/execve.2.html). A reachable privileged binary that accepts untrusted input merits offline source or disassembly review for memory-safety bugs, such as an unbounded [`scanf` string conversion](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) into a fixed buffer. The service mapping and set-user-ID metadata are leads, not proof of such a bug; do not send crash inputs or debug the live privileged service during passive enumeration.

For a custom privileged listener with readable source, review each caller-controlled length used by a copy operation such as [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Checking only that the current write index is within a fixed buffer does not establish that the **copy length** fits the remaining space; verify `copy_length <= capacity - index` after confirming the index is in range, and check signedness and arithmetic overflow. This is a review lead only when the input reaches that operation, the listener is accessible to the lower-privileged user, and the process retains a higher effective identity. Inspect source and process metadata offline; do not send crash inputs to the live service during enumeration.

On systems using **Upstart**, system job definitions can reside under `/etc/init/*.conf`. A job file writable by the current user matters when the active init daemon loads that exact job, its `script` or `exec` stanza runs as a higher-privileged identity, and the user can start it through an allowed `initctl` command or another real trigger. A sudo `initctl` grant alone does not prove that any job file is writable or that a modified job will run. Check the exact job file permissions, effective run-as setting, active daemon, and trigger without editing or starting the job during enumeration. See the [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) and [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) manuals.

A readable autologin password file, such as `/etc/autologin/passwd` on systems whose [boot job reads that exact path](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), is a credential-exposure lead. Confirm the boot job is installed and uses the file, then verify separately whether the password is valid for another local account or service. The filename alone does not establish password reuse; record path and access metadata without putting the password into shared enumeration output.

A unit's `ExecStart=` or a scheduled command may reveal the exact pathname of a script inside an unlistable directory. [Directory search permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html) can still let the current identity traverse that known path; confirm search access on every parent and read permission on the file rather than assuming a failed directory listing protects it. A readable script may contain a transfer credential, but crossing to another account requires that credential to remain valid and be independently accepted there. Record the path and permission evidence without printing secret values into shared logs.

For a scheduled CommonJS Node.js script, review bare imports such as `require('package')` even when the script itself is read-only. [Node searches `node_modules` beside the importing file and then in its ancestor directories](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), before falling back to configured global paths. A lower-privileged user who can **write and search** one of those ancestor directories may be able to create an earlier-matching package. Confirm the exact import is reached, the selected package is not a built-in module, the relevant path can be created or changed, the module resolves there in the installed runtime, and a higher-privileged job will load it on a future invocation. Writable parent metadata is only a review cue; inspect the script and scheduler passively without planting a module or triggering the job.

A private Python package index is another trust boundary when an automated job installs packages under a different OS identity. Correlate the exact job and run-as account with its configured index, selected package names, and whether a lower-privileged user can publish or replace a package that the job will actually install. Building a source distribution may run its build backend or legacy `setup.py` under the installer's identity; importing the installed package is a separate execution path. An index listener, readable upload password hash, or package filename alone does not establish that chain. Review the job, index authorization, and package provenance without uploading or installing anything during enumeration. See [pip's build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) and [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/).

A privileged agent may poll a task queue managed by a separate web service or container. If a lower-trust identity can write the service's task database, determine whether those rows are actually served to that agent and whether a command task runs with the agent's OS identity. Confirm database write access, the target session or routing key, active polling, task authorization, and the agent's effective user separately. Root inside a container does not itself imply host-root access; the boundary is crossed only if a host-privileged consumer executes attacker-controlled task data. Inspect process, database-file, and service metadata without modifying the queue or sending a task during enumeration.

When a privileged Python service exposes a local HTTP or socket endpoint, a readable script can reveal an input-to-code path even if its file permissions prevent modification. Correlate the active process and unit identity with the exact script, listener, route authorization, and caller-controlled fields. Then trace those fields through parsing and validation to a dynamic `eval()` or `exec()` sink. In particular, constructing a new f-string from request text and evaluating it can interpret attacker-supplied replacement fields as Python expressions ([Python `eval` warning](https://docs.python.org/3/library/functions.html#eval); [f-string semantics](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). A bare `eval` match or loopback binding does not prove that an untrusted caller reaches the sink; review the actual dataflow and access controls without sending a test payload during enumeration.

An empty but writable `/etc/systemd/system/<unit>.service.d` directory matters even when the unit file and every existing drop-in are protected: the user may create a new `.conf` override. Check that the directory is writable and searchable by the current identity, the unit is loaded and runs as root, and whether a daemon reload followed by a restart will occur. A reload or restart permission, timer, or later boot can make the change effective; directory write access alone does not execute it immediately.

For running services, follow literal `EnvironmentFile=` paths from the unit's `[Service]` section, including files whose names do not start with `.env`. If a low-privilege user can read one, list credential-like key names such as `API_TOKEN` or `APP_SECRET_KEY` without printing the values into shared logs. Check drop-in overrides and optional `-` prefixes when assessing the effective unit. Readability is a credential-exposure lead; the value must still be valid for a privileged action to yield escalation.

### Privileged processing of untrusted uploads

A root-run file watcher can hand files from a user-writable upload directory to a short-lived parser or extractor. Follow the running watcher's parent script or service and confirm the exact directory, who can place files there, the child command and its arguments, and the identity under which the child runs. A process snapshot may show the watcher while missing the extractor between uploads. Do not place a test payload or trigger the watcher during passive enumeration.

One concrete example is Binwalk's extraction mode (`-e`) processing attacker-controlled PFS data. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) allowed the PFS extractor to write outside its intended directory, including a plugin path that Binwalk could later load. Upstream included the fix in [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), but distribution backports can retain an older displayed version; check the installed package's security status, such as the [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510), before judging applicability. An installed Binwalk version alone does not establish a privilege-escalation path: extraction must actually be invoked by a more privileged process on input the lower-privileged user can control.

### Scheduled builds with local dependencies

A scheduled `cargo run` recompiles source as the job's run-as user. Inspect the manifest's local `{ path = "..." }` dependencies and the source and parent-directory permissions of each dependency, not just the main crate. If a lower-privileged user can modify a dependency that Cargo compiles and the scheduled job runs its result, the compiled code can execute as that run-as user. Confirm the effective scheduler command, working directory, dependency resolution, and whether a rebuild will occur; a writable Rust source file elsewhere is only a lead. Reading the manifest and path metadata is enough for passive triage. See the [Cargo path-dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

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
