# JIRA

### Check Privileges

Inside a Jira instance **any user** \(even **non-authenticated**\) can **check its privileges** in `/rest/api/2/mypermissions` or `/rest/api/3/mypermissions` . These endpoints will return your current privileges.  
If a **non-authenticated** user have any **privilege**, this is a **vulnerability** \(bounty?\).  
If an **authenticated** user have any **unexpected privilege**, this a a **vuln**.

```bash
#Check non-authenticated privileges
curl https://jira.some.example.com/rest/api/2/mypermissions | jq | grep -iB6 '"havePermission": true'
```

### Check Exploits

Check and exploit JIRA vulnerabilities with [https://github.com/0x48piraj/Jiraffe](https://github.com/0x48piraj/Jiraffe)

