# GCP - Compute & Network Enumeration

## Compute instances

It would be interesting if you can **get the zones** the project is using and the **list of all the running instances** and details about each of them.

The details may include:

* **Network info**: Internal and external IP addresses, network and subnetwork names and security group
* Custom **key/values in the metadata** of the instance
* **Protection** information like `shieldedInstanceConfig` and `shieldedInstanceIntegrityPolicy`
* **Screenshot** and the **OS** running
* Try to **ssh** into it and try to **modify** the **metadata**

```bash
# Get list of zones
## It's interesting to know which zones are being used
gcloud compute regions list | grep -E "NAME|[^0]/"

# List compute instances & get info
gcloud compute instances list
gcloud compute instances describe <instance name> --project <project name>
gcloud compute instances get-screenshot <instance name> --project <project name>
gcloud compute instances os-inventory list-instances #Get OS info of instances (OS Config agent is running on instances)

# Try to SSH & modify metadata
gcloud compute ssh <instance>
gcloud compute instances add-metadata [INSTANCE] --metadata-from-file ssh-keys=meta.txt
```

For more information about how to **SSH** or **modify the metadata** of an instance to **escalate privileges** check this page:

{% content-ref url="gcp-local-privilege-escalation-ssh-pivoting.md" %}
[gcp-local-privilege-escalation-ssh-pivoting.md](gcp-local-privilege-escalation-ssh-pivoting.md)
{% endcontent-ref %}

### Custom Metadata

Administrators can add [custom metadata](https://cloud.google.com/compute/docs/storing-retrieving-metadata#custom) at the instance and project level. This is simply a way to pass **arbitrary key/value pairs into an instance**, and is commonly used for environment variables and startup/shutdown scripts. This can be obtained using the `describe` method from a command in the previous section, but it could also be retrieved from the inside of the instance accessing the metadata endpoint.

```bash
# view project metadata
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"

# view instance metadata
curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"
```

### Serial Console Logs

Compute instances may be **writing output from the OS and BIOS to serial ports**. Serial console logs may expose **sensitive information** from the system logs which low privileged user may not usually see, but with the appropriate IAM permissions you may be able to read them.

You can use the following [gcloud command](https://cloud.google.com/sdk/gcloud/reference/compute/instances/get-serial-port-output) to query the serial port logs:

```
gcloud compute instances get-serial-port-output instance-name \
  --port port \
  --start start \
  --zone zone
```

```
$ gcloud compute images export --image test-image \
    --export-format qcow2 --destination-uri [BUCKET]
```

You can then [export](https://cloud.google.com/sdk/gcloud/reference/compute/images/export) the virtual disks from any image in multiple formats. The following command would export the image `test-image` in qcow2 format, allowing you to download the file and build a VM locally for further investigation:

```
$ gcloud compute images list --no-standard-images
```

## Images

### Custom Images

**Custom compute images may contain sensitive details **or other vulnerable configurations that you can exploit. You can query the list of non-standard images in a project with the following command:

```
gcloud compute images list --no-standard-images
```

You can then** **[**export**](https://cloud.google.com/sdk/gcloud/reference/compute/images/export)** the virtual disks **from any image in multiple formats. The following command would export the image `test-image` in qcow2 format, allowing you to download the file and build a VM locally for further investigation:

```
gcloud compute images export --image test-image \
    --export-format qcow2 --destination-uri [BUCKET]
```

More generic enumeration:

```bash
gcloud compute images list
gcloud compute images list --project windows-cloud --no-standard-images #non-Shielded VM Windows Server images
gcloud compute images list --project gce-uefi-images --no-standard-images #available Shielded VM images, including Windows images
```

### Custom Instance Templates

An [instance template](https://cloud.google.com/compute/docs/instance-templates/) defines instance properties to help deploy consistent configurations. These may contain the same types of sensitive data as a running instance's custom metadata. You can use the following commands to investigate:

```bash
# List the available templates
$ gcloud compute instance-templates list

# Get the details of a specific template
$ gcloud compute instance-templates describe [TEMPLATE NAME]
```
