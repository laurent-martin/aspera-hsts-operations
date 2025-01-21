# IBM Aspera HSTS Operations

This document lists some common configuration on Aspera HSTS

## Configuration as tethered node in AoC

### Pre-requisites

In order to tether a self-managed node to Aspera on Cloud, the following are requited:

- A self-managed system with admin access, typically a Linux Virtual Machine
- A public IP address where this machine is reachable on a minimum of 2 TCP ports and 1 UDP port
- A DNS A record (FQDN) for that IP address (or use freedns)
- A TLS certificate for that FQDN (or use letsencypt: requires port TCP/443)
- The installation package for HSTS: for example:

  `ibm-aspera-hsts-4.4.5.1646-linux-64-release.rpm`

- An evaluation license file. For example:

  `87650-AsperaEnterprise-unlim.eval.aspera-license`

### Installation and configuration of tethered node

We assume here that a compatible Virtual Machine (or physical) is installed with a RHEL-compatible Linux distribution: RHEL, Rocky Linux, Alma Linux, etc...

> **Note:** The following commands are executed as `root` inside `root`'s home (`/root`).
> To impersonate root, execute: `sudo -i`
>
> **Note:** We need to generate some secrets of given length.
> Several tools can be used for random.
> For example we will use `tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40` to generate a 40 character random string.
> We could also use `openssl rand -base64 40|head -c 40` for the same.

For convenience, let's create a shell config file with parameters used:

```bash
test $(id -u) = 0 || echo "ERROR: execute as root"
variables_file=/root/aspera_vars.sh
aspera_rpm=./ibm-aspera-hsts-4.4.5.1646-linux-64-release.rpm
aspera_eval_lic=./87650-AsperaEnterprise-unlim.eval.aspera-license
aspera_os_user=xfer
aspera_home=/home/$aspera_os_user
aspera_storage_root=$aspera_home/aoc
aspera_node_user=node_admin
aspera_node_pass=$(tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40)
PATH=/opt/aspera/bin:$PATH
set|grep ^aspera_ > $variables_file
echo 'PATH=/opt/aspera/bin:$PATH' >> $variables_file
```

At any time, if you open a new terminal, you can reload the configuration variables with:

```bash
variables_file=/root/aspera_vars.sh
source $variables_file
```

Install the HSTS software:

```bash
rpm -Uvh --nodeps $aspera_rpm
```

> **Note:** `--nodeps` is to avoid having to install `perl`.

Install the license file in `/opt/aspera/etc/aspera-license`.
This file must be world-readable, or at least readable by `asperadaemons` and transfer users.

```bash
cp $aspera_eval_lic /opt/aspera/etc/aspera-license
chmod a+r /opt/aspera/etc/aspera-license
```

As Aspera uses SSH by default, a protection is provided with a secure shell: `aspshell`.
This shell can be declared as legitimate shell to avoid warning messages (optinal):

```bash
grep -qxF '/bin/aspshell' /etc/shells || echo '/bin/aspshell' >> /etc/shells
```

When used with AoC, only one transfer user is used: `xfer`.
Optionally we can create a group.
We make sure to block direct login with that user.
Create this user:

```bash
groupadd asperausers
useradd --create-home --no-user-group --gid asperausers --shell /bin/aspshell $aspera_os_user
passwd --lock $aspera_os_user
chage --mindays 0 --maxdays 99999 --inactive -1 --expiredate -1 $aspera_os_user
```

For a PoC, it can be easier to use a static token encryption key:

```bash
asconfigurator -x 'set_node_data;token_dynamic_key,false'
asconfigurator -x "set_node_data;token_encryption_key,$(tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40)"
```

If you prefer to use dynamic keys (skip this part if you like KISS):

```bash
asconfigurator -x 'set_node_data;token_dynamic_key,true'
asconfigurator -x 'set_node_data;token_encryption_key,AS_NULL'
tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40|askmscli -rs redis-primary-key
askmscli --init-keystore --user=$aspera_os_user
```

Configure this transfer user for use with tokens:

```bash
mkdir -p $aspera_home/.ssh
cp /opt/aspera/var/aspera_tokenauth_id_rsa.pub $aspera_home/.ssh/authorized_keys
chmod -R go-rwx $aspera_home/.ssh
chown -R $aspera_os_user: $aspera_home
```

Let's define the main storage location:

```bash
mkdir -p $aspera_storage_root
chown $aspera_os_user: $aspera_storage_root
asconfigurator -x "set_user_data;user_name,xfer;absolute,AS_NULL;file_restriction,|file:///$aspera_storage_root/*"
```

Aspera on Cloud requires activity logging:

```bash
asconfigurator -x 'set_server_data;activity_logging,true;activity_event_logging,true;activity_file_event_logging,true;activity_bandwidth_logging,true'
asconfigurator -x 'set_node_data;pre_calculate_job_size,yes;async_activity_logging,true'
```

Let's create a node API user and save the credentials:

```bash
/opt/aspera/bin/asnodeadmin -a -u $aspera_node_user -p $aspera_node_pass -x $aspera_os_user
systemctl restart asperanoded
```
