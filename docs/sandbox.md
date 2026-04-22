# Local Sandboxing Install and Setup

## Prerequisites

CAPE is strongly encouraged to be installed on a **bare metal Linux machine**, not inside a VM. Running CAPE inside a VM (e.g. VirtualBox or WSL) might cause the hypervisor to fail as it requires direct access to CPU virtualization extensions. Dual-booting Ubuntu 24.04 alongside Windows is the recommended approach if your primary OS is Windows. If you are wanting to run it inside a VM, VMware Workstation Pro has been the most successful platform to do so.

---

## Installing CAPE and the Hypervisor

A script to install KVM, Virtual Manager, and CAPE is present in `services/sandbox`. The script is resumable — if a reboot is required between stages, simply re-run the same command after rebooting, and it will pick up where it left off.

Navigate to `services/sandbox` inside the project and run:

```bash
sudo chmod +x install_cape.sh
sudo ./install_cape.sh <username>
```

Replace `<username>` with your non-root Linux user (e.g. `sudo ./install_cape.sh john`).

**Your machine will reboot multiple times during installation. Each time, re-run the same command, and it will continue from where it left off. Repeat until you see the success message.**

---

## Setting Up the Windows Guest VM

This particular setup requires that you have a copy of the Guest image that will be used to run the malware analysis on. If you do not, there are resources online on how to properly setup a VM for malware analysis. We recommend looking into [this article](https://medium.com/@rizqisetyokus/building-capev2-automated-malware-analysis-sandbox-part-2-0c47e4b5cbcd).

### 1. Place the disk image

Copy the Windows disk image to `/var/lib/libvirt/images/win10.qcow2` and set the correct permissions:

```bash
sudo cp /path/to/win10.qcow2 /var/lib/libvirt/images/win10.qcow2
sudo chown root:libvirt /var/lib/libvirt/images/win10.qcow2
sudo chmod 660 /var/lib/libvirt/images/win10.qcow2
```

If the image is compressed, decompress it first using `qemu-img convert` before copying it.

### 2. Define the VM

```bash
sudo virsh define /path/to/win10.xml
```

If you get a domain error, ensure the XML uses `<name>`, not `<n>` for the VM name tag, and that the `<source file=.../>` path points to `/var/lib/libvirt/images/win10.qcow2` with no `<backingStore>` chain.

### 3. Start the VM and verify the CAPE agent

Start the VM:

```bash
sudo virsh start win10
```

Open Virtual Manager (`virt-manager`) to access the VM display. Log in with username `virus` (no password). Inside the Windows VM, ensure the network adapter is set to a static IP on libvirt's default network:

- IP address: `192.168.122.130`
- Subnet mask: `255.255.255.0`
- Default gateway: `192.168.122.1`
- DNS: `8.8.8.8`

Then, verify the CAPE agent is reachable from the host:

```bash
curl 192.168.122.130:8000
```

You should see a JSON response confirming the CAPE agent is running.

### 4. Take a snapshot

In Virtual Manager, go to **View > Snapshots** and create a snapshot. **Name it exactly `snapshot1`** — this name is referenced in the CAPE config.

Make sure that this snapshot is in a ready state where the VM is running, the CAPE agent can be reached, and all the applications you want running are running. This snapshot will be the state in which samples will be executed when submitted.

---

## Configuring CAPE

### 1. Copy the config files

Config files are located in the Google Drive under the CAPE VM folder. Once downloaded, copy them to the CAPE config directory:

```bash
sudo cp /path/to/conf/*.conf /opt/CAPEv2/conf/
```

### 2. Configure kvm.conf

Ensure `/opt/CAPEv2/conf/kvm.conf` has the correct VM settings:

```ini
[kvm]
machines = win10
interface = virbr0
dsn = qemu:///system

[win10]
label = win10
platform = windows
ip = 192.168.122.130
tags = win10
snapshot = snapshot1
arch = x64
```

If you find that CAPE cannot find the VM, ensure that the label provided for the VM is the same as the VM name returned by running this command: 

```bash
sudo virsh list --all
```

#### 2.1 Running more than one VM
The current setup is made to only run one VM. If you want to analyse samples concurrently, you can duplicate the guest VM in Virtual Manager and update `/opt/CAPEv2/conf/kvm.conf`.

To add a new VM to use, add the VM name to the machine section of the config as a comma-separated list and add a new section for it. This is an example of duplicating the Windows VM that we already have and updating `/opt/CAPEv2/conf/kvm.conf`:

```bash
[kvm]
machines = win10, win10_2
interface = virbr0
dsn = qemu:///system

[win10]
label = win10
platform = windows
ip = 192.168.122.130
tags = win10
snapshot = snapshot1
arch = x64

[win10_2]
label = win10
platform = windows
ip = 192.168.122.131
tags = win10
snapshot = snapshot1
arch = x64
```

After this, CAPE will automatically choose the first available VM to send samples to in the win10 group.

### 3. Configure cuckoo.conf

Ensure the ResultServer IP in `/opt/CAPEv2/conf/cuckoo.conf` is set to the host's libvirt bridge IP:

```ini
[resultserver]
ip = 192.168.122.1
port = 2042
```

---

## Starting CAPE Services

```bash
sudo systemctl restart cape.service
sudo systemctl restart cape-processor.service
sudo systemctl restart cape-rooter.service
sudo systemctl restart cape-web.service
sudo systemctl restart suricata.service
```

CAPE should now be accessible at `http://localhost:8000/`. You can verify it is running correctly with:

```bash
sudo journalctl -u cape.service -n 50 --no-pager
```

Look for the line `Waiting for analysis tasks` to confirm successful startup.

---

## Submitting Samples

Go to `http://localhost:8000/` and use the **Submit** tab to upload a sample. Make sure to add **`win10`** in the tags field so CAPE routes the analysis to the correct VM group.

---

## Extra: Setting up Internet Access for Guest VM
With the current setup, the guest VM runs without the possibility of accessing the internet when running samples, also called none routing. It is possible to change that to route traffic through: your direct network interface, InetSim, Tor, Tun, VPN, and Wireguard VPN.

The first step in this setup is activating CAPE's router utility by using this command:
```bash
sudo python3 utils/rooter.py -g cape
```

### Modifying Ubuntu network manager config

After this, we can activate IP forwarding by running the following:
```bash
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
```
> **_NOTE:_** running these two commands are not permanent and therefore need to be re-executed after every restart.

On Ubuntu, we have to change the network manager used by default by running these commands:
```bash
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager
sudo systemctl mask NetworkManager

sudo systemctl unmask systemd-networkd
sudo systemctl enable systemd-networkd
sudo systemctl start systemd-networkd
```

Next, we need to create our own manual **netplan** configuration by editing the file `/etc/netplan/99-manual.yaml` and adding all of the network interface of our system manually. An example is provided in the [CAPE documentation](https://capev2.readthedocs.io/en/latest/installation/host/routing.html#routing) with more detailed explanations.
> **_NOTE:_** The routing table **NUMBER** specified in the netplan config file should be the SAME as the one specified in `/etc/iproute2/rt_tables`.

After editing the **netplan** config, we can execute the changes with 
```bash
sudo netplan apply
```

### Modifying firewall rules

We can now make modifications to the `ufw` Ubuntu firewall to secure from analysis VM traffic trying to interact with the management interface of CAPE. To do that, we can check the interface details with
```bash
ip addr
```
We can then run the following commands, replacing `int` and `ip` with the proper interface name and IP for the management interface of CAPE.
```bash
# HTTP
sudo ufw allow in on <int> to <ip> port 80 proto tcp

# HTTPS
sudo ufw allow in on <int> to <ip> port 443 proto tcp

# SSH
sudo ufw allow in on <int> to <ip> port 22 proto tcp

# SMB (smbd is enabled by default on desktop versions of Ubuntu)
sudo ufw allow in on <int> to <ip> port 22 proto tcp

# RDP (if xrdp is used on the server)
sudo ufw allow in on <int> to <ip> port 445 proto tcp
```

We then need to allow the analysis VMs to access the CAPE result server on port 2042 by running the following command:
```bash
sudo ufw allow in on virbr0 to 192.168.122.1 port 2042 proto tcp
```
Finally, we can enable the firewall:
```bash
sudo ufw enable
```

### Setting up routing
Now that we have set up the system, we can go into CAPE's configuration to choose our method of routing. With each selection being different, please look thoroughly at the official [CAPE documentation](https://capev2.readthedocs.io/en/latest/installation/host/routing.html#routing) as well as the [GitHub repo](https://github.com/kevoreilly/CAPEv2/blob/master/conf/default/routing.conf.default) for the default config files, as the comments are really helpful in setting everything up to your needs.


---

## Notes

- The win10 VM will automatically be started and stopped by CAPE. After each analysis, it will revert to the provided snapshot, which is why it needs to be in a running state.
- Logs for all CAPE services can be viewed with `sudo journalctl -u <service-name>`