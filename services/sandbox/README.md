# Local Sandboxing Install and Setup

## Prerequisites

CAPE must be installed on a **bare metal Linux machine**, not inside a VM. Running CAPE inside a VM (e.g. VirtualBox or WSL) will cause KVM to fail as it requires direct access to CPU virtualization extensions. Dual-booting Ubuntu 24.04 alongside Windows is the recommended approach if your primary OS is Windows.

---

## Installing CAPE and the Hypervisor

A script to install KVM, Virtual Manager, and CAPE is present in `services/sandbox`. The script is resumable — if a reboot is required between stages, simply re-run the same command after rebooting and it will pick up where it left off.

Navigate to `services/sandbox` inside the project and run:

```bash
sudo chmod +x install_cape.sh
sudo ./install_cape.sh <username>
```

Replace `<username>` with your non-root Linux user (e.g. `sudo ./install_cape.sh john`).

**Your machine will reboot multiple times during installation. Each time, re-run the same command and it will continue from where it left off. Repeat until you see the success message.**

---

## Setting Up the Windows Guest VM

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

If you get a domain error, ensure the XML uses `<name>` not `<n>` for the VM name tag, and that the `<source file=.../>` path points to `/var/lib/libvirt/images/win10.qcow2` with no `<backingStore>` chain.

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

Then verify the CAPE agent is reachable from the host:

```bash
curl 192.168.122.130:8000
```

You should see a JSON response confirming the CAPE agent is running.

### 4. Take a snapshot

In Virtual Manager, go to **View > Snapshots** and create a snapshot. **Name it exactly `snapshot1`** — this name is referenced in the CAPE config.

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

Go to `http://localhost:8000/` and use the **Submit** tab to upload a sample. Make sure to add **`win10`** in the tags field so CAPE routes the analysis to the correct VM.

---

## Notes

- The win10 VM must be running before submitting samples. CAPE will automatically restore it to `snapshot1` between analyses.
- After rebooting Ubuntu, start the VM manually if it does not start automatically: `sudo virsh start win10`
- Logs for all CAPE services can be viewed with `sudo journalctl -u <service-name>`
