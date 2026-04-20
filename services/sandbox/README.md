# Local Sandboxing Install and Setup

## Installing Cape and Hypervisor

A script to install KVM, Virtual Manager, and Cape is present in services/sandbox. This automated script install the necessary libraries for Cape to run. Note that these are very specific on their version and might not work if the versions missmatch. It is therefore using poetry to manage the packages required. This scrit performs a basic recommended installation with KVM as its supervisor. You can chose a different hypervisor but you will have to manually set everything up following the Cape documentation. It is important that Cape is installed on your bare machine and not inside a VM to minimize the issues that you may face with it.

To install Cape, navigate to your services/sandbox foler inside the project and run these commands:
```
sudo chmod +x install_cape.sh
./install_cape.sh <username>
```

**Your machine will have to restart during the install process. After it has restarted, run the second command again and it will pick up the install porcess back where it started. Do this until your terminal shows to sucess message.**


## Setting up a guest VM
paste files in /var/lib/libvirt/images/
make sure the path in the xml file is pointing to the qcow2 file correctly
run: ```virsh define <vm-name>.xml```
If you get domain error, run the virsh commands with sudo

spin up the vm in virtual manager and then from your host cmd run:
```curl 192.168.122.130:8000```
Should see a confirmation from the Cape agent running
On virtual manager, go to view>snapshots and create a snapshot leaving the name snapshot1
If issues arise with spinning up the VM, check that kvm.conf is using the right snapshot name

Tweak Cape config:
paste the cape config files provided into /opt/CAPEv2/conf
files locatedd in the google drive under the CAPE VM folder

Restart services to run cape
```
sudo systemctl restart cape.service
sudo systemctl restart cape-processor.service
sudo systemctl restart cape-rooter.service
sudo systemctl restart cape-web.service
sudo systemctl restart suricata.service
```

should now be able to go to http://localhost:8000/ and submit samples in the submit tab. Make sure to add "win10" in the tag section







