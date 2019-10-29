# aci_workshop_code_samples


# Summary
---

Collection of simple code samples for ACI programmability. Includes beginner level ansible playbooks and python code snippets used or referenced in DevNet Workshop DEVWKS-1309 

This repository contains sample code for automating various types of tasks relating to ACI configuration and initial ACI fabric bringup.

Following are the step by step instructions for the Cisco Live Devnet Workshop.  The samples include both Ansible playbooks and Python scripts utilizing Cobra SDK.

# Workshop Instructions
---

# I. Environment Setup
---
This is using Python 2. It is recommended to run this package in a virtual environment. 

**1. Open Terminal application**

![Terminal](https://github.com/sheerens/temp_workshop_repo/blob/master/Documentation/Terminal_Icon.png)

**2. Change to home directory**

```text
cd
```
**3. Install virtual environment package**

```text
sudo pip install virtualenv
```

**4. Check your default version of Python**

```text
python --version
```

**5(a). If python version is 2.x then do this:**

```text
virtualenv aci-workshop
```

**5(b). If python version is 3.x then do this:**

```text
virtualenv aci-workshop --python=/usr/bin/python2.7
```

**6. Activate the virtual environment**

```text
source aci-workshop/bin/activate
```

**7. Clone "aci_workshop_code_samples" repository**

```text
git clone https://github.com/CiscoDevNet/aci_workshop_code_samples.git
```
**8. Change directory**

```text
cd aci_workshop_code_samples
```

**9. Install requirements**

```text
pip install -r requirements.txt
```

**10. Install Ansible**

```text
pip install ansible==2.7.8
```

**11. Download Cobra SDK egg files**

```text
THIS STEP HAS ALREADY BEEN DONE FOR YOU:
   
	download cobra eggs - from https://<apic>/cobra/_downloads
   
	The 2 egg files have been placed in your Downloads directory
```

**12. Change directory**

```text
cd $HOME/Downloads
```

**13. Install Cisco APIC Python SDK - acicobra egg file**

```text
easy_install -Z acicobra-3.2_7f-py2.7.egg
```
**14. Install Cisco APIC Python SDK - acimodel egg file**

```text
easy_install -Z acimodel-3.2_7f-py2.7.egg
```

**15. Test APIC Access**

```text
Browse to your APIC simulator: https://<ip address> and login
```


# II. Ansible Playbook - ACI Configuration for Firewall Solution
---

***Create a Unique Tenant***

**16. In Terminal, return to "aci_workshop_code_samples" directory**

```text
cd $HOME/aci_workshop_code_samples
```

**17. Open the file "tenant_create.yml" using TextEdit**

```text
open -e tenant_create.yml
```

**18. Make these changes to the file:  tenant_create.yml**
```text
Verify or make changes to insure these fields are as noted:
	
	aci_hostname:  <your APIC simulator>
	tenant:        <your unique tenant name>
	description:   <some description>
	
SAVE YOUR CHANGES - click on File, click on Save
```

**19. Return to command line and execute the Playbook**

```text
	ansible-playbook tenant_create.yml
```

**20. Verify tenant was created in Web UI**

```text
	Browse to your APIC simulator: https://<ip address> and login
```


***Run the Ansible Playbook to create ACI Firewall Config***

**21. In Terminal, change directory to aci_workshop_code_samples/playbook_vars/aci_workshop_fab1**

```text
cd $HOME/aci_workshop_code_samples/playbook_vars/aci_workshop_fab1
```


**22. Open the file "aci_fw_config_vars.yml" using TextEdit**

```text
open -e aci_fw_config_vars.yml

```

**23. Modify this file: aci_fw_config_vars.yml**
```text
Note: this is the input variable file for the Playbook we will run later.
	
Verify or make changes to insure these fields are as noted:
	
	aci_hostname:  <your APIC simulator>
	aci_tenant:    <your unique tenant name>
	
SAVE YOUR CHANGES - click on File, click on Save
```

**24. In Terminal, change directory to aci-workshop**

```text
cd $HOME/aci_workshop_code_samples
```



**25. Return to command line and execute the Playbook**

```text
	ansible-playbook run_firewall_build_demo.yml -e @./playbook_vars/aci_workshop_fab1/aci_fw_config_vars.yml
```

**26. Login to APIC to Verify/Monitor changes within your tenant's Networking section**

```text
	Browse to your APIC simulator: https://<ip address> and login
```

# III. Python Scripts (with Cobra SDK) - ACI Fabric Bringup and Base Configuration
---



***Security Policy Configuration***

**27. Change to python_scripts directory**

```text
	cd $HOME/aci_workshop_code_samples/python_scripts 
```

**28. Open the file "policy_cfg_source.yml" using TextEdit**

```text
open -e policy_cfg_source.yml
```


**29. Modify this file:  policy_cfg_source.yml**
```text
Verify or make changes to insure the tenant name is correct:
	
	tenants:
      -
        name: "<this is YOUR tenant you just created>"
	
SAVE YOUR CHANGES - click on File, click on Save
```

**30. Return to command line, and view the Python script options**

```text
	python policy_cfg.py -h
```


**31. Execute the python script**

```text
	python policy_cfg.py -a <your apic> -u admin -p <password> -f policy_cfg_source.yml
```

**33. Login to APIC to Verify/Monitor changes within your tenant's Contract section**

```text
	Browse to your APIC simulator: https://<ip address> and login
```

***Time Permitting:***
***Fabric Discovery***

**33. Change to python_scripts directory**

```text
	cd $HOME/aci_workshop_code_samples/python_scripts 
```

**34. Return to the command line, and view the Python script options**

```text
	python fabric_site_specific.py -h
```

**35. Execute the python script**

```text
	python fabric_site_specific.py -a <your apic> -u admin -p <password> -f fabric_site_acisim.yml
```
