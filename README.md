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
pip install virtualenv   (may need: sudo pip install virtualenv)
```

**4. Create a virtual environment for this workshop**

```text
virtualenv aci-workshop
```

**5. Activate the virtual environment**

```text
source aci-workshop/bin/activate
```

**6. Clone aci-prog-workshop repository**

```text
git clone https://github.com/CiscoDevNet/aci_workshop_code_samples.git
```
**7. Change directory**

```text
cd aci_workshop_code_samples
```

**8. Install requirements**

```text
pip install -r requirements.txt
```

**9. Install Ansible**

```text
pip install ansible==2.7.8
```

**10. Download Cobra SDK egg files**

```text
THIS STEP HAS ALREADY BEEN DONE FOR YOU:
   
	download cobra eggs - from https://<apic>/cobra/_downloads
   
	The 2 egg files have been placed in your Downloads directory
```

**11. Change directory**

```text
cd $HOME/Downloads
```

**12. Install Cisco APIC Python SDK - acicobra egg file**

```text
easy_install -Z acicobra-3.2_7f-py2.7.egg
```
**13. Install Cisco APIC Python SDK - acimodel egg file**

```text
easy_install -Z acimodel-3.2_7f-py2.7.egg
```

**14. Test APIC Access**

```text
Browse to your APIC simulator: https://<ip address> and login
```


# II. Ansible Playbook - ACI Configuration for Firewall Solution
---

***Create a Unique Tenant***

**15. In Terminal, return to "aci_workshop_code_samples" directory**

```text
cd $HOME/aci_workshop_code_samples
```

**16. Open the file "tenant_create.yml" using TextEdit**

```text
open -e tenant_create.yml
```

**17. Make these changes to the file:  tenant_create.yml**
```text
Verify or make changes to insure these fields are as noted:
	
	aci_hostname:  <your APIC simulator>
	tenant:        <your unique tenant name>
	description:   <some description>
	
SAVE YOUR CHANGES - click on File, click on Save
```

**18. Return to command line and execute the Playbook**

```text
	ansible-playbook tenant_create.yml
```

**19. Verify tenant was created in Web UI**

```text
	Browse to your APIC simulator: https://<ip address> and login
```
***Verify tenant creation with Ansible playbook***

**20. Open the file "tenant_query.yml" using TextEdit**

```text
open -e tenant_query.yml

```

**21. Make these changes to the file:  tenant_query.yml**
```text
Verify or make changes to insure these fields are as noted:
	
	aci_hostname:  <your APIC simulator>
	tenant:        <your unique tenant name>
	description:   <some description>
	
SAVE YOUR CHANGES - click on File, click on Save
```

**22. Return to command line and execute the Playbook**

```text
	ansible-playbook tenant_query.yml
```

***Run the Ansible Playbook to create ACI Firewall Config***

**23. In Terminal, change directory to aci-workshop/playbook_vars/aci_workshop_fab1**

```text
cd $HOME/aci_workshop_code_samples/playbook_vars/aci_workshop_fab1
```


**24. Open the file "aci_fw_config_vars.yml" using TextEdit**

```text
open -e aci_fw_config_vars.yml

```

**25. Modify this file: aci_fw_config_vars.yml**
```text
Note: this is the input variable file for the Playbook we will run later.
	
Verify or make changes to insure these fields are as noted:
	
	aci_hostname:  <your APIC simulator>
	aci_tenant:    <your unique tenant name>
	
SAVE YOUR CHANGES - click on File, click on Save
```

**26. In Terminal, change directory to aci-workshop**

```text
cd $HOME/aci_workshop_code_samples
```



**27. Return to command line and execute the Playbook**

```text
	ansible-playbook run_firewall_build_demo.yml -e @./playbook_vars/aci_workshop_fab1/aci_fw_config_vars.yml
```

**28. Login to APIC to Verify/Monitor changes within your tenant's Networking section**

```text
	Browse to your APIC simulator: https://<ip address> and login
```

# III. Python Scripts (with Cobra SDK) - ACI Fabric Bringup and Base Configuration
---



***Security Policy Configuration***

**29. Change to python_scripts directory**

```text
	cd $HOME/aci_workshop_code_samples/python_scripts 
```

**30. Open the file "policy_cfg_source.yml" using TextEdit**

```text
open -e policy_cfg_source.yml
```


**31. Modify this file:  policy_cfg_source.yml**
```text
Verify or make changes to insure the tenant name is correct:
	
	tenants:
      -
        name: "<this is YOUR tenant you just created>"
	
SAVE YOUR CHANGES - click on File, click on Save
```

**32. Return to command line, and view the Python script options**

```text
	python policy_cfg.py -h
```


**33. Execute the python script**

```text
	python policy_cfg.py -a <your apic> -u admin -p <password> -f policy_cfg_source.yml
```

***Time Permitting:***
***Fabric Discovery***

**34. Change to python_scripts directory**

```text
	cd $HOME/aci_workshop_code_samples/python_scripts 
```

**35. Return to the command line, and view the Python script options**

```text
	python fabric_site_specific.py -h
```

**36. Execute the python script**

```text
	python fabric_site_specific.py -a <your apic> -u admin -p <password> -f fabric_site_acisim.yml
```

***Time Permitting:***
***Fabric Base Configuration***

**37. Change to python_scripts directory**

```text
	cd $HOME/aci_workshop_code_samples/python_scripts 
```

**38. Open this file and examine contents:  base_config.yml**

```text
 open -e policy_cfg_source.yml
```
   Note:  This file is the source/input file for the base configuration script.


**39. Return to the command line, and view the Python script options**

```text
	python fabric_base.py -h
```

**40. Execute the python script**

```text
	python fabric_base.py -a <your apic> -u admin -p <password>
```
