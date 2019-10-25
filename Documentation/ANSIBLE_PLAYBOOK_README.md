# Automated Build of ACI Configuration of DMZaaS FW Solution

## Getting Started

These instructions will get a copy of the project up and running on your local machine for development and testing purposes.

### Pre-requisites:
- The following software should be installed on your local machine
    - Ansible 2.7  (https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)
    
### Installing

Clone the repository to a directory of your choice.
```
git clone https://github.com/CiscoDevNet/aci_workshop_code_samples.git
```

## Overview of Playbooks

The DMZ FW solution consists of a pair of Service Leafs, and 2 pairs of FWs (one pair for Internal, one pair for DMZ) attached to those leafs.

The first playbook will create the necessary ACI objects for the initial push of the DMZ FW solution, including:
  - l3Outs (with Node and Logical Interface policies)
  - VRFs
  - VRF level contracts
  - Fabric access policies (Vlan Pool, Domain, AEP, Interface Policy Groups, Interface selectors)
  - EPG and BD for inter-FW link
    
The input file is a single site/fabric specific yaml file, which is specified on the command line when executing the playbooks.

Playbook:     **run_dmzdc_fw_build.yml**


### Input var file


The input var file is specified when executing the ansible playbook.  It is structured into 4 sections.
The first 3 sections are used by the first playbook (run_dmzdc_fw_build.yml) and the last section (section 4)
is used by the second playbook (run_dmz_fw_static_routes.yml)

    (1) Site specific variables
  
    (2) yaml list of l3Outs to be created/modified
  
    (3) EPG/BD creation variables (this is for link between FW pairs)
    
    (4) Static routes to be implemented during live cutover (this is used by DIFFERENT playbook)
  
Variables are commented and should be self-explanatory. 



There are 2 steps in running the first playbook:
  - First, run it with the "validate_input" option as a pre-check
```
ansible-playbook run_dmzdc_fw_build.yml -t validate_input -e @./group_vars/svl_fab4_vars/svl_fab4_l3out_fw_config1.yml
```
  - Second, once any corrections are made to input, execute the playbook.

```
ansible-playbook run_dmzdc_fw_build.yml -e @./group_vars/svl_fab4_vars/svl_fab4_l3out_fw_config1.yml
```





### Assumptions

The playbook assumes the Service Leafs have been provisioned into the fabric, and that the Leaf Profile (eg. sw3823-swPrfl) and associated Leaf Interface Selector Profile (eg. sw3823-IfPrfl) have been created in the configuration.


  
  
### Templates
  
Templates are stored in the top level directory "templates_json"
  
### Roles

The main playbook calls various roles/task files, including l3out_complete.yml, node_and_life_profiles.yml, fabric_access_policies.yml, and epg_create.yml



# Testing the playbook

You can use the examples above to run the playbook, with the test input file, in any lab fabric or ACI simulator.

Note that there are no physical switches associated with sw3823 and sw3824 but that does not affect the playbook execution, although it will generate some faults within both new and modified l3Outs.
 
