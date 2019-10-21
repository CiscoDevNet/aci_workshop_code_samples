from cobra.mit.access import MoDirectory
from cobra.mit.session import LoginSession
from cobra.mit.request import ConfigRequest
from cobra.model.fv import Tenant

# Because it is in a different place on other systems.
try:
    import requests.packages.urllib3 as urllib3
except:
    import urllib3

# This will suppress warnings from logins without valid certificate
urllib3.disable_warnings()

# create login session
session = LoginSession('https://test_apic', 'admin', 'acisim123')
moDir = MoDirectory(session)
moDir.login()

# Get the top level policy universe directory
uniMo = moDir.lookupByDn('uni')

# create the tenant object
fvTenantMo = Tenant(uniMo, 'CobraSDK-tenant123')

# Commit tenant
cfgRequest = ConfigRequest()
cfgRequest.addMo(fvTenantMo)
moDir.commit(cfgRequest)