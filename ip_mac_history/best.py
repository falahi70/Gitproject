from pysnmp.hlapi import *

# Set the SNMP parameters for the target device
community_string = 'CoreInspect'
ip_address = '192.168.62.254'
snmp_port = 161

# Set the OID for the ARP table
arp_table_oid = '1.3.6.1.2.1.4.22.1.2'

# Build the SNMP GET request
snmp_get = getCmd(SnmpEngine(),
                  CommunityData(community_string),
                  UdpTransportTarget((ip_address, snmp_port)),
                  ContextData(),
                  ObjectType(ObjectIdentity(arp_table_oid)))

# Send the SNMP GET request and get the response
error_indication, error_status, error_index, var_binds = next(snmp_get)

# Check for errors and print the ARP table information
if error_indication:
    print(error_indication)
else:
    if error_status:
        print('%s at %s' % (error_status.prettyPrint(),
                            error_index and var_binds[int(error_index) - 1][0] or '?'))
    else:
        for var_bind in var_binds:
            print('%s = %s' % (var_bind.prettyPrint(), var_bind))