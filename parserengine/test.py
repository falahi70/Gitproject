import os
from netmiko import ConnectHandler
from ntc_templates.parse import parse_output



os.environ["NTC_TEMPLATES_DIR"] = r"C:\Users\Nochi\Desktop\templates"


output = open("showInformation.txt", "r", encoding="utf-8", errors="ignore").read()

vlan_parsed = str(parse_output(platform="hp_oa", command="show information", data=output))
print(vlan_parsed)
# vlan_parsed = vlan_parsed.replace('"', r'\"')
# vlan_parsed = vlan_parsed.replace("'", '"')
# print(vlan_parsed)