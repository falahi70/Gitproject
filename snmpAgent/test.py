data = "OID=.1.3.6.1.2.1.1.1.0, Type=OctetString, Value=Cisco IOS Software [Everest], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.6.8, RELEASE SOFTWARE (fc3)"

line = data.split(", ", 2)
data_dict = {}
try:
    for data in line:
        key_value = data.split("=")
        key = key_value[0]
        value = key_value[1]
        while value[0] == " ":
            value = value[1:]
        data_dict[key] = value
        if key == "OID":
            oid_data = value.rsplit(".", 4)
            oid_data = f"{oid_data[-4]}.{oid_data[-3]}.{oid_data[-2]}.{oid_data[-1]}"
            data_dict["oid_data"] = oid_data

except Exception as e:
    print({})
print(data_dict)