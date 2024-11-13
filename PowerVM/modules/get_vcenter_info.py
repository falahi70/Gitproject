import sys
import pandas as pd

def vcenter_information_gathering(ip_address, output_file):

    vcenter_IP_Address = ip_address

    data_dict = dict()

    df_excel = pd.ExcelFile(output_file, engine='openpyxl')

    ##### Getting VM Name Of The Target VCenter.
    sheetname = "vNetwork"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    ip_index = 0
    for index, row in df.iterrows():
        if row["vNetworkIP4Address"] == vcenter_IP_Address:
            ip_index = index
    if ip_index == 0:
        print("IP Address Was Not Found!")
        sys.exit(-1)

    for index, row in df.iterrows():
        if int(index) == ip_index:
            vcenter_name = row["vNetworkVMName"]

    ##### Fetching vCPU Info From Excel File
    sheetname = "vCPU"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    cpu_information = {
        "vCPUCPUs": [],
        "vCPUSockets": [],
        "vCPUCoresPerSocket": []
    }
    for index, row in df.iterrows():
        if row["vCPUVMName"] == vcenter_name:
            cpu_information["vCPUCPUs"].append(row["vCPUCPUs"])
            cpu_information["vCPUSockets"].append(row["vCPUSockets"])
            cpu_information["vCPUCoresPerSocket"].append(row["vCPUCoresPerSocket"])
    data_dict["vCPU"] = cpu_information

    ##### Fetching vMemory Info From Excel File
    sheetname = "vMemory"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    memory_information = {
        "vMemorySizeMiB": []
    }
    for index, row in df.iterrows():
        if row["vMemoryVMName"] == vcenter_name:
            memory_information["vMemorySizeMiB"].append(row["vMemorySizeMiB"])
    data_dict["vMemory"] = memory_information

    ##### Fetching vPartition Info From Excel File
    sheetname = "vPartition"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    partition_information = {
        "Total": 0
    }
    total_sums = []
    for index, row in df.iterrows():
        if row["vPartitionVMName"] == vcenter_name:
            partition_information[row["vPartitionDisk"]] = row["vPartitionCapacityMiB"]
            total_sums.append(row["vPartitionCapacityMiB"])
    partition_information["Total"] = sum(total_sums)
    data_dict["vPartition"] = partition_information

    ##### Fetching vNetwork Info From Excel File
    sheetname = "vNetwork"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    network_information = []
    for index, row in df.iterrows():
        if row["vNetworkVMName"] == vcenter_name:
            network_information_tmp = {}
            network_information_tmp["IPv4_Address"] = row["vNetworkIP4Address"]
            network_information_tmp["vNetworkAdapter"] = row["vNetworkAdapter"]
            network_information_tmp["vNetworkName"] = row["vNetworkName"]
            network_information_tmp["vNetworkSwitch"] = row["vNetworkSwitch"]
            network_information_tmp["vNetworkConnected"] = row["vNetworkConnected"]
            network_information_tmp["vNetworkMacAddress"] = row["vNetworkMacAddress"]
            network_information_tmp["vNetworkHostName"] = row["vNetworkHost"]
            network_information.append(network_information_tmp)

    data_dict["vNetwork"] = network_information

    ##### Fetching vCD Info From Excel File
    sheetname = "vCD"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    vcd_information = {}
    for index, row in df.iterrows():
        if row["vCDVMName"] == vcenter_name:
            vcd_information[row["vCDlabel"]] = {}
            vcd_information[row["vCDlabel"]]["vCDSummary"] = row["vCDSummary"]
            vcd_information[row["vCDlabel"]]["vCDConnected"] = row["vCDConnected"]
    data_dict["vCD"] = vcd_information

    ##### Fetching vCD Info From Excel File
    sheetname = "vUSB"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    usb_information = {}
    for index, row in df.iterrows():
        if row["vUSBVMName"] == vcenter_name:
            usb_information[row["vUSBLabel"]] = {}
            usb_information[row["vUSBLabel"]]["vUSBSummary"] = row["vUSBSummary"]
            usb_information[row["vUSBLabel"]]["vUSBConnected"] = row["vUSBConnected"]
            usb_information[row["vUSBLabel"]]["vUSBFamily"] = row["vUSBFamily"]
            usb_information[row["vUSBLabel"]]["vUSBSpeed"] = row["vUSBSpeed"]
    data_dict["vUSB"] = usb_information

    ##### Fetching vInfo Info From Excel File
    sheetname = "vInfo"
    df = pd.read_excel(df_excel, sheet_name=sheetname)
    ginfo_information = {
        "vmName": vcenter_name,
        "vInfoGuestHostName": [],
        "vInfoCPUs": [],
        "vInfoMemory": [],
        "vInfoNICs": [],
        "vInfoNumVirtualDisks": [],
        "Annotation": [],
        "vInfoVISDKServerType": []
    }
    for index, row in df.iterrows():
        if row["vInfoVMName"] == vcenter_name:
            ginfo_information["vInfoGuestHostName"].append(row["vInfoGuestHostName"])
            ginfo_information["vInfoCPUs"].append(row["vInfoCPUs"])
            ginfo_information["vInfoMemory"].append(row["vInfoMemory"])
            ginfo_information["vInfoNICs"].append(row["vInfoNICs"])
            ginfo_information["vInfoNumVirtualDisks"].append(row["vInfoNumVirtualDisks"])
            try:
                ginfo_information["Annotation"].append(row["Annotation"])
            except Exception as e:
                pass
            ginfo_information["vInfoVISDKServerType"].append(row["vInfoVISDKServerType"])
    data_dict["vInfo"] = ginfo_information

    delete_candidate = []
    for key in data_dict.keys():
        if len(data_dict[key]) < 1:
            delete_candidate.append(key)
    for key in delete_candidate:
        del data_dict[key]

    data_dict = str(data_dict)
    data_dict = data_dict.replace('"', r'\"')
    data_dict = data_dict.replace("'", '"')
    data_dict = data_dict.replace("True", 'true')
    data_dict = data_dict.replace("False", 'false')

    return data_dict