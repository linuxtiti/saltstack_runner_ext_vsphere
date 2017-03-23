#!/usr/bin/env python


# Import Python Libs
from __future__ import print_function
from time import clock
from os.path import basename
from collections import OrderedDict
from IPy import IP
import json,logging,atexit,sys


# Import Salt Libs
from salt.exceptions import SaltSystemExit

# Import Third Party Libs
try:
    import pyVmomi
    #from pyVim import connect
    from pyVim.connect import GetSi, SmartConnect, Disconnect
    from pyVmomi import vim
    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False

# Get Logging Started
log = logging.getLogger(__name__)
MODULE_FULL_PATH = sys._getframe().f_code.co_filename
MODULE_NAME = basename(MODULE_FULL_PATH).split(".")[0]


def __virtual__():
    '''
    Only load if PyVmomi is installed.
    '''
    if HAS_PYVMOMI:
        return True
    else:
        return False, 'Missing dependency: The ext.module.vmware_info requires pyVmomi.'


START = clock()
# Shamelessly borrowed from:
# https://github.com/dnaeon/py-vconnector/blob/master/src/vconnector/core.py
def collect_properties(service_instance, view_ref, obj_type, path_set=None,
                       include_mors=False):
    """
    Collect properties for managed objects from a view ref

    Check the vSphere API documentation for example on retrieving
    object properties:

        - http://goo.gl/erbFDz

    Args:
        si          (ServiceInstance): ServiceInstance connection
        view_ref (pyVmomi.vim.view.*): Starting point of inventory navigation
        obj_type      (pyVmomi.vim.*): Type of managed object
        path_set               (list): List of properties to retrieve
        include_mors           (bool): If True include the managed objects
                                       refs in the result

    Returns:
        A list of properties for the managed objects

    """
    collector = service_instance.content.propertyCollector

    # Create object specification to define the starting point of
    # inventory navigation
    obj_spec = pyVmomi.vmodl.query.PropertyCollector.ObjectSpec()
    obj_spec.obj = view_ref
    obj_spec.skip = True

    # Create a traversal specification to identify the path for collection
    traversal_spec = pyVmomi.vmodl.query.PropertyCollector.TraversalSpec()
    traversal_spec.name = 'traverseEntities'
    traversal_spec.path = 'view'
    traversal_spec.skip = False
    traversal_spec.type = view_ref.__class__
    obj_spec.selectSet = [traversal_spec]

    # Identify the properties to the retrieved
    property_spec = pyVmomi.vmodl.query.PropertyCollector.PropertySpec()
    property_spec.type = obj_type

    if not path_set:
        property_spec.all = True

    property_spec.pathSet = path_set

    # Add the object and property specification to the
    # property filter specification
    filter_spec = pyVmomi.vmodl.query.PropertyCollector.FilterSpec()
    filter_spec.objectSet = [obj_spec]
    filter_spec.propSet = [property_spec]

    # Retrieve properties
    props = collector.RetrieveContents([filter_spec])

    data = []
    for obj in props:
        properties = {}
        for prop in obj.propSet:
            properties[prop.name] = prop.val

        if include_mors:
            properties['obj'] = obj.obj

        data.append(properties)
    return data

def get_service_instance(host, username, password, protocol=None, port=None):
    '''
    Authenticate with a vCenter server or ESX/ESXi host and return the service instance object.

    host
        The location of the vCenter server or ESX/ESXi host.

    username
        The username used to login to the vCenter server or ESX/ESXi host.

    password
        The password used to login to the vCenter server or ESX/ESXi host.

    protocol
        Optionally set to alternate protocol if the vCenter server or ESX/ESXi host is not
        using the default protocol. Default protocol is ``https``.

    port
        Optionally set to alternate port if the vCenter server or ESX/ESXi host is not
        using the default port. Default port is ``443``.
    '''
    if protocol is None:
        protocol = 'https'
    if port is None:
        port = 443

    service_instance = GetSi()
    if service_instance:
        if service_instance._GetStub().host == ':'.join([host, str(port)]):
            return service_instance
        Disconnect(service_instance)
    #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    #context.verify_mode = ssl.CERT_NONE
    try:
        service_instance = SmartConnect(
            host=host,
            user=username,
            pwd=password,
            protocol=protocol,
            port=int(port)
            #sslContext=context
        )
    except Exception as exc:
        default_msg = 'Could not connect to host \'{0}\'. ' \
                      'Please check the debug log for more information.'.format(host)
        try:
            if (isinstance(exc, vim.fault.HostConnectFault) and '[SSL: CERTIFICATE_VERIFY_FAILED]' in exc.msg) or '[SSL: CERTIFICATE_VERIFY_FAILED]' in str(exc):
                import ssl
                default_context = ssl._create_default_https_context
                ssl._create_default_https_context = ssl._create_unverified_context
                service_instance = SmartConnect(
                    host=host,
                    user=username,
                    pwd=password,
                    protocol=protocol,
                    port=port
                )
                ssl._create_default_https_context = default_context
            elif (isinstance(exc, vim.fault.HostConnectFault) and 'SSL3_GET_SERVER_CERTIFICATE\', \'certificate verify failed' in exc.msg) or 'SSL3_GET_SERVER_CERTIFICATE\', \'certificate verify failed' in str(exc):
                import ssl
                default_context = ssl._create_default_https_context
                ssl._create_default_https_context = ssl._create_unverified_context
                service_instance = SmartConnect(
                    host=host,
                    user=username,
                    pwd=password,
                    protocol=protocol,
                    port=port
                )
                ssl._create_default_https_context = default_context
            else:
                err_msg = exc.msg if hasattr(exc, 'msg') else default_msg
                log.debug(exc)
                #raise SaltSystemExit(err_msg)
                return err_msg

        except Exception as exc:
            if 'certificate verify failed' in str(exc):
                import ssl
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                context.verify_mode = ssl.CERT_NONE
                service_instance = SmartConnect(
                    host=host,
                    user=username,
                    pwd=password,
                    protocol=protocol,
                    port=port,
                    sslContext=context
                )
            else:
                err_msg = exc.msg if hasattr(exc, 'msg') else default_msg
                log.debug(exc)
                #raise SaltSystemExit(err_msg)
                return err_msg

    atexit.register(Disconnect, service_instance)
    return service_instance


def get_container_view(service_instance, obj_type, container=None):
    """
    Get a vSphere Container View reference to all objects of type 'obj_type'

    It is up to the caller to take care of destroying the View when no longer
    needed.

    Args:
        obj_type (list): A list of managed object types

    Returns:
        A container view ref to the discovered managed objects

    """
    if not container:
        container = service_instance.content.rootFolder

    view_ref = service_instance.content.viewManager.CreateContainerView(
        container=container,
        type=obj_type,
        recursive=True
    )
    return view_ref


def endit():
    """
    times how long it took for this script to run.

    :return:
    """
    end = clock()
    total = end - START
    print("Completion time: {0} seconds.".format(total))


def _getAllGuestInfo(service_instance,info_type=None,vm_uuid=None):
    vm_properties = ["name", "config.uuid","summary.config.instanceUuid","summary.overallStatus",
                     "config.hardware.numCPU","config.hardware.numCoresPerSocket",
                     "config.hardware.memoryMB", "guest.guestState","guest.ipAddress","guest.hostName",
                     "guest.disk","config.guestFullName", "config.guestId","storage.perDatastoreUsage",
                     "config.version","config.template","config.hardware.device","guest.ipStack","guest.net",
                     "summary.quickStats","guest.toolsRunningStatus","guest.toolsVersion","guest.toolsStatus",
                     "guest.toolsVersionStatus2","runtime.powerState"]

    # args = cli.get_args()

    view = get_container_view(service_instance,
                              obj_type=[vim.VirtualMachine])
    vm_raw_data = collect_properties(service_instance, view_ref=view,
                                 obj_type=vim.VirtualMachine,
                                 path_set=vm_properties,
                                 include_mors=True)
    vm_data_dict1 = OrderedDict()
    for vm in vm_raw_data:
        tmp_vm_info_dict = OrderedDict()
        tmp_route_table = list()
        tmp_dns_config = list()
        tmp_nic_info_dict = OrderedDict()
        if vm.get("summary.quickStats"):
            vm_cpu_usage = vm.get("summary.quickStats").overallCpuUsage
            vm_mem_usage = vm.get("summary.quickStats").guestMemoryUsage
            vm_mem_usage_bytes = vm.get("summary.quickStats").guestMemoryUsage * 1024 * 1024
        else:
            vm_cpu_usage = None
            vm_mem_usage = None
            vm_mem_usage_bytes = None
        tmp_vm_info_dict["Name"] = vm["name"]
        tmp_vm_info_dict["instance UUID"] = vm.get("summary.config.instanceUuid")
        tmp_vm_info_dict["BIOS UUID"] = vm.get("config.uuid")
        tmp_vm_info_dict["CPUs"] = vm.get("config.hardware.numCPU")
        tmp_vm_info_dict["numCoresPerSocket"] = vm.get("config.hardware.numCoresPerSocket")
        if vm.get("config.hardware.numCPU") is None or vm.get("config.hardware.numCoresPerSocket") is None:
            tmp_vm_info_dict["numTotalCores"] = None
        else:
            tmp_vm_info_dict["numTotalCores"] = vm["config.hardware.numCoresPerSocket"] * vm["config.hardware.numCPU"]
        tmp_vm_info_dict["cpuUsage"] = vm_cpu_usage
        tmp_vm_info_dict["MemoryMB"] = vm.get("config.hardware.memoryMB")
        tmp_vm_info_dict["MemoryActive"] = vm_mem_usage
        if tmp_vm_info_dict["MemoryMB"] is None:
            tmp_vm_info_dict["MemoryBytes"] = None
        else:
            tmp_vm_info_dict["MemoryBytes"] = vm["config.hardware.memoryMB"] * 1024 * 1024
        tmp_vm_info_dict["MemoryActiveBytes"] = vm_mem_usage_bytes
        tmp_vm_info_dict["Guest PowerState"] = vm.get("guest.guestState")
        tmp_vm_info_dict["VM PowerState"] = vm.get("runtime.powerState")
        tmp_vm_info_dict["Guest Full Name"] = vm.get("config.guestFullName")
        tmp_vm_info_dict["Guest Container Type"] = vm.get("config.guestId")
        tmp_vm_info_dict["Container Version"] = vm.get("config.version")
        tmp_vm_info_dict["template_flag"] = vm.get("config.template")
        tmp_vm_info_dict["Vm Status"] = vm.get("summary.overallStatus")
        tmp_vm_info_dict["ipaddress"] = vm.get("guest.ipAddress")
        tmp_vm_info_dict["hostname"] = vm.get("guest.hostName")
        vm_tool_status = vm.get("guest.toolsVersionStatus2")
        if vm_tool_status == "guestToolsNotInstalled":
            tmp_vm_info_dict["vm_tool installed"] = False
            tmp_vm_info_dict["vm_tool Version"] = None
            tmp_vm_info_dict["vm_tool Stauts"] = None
        else:
            tmp_vm_info_dict["vm_tool installed"] = True
            tmp_vm_info_dict["vm_tool Version"] = vm.get("guest.toolsVersion")
            tmp_vm_info_dict["vm_tool RunningStauts"] = vm.get("guest.toolsRunningStatus")
        ip_stack_info_list = list()
        ip_stack_info_list = vm.get("guest.ipStack")
        if ip_stack_info_list is None:
            pass
        else:
            for ip_stack in ip_stack_info_list:
                route_info_list = ip_stack.ipRouteConfig.ipRoute
                #tmp_dns_config.append({"ipaddr":ip_stack.dnsConfig.ipAddress,"hostname":ip_stack.dnsConfig.hostName})
                for dns_ip in ip_stack.dnsConfig.ipAddress:
                    tmp_dns_config.append(dns_ip)
                for route_info_obj in route_info_list:
                    route_info = OrderedDict()
                    route_info["network"] = route_info_obj.network
                    route_info["netmask"] = IP(str(route_info_obj.network) + '/' + str(route_info_obj.prefixLength)).strNetmask()
                    route_info["gateway_ipaddr"] = route_info_obj.gateway.ipAddress
                    route_info["deviceId"] = route_info_obj.gateway.device
                    tmp_route_table.append(route_info)
            #tmp_vm_info_dict["route table"] = tmp_route_table
        tmp_vm_info_dict["dns"] = tmp_dns_config
        nic_info_list = vm.get("guest.net")
        if nic_info_list is None:
            pass
        else:
            nic_num = 0
            for nic_info_obj in nic_info_list:
                nic_mac = nic_info_obj.macAddress
                ipaddr_list = list()          
                #if isinstance(nic_info_obj.ipConfig.ipAddress,list):
                try:
                    for ip_addr_obj in nic_info_obj.ipConfig.ipAddress:
                        if IP(ip_addr_obj.ipAddress).version() == 6:
                            continue
                        else:
                            ip_addr_dict = OrderedDict()
                            ip_addr_dict["ip"] = ip_addr_obj.ipAddress
                            ip_addr_dict["protocol version"] = "IPv" + str(IP(ip_addr_obj.ipAddress).version())
                            #IP("192.168.10.38").make_net(24).strNetmask()
                            ip_addr_dict["netmask"] = IP(ip_addr_obj.ipAddress).make_net(ip_addr_obj.prefixLength).strNetmask()
                            for route in tmp_route_table:
                                if int(route["deviceId"]) == nic_num and route["network"] == "0.0.0.0":
                                    if IP(ip_addr_obj.ipAddress).version() == 4:
                                        ip_addr_dict["default gateway"] = route["gateway_ipaddr"]
                                    else:
                                        pass
                            ipaddr_list.append(ip_addr_dict)
                except Exception:
                    ip_addr_dict = None
                    ipaddr_list.append(ip_addr_dict)
                tmp_nic_info_dict[nic_mac] = ipaddr_list
                nic_num += 1

        ds_usage = vm.get("storage.perDatastoreUsage")
        if vm.get("config.hardware.device"):
            net_interface_info = OrderedDict()
            virtual_disk_info = OrderedDict()
            virtualDeviceList = vm.get("config.hardware.device")
            for vd_obj in virtualDeviceList:
                temp_info = OrderedDict()
                if isinstance(vd_obj,vim.VirtualEthernetCard):
                    nic_mac_addr = vd_obj.macAddress
                    temp_info["name"] = vd_obj.deviceInfo.label
                    temp_info["device_key"] = vd_obj.key
                    temp_info["summary"] = vd_obj.deviceInfo.summary
                    #temp_info["network"] = vd_obj.backing.network
                    temp_info["connected"] = vd_obj.connectable.connected
                    temp_info["status"] = vd_obj.connectable.status
                    if len(tmp_nic_info_dict) != 0:
                        temp_info["ipaddr info"] =tmp_nic_info_dict.get(nic_mac_addr)
                    else:
                        temp_info["ipaddr info"] = None
                    net_interface_info[nic_mac_addr] = temp_info
                if isinstance(vd_obj,vim.vm.device.VirtualDisk):
                    temp_info["device_key"] = vd_obj.key
                    temp_info["diskmode"] = vd_obj.backing.diskMode
                    temp_info["thinProvisioned"] = vd_obj.backing.thinProvisioned
                    #temp_info["datastore"] = vd_obj.backing.datastore
                    for perDs in ds_usage:
                        if vd_obj.backing.datastore == perDs.datastore:
                            temp_info["spaceUsed"] = perDs.committed
                    temp_info["capacityInBytes"] = vd_obj.capacityInBytes
                    temp_info["diskUuid"] = vd_obj.backing.uuid
                    virtual_disk_info[vd_obj.deviceInfo.label] = temp_info
        tmp_vm_info_dict["virtualDisk"] = virtual_disk_info
        tmp_vm_info_dict["NIC"] = net_interface_info
        if vm.get("guest.disk"):
            guest_disk_info = OrderedDict()
            disk_info_list = vm.get("guest.disk")
            for d_info in disk_info_list:
                fs_name = d_info.diskPath
                fs_capacity = d_info.capacity
                fs_free = d_info.freeSpace
                guest_disk_info[fs_name] = {"capacity": fs_capacity,"freeSpace": fs_free}
            tmp_vm_info_dict["diskinfo"] = guest_disk_info
        else:
            tmp_vm_info_dict["diskinfo"] = None
        vm_data_dict1[vm["name"]] = tmp_vm_info_dict

    # print("")
    # print("Found {0} VirtualMachines.".format(len(vm_data)))
    #return json.dumps(vm_data_dict1)
    query_result_dict = dict()
    if info_type:
        if info_type == "all":
            query_result_dict = vm_data_dict1
        elif info_type == "template":
            all_vm_name_list = vm_data_dict1.keys()
            for vm_name in all_vm_name_list:
                if vm_data_dict1[vm_name].get("template_flag"):
                    query_result_dict[vm_name] = vm_data_dict1[vm_name]
        elif info_type == "vm":
            all_vm_name_list = vm_data_dict1.keys()
            for vm_name in all_vm_name_list:
                if not vm_data_dict1[vm_name].get("template_flag"):
                    query_result_dict[vm_name] = vm_data_dict1[vm_name]
    elif vm_uuid:
        all_vm_name_list = vm_data_dict1.keys()
        for vm_name in all_vm_name_list:
            if vm_data_dict1[vm_name]["instance UUID"] == vm_uuid:
                query_result_dict[vm_name] = vm_data_dict1[vm_name]
    else:
        query_result_dict["error"] = "wrong info type,nothing to display"
    return  query_result_dict


def _getDataStoreInfo(service_instance):
    ds_properties = ["summary.name", "summary.url", "summary.datastore",
                     "summary.freeSpace", "summary.capacity", "summary.accessible"]

    ds_view = get_container_view(service_instance,
                                 obj_type=[vim.Datastore])
    ds_data = collect_properties(service_instance, view_ref=ds_view,
                                 obj_type=vim.Datastore,
                                 path_set=ds_properties,
                                 include_mors=True)
    all_datastore_total = 0.0
    all_datastore_used = 0.0
    all_datastore_free = 0.0

    for ds_detail in ds_data:
        all_datastore_total += ds_detail["summary.capacity"]
        all_datastore_free += ds_detail["summary.freeSpace"]

    all_datastore_used = all_datastore_total - all_datastore_free
    ret_dict = dict()
    #2016 11 17 no longer display ip addr of the vcenter
    #ret_dict["vc_host"] = vc_host
    #2016-11-18 send ds data in GB back to java, no longer to display "GB"
    ret_dict["total"] = str(round(float(all_datastore_total) / 1024 / 1024 / 1024, 2))
    ret_dict["used"] = str(round(float(all_datastore_used) / 1024 / 1024 / 1024, 2))
    ret_dict["free"] = str(round(float(all_datastore_free) / 1024 / 1024 / 1024, 2))
    return ret_dict


def _getDataStoreDetails(service_instance,info_type="all"):
    ds_properties = ["summary.name", "summary.url", "summary.datastore",
                     "summary.freeSpace", "summary.capacity", "summary.accessible",
                     "vm"]

    ds_view = get_container_view(service_instance,
                                 obj_type=[vim.Datastore])
    ds_raw_data = collect_properties(service_instance, view_ref=ds_view,
                                 obj_type=vim.Datastore,
                                 path_set=ds_properties,
                                 include_mors=True)
    ds_details = dict()
    for ds_info in ds_raw_data:
        temp_info_dict = dict()
        temp_info_dict["capacity"] = ds_info.get("summary.capacity")
        temp_info_dict["free"] = ds_info.get("summary.freeSpace")
        temp_info_dict["dsUrl"] = ds_info.get("summary.url")
        vm_on_ds = dict()
        for vm_obj in ds_info.get("vm"):
            vm_on_ds[vm_obj.name] = vm_obj.summary.config.instanceUuid
        temp_info_dict["vm"] = vm_on_ds
        ds_details[ds_info.get("summary.name")] = temp_info_dict
    qurey_result_dict = dict()
    if info_type == "all":
        qurey_result_dict = ds_details
    return qurey_result_dict

def _getVcSummary(service_instance):
    #pass
    hs_view = get_container_view(service_instance,
                                 obj_type=[vim.HostSystem])
    hs_summary_path = ["name", "summary.hardware.memorySize","summary.hardware.cpuModel","summary.hardware.cpuMhz",
                       "summary.hardware.numCpuPkgs","summary.hardware.numCpuCores","summary.hardware.numCpuThreads",
                       "summary.overallStatus","summary.quickStats.overallCpuUsage","summary.quickStats.overallMemoryUsage",
                       "summary.quickStats.uptime","runtime.connectionState"
                       ]

    hs_summary_data = collect_properties(service_instance, view_ref=hs_view,
                                         obj_type=vim.HostSystem,
                                         path_set=hs_summary_path,
                                         include_mors=True)

    total_cpu_res = 0.0
    cpu_res_used = 0.0
    total_mem_size_bytes = 0
    total_mem_used_mb = 0
    total_num_of_esxi = len(hs_summary_data)
    num_of_esxi_online = 0
    num_of_esxi_offline = 0
    num_of_esxi_unknown = 0
    for esxi_data in hs_summary_data:
        total_cpu_res += esxi_data["summary.hardware.numCpuCores"] * esxi_data["summary.hardware.cpuMhz"]
        cpu_res_used += esxi_data["summary.quickStats.overallCpuUsage"]
        total_mem_size_bytes += esxi_data["summary.hardware.memorySize"]
        total_mem_used_mb += esxi_data["summary.quickStats.overallMemoryUsage"]
        if esxi_data["runtime.connectionState"] == "connected":
            num_of_esxi_online += 1
        elif esxi_data["runtime.connectionState"] == "disconnected":
            num_of_esxi_offline += 1
        elif esxi_data["runtime.connectionState"] == "notResponding":
            num_of_esxi_unknown += 1
    """
    variable name look like something like ***summary,will be used as part of return string
    """
    cpu_summary = dict()
    #2016-11-18 no more display MHz,send raw data back to java
    cpu_summary["total_cpu_res"] = str(total_cpu_res)
    cpu_summary["used"] = str(cpu_res_used)
    cpu_summary["free"] = str(total_cpu_res - cpu_res_used)
    
    
    mem_summary = dict()
    #2016-11-18 send GB data back to java ,but no more display "GB"
    total_mem_size_gb = round(float(total_mem_size_bytes) / 1024 / 1024 / 1024, 1)
    total_mem_used_gb = round(float(total_mem_used_mb) / 1024 ,1)
    mem_summary["total"] = str(total_mem_size_gb)
    mem_summary["used"] = str(total_mem_used_gb)
    mem_summary["free"] = str(total_mem_size_gb - total_mem_used_gb)
    
    esxi_host_summary = dict()
    esxi_host_summary["num_of_esxi"] = total_num_of_esxi
    esxi_host_summary["online"] = num_of_esxi_online
    esxi_host_summary["offline"] = num_of_esxi_offline
    esxi_host_summary["unknown"] = num_of_esxi_unknown
    
    ds_summary = _getDataStoreInfo(service_instance)
    
    vm_host_summary = dict()
    vm_host_data = _getAllGuestInfo(service_instance,info_type="all")
    vm_host_summary["num_of_vm"] = len(vm_host_data.keys())
    vm_host_summary["online"] = 0
    vm_host_summary["offline"] = 0
    vm_host_summary["unknown"] = 0
    for vm_host_name in vm_host_data.keys():
        if vm_host_data[vm_host_name]["Guest PowerState"] == "running":
            vm_host_summary["online"] += 1
        elif vm_host_data[vm_host_name]["Guest PowerState"] == "notrunning":
            vm_host_summary["offline"] += 1
        else:
            vm_host_summary["unknown"] += 1


    #return str
    vc_summary_dict={
        "cpu":cpu_summary,
        "mem":mem_summary,
        "datastore":ds_summary,
        "esxi_host":esxi_host_summary,
        "vm_host":vm_host_summary
    }
    #return json.dumps(vc_summary_dict)
    return  vc_summary_dict


def _getDcDetailInfo(service_instance,info_type="all"):
    dc_properties = ["name","hostFolder"]

    dc_view = get_container_view(service_instance,
                                 obj_type=[vim.Datacenter])
    dc_raw_data = collect_properties(service_instance, view_ref=dc_view,
                                 obj_type=vim.Datacenter,
                                 path_set=dc_properties,
                                 include_mors=True)
    dc_summary_data = OrderedDict()
    for dc_info in dc_raw_data:
        temp_dc_info_dict = OrderedDict()
        clu_in_dc_num = 0
        ds_obj_dict = dict()
        ds_obj_dict["ds_num"] = 0
        ds_obj_dict["name_list"] = list()
        esxi_in_dc_num = 0
        vm_in_dc_num = 0
        net_in_dc_num = 0
        totalCpu_in_dc = 0  #MHz
        totalCpuUsage_in_dc = 0
        totalMem_in_dc = 0  #bytes
        totalMemUsage_in_dc = 0
        totalDsCapacity_in_dc = 0
        totalDsFree_in_dc = 0
        temp_dc_info_dict["name"] = dc_info.get("name")
        hosts_obj_list = dc_info.get("hostFolder").childEntity  #should be a cluster list ,normaly
        #clu_in_dc_num = len(hosts_obj_list)
        multi_cluster_info = OrderedDict()
        #multi_host_info = dict()
        for host_obj in hosts_obj_list:
            temp_host_info_dict = OrderedDict()
            if isinstance(host_obj,vim.ClusterComputeResource):
                clu_in_dc_num += 1
                net_in_dc_num += len(host_obj.network)
                temp_host_info_dict["name"] = host_obj.name
                temp_host_info_dict["numHost"] = host_obj.summary.numHosts
                temp_host_info_dict["numHostOnline"] = host_obj.summary.numEffectiveHosts
                temp_host_info_dict["totalCpu"] = host_obj.summary.totalCpu
                totalCpu_in_dc += host_obj.summary.totalCpu
                temp_host_info_dict["numCpuCores"] = host_obj.summary.numCpuCores
                temp_host_info_dict["numCpuThreads"] = host_obj.summary.numCpuThreads
                temp_host_info_dict["totalMemory"] = host_obj.summary.totalMemory
                totalMem_in_dc += host_obj.summary.totalMemory  #bytes
                temp_host_info_dict["das enabled"] = host_obj.configuration.dasConfig.enabled
                temp_host_info_dict["drs enabled"] = host_obj.configuration.drsConfig.enabled
                config_ds = list()
                for ds_obj in host_obj.datastore:
                    config_ds.append(ds_obj.name)
                    if ds_obj.name in ds_obj_dict["name_list"]:
                        pass
                    else:
                        ds_obj_dict["ds_num"] += 1
                        ds_obj_dict["name_list"].append(ds_obj.name)
                temp_host_info_dict["datastore list"] = config_ds
                tmp_datastore_info = _getDataStoreDetails(service_instance)
                for ds_name in config_ds:
                    tmp_ds_detail_info = tmp_datastore_info[ds_name]
                    totalDsCapacity_in_dc += tmp_ds_detail_info["capacity"]
                    totalDsFree_in_dc += tmp_ds_detail_info["free"]
                #ds_in_dc_num += len(config_ds)
                config_vm = dict()
                config_template = dict()
                config_esxi = list()
                esxi_detail_info = OrderedDict()
                for esxi_obj in host_obj.host:
                    config_esxi.append(esxi_obj.name)
                    temp_esxi_detail_info = OrderedDict()
                    #vm_on_esxi_list = list()
                    vm_on_esxi_list = OrderedDict()
                    for vm_obj in esxi_obj.vm:
                        if hasattr(vm_obj.summary.config,"instanceUuid"):
                            vm_ins_uuid = vm_obj.summary.config.instanceUuid
                        else:
                            vm_ins_uuid = None
                        vm_on_esxi_list[vm_obj.name] = vm_ins_uuid
                        if hasattr(vm_obj.config,"template"):
                            if vm_obj.config.template:
                                config_template[vm_obj.name] = vm_obj.summary.config.instanceUuid
                            else:
                                config_vm[vm_obj.name] = vm_obj.summary.config.instanceUuid
                    temp_esxi_detail_info["vm list"] = vm_on_esxi_list
                    temp_esxi_detail_info["vendor"] = esxi_obj.summary.hardware.vendor
                    temp_esxi_detail_info["model"] = esxi_obj.summary.hardware.model
                    temp_esxi_detail_info["uuid"] = esxi_obj.summary.hardware.uuid
                    temp_esxi_detail_info["memorySize"] = esxi_obj.summary.hardware.memorySize
                    temp_esxi_detail_info["cpuModel"] = esxi_obj.summary.hardware.cpuModel
                    temp_esxi_detail_info["cpuMhz"] = esxi_obj.summary.hardware.cpuMhz
                    temp_esxi_detail_info["numCpuPkgs"] = esxi_obj.summary.hardware.numCpuPkgs
                    temp_esxi_detail_info["numCpuCores"] = esxi_obj.summary.hardware.numCpuCores
                    temp_esxi_detail_info["numCpuThreads"] = esxi_obj.summary.hardware.numCpuThreads
                    temp_esxi_detail_info["numNics"] = esxi_obj.summary.hardware.numNics
                    temp_esxi_detail_info["numHBAs"] = esxi_obj.summary.hardware.numHBAs
                    esxi_detail_info[esxi_obj.name] = temp_esxi_detail_info
                temp_host_info_dict["esxi host list"] = config_esxi
                temp_host_info_dict["template list"] = config_template
                template_summary_dict = OrderedDict()
                template_detail_info = _getAllGuestInfo(service_instance,"template")
                for template_name in config_template.keys():
                    tmp_vm_detail_info = template_detail_info[template_name]
                    tmp_vm_summary_info = OrderedDict()
                    property_list = ['Name', 'instance UUID', 'Container Version', 'Guest Container Type', 'Guest Full Name', 'hostname',
                        'CPUs', 'numCoresPerSocket', 'numTotalCores', 'MemoryMB', 'MemoryBytes', 'dns', 'virtualDisk', 'NIC']
                    for p_name in property_list:
                        tmp_vm_summary_info[p_name] = tmp_vm_detail_info[p_name]
                        totalCpuUsage_in_dc += tmp_vm_detail_info["cpuUsage"]
                        totalMemUsage_in_dc += tmp_vm_detail_info["MemoryActiveBytes"]
                    template_summary_dict[template_name] = tmp_vm_summary_info
                temp_host_info_dict["vm list"] = config_vm
                vm_detail_info = _getAllGuestInfo(service_instance, "vm")
                for vm_name in config_vm.keys():
                    tmp_vm_detail_info = vm_detail_info[vm_name]
                    totalCpuUsage_in_dc += tmp_vm_detail_info["cpuUsage"]
                    totalMemUsage_in_dc += tmp_vm_detail_info["MemoryActiveBytes"]
                vm_in_dc_num += (len(config_vm) + len(config_template))
                esxi_in_dc_num += len(config_esxi)
                temp_host_info_dict["template details"] = template_summary_dict
                temp_host_info_dict["esxi host details"] = esxi_detail_info
            multi_cluster_info[host_obj.name] = temp_host_info_dict
        temp_dc_info_dict["cluster info"] = multi_cluster_info
        temp_dc_info_dict["obj count"] = {
            "cluster": clu_in_dc_num,
            "esxi": esxi_in_dc_num,
            "datastore": ds_obj_dict["ds_num"],
            "vm": vm_in_dc_num,
            "network": net_in_dc_num
        }
        resource_usage_dict = OrderedDict()
        resource_usage_dict = {
            "totalCpu": totalCpu_in_dc,
            "totalCpuUsage": totalCpuUsage_in_dc,
            "totalMem": totalMem_in_dc,
            "totalMemUsage": totalMemUsage_in_dc,
            "totalDs": totalDsCapacity_in_dc,
            "totalDsUsage": (totalDsCapacity_in_dc - totalDsFree_in_dc)
        }
        temp_dc_info_dict["resource usage"] = resource_usage_dict
        dc_summary_data[dc_info.get("name")] = temp_dc_info_dict
    return_dict = OrderedDict()
    if info_type == "all":
        return_dict = dc_summary_data
    #elif info_type == "name_list":
    #    dc_name_list = dc_summary_data.keys()
    #    for dc_name in dc_name_list:
    #        temp_dc_info_dict_2 = OrderedDict()
    #        temp_dc_info_dict_2[]
    return return_dict

def VcSummaryInfo(v_host,v_user,v_pwd,v_port,v_protocol=None):
    service_instance = None
    try:
        service_instance = get_service_instance(v_host, v_user, v_pwd, v_protocol, int(v_port))
        # print("Connected")
        log.debug("%s Connected", v_host)
    except IOError as e:
        log.debug(e)

    #if isinstance(service_instance,(list,str)):
    #    #raise SystemExit("Unable to connect to host with supplied info.")
    #    ret_str = "query info failed: " + str(service_instance)
    #    return ret_str
    #else:
    #    return _getVcSummary(service_instance)
    ret_dict = dict()
    #full_path = sys._getframe().f_code.co_filename
    #module_name = basename(full_path).split(".")[0]
    func_name=sys._getframe().f_code.co_name
    oper_func= MODULE_NAME + "." + func_name
    ret_dict["oper_fun"] = oper_func
    if isinstance(service_instance,(list,str)):
        ret_result = 1
        ret_errmsg = "query info failed: " + str(service_instance)
        ret_data = ""
    else:
        ret_data = _getVcSummary(service_instance)
        if ret_data is not None:
            ret_result = 0
            ret_errmsg = ""
        else:
            ret_result = 1
            ret_errmsg = "operate failed: . Please check the debug log for more information."
    ret_dict["result"] = ret_result
    ret_dict["errmsg"] = ret_errmsg
    ret_dict["data"] = ret_data
    Disconnect(service_instance)
    return json.dumps(ret_dict)


def GetAllTemplateInfo(v_host,v_user,v_pwd,v_port,v_protocol=None):
    ret_dict = dict()
    func_name=sys._getframe().f_code.co_name
    oper_func= MODULE_NAME + "." + func_name
    ret_dict["oper_fun"] = oper_func
    service_instance = None
    try:
        service_instance = get_service_instance(v_host, v_user, v_pwd, v_protocol, int(v_port))
        # print("Connected")
        log.debug("%s Connected", v_host)
    except IOError as e:
        log.debug(e)
    if isinstance(service_instance,(list,str)):
        ret_result = 1
        ret_errmsg = "query info failed: " + str(service_instance)
        ret_data = ""
    else:
        ret_data = _getAllGuestInfo(service_instance,info_type="template")
        if ret_data is not None:
            ret_result = 0
            ret_errmsg = ""
        else:
            ret_result = 1
            ret_errmsg = "operate failed: . Please check the debug log for more information."
    ret_dict["result"] = ret_result
    ret_dict["errmsg"] = ret_errmsg
    ret_dict["data"] = ret_data
    Disconnect(service_instance)
    return json.dumps(ret_dict)


def GetAllVmInfo(v_host,v_user,v_pwd,v_port,v_protocol=None):
    ret_dict = dict()
    func_name=sys._getframe().f_code.co_name
    oper_func= MODULE_NAME + "." + func_name
    ret_dict["oper_fun"] = oper_func
    service_instance = None
    try:
        service_instance = get_service_instance(v_host, v_user, v_pwd, v_protocol, int(v_port))
        # print("Connected")
        log.debug("%s Connected", v_host)
    except IOError as e:
        log.debug(e)
    if isinstance(service_instance,(list,str)):
        ret_result = 1
        ret_errmsg = "query info failed: " + str(service_instance)
        ret_data = ""
    else:
        ret_data = _getAllGuestInfo(service_instance,info_type="vm")
        if ret_data is not None:
            ret_result = 0
            ret_errmsg = ""
        else:
            ret_result = 1
            ret_errmsg = "operate failed: . Please check the debug log for more information."
    ret_dict["result"] = ret_result
    ret_dict["errmsg"] = ret_errmsg
    ret_dict["data"] = ret_data
    Disconnect(service_instance)
    return json.dumps(ret_dict)


def GetDataStoreInfo(v_host, v_user, v_pwd, v_port, v_protocol=None):
    service_instance = None
    try:
        service_instance = get_service_instance(v_host, v_user, v_pwd, v_protocol, int(v_port))
        # print("Connected")
        log.debug("%s Connected", v_host)
    except IOError as e:
        log.debug(e)

    # if not service_instance:
    #    raise SystemExit("Unable to connect to host with supplied info.")
    # if isinstance(service_instance,(list,str)):
    #    ret_str = "query info failed: " + str(service_instance)
    #    return ret_str
    # else:
    #    return _getDataStoreInfo(service_instance)
    ret_dict = dict()
    # full_path = sys._getframe().f_code.co_filename
    # module_name = basename(full_path).split(".")[0]
    func_name = sys._getframe().f_code.co_name
    oper_func = MODULE_NAME + "." + func_name
    ret_dict["oper_fun"] = oper_func
    if isinstance(service_instance, (list, str)):
        ret_result = 1
        ret_errmsg = "query info failed: " + str(service_instance)
        ret_data = ""
    else:
        ret_data = _getDataStoreInfo(service_instance)
        if ret_data is not None:
            ret_result = 0
            ret_errmsg = ""
        else:
            ret_result = 1
            ret_errmsg = "operate failed: . Please check the debug log for more information."
    ret_dict["result"] = ret_result
    ret_dict["errmsg"] = ret_errmsg
    ret_dict["data"] = ret_data
    Disconnect(service_instance)
    return json.dumps(ret_dict)


def GetAllGuestInfo(v_host,v_user,v_pwd,v_port,v_protocol=None,vm_uuid=None):
    service_instance = None
    try:
        service_instance = get_service_instance(v_host,v_user,v_pwd,v_protocol,int(v_port))
        #print("Connected")
        log.debug("%s Connected",v_host)
    except IOError as e:
        log.debug(e)

    ret_dict = dict()
    func_name=sys._getframe().f_code.co_name
    oper_func= MODULE_NAME + "." + func_name
    ret_dict["oper_fun"] = oper_func
    if isinstance(service_instance,(list,str)):
        ret_result = 1
        ret_errmsg = "query info failed: " + str(service_instance)
        ret_data = ""
    else:
        if vm_uuid:
            ret_data = _getAllGuestInfo(service_instance, vm_uuid=vm_uuid)
        else:
            ret_data = _getAllGuestInfo(service_instance,info_type="all")
        if ret_data is not None:
            ret_result = 0
            ret_errmsg = ""
        else:
            ret_result = 1
            ret_errmsg = "operate failed: . Please check the debug log for more information."
    ret_dict["result"] = ret_result
    ret_dict["errmsg"] = ret_errmsg
    ret_dict["data"] = ret_data
    Disconnect(service_instance)
    return json.dumps(ret_dict)


def GetAllDataStoreInfo(v_host,v_user,v_pwd,v_port,v_protocol=None):
    service_instance = None
    ret_dict = dict()
    func_name=sys._getframe().f_code.co_name
    oper_func= MODULE_NAME + "." + func_name
    ret_dict["oper_fun"] = oper_func
    try:
        service_instance = get_service_instance(v_host,v_user,v_pwd,v_protocol,int(v_port))
        #print("Connected")
        log.debug("%s Connected",v_host)
    except IOError as e:
        log.debug(e)
    if isinstance(service_instance,(list,str)):
        ret_result = 1
        ret_errmsg = "query info failed: " + str(service_instance)
        ret_data = ""
    else:
        ret_data = _getDataStoreDetails(service_instance,"all")
        if ret_data is not None:
            ret_result = 0
            ret_errmsg = ""
        else:
            ret_result = 1
            ret_errmsg = "operate failed: . Please check the debug log for more information."
    ret_dict["result"] = ret_result
    ret_dict["errmsg"] = ret_errmsg
    ret_dict["data"] = ret_data
    Disconnect(service_instance)
    return json.dumps(ret_dict)


def GetAllDcInfo(v_host,v_user,v_pwd,v_port,v_protocol=None):
    service_instance = None
    ret_dict = dict()
    func_name = sys._getframe().f_code.co_name
    oper_func = MODULE_NAME + "." + func_name
    ret_dict["oper_fun"] = oper_func
    try:
        service_instance = get_service_instance(v_host, v_user, v_pwd, v_protocol, int(v_port))
        # print("Connected")
        log.debug("%s Connected", v_host)
    except IOError as e:
        log.debug(e)
    if isinstance(service_instance, (list, str)):
        ret_result = 1
        ret_errmsg = "query info failed: " + str(service_instance)
        ret_data = ""
    else:
        ret_data = _getDcDetailInfo(service_instance, "all")
        if ret_data is not None:
            ret_result = 0
            ret_errmsg = ""
        else:
            ret_result = 1
            ret_errmsg = "operate failed: . Please check the debug log for more information."
    ret_dict["result"] = ret_result
    ret_dict["errmsg"] = ret_errmsg
    ret_dict["data"] = ret_data
    Disconnect(service_instance)
    return json.dumps(ret_dict)
