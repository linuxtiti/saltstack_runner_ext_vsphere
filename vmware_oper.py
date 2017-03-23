#!/usr/bin/env python
"""
 Written by Michael Rice
 Github: https://github.com/michaelrice
 Website: https://michaelrice.github.io/
 Blog: http://www.errr-online.com/
 This code has been released under the terms of the Apache 2 licenses
 http://www.apache.org/licenses/LICENSE-2.0.html

 Script to do some shit to vmw on vcenter or esxi
 author : lim@shsnc.com
 time: 2016-11-22 18:20
 version: 0.1

 time: 2016-11-22 19:40
 version: 0.11

 time: 2016-11-24 12:22
 version: 0.12
 change history:
    fix function VmOsManager: shutdonw / reboot unable to JSON serialize err msg problem

 time: 2016-11-24 18:26
 version: 0.13
 change history:
    modify VmOsManager and VmPowerManager : make it accept a uuid array

 time: 2016-11-29 19:20
 version: 0.2 dev
 change history:
    add clone vm function , not usable,not update to 192.168.11.38

 time: 2016-12-04 18:38
 version: 0.21
 change history:
    add vm clone function,reconfig vm function, destory vm function

 time: 2016-12-05 15:40
 version: 0.22 
 change history:
    number related variables : force to do str->int translate

 time: 2016-12-05 18:23
 version: 0.23
 change history:
    modify reconfigvm  , make it can change old vdisk ' diskmode

 time: 2016-12-05 18:59
 version: 0.24
 change history:
    destory vm ,accept "vm_uuid" or "vm_name"

 time: 2016-12-06 20:19
 version: 0.25
 change history:
    fix task query

 time: 2016-12-07 19:02
 version: 0.26
 change history:
    modified reconfigvm ,support del disk
"""

# Import Python Libs
from __future__ import print_function
from time import clock
from datetime import timedelta
from os.path import basename
from collections import OrderedDict
import json, logging, atexit, sys

# Import Salt Libs
# from salt.exceptions import SaltSystemExit

# Import Third Party Libs
try:
    import pyVmomi
    # from pyVim import connect
    from pyVim.connect import GetSi, SmartConnect, Disconnect
    from pyVmomi import vim
    from pyVmomi import vmodl

    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False

# Get Logging Started
log = logging.getLogger(__name__)
START = clock()  # MayBe we will need this later to record running time to perform one operation
MODULE_FULL_PATH = sys._getframe().f_code.co_filename
MODULE_NAME = basename(MODULE_FULL_PATH).split(".")[0]
"""
how to get a function name dynamic?
func_name=sys._getframe().f_code.co_name
"""


def __virtual__():
    '''
    Only load if PyVmomi is installed.
    '''
    if HAS_PYVMOMI:
        return True
    else:
        return False, 'Missing dependency: The ext.module.vmware_info requires pyVmomi.'


def get_service_instance(host, username, password, port=None, protocol=None):
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
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    # context.verify_mode = ssl.CERT_NONE
    try:
        service_instance = SmartConnect(
            host=host,
            user=username,
            pwd=password,
            protocol=protocol,
            port=int(port)
            # sslContext=context
        )
    except Exception as exc:
        default_msg = 'Could not connect to host \'{0}\'. ' \
                      'Please check the debug log for more information.'.format(host)
        try:
            if (isinstance(exc,
                           vim.fault.HostConnectFault) and '[SSL: CERTIFICATE_VERIFY_FAILED]' in exc.msg) or '[SSL: CERTIFICATE_VERIFY_FAILED]' in str(
                    exc):
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
            elif (isinstance(exc,
                             vim.fault.HostConnectFault) and 'SSL3_GET_SERVER_CERTIFICATE\', \'certificate verify failed' in exc.msg) or 'SSL3_GET_SERVER_CERTIFICATE\', \'certificate verify failed' in str(
                    exc):
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
                # raise SaltSystemExit(err_msg)
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
                # raise SaltSystemExit(err_msg)
                return err_msg

    atexit.register(Disconnect, service_instance)
    return service_instance


def wait_for_tasks(service_instance, tasks):
    """Given the service instance si and tasks, it returns after all the
   tasks are complete
   """
    property_collector = service_instance.content.propertyCollector
    task_list = [str(task) for task in tasks]
    # Create filter
    obj_specs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task)
                 for task in tasks]
    property_spec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task,
                                                               pathSet=[],
                                                               all=True)
    filter_spec = vmodl.query.PropertyCollector.FilterSpec()
    filter_spec.objectSet = obj_specs
    filter_spec.propSet = [property_spec]
    pcfilter = property_collector.CreateFilter(filter_spec, True)
    try:
        version, state = None, None
        # Loop looking for updates till the state moves to a completed state.
        while len(task_list):
            update = property_collector.WaitForUpdates(version)
            for filter_set in update.filterSet:
                for obj_set in filter_set.objectSet:
                    task = obj_set.obj
                    for change in obj_set.changeSet:
                        if change.name == 'info':
                            state = change.val.state
                        elif change.name == 'info.state':
                            state = change.val
                        else:
                            continue

                        if not str(task) in task_list:
                            continue

                        if state == vim.TaskInfo.State.success:
                            # Remove task from taskList
                            task_list.remove(str(task))
                        elif state == vim.TaskInfo.State.error:
                            raise task.info.error
            # Move to next version
            version = update.version
    finally:
        if pcfilter:
            pcfilter.Destroy()


def endit():
    """
    times how long it took for this script to run.

    :return:
    """
    end = clock()
    total = end - START
    print("Completion time: {0} seconds.".format(total))


def _findVmByUuid(service_instance, vm_uuid):
    """
    :param service_instance:
    :param vm_uuid:
    :return:
        if find that vm using given uuid,return will be a vm instance
        if not ,return an string which is a err message
    """
    search_index = service_instance.content.searchIndex
    vm_instance = search_index.FindByUuid(None, vm_uuid, True, True)
    def_err_msg = "Could not find virtual machine by uuid %s" % vm_uuid

    if vm_instance is None:
        return def_err_msg
    else:
        return vm_instance


def _findHsByUuid(service_instance, vm_uuid):
    """
    :param service_instance:
    :param vm_uuid:
    :return:
        if find that vm using given uuid,return will be a vm instance
        if not ,return an string which is a err message
    """
    search_index = service_instance.content.searchIndex
    hostSystem = search_index.FindByUuid(None, vm_uuid, False, True)
    def_err_msg = "Could not find virtual machine by uuid %s" % vm_uuid

    if hostSystem is None:
        return def_err_msg
    else:
        return hostSystem


def _getTaskHistoryCollectorByEntity(service_instance, vm_uuid):
    tm_instance = service_instance.content.taskManager
    vm_instance = _findVmByUuid(service_instance, vm_uuid)
    if not isinstance(vm_instance, vim.VirtualMachine):
        return vm_instance
    else:
        # tfsbe : task filter specify by entiry(ManageEntiry)
        tfsbe = vim.TaskFilterSpec.ByEntity(entity=vm_instance, recursion="all")
        task_filter_spc = vim.TaskFilterSpec(entity=tfsbe)
        his_task_collector = tm_instance.CreateCollectorForTasks(task_filter_spc)
        return his_task_collector


def _get_obj(content, vimtype, name):
    """
    Return an object by name, if name is None the
    first found object is returned
    """
    obj = None
    container = content.viewManager.CreateContainerView(
        content.rootFolder, vimtype, True)
    for c in container.view:
        if name:
            if c.name == name:
                obj = c
                break
        else:
            obj = c
            break

    return obj


def _cloneVm(content, template, vm_name, datacenter_name, cluster_name, power_on, deploy_settings=None,
             resource_pool=None,
             vm_folder=None, datastore_name=None):
    """
    Clone a VM from a template/VM, datacenter_name, vm_folder, datastore_name
    cluster_name, resource_pool, and power_on are all optional.
    """

    # if none git the first one
    datacenter = _get_obj(content, [vim.Datacenter], datacenter_name)

    if vm_folder:
        destfolder = _get_obj(content, [vim.Folder], vm_folder)
    else:
        destfolder = datacenter.vmFolder

    if datastore_name:
        datastore = _get_obj(content, [vim.Datastore], datastore_name)
    else:
        datastore = _get_obj(
            content, [vim.Datastore], template.datastore[0].info.name)

    # if None, get the first one
    cluster = _get_obj(content, [vim.ClusterComputeResource], cluster_name)

    if resource_pool:
        resource_pool = _get_obj(content, [vim.ResourcePool], resource_pool)
    else:
        resource_pool = cluster.resourcePool

    template_vm_haredware_dict = OrderedDict()
    nic_obj_list = list()
    device_key_list = list()
    device_unitnum_list = list()
    template_pci_controller = None
    max_nic_device_key = 0
    max_nic_unit_number = 0
    template_vm_haredware_dict["numCPU"] = int(template.config.hardware.numCPU)
    template_vm_haredware_dict["numCoresPerSocket"] = int(template.config.hardware.numCoresPerSocket)
    template_vm_haredware_dict["memoryMB"] = int(template.config.hardware.memoryMB)
    for dev_obj in template.config.hardware.device:
        device_key_list.append(dev_obj.key)
        device_unitnum_list.append(dev_obj.unitNumber)
        if isinstance(dev_obj, vim.VirtualEthernetCard):
            nic_obj_list.append(dev_obj)
            if dev_obj.unitNumber > max_nic_unit_number:
                max_nic_unit_number = dev_obj.unitNumber
            if dev_obj.key > max_nic_device_key:
                max_nic_device_key = dev_obj.key
        if isinstance(dev_obj, vim.vm.device.VirtualPCIController):
            template_pci_controller = dev_obj
    template_vm_haredware_dict["max_nic_key"] = max_nic_device_key
    template_vm_haredware_dict["max_nic_unitnum"] = max_nic_unit_number
    template_vm_haredware_dict["nic_list"] = nic_obj_list
    template_vm_haredware_dict["nic_controller"] = template_pci_controller
    template_vm_haredware_dict["key_list"] = device_key_list
    template_vm_haredware_dict["unitnum_list"] = device_unitnum_list
    # VM config (cpu and mem resource configration)spec
    vmconf = vim.vm.ConfigSpec()
    if deploy_settings.get("numCPU"):
        vmconf.numCPUs = int(deploy_settings.get("numCPU"))
    else:
        vmconf.numCPUs = template_vm_haredware_dict["numCPU"]
    if deploy_settings.get("numCoresPerSocket"):
        vmconf.numCoresPerSocket = int(deploy_settings.get("numCoresPerSocket"))
    else:
        vmconf.numCoresPerSocket = template_vm_haredware_dict["numCoresPerSocket"]
    if deploy_settings.get("memoryBytes"):
        vmconf.memoryMB = int(deploy_settings.get("memoryBytes")) / 1024 / 1024
    elif deploy_settings.get("memoryMB"):
        vmconf.memoryMB = int(deploy_settings.get("memoryMB"))
    else:
        vmconf.memoryMB = template_vm_haredware_dict["memoryMB"]
    vmconf.cpuHotAddEnabled = True
    vmconf.memoryHotAddEnabled = True
    # DNS settings
    globalip = vim.vm.customization.GlobalIPSettings()
    if deploy_settings.get("dns_servers"):
        globalip.dnsServerList = deploy_settings['dns_servers']
    else:
        globalip.dnsServerList = ["114.114.114.114"]
    # globalip.dnsSuffixList = ip_settings[0]['domain']

    # device setting (only support VirtualEthernetCard )
    new_add_devices = list()
    adaptermaps = list()
    tmp_counter = 0
    if deploy_settings.get("nic"):
        config_spec_nic = len(deploy_settings.get("nic"))
        num_of_new_vm_nic = config_spec_nic
    else:
        num_of_new_vm_nic = len(template_vm_haredware_dict["nic_list"])
    while tmp_counter < num_of_new_vm_nic:
        adaptermaps.append(None)
        tmp_counter += 1
    # print(deploy_settings)
    if deploy_settings.get("nic"):
        # print(deploy_settings["nic"])
        order_nic_name_list = sorted(deploy_settings.get("nic").keys())
        # print(order_nic_name_list)
        # for vnic_label in deploy_settings.get("nic").keys():
        for nic_index, vnic_label in enumerate(order_nic_name_list):
            tmp_virtual_nic_device = None
            nic = None  # nic should be nic_spce,too lazy to change name
            # print(nic_index,vnic_label)
            # print(vdisk_label)
            nic_config = deploy_settings.get("nic")[vnic_label]
            # print(nic_config)
            for t_d_obj in template_vm_haredware_dict["nic_list"]:
                if t_d_obj.deviceInfo.label == vnic_label:
                    tmp_virtual_nic_device = t_d_obj
            nic_exist = True if tmp_virtual_nic_device else False
            if nic_exist:
                # nic = vim.vm.device.VirtualDeviceSpec()
                # nic.device = tmp_virtual_nic_device
                # print(nic.device)
                new_network_name = str(nic_config["network"])
                template_nic_network_name = tmp_virtual_nic_device.backing.network.name
                if new_network_name == template_nic_network_name:
                    pass
                else:
                    nic = vim.vm.device.VirtualDeviceSpec()
                    nic.device = tmp_virtual_nic_device
                    nic.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit  # or edit if a device exists
                    nic.device.backing.deviceName = new_network_name
                    nic.device.backing.network = _get_obj(content, [vim.Network], new_network_name)
            else:
                nic = vim.vm.device.VirtualDeviceSpec()
                nic.operation = vim.vm.device.VirtualDeviceSpec.Operation.add  # or edit if a device exists
                nic.fileOperation = "create"
                nic.device = vim.vm.device.VirtualE1000()
                nic.device.deviceInfo = vim.Description()
                nic.device.deviceInfo.summary = nic_config["network"]
                nic.device.wakeOnLanEnabled = True
                nic.device.addressType = 'assigned'
                find_key_num = 1
                test_key_num = template_vm_haredware_dict["max_nic_key"] + 1
                while find_key_num != 0:
                    if test_key_num in template_vm_haredware_dict["key_list"]:
                        test_key_num += 1
                    else:
                        nic.device.key = test_key_num
                        find_key_num = 0
                # nic.device.key = template_vm_haredware_dict["nic_max_key"] + 1
                template_vm_haredware_dict["nic_max_key"] = test_key_num
                nic.device.controllerKey = template_vm_haredware_dict["nic_controller"].key
                find_unitnum = 1
                test_unitnum = template_vm_haredware_dict["max_nic_unitnum"] + 1
                while find_unitnum != 0:
                    if test_unitnum in template_vm_haredware_dict["unitnum_list"]:
                        test_unitnum += 1
                    else:
                        nic.device.unitNumber = test_unitnum
                        find_unitnum = 0
                # nic.device.unitNumber = template_vm_haredware_dict["nic_max_unit_number"] + 1
                template_vm_haredware_dict["nic_max_unit_number"] = test_unitnum
                nic.device.deviceInfo = vim.Description()
                num_of_nic = len(template_vm_haredware_dict["nic_list"])
                nic.device.deviceInfo.label = "Network Adapter %s" % (num_of_nic + 1)
                nic.device.deviceInfo.summary = nic_config["network"]
                nic.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
                nic.device.backing.network = _get_obj(content, [vim.Network], nic_config["network"])
                nic.device.backing.deviceName = nic_config["network"]
                nic.device.backing.useAutoDetect = False
                nic.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
                nic.device.connectable.startConnected = True
                nic.device.connectable.allowGuestControl = True
            if nic:
                # print(nic)
                new_add_devices.append(nic)
            guest_map = vim.vm.customization.AdapterMapping()
            guest_map.adapter = vim.vm.customization.IPSettings()
            if nic_config.get("ip"):
                guest_map.adapter.ip = vim.vm.customization.FixedIp()
                guest_map.adapter.ip.ipAddress = str(nic_config.get("ip"))
                if nic_config.get("subnet_mask"):
                    guest_map.adapter.subnetMask = str(nic_config.get("subnet_mask"))
                else:
                    guest_map.adapter.subnetMask = str("255.255.255.0")
            else:
                guest_map.adapter.ip = vim.vm.customization.DhcpIpGenerator()
            adaptermaps[nic_index] = guest_map
    nic_index = 0
    for nic_index, nic_mapping in enumerate(adaptermaps):
        if nic_mapping is None:
            guest_map = vim.vm.customization.AdapterMapping()
            guest_map.adapter = vim.vm.customization.IPSettings()
            guest_map.adapter.ip = vim.vm.customization.DhcpIpGenerator()
            adaptermaps[nic_index] = guest_map
    ident = vim.vm.customization.LinuxPrep()
    ident.hwClockUTC = False
    ident.hostName = vim.vm.customization.FixedName()
    if deploy_settings.get("domain"):
        ident.domain = deploy_settings["domain"]
    else:
        ident.domain = "localhost.local"
    if deploy_settings.get("hostname"):
        ident.hostName.name = deploy_settings["hostname"]
    else:
        ident.hostName.name = "localhost"

    if deploy_settings.get("timezone"):
        ident.timeZone = deploy_settings["timezone"]
    else:
        ident.timeZone = "Asia/Shanghai"
    # print(ident)
    customspec = vim.vm.customization.Specification()
    customspec.globalIPSettings = globalip
    customspec.nicSettingMap = adaptermaps
    customspec.identity = ident
    # print(customspec)
    relospec = vim.vm.RelocateSpec()
    relospec.datastore = datastore
    relospec.pool = resource_pool
    clonespec = vim.vm.CloneSpec()
    clonespec.location = relospec
    clonespec.config = vmconf
    # clonespec.customization = customspec
    clonespec.powerOn = power_on
    clonespec.template = False

    clone_task = template.CloneVM_Task(folder=destfolder, name=vm_name, spec=clonespec)
    query_ticket = {"uuid": template.config.instanceUuid, "task_key": clone_task.info.key,
                    "eventid": str(clone_task.info.eventChainId)}
    result_dict = {"data": query_ticket, "errmsg": "", "result": 0}
    return result_dict


def _destroy_vm(service_instance, vm_obj):
    if vm_obj.runtime.powerState == "poweredOn":
        pf_task = vm_obj.PowerOffVM_Task()
        wait_for_tasks(service_instance, [pf_task])
        # print("{0}".format(TASK.info.state))
    # print("Destroying VM from vSphere.")
    dv_task = vm_obj.Destroy_Task()
    query_ticket = {"uuid": "", "task_key": dv_task.info.key,
                    "eventid": str(dv_task.info.eventChainId)}
    result_dict = {"data": query_ticket, "errmsg": "", "result": 0}
    # return dv_task
    return result_dict


def _reconfig_vm(content, vm_obj, vm_spec):
    target_vm_haredware_dict = dict()
    target_vm_haredware_dict["numCPU"] = int(vm_obj.config.hardware.numCPU)
    target_vm_haredware_dict["numCoresPerSocket"] = int(vm_obj.config.hardware.numCoresPerSocket)
    target_vm_haredware_dict["memoryMB"] = int(vm_obj.config.hardware.memoryMB)
    disk_obj_list = list()
    disk_file_dir_list = list()
    device_key_list = list()
    device_unitnum_list = list()
    nic_obj_list = list()
    template_controller = None
    template_pci_controller = None
    max_unit_number = 0
    max_nic_unit_number = 0
    max_device_key = 0
    max_nic_device_key = 0
    for dev_obj in vm_obj.config.hardware.device:
        if isinstance(dev_obj, vim.vm.device.VirtualDisk):
            disk_obj_list.append(dev_obj)
            device_key_list.append(dev_obj.key)
            device_unitnum_list.append(dev_obj.unitNumber)
            disk_file_dir = dev_obj.backing.fileName.split("/")[0]
            disk_file_dir_list.append(disk_file_dir)
            if dev_obj.unitNumber > max_unit_number:
                max_unit_number = dev_obj.unitNumber
            if dev_obj.key > max_device_key:
                max_device_key = dev_obj.key
        if isinstance(dev_obj, vim.VirtualEthernetCard):
            nic_obj_list.append(dev_obj)
            if dev_obj.unitNumber > max_nic_unit_number:
                max_nic_unit_number = dev_obj.unitNumber
            if dev_obj.key > max_nic_device_key:
                max_nic_device_key = dev_obj.key
        if isinstance(dev_obj, vim.vm.device.VirtualSCSIController):
            template_controller = dev_obj
        if isinstance(dev_obj, vim.vm.device.VirtualPCIController):
            template_pci_controller = dev_obj
    target_vm_haredware_dict["key_list"] = device_key_list
    target_vm_haredware_dict["unitnum_list"] = device_unitnum_list
    target_vm_haredware_dict["disk list"] = disk_obj_list
    target_vm_haredware_dict["disk_number"] = len(disk_obj_list)
    target_vm_haredware_dict["disk_controller"] = template_controller
    target_vm_haredware_dict["disk_unit_number"] = max_unit_number
    target_vm_haredware_dict["disk_device_key"] = max_device_key
    target_vm_haredware_dict["nic_list"] = nic_obj_list
    target_vm_haredware_dict["nic_controller"] = template_pci_controller
    target_vm_haredware_dict["max_nic_key"] = max_nic_device_key
    target_vm_haredware_dict["max_nic_unitnum"] = max_nic_unit_number

    devices = []
    # VM config (cpu and mem resource configration)spec
    # if deploy_settings:
    deploy_settings = vm_spec
    vmconf = vim.vm.ConfigSpec()
    if deploy_settings.get("numCPU"):
        vmconf.numCPUs = int(deploy_settings.get("numCPU"))
    else:
        vmconf.numCPUs = target_vm_haredware_dict["numCPU"]
    if deploy_settings.get("numCoresPerSocket"):
        vmconf.numCoresPerSocket = int(deploy_settings.get("numCoresPerSocket"))
    else:
        vmconf.numCoresPerSocket = target_vm_haredware_dict["numCoresPerSocket"]
    if deploy_settings.get("memoryBytes"):
        vmconf.memoryMB = int(deploy_settings.get("memoryBytes")) / 1024 / 1024
    elif deploy_settings.get("memoryMB"):
        vmconf.memoryMB = int(deploy_settings.get("memoryMB"))
    else:
        vmconf.memoryMB = target_vm_haredware_dict["memoryMB"]
    vmconf.cpuHotAddEnabled = True
    vmconf.memoryHotAddEnabled = True
    if deploy_settings.get("disk"):
        #disk_lable_list = sorted(deploy_settings.get("disk").keys())
        for vdisk_label in deploy_settings.get("disk").keys():
            tmp_virtual_disk_device = None
            disk_spec = None
            print(vdisk_label)
            disk_oper_config = deploy_settings.get("disk")[vdisk_label]
            print(disk_oper_config)
            if disk_oper_config.get("datastore_name"):
                datastore = _get_obj(content, [vim.Datastore], disk_oper_config.get("datastore_name"))
            else:
                datastore = _get_obj(
                    content, [vim.Datastore], vm_obj.datastore[0].info.name)
            for t_d_obj in target_vm_haredware_dict["disk list"]:
                if t_d_obj.deviceInfo.label == vdisk_label:
                    tmp_virtual_disk_device = t_d_obj
            disk_exist = True if tmp_virtual_disk_device else False
            try:
                disk_oper_action = disk_oper_config["disk_oper"]
                log.debug("disk opertation type %s" ,disk_oper_action)
            except:
                disk_oper_action = None
                log.debug("something wrong here,empty disk operation type")
            if disk_exist:
                log.debug("found target disk %s",vdisk_label)
                #try:
                new_capacity_in_bytes = int(disk_oper_config.get("capacityBytes"))
                #except Exception:
                #    new_capacity_in_bytes = 0
                old_capacity_in_bytes = tmp_virtual_disk_device.capacityInBytes
                if disk_oper_action == "del":
                    print("need to del disk %s" % vdisk_label)
                    disk_spec = vim.vm.device.VirtualDeviceSpec()
                    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
                    disk_spec.device = tmp_virtual_disk_device
                elif disk_oper_action == "edit" and new_capacity_in_bytes > old_capacity_in_bytes:
                    print("need to resize disk %s" % vdisk_label)
                    disk_spec = vim.vm.device.VirtualDeviceSpec()
                    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
                    disk_spec.device = vim.vm.device.VirtualDisk()
                    disk_spec.device.key = tmp_virtual_disk_device.key
                    disk_spec.device.backing = tmp_virtual_disk_device.backing
                    disk_spec.device.backing.datastore = tmp_virtual_disk_device.backing.datastore
                    if disk_oper_config.get("disk_mode"):
                        disk_spec.device.backing.diskMode = disk_oper_config.get("disk_mode")
                    else:
                        disk_spec.device.backing.diskMode = tmp_virtual_disk_device.backing.diskMode
                    disk_spec.device.backing.fileName = tmp_virtual_disk_device.backing.fileName
                    if disk_oper_config.get("disk_thin"):
                        disk_spec.device.backing.thinProvisioned = disk_oper_config.get("disk_thin")
                    else:
                        disk_spec.device.backing.thinProvisioned = tmp_virtual_disk_device.backing.thinProvisioned
                    disk_spec.device.controllerKey = tmp_virtual_disk_device.controllerKey
                    disk_spec.device.unitNumber = tmp_virtual_disk_device.unitNumber
                    disk_spec.device.capacityInBytes = new_capacity_in_bytes
                    disk_spec.device.capacityInKB = new_capacity_in_bytes / 1024
            else:
                if disk_oper_action == 'add':
                    print("need to add new disk %s" % vdisk_label)
                    new_capacity = int(disk_oper_config.get("capacityBytes"))
                    disk_spec = vim.vm.device.VirtualDeviceSpec()
                    disk_spec.fileOperation = "create"
                    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
                    disk_spec.device = vim.vm.device.VirtualDisk()
                    disk_spec.device.deviceInfo = vim.Description()
                    disk_spec.device.deviceInfo.label = vdisk_label
                    disk_spec.device.key = target_vm_haredware_dict["disk_device_key"] + 1
                    target_vm_haredware_dict["disk_device_key"] += 1
                    disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
                    disk_spec.device.backing.datastore = datastore
                    if disk_oper_config.get("disk_mode"):
                        disk_spec.device.backing.diskMode = disk_oper_config.get("disk_mode")
                    else:
                        disk_spec.device.backing.diskMode = "independent_persistent"
                    if disk_oper_config.get("disk_thin"):
                        disk_spec.device.backing.thinProvisioned = disk_oper_config.get("disk_thin")
                    else:
                        disk_spec.device.backing.thinProvisioned = True
                    disk_spec.device.controllerKey = template_controller.key
                    disk_spec.device.unitNumber = target_vm_haredware_dict["disk_unit_number"] + 1
                    target_vm_haredware_dict["disk_unit_number"] += 1
                    disk_spec.device.capacityInKB = new_capacity / 1024
                    disk_spec.device.capacityInBytes = new_capacity
            if disk_spec:
                # print(disk_spec)
                devices.append(disk_spec)
    vmconf.deviceChange = devices
    # print(vmconf)
    reconfig_task = vm_obj.ReconfigVM_Task(spec=vmconf)
    query_ticket = {"uuid": vm_obj.config.instanceUuid, "task_key": reconfig_task.info.key,
                    "eventid": str(reconfig_task.info.eventChainId)}
    # wait_for_task(task)
    result_dict = {"data": query_ticket, "errmsg": "", "result": 0}
    return result_dict


def _vmPowerOper(vm_instance, oper_type):
    """
    perform an power task on a vm ,poweron/poweroff ,suspend,an so on
    :param vm_instance:
    :param oper_type: poweron/poweroff/suspend/reset/status
    :return:
        {
            "result": 0 is ok,1 is failed
            "data": normal output,
            "errmsg": err message
        }
    """
    if oper_type == "poweron":
        # do something to the vm
        power_oper_task = vm_instance.PowerOn()
    elif oper_type == "poweroff":
        power_oper_task = vm_instance.PowerOff()
    elif oper_type == "suspend":
        power_oper_task = vm_instance.Suspend()
    elif oper_type == "reset":
        power_oper_task = vm_instance.Reset()
    elif oper_type == "status":
        result_dict = {"data": vm_instance.summary.runtime.powerState, "errmsg": "", "result": 0}
        return result_dict
    else:
        result_dict = {"data": "", "errmsg": "unsupport operation,nothing to do here", "result": 1}
        return result_dict
    vm_instance_uuid = str(vm_instance.config.instanceUuid)
    query_ticket = {"uuid": vm_instance_uuid, "task_key": power_oper_task.info.key,
                    "eventid": str(power_oper_task.info.eventChainId)}
    result_dict = {"data": query_ticket, "errmsg": "", "result": 0}
    return result_dict


def _vmGuestOper(vm_instance, oper_type):
    """
    to shutdown or restart Guest Os on VM
    :param vm_instance:
    :param oper_type: shutdown/reboot/status/startup
    :return:
    """
    # turn off os :ShutdownGuest()
    # restart os: RebootGuest()
    # os status : guest.guestState
    vm_instance_uuid = str(vm_instance.config.instanceUuid)
    result_dict = dict()
    if oper_type == "shutdown":
        try:
            vm_instance.ShutdownGuest()
            result_dict = {"data": "", "errmsg": "", "result": 0}
        except Exception as e:
            result_dict = {"data": "", "errmsg": str(e.msg), "result": 1}
    elif oper_type == "reboot":
        # os_oper_task = vm_instance.RebootGuest()
        try:
            vm_instance.RebootGuest()
            result_dict = {"data": "", "errmsg": "", "result": 0}
        except Exception as e:
            result_dict = {"data": "", "errmsg": str(e.msg), "result": 1}
    # elif oper_type == "startup":
    #    return _vmPowerOper(vm_instance,"poweron")
    elif oper_type == "status":
        result_dict = {"data": vm_instance.guest.guestState, "errmsg": "", "result": 0}
        return result_dict
    else:
        result_dict = {"data": "", "errmsg": "unsupport operation,nothing to do here", "result": 1}
        return result_dict

    # query_ticket = {"uuid":vm_instance_uuid,"task_key":os_oper_task.info.key,"eventid":os_oper_task.info.eventChainId}
    # result_dict = {"data": query_ticket, "errmsg": "", "result": 0}
    return result_dict


def VmPowerManager(v_host, v_user, v_pwd, v_port, v_uuid, v_oper):
    _of_name = MODULE_NAME + "." + sys._getframe().f_code.co_name
    ret_dict = dict()
    ret_dict["oper_fun"] = _of_name
    if not isinstance(v_uuid, list):
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = "v_uuid shuld be a array ,wrong parameter type"
        return json.dumps(ret_dict)
    si = get_service_instance(v_host, v_user, v_pwd, v_port, protocol=None)
    if not isinstance(si, vim.ServiceInstance):
        # err cant connect to vcenter
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = str(si)
    else:
        result_flag = 0
        ret_dict_data_dict = dict()
        for vm_id in v_uuid:
            vmi = _findVmByUuid(si, vm_id)
            if not isinstance(vmi, vim.VirtualMachine):
                # err cant find a vm using given uuid
                ret_dict_data_dict[vm_id] = {"data": "", "result": 1, "errmsg": str(vmi)}
                result_flag += 1
            else:
                ret_pm_dict = _vmPowerOper(vmi, v_oper)  # power management operation result dict
                ret_dict_data_dict[vm_id] = ret_pm_dict
                result_flag += ret_pm_dict["result"]
        if result_flag == 0:
            ret_dict["result"] = 0
            ret_dict["errmsg"] = ""
        elif result_flag == len(v_uuid):
            ret_dict["result"] = 1
            ret_dict["errmsg"] = "All operation failed"
        else:
            ret_dict["result"] = 2
            ret_dict["errmsg"] = "some ok,somm failed"
        ret_dict["data"] = ret_dict_data_dict
    return json.dumps(ret_dict)


def VmOsManager(v_host, v_user, v_pwd, v_port, v_uuid, v_oper, ):
    _of_name = MODULE_NAME + "." + sys._getframe().f_code.co_name
    ret_dict = dict()
    ret_dict["oper_fun"] = _of_name
    if not isinstance(v_uuid, list):
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = "v_uuid shuld be a array ,wrong parameter type"
        return json.dumps(ret_dict)
    si = get_service_instance(v_host, v_user, v_pwd, v_port, protocol=None)
    if not isinstance(si, vim.ServiceInstance):
        # err cant connect to vcenter
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = str(si)
    else:
        result_flag = 0
        ret_dict_data_dict = dict()
        for vm_id in v_uuid:
            vmi = _findVmByUuid(si, vm_id)
            if not isinstance(vmi, vim.VirtualMachine):
                ret_dict_data_dict[vm_id] = {"data": "", "result": 1, "errmsg": str(vmi)}
                result_flag += 1
            else:
                ret_om_dict = _vmGuestOper(vmi, v_oper)
                ret_dict_data_dict[vm_id] = ret_om_dict
                result_flag += ret_om_dict["result"]
        if result_flag == 0:
            ret_dict["result"] = 0
            ret_dict["errmsg"] = ""
        elif result_flag == len(v_uuid):
            ret_dict["result"] = 1
            ret_dict["errmsg"] = "All operation failed"
        else:
            ret_dict["result"] = 2
            ret_dict["errmsg"] = "some ok,somm failed"
        ret_dict["data"] = ret_dict_data_dict
    return json.dumps(ret_dict)


def SingleTaskQuery(v_host, v_user, v_pwd, v_port, query_ticket_jstr):
    'get history task details'
    _of_name = MODULE_NAME + "." + sys._getframe().f_code.co_name
    ret_dict = dict()
    ret_dict["oper_fun"] = _of_name
    try:
        query_ticket = json.loads(query_ticket_jstr)
    except Exception as e:
        ret_dict["data"] = ""
        ret_dict["errmsg"] = "wrong input %s" % str(e)
        ret_dict["result"] = 1
        return json.dumps(ret_dict)
    vm_uuid = query_ticket.get("uuid")
    task_key = query_ticket.get("task_key")
    e_id = query_ticket.get("eventid")
    if vm_uuid is None or task_key is None or e_id is None:
        ret_dict["data"] = ""
        ret_dict["errmsg"] = "wrong input: missing query parameter"
        ret_dict["result"] = 1
        return json.dumps(ret_dict)
    task_query = task_key + "_" + str(e_id)
    si = get_service_instance(v_host, v_user, v_pwd, v_port, protocol=None)
    if not isinstance(si, vim.ServiceInstance):
        # err cant connect to vcenter
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = str(si)
    else:
        try:
            THcollector = _getTaskHistoryCollectorByEntity(si, vm_uuid)
        except Exception as e:
            ret_dict["data"] = ""
            ret_dict["result"] = 1
            ret_dict["errmsg"] = str(e)
            return json.dumps(ret_dict)
        if not isinstance(THcollector, vim.TaskHistoryCollector):
            ret_dict["data"] = ""
            ret_dict["result"] = 1
            ret_dict["errmsg"] = str(THcollector)
        else:
            recent_10_task_list = THcollector.latestPage
            rtt_dict = dict()  # rtt stands for recent ten task
            for temp_task_info in recent_10_task_list:
                info_dict = dict()
                search_key = temp_task_info.key + "_" + str(temp_task_info.eventChainId)
                info_dict["descriptionId"] = temp_task_info.descriptionId
                info_dict["vmName"] = temp_task_info.entityName
                info_dict["state"] = temp_task_info.state
                # info_dict["error"] = str(type(temp_task_info.error))
                err_object = temp_task_info.error
                try:
                    info_dict["error"] = err_object.msg
                except Exception:
                    info_dict["error"] = "unknown"
                # info_dict["result"] = temp_task_info.result
                ret_value_obj = temp_task_info.result
                if isinstance(ret_value_obj, str):
                    info_dict["result"] = ret_value_obj
                elif isinstance(ret_value_obj, vim.ManagedEntity):
                    try:
                        info_dict["result"] = {ret_value_obj.name: ret_value_obj.summary.config.instanceUuid}
                    except Exception:
                        info_dict["result"] = None
                else:
                    info_dict["result"] = None
                info_dict["startTime"] = (temp_task_info.startTime + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
                try:
                    info_dict["completeTime"] = (temp_task_info.completeTime + timedelta(hours=8)).strftime(
                        '%Y-%m-%d %H:%M:%S')
                except Exception:
                    info_dict["completeTime"] = "unknown"
                rtt_dict[search_key] = info_dict
            rtt_name_list = rtt_dict.keys()
            if task_query in rtt_name_list:
                ret_dict["data"] = rtt_dict[task_query]
            else:
                ret_dict["data"] = "can not find a match task recently"
            ret_dict["result"] = 0
            ret_dict["errmsg"] = ""
    return json.dumps(ret_dict)


def CloneVm(v_host, v_user, v_pwd, v_port, clone_spec):
    _of_name = MODULE_NAME + "." + sys._getframe().f_code.co_name
    ret_dict = dict()
    ret_dict["oper_fun"] = _of_name
    try:
        v_clone_spec = json.loads(clone_spec)
    except Exception as e:
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = "v_clone_spec shuld be multi kv pairs ,wrong parameter type"
        return json.dumps(ret_dict)
    si = get_service_instance(v_host, v_user, v_pwd, v_port, protocol=None)
    if not isinstance(si, vim.ServiceInstance):
        # err cant connect to vcenter
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = str(si)
        return json.dumps(ret_dict)
    else:
        content = si.RetrieveContent()
        dc_name = v_clone_spec.get("datacenter")
        clu_name = v_clone_spec.get("cluster")
        new_vm_name = v_clone_spec.get("vm_name")
        template_name = v_clone_spec.get("template")
        if v_clone_spec.get("poweron"):
            power_flag = v_clone_spec.get("poweron")
        else:
            power_flag = False
        clone_setting = v_clone_spec.get("clone_setting")
        if dc_name is None or clu_name is None or new_vm_name is None or template_name is None:
            ret_dict["data"] = ""
            ret_dict["result"] = 1
            ret_dict["errmsg"] = "missing key parameter ,cant clone vm"
            # return json.dumps(ret_dict)
        else:
            template_obj = _get_obj(content, [vim.VirtualMachine], template_name)
            if template_obj:
                ret_clone_dict = _cloneVm(content, template_obj, vm_name=new_vm_name, datacenter_name=dc_name
                                          , cluster_name=clu_name, power_on=power_flag, deploy_settings=clone_setting)
                ret_dict["data"] = ret_clone_dict["data"]
                ret_dict["result"] = ret_clone_dict["result"]
                ret_dict["errmsg"] = ret_clone_dict["errmsg"]
            else:
                ret_dict["data"] = ""
                ret_dict["result"] = 1
                ret_dict["errmsg"] = "can't find template you ask for,cant clone vm"
        return json.dumps(ret_dict)


def DestroyVm(v_host, v_user, v_pwd, v_port, vm_uuid=None, vm_name=None):
    _of_name = MODULE_NAME + "." + sys._getframe().f_code.co_name
    ret_dict = dict()
    ret_dict["oper_fun"] = _of_name
    si = get_service_instance(v_host, v_user, v_pwd, v_port, protocol=None)
    if not isinstance(si, vim.ServiceInstance):
        # err cant connect to vcenter
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = str(si)
    else:
        content = si.RetrieveContent()
        if vm_uuid:
            vm_obj = _findVmByUuid(si, vm_uuid)
        elif vm_name:
            vm_obj = _get_obj(content, [vim.VirtualMachine], vm_name)
        if vm_obj:
            ret_dv_dict = _destroy_vm(si, vm_obj)
            ret_dict["data"] = ret_dv_dict["data"]
            ret_dict["result"] = ret_dv_dict["result"]
            ret_dict["errmsg"] = ret_dv_dict["errmsg"]
        else:
            ret_dict["data"] = ""
            ret_dict["result"] = 1
            ret_dict["errmsg"] = "can't find VM you ask for,cant destroy vm"
    return json.dumps(ret_dict)


def ReconfigVm(v_host, v_user, v_pwd, v_port, vm_uuid, vm_spec):
    _of_name = MODULE_NAME + "." + sys._getframe().f_code.co_name
    ret_dict = dict()
    ret_dict["oper_fun"] = _of_name
    try:
        vm_spec_dict = json.loads(vm_spec)
    except Exception as e:
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = "failed to load json string,wrong format,unable to reconfig vm"
        return json.dumps(ret_dict)
    si = get_service_instance(v_host, v_user, v_pwd, v_port, protocol=None)
    if not isinstance(si, vim.ServiceInstance):
        # err cant connect to vcenter
        ret_dict["data"] = ""
        ret_dict["result"] = 1
        ret_dict["errmsg"] = str(si)
    else:
        vm_obj = _findVmByUuid(si, vm_uuid)
        content = si.RetrieveContent()
        if vm_obj:
            ret_rv_dict = _reconfig_vm(content, vm_obj, vm_spec_dict)
            ret_dict["data"] = ret_rv_dict["data"]
            ret_dict["result"] = ret_rv_dict["result"]
            ret_dict["errmsg"] = ret_rv_dict["errmsg"]
        else:
            ret_dict["data"] = ""
            ret_dict["result"] = 1
            ret_dict["errmsg"] = "can't find VM you ask for,cant reconfig vm"
    return json.dumps(ret_dict)
