#!/usr/bin/env python

# Import Python Libs
from __future__ import print_function
from os.path import basename
import atexit
from time import clock
import json,logging,socket,sys

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

def __virtual__():
    '''
    Only load if PyVmomi is installed.
    '''
    if HAS_PYVMOMI:
        return True
    else:
        return False, 'Missing dependency: The ext.module.vmware_info requires pyVmomi.'

def _test_port(check_host,check_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(7)
    address = check_host
    port = int(check_port)
    ADDR = (address,port)
    try:
        s.connect(ADDR)
        return 0
    except Exception as e:
        log.debug(e)
        return str(e)
    s.close()
        
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

#host, username, password, port=None ,protocol=None
def TestConn(v_host,v_user,v_pwd,v_port=None,v_protocol=None):
    if v_port is None:
        v_port = 443
    port_status=_test_port(v_host,v_port)
    ret_dict = dict()
    full_path = sys._getframe().f_code.co_filename
    module_name = basename(full_path).split(".")[0]
    func_name=sys._getframe().f_code.co_name
    oper_func= module_name + "." + func_name
    ret_dict["oper_fun"] = oper_func

    if isinstance(port_status,str):
        ret_str={"result":"1","data":"","errmsg": "Connetion Failed " + port_status ,"oper_fun": oper_func}
    else:
        print(port_status)
        print(v_host,v_user,v_pwd,v_protocol,v_port)
        si=get_service_instance(v_host,v_user,v_pwd,v_protocol,v_port)
        print(type(si))
        if isinstance(si,(str,list)):
            ret_str={"result":"1","data":"Connetion Failed","errmsg":si, "oper_fun": oper_func}
            log.debug(si)
        else:
            ret_str={"result":"0","data":"Connetion Ok","errmsg":"", "oper_fun": oper_func}
    return json.dumps(ret_str)
    
