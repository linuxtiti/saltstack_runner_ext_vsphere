# saltstack_runner_ext_vsphere
# 1,get information from vCenter, such as datastore/esxi host/network; 2,create  vm from template
# 以扩展salt module方式实现vSphere操作，可以操作vcenter或者直接操作esxi
# 文档格式为YAML，推荐使用notepad++打开的，可以选择“语言”——》“YAML”，可以支持折叠、展开等操作，可以隐藏掉不想看的部分
# 测试类和查询类的操作，都是同步操作

#测试类：
vmware_test.py:
  - 功能: 
      各种和测试相关的函数/方法/接口（大家自己挑一个习惯的名字吧)
  - 更新历史:
      - v0.2: 
          - 将返回字符串格式统一为{oper_fun:"",result:"",errmsg:"",data:""}
  - 接口列表:      
      - vmware_test.TestConn:
          - 功能描述: 测试连接到vcenter
          - 调用方式:
              curl -sSk https://localhost:8000/ -H 'Accept: application/x-yaml' \
              -H 'X-Auth-Token:  c197be92ae5f87be148ffece04db4479d186d234' \
              -H 'Content-Type: application/json' \
              '-d 
              {
              "client": "runner", 
              "fun": "vmware_test.TestConn",
              "v_host":"xxx.xxx.xxx.xxx",
              "v_user":"xxxxx",
              "v_pwd":"xxxxxx",
              "v_port":"443"
              }'
          - 返回值:
            - 登录正常:
                {"oper_fun": "vmware_test.TestConn", "data": "Connetion Ok", "result": "0", "errmsg":""}
            - 用户密码错:
                {"oper_fun": "vmware_test.TestConn", "data": "Connetion Failed", "result": "1",
                "errmsg": "Cannot complete login due to an incorrect user name or password."}
            - 网络连接失败:
                {"oper_fun": "vmware_test.TestConn", "data": "", "result": "1", 
                "errmsg": "Connetion Failed [Errno 111] Connection refused"}
#查询类：
vmware_info.py:
  - 功能: 
      从vcenter获取信息的函数/方法/接口（大家自己挑一个习惯的名字吧)
  - 接口列表:
      - vmware_info.GetAllGuestInfo:
         - 功能描述: 
             查询所有的虚拟机信息，返回值中包括虚拟机名称、uuid、已分配的cpu内存、
             可兼容的vmware软件版本等
         - 调用方式:
             {
             "client": "runner",
             "fun": "vmware_info.GetAllGuestInfo",
             "v_host":"xxx.xxx.xxx.xxx",
             "v_user":"xxxx",
             "v_pwd":"xxxxxxxxx",
             "v_port":"443",
             "vm_uuid": "" 
             #虚拟机的uuid，用于查询单个虚拟机的信息，可以忽略
             }'
          - 返回值:
              略（太多）
      - vmware_info.GetAllTemplateInfo:
          - 功能描述:
              只打印标记为模板的虚拟机的信息
          - 调用方式:
              略（和GetAllGuestInfo相同）
          - 返回值:
              略（和GetAllGuestInfo相同）
      - vmware_info.GetAllVmInfo:
          - 功能描述:
              只打印非模板虚拟机（VM）信息
          - 调用方式:
              略（和GetAllGuestInfo相同）
          - 返回值:
              略（和GetAllGuestInfo相同）        
      - vmware_info.GetDataStoreInfo:
          - 功能描述:
              查询vcenter的datastore数据，返回一个总的结果：可用空间多少、已用多少、空闲多少
              返回值的单位是bytes
          - 返回值:
              {
                "data": {
                    "total": "832.25",
                    "free": "766.61",
                    "used": "65.64"
                },
                "result": 0,
                "oper_fun": "vmware_info.GetDataStoreInfo",
                "errmsg": ""
              }
      - vmware_info.VcSummaryInfo:
          - 功能描述: 
              返回vcenter的简要信息，包括cpu、内存、存储使用情况，“在线/离线”esxi主机数量，“在线/离线”虚拟机数量
          - 返回值:
              {
                  "data": {
                      "mem": {          #单位是G
                          "total": "4.0",
                          "free": "2.6",
                          "used": "1.4"
                      },
                      "datastore": {  #单位是G
                          "total": "832.25",
                          "used": "54.75",
                          "free": "777.5"
                      },
                      "vm_host": {
                          "unknown": 1,    #在vspher的文档中，虚拟机的状态共有6种
                          "offline": 0,    #除了online、offline和unknown以外，还有"shuttingdown resetting standby"   
                          "num_of_vm": 1,  #这里为了简化输出，暂时把其余三种都归类为unknown
                          "online": 0
                      },
                      "cpu": {
                          "total_cpu_res": "6784.0",  #单位MHz，这里的计算方式是 "物理core的数量" x "cpu的主频" 
                          "free": "6694.0",
                          "used": "90.0"
                      },
                      "esxi_host": {
                          "num_of_esxi": 1,
                          "offline": 0,
                          "unknown": 0,
                          "online": 1
                      }
                  },
                  "result": 0,
                  "oper_fun": "vmware_info.VcSummaryInfo",
                  "errmsg": ""
              }
          
      - vmware_info.GetAllDcInfo:
          - 功能描述:
              返回DataCenter的配置信息，包括datacenter下面的cluster，以及cluster里面的esxi
          - 返回值:
            {
                "data": {
                    "likev": {
                        "name": "likev",
                        "cluster info": {
                            "cluster2": {
                                "name": "cluster2",
                                "numHost": 1,
                                "numHostOnline": 1,
                                "totalCpu": 6784,
                                "numCpuCores": 2,
                                "numCpuThreads": 2,
                                "totalMemory": 4294430720,
                                "das enabled": false,
                                "drs enabled": false,
                                "datastore list": [
                                    "iscsi_10.25"
                                ],
                                "esxi host list": [
                                    "192.168.10.24"
                                ],
                                "template list": {},
                                "vm list": {
                                    "test": "500b8e2c-73ce-b2d1-35b2-63c8bbcb1423"
                                },
                                "template details": {},
                                "esxi host details": {
                                    "192.168.10.24": {
                                        "vm list": [
                                            "test"
                                        ],
                                        "vendor": "VMware, Inc.",
                                        "model": "VMware Virtual Platform",
                                        "uuid": "08c94d56-d9a7-e9d4-7def-8a2d2d0f07e4",
                                        "memorySize": 4294430720,
                                        "cpuModel": "Intel(R) Core(TM) i3-3240 CPU @ 3.40GHz",
                                        "cpuMhz": 3392,
                                        "numCpuPkgs": 2,
                                        "numCpuCores": 2,
                                        "numCpuThreads": 2,
                                        "numNics": 1,
                                        "numHBAs": 4
                                    }
                                }
                            },
                            "cluster": {
                                "name": "cluster",
                                "numHost": 1,
                                "numHostOnline": 1,
                                "totalCpu": 6784,
                                "numCpuCores": 2,
                                "numCpuThreads": 2,
                                "totalMemory": 4294430720,
                                "das enabled": false,
                                "drs enabled": true,
                                "datastore list": [
                                    "iscsi_10.25"
                                ],
                                "esxi host list": [
                                    "192.168.10.26"
                                ],
                                "template list": {
                                    "template 7.2": "500b40f3-5447-82be-2e58-0b945dcda2da",
                                    "centos 6": "500bd2cb-f9de-9fa7-ed92-1d25469fe433"
                                },
                                "vm list": {
                                    "CentOS72node01": "500b66ff-8e42-7ad4-c09c-b2d5fcf97061",
                                    "bb1": "500bda45-f783-3784-7b39-5e59436926fc"
                                },
                                "template details": {
                                    "template 7.2": {
                                        "Name": "template 7.2",
                                        "instance UUID": "500b40f3-5447-82be-2e58-0b945dcda2da",
                                        "Container Version": "vmx-11",
                                        "Guest Container Type": "centos64Guest",
                                        "Guest Full Name": "CentOS 4/5/6/7 (64-bit)",
                                        "hostname": null,
                                        "CPUs": 2,
                                        "numCoresPerSocket": 1,
                                        "numTotalCores": 2,
                                        "MemoryMB": 2048,
                                        "MemoryBytes": 2147483648,
                                        "dns": [],
                                        "virtualDisk": {
                                            "Hard disk 1": {
                                                "diskmode": "persistent",
                                                "thinProvisioned": true,
                                                "spaceUsed": 9807342466,
                                                "capacityInBytes": 107374182400,
                                                "diskUuid": "6000C29a-8089-0175-3018-8141d1c9c1aa"
                                            }
                                        },
                                        "NIC": {
                                            "00:50:56:8b:cd:32": {
                                                "name": "Network adapter 1",
                                                "summary": "VM Network",
                                                "connected": false,
                                                "status": "untried",
                                                "ipaddr info": null
                                            }
                                        }
                                    },
                                    "centos 6": {
                                        "Name": "centos 6",
                                        "instance UUID": "500bd2cb-f9de-9fa7-ed92-1d25469fe433",
                                        "Container Version": "vmx-08",
                                        "Guest Container Type": "centos64Guest",
                                        "Guest Full Name": "CentOS 4/5/6/7 (64-bit)",
                                        "hostname": "localhost.localdomain",
                                        "CPUs": 1,
                                        "numCoresPerSocket": 1,
                                        "numTotalCores": 1,
                                        "MemoryMB": 512,
                                        "MemoryBytes": 536870912,
                                        "dns": [
                                            "127.0.0.1"
                                        ],
                                        "virtualDisk": {
                                            "Hard disk 1": {
                                                "diskmode": "persistent",
                                                "thinProvisioned": true,
                                                "spaceUsed": 3526105224,
                                                "capacityInBytes": 64424509440,
                                                "diskUuid": "6000C291-77c5-3e40-6a7d-8d87d6b98e71"
                                            }
                                        },
                                        "NIC": {
                                            "00:50:56:8b:a3:c5": {
                                                "name": "Network adapter 1",
                                                "summary": "VM Network",
                                                "connected": false,
                                                "status": "untried",
                                                "ipaddr info": null
                                            }
                                        }
                                    }
                                },
                                "esxi host details": {
                                    "192.168.10.26": {
                                        "vm list": [
                                            "centos 6",
                                            "template 7.2",
                                            "bb1",
                                            "CentOS72node01"
                                        ],
                                        "vendor": "VMware, Inc.",
                                        "model": "VMware Virtual Platform",
                                        "uuid": "6eca4d56-38e4-bc8f-efe3-a501bac75789",
                                        "memorySize": 4294430720,
                                        "cpuModel": "Intel(R) Core(TM) i3-3240 CPU @ 3.40GHz",
                                        "cpuMhz": 3392,
                                        "numCpuPkgs": 2,
                                        "numCpuCores": 2,
                                        "numCpuThreads": 2,
                                        "numNics": 1,
                                        "numHBAs": 4
                                    }
                                }
                            }
                        },
                        "obj count": {
                            "cluster": 2,
                            "datastore": 1,
                            "vm": 5,
                            "network": 6,
                            "esxi": 2
                        },
                        "resource usage": {
                            "totalDsUsage": 187577663488,
                            #存储已用空间，bytes
                            "totalMem": 8588861440,
                            #总内存大小，所有cluster的总内存之和
                            "totalCpu": 13568,
                            #总的可用的cpu资源，MHz单位，所有cluster的总cpu资源加和
                            "totalDs": 1717450047488,
                            #存储空间容量大小，bytes单位
                            "totalMemUsage": 15728640,
                            #dc中所有虚拟机的实际内存消耗量加和，bytes
                            "totalCpuUsage": 0
                            #dc中所有虚拟机的实际cpu消耗量加和 ,MHz单位
                        }
                    }
                },
                "result": 0,
                "oper_fun": "vmware_info.GetAllDcInfo",
                "errmsg": ""
                }
      - vmware_info.GetAllDataStoreInfo:
          - 功能描述:
              打印Datastore的容量、空闲、datastore上有哪些虚拟机（vm）/模板（template）
          - 调用方式:
              {
                "client": "runner",
                "fun": "vmware_info.GetAllDataStoreInfo",
                "v_host":"xxx.xxx.xxx.xxx",
                "v_user":"xxx",
                "v_pwd":"xxxx",
                "v_port":"443"
              }'
          - 返回值:
              {
                  "data": {
                      "iscsi_10.25": {
                          "capacity": 858725023744,  
                          #单位是bytes，下同
                          "vm": {
                              "CentOS72node01": "500b66ff-8e42-7ad4-c09c-b2d5fcf97061",
                              "template 7.2": "500b40f3-5447-82be-2e58-0b945dcda2da",
                              "centos 6": "500bd2cb-f9de-9fa7-ed92-1d25469fe433",
                              "bb1": "500bda45-f783-3784-7b39-5e59436926fc"
                          },
                          "free": 783363866624,
                          "dsUrl": "ds:///vmfs/volumes/5827a7db-cd63580d-29c1-000c29c75789/"
                      }
                  },
                  "result": 0,
                  "oper_fun": "vmware_info.GetAllDataStoreInfo",
                  "errmsg": ""
              }              
#操作类
vmware_oper.py:
  - 功能:
      - 1: 操作单个虚拟机（电源开关机挂起重置）、虚拟机上OS（启动、停止、重启）
      - 2: 查询单个历史任务的结果  
  - 接口列表:
      - vmware_oper.VmPowerManager:
          - 功能描述: 对虚拟机执行电源相关操作，对应vcenter界面上打开电源、关闭电源
          - 调用方式:
              {
              "client": "runner", 
              "fun": "vmware_oper.VmPowerManager",
              "v_host":"xxx.xxx.xxx.xxx",
              "v_user":"xxx",
              "v_pwd":"xxxxxxx",
              "v_port":"443"
              "v_uuid":["500bda45-f783-3784-7b39-5e59436926fc","500bd2cb-f9de-9fa7-ed92-1d25469fe433"],
              #这里的uuid是instance uuid
              #1124更新:如果同时操作多个虚拟机 [uuid1,uuid2,……]
              "v_oper":"poweron"   #poweron：打开电源/poweroff：关闭/suspend：挂起/reset：重置/status：查询状态
              }'
          - 返回值:
              {
                "data": 
                  {
                    "500bda45-f783-3784-7b39-5e59436926fc": {
                        "data": {
                            "eventid": "19270",
                            "uuid": "500bda45-f783-3784-7b39-5e59436926fc",
                            "task_key": "task-447"
                        },
                        "result": 0,
                        "errmsg": ""
                    },
                    "500bd2cb-f9de-9fa7-ed92-1d25469fe433": {
                        "data": {
                            "eventid": "19271",
                            "uuid": "500bd2cb-f9de-9fa7-ed92-1d25469fe433",
                            "task_key": "task-448"
                        },
                        "result": 0,
                        "errmsg": ""
                    }
                  }
                #开关机这些操作在vcenter中都是异步任务，提交成功会返回一个taskInfo的对象
                #这里抓取了部分属性作为返回值，也是后面查询task结果是需要的查询参数，
                #把"data"里面的内容转换为一个json字符串作为查询任务的一个参数
                #如果是执行"status"查询操作，"data"的内容就是一个表示power状态的字符串,"poweredOn"或者"poweredOff"
                #1124更新: 输出结果改为嵌套方式，第一级的key值虚拟机的uuid
                "result": 0,
                "oper_fun": "vmware_oper.VmPowerManager",
                "errmsg": ""
              }
      - vmware_oper.VmOsManager:
          - 功能描述: 对虚拟机上操作系统执行启动、关闭和重启
          - 调用方式:
              {
              "client": "runner", 
              "fun": "vmware_oper.VmOsManager",
              "v_host":"xxx.xxx.xxx.xxx",
              "v_user":"xxxx",
              "v_pwd":"xxxxx",
              "v_port":"443"
              "v_uuid":["500bda45-f783-3784-7b39-5e59436926fc","500bd2cb-f9de-9fa7-ed92-1d25469fe433" ]
              #这里的uuid是instance uuid
              #1124更新:如果同时操作多个虚拟机 [uuid1,uuid2,……]
              "v_oper":"shutdown"   
              #shutdown：关机，reboot：重启，status：状态，
              #startup: 启动，这里实际上是调用的VmPowerManager的poweron操作 1124更新：不再支持startup操作
              }'
          - 返回值:
              {
                "data": 
                   {
                     "500bda45-f783-3784-7b39-5e59436926fc": {
                         "data": "running",
                         "result": 0,
                         "errmsg": ""
                     },
                     "500bd2cb-f9de-9fa7-ed92-1d25469fe433": {
                         "data": "notRunning",
                         "result": 0,
                         "errmsg": ""
                     }
                   },    
                #shutdown和reboot，"data"为空，这两个操作是虚拟机上OS发出shutdown或者reboot的指令，不保证成功也不等VM的返回
                #而且这两个操作不是vcenter的task，也就没有taskInfo的返回对象
                #startup："data"这里会有返回的task信息，和VmPowerManager的poweron操作返回值是一样格式
                #status: "data"会是一个表示状态的字符串 "running" 或者 "notRunning"
                #1124更新: 输出结果改为嵌套方式，第一级的key值虚拟机的uuid
                "result": 0,   
                #0表示全部成功，1表示全部失败，2表示部分失败
                "oper_fun": "vmware_oper.VmOsManager", 
                "errmsg": ""
              }
      - vmware_oper.CloneVm:
          - 功能描述: 从模板部署虚拟机：
          - 调用方式:
              {
              "client": "runner", 
              "fun": "vmware_oper.CloneVm",
              "v_host":"xxx.xxx.xxx.xxx",
              "v_user":"xxxx",
              "v_pwd":"xxxxx",
              "v_port":"443",
              clone_spec:  #json格式字符串
                {
                    "datacenter": "likev",  
                    #datacenter的名字
                    "cluster": "cluster",  
                    #集群的名字
                    "vm_name": "clone_test01", 
                    #新虚拟机的名称
                    "template": "template 7.2",      
                    #模板名称
                    "clone_setting":{
                        "numCPU" : 1,   
                        #虚拟cpu数量
                        "numCoresPerSocket": 1,
                        #每个虚拟cpu中的core的数量
                        "memoryMB": 256,
                        #内存大小，还可以用”memoryBytes“，作为内存值的key
                        "hostname": "clone_test01",
                        #可以没有hostname，如果不设置就是虚拟机的名称
                        "dns_servers": ["202.96.128.166","202.96.128.86"]
                        #dns可以忽略，默认值是114.114.114.114
                        },
                    "poweron": False
                }
              }
              
          - 返回值:
                {   
                    "data": 
                    #利用data内的值去查询操作结果
                        {"eventid": "40337", 
                        "uuid": "500b40f3-5447-82be-2e58-0b945dcda2da", 
                        "task_key": "task-624"}, 
                    "result": 0, 
                    "oper_fun": "vmware_oper.CloneVm", 
                    "errmsg": ""
                }'
      - vmware_oper.ReconfigVm:
          - 功能描述: 重新配置虚拟机的硬件配置（目前只支持添加或者增大磁盘空间）
          - 调用方式:
              {
              "client": "runner", 
              "fun": "vmware_oper.CloneVm",
              "v_host":"xxx.xxx.xxx.xxx",
              "v_user":"xxxx",
              "v_pwd":"xxxxxxxxx",
              "v_port":"443",
              "vm_uuid": "" , 
              #新虚拟机的uuid，在clone任务查询返回值中result字段可以取到
              "vm_spec":
                {
                    'numCPU': 2, 
                    'numCoresPerSocket': 1,
                    'memoryMB': 512,
                    #还是可以memoryBytes作为key，用memoryMB也可以
                    'disk': 
                    {'Hard disk 1':    #第一块磁盘
                        {'capacityBytes': 118111600640, 
                        'disk_thin': True,
                        'disk_mode': "",
                        # 可以忽略，旧磁盘的默认值是 模板虚拟机的磁盘的disk_mode的值
                        'disk_oper': "edit"  
                        #本次操作类型：新增、编辑还是删除
                        #add： 新增磁盘
                        #edit：编辑已有磁盘，磁盘容量的调整目前只支持增大
                        #del： 删除已有磁盘
                        }, 
                    'Hard disk 2':    #第二块磁盘
                        {'capacityBytes': 10737418240, 
                        'disk_thin': True,
                        'disk_mode': "",
                        # 可以忽略，新加磁盘时候的默认值是independent_persistent
                        'disk_oper': "add"
                        }
                    } 
                }
              }
          - 返回值:
                {
                    "data": {  
                    #查任务结果的方式和clone一样            
                    "eventid": "40347", 
                        "uuid": "500bfb56-2179-2eae-8137-30d13e994339", 
                        "task_key": "task-627"}, 
                    "result": 0, 
                    "oper_fun": "vmware_oper.ReconfigVm", 
                    "errmsg": ""
                }
      - vmware_oper.DestroyVm:
          - 功能描述: 删除虚拟机
          - 调用方式: 
              {
                "client": "runner", 
                "fun": "vmware_oper.CloneVm",
                "v_host":"xxx.xxx.xxx.xxx",
                "v_user":"xxx",
                "v_pwd":"xxx",
                "v_port":"443", 
                "vm_uuid": ""
                #或者用vm_name，两个key都可以
               }
          - 返回值:
                {
                    "data": {"eventid": "40353", "uuid": "", "task_key": "task-629"}, 
                    #暂时还查不了删除虚拟机的任务结果
                    "result": 0, 
                    "oper_fun": "vmware_oper.DestroyVm", 
                    "errmsg": ""
                }

      - vmware_oper.SingleTaskQuery:
          - 功能描述: 查询单个历史任务的信息
          - 调用方式:
              {
              "client": "runner", 
              "fun": "vmware_oper.SingleTaskQuery",
              "v_host":"xxx.xxx.xxx.xxx",
              "v_user":"xxx",
              "v_pwd":"xxxx",
              "v_port":"443"
              "query_ticket_jstr": {"eventid": "14464", "uuid": "500b66ff-8e42-7ad4-c09c-b2d5fcf97061", "task_key": "task-311"}
              #json格式字符串，字符串的内容由poweron/poweroff等vcenter task的返回值拼接      
              }
          - 返回值:
              {
                "data": {
                    "descriptionId": "VirtualMachine.powerOff",
                    "state": "success",
                    "result": null,
                    "startTime": "2016-11-22 19:05:55",
                    "error": null,
                    "vmName": "CentOS72node01",
                    "completeTime": "2016-11-22 19:05:55"
                },
                #如果没有找到的话，这里会是一个字符串"can not find a match task recently"
                "result": 0,
                "oper_fun": "vmware_oper.SingleTaskQuery",
                "errmsg": ""
              }
