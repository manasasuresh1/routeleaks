from netmiko import Netmiko
import netmiko
import os
import json
import time
def func1():

        hoo = []

        if os.path.isfile ('./data.json'):
                fh = open('data.json', 'r')
                data = json.load(fh)
                boo =[]
                for val in data.keys():
                    hoo.append(val)
                    boo.append(data[val])
                fh.close()

        username=[]
        ip=[]
        password=[]

        for values in boo:

                    i=0
                    for ele in values.keys():
                            if i == 0:
                                username.append(values[ele])
                            if i == 1:
                                ip.append(values[ele])
                            if i == 2:
                                password.append(values[ele])
                            i = i+1
        j = 0

        lst1 = []
        lst2 = []
        print (username)
        print (ip)
        print (password)
        prefix = "100.100.100.100/32"
        for go in password: 
                        
                            device_1 = {
                                'username': username[j],
                                'password': ip[j],
                                'ip': go,
                                'device_type': 'linux',
                            }
                            
                            net_connect = netmiko.ConnectHandler(**device_1)
                            print ('command started')
                            ou = net_connect.send_command('terminal length 0')
                            o = net_connect.send_command_timing('ssh -t root@20.0.0.2')
                            print(o)
                            z = net_connect.send_command_timing('Lab123')
                            print(z)
                            a1 = net_connect.send_command_timing('cli')
                            print(a1)
                            b1 = net_connect.send_command_timing('configure')
                            print(b1)
                            b2 = net_connect.send_command_timing ('delete policy-options prefix-list bgplist '+prefix)
                            print (b2)
                            b3 = net_connect.send_command_timing ('commit and-quit')
                            print(b3)
                            b10 = net_connect.send_command_timing('configure')
                            print(b10)
                            b4 = net_connect.send_command_timing ('delete firewall filter routeleak')
                            print(b4)
                            b12 = net_connect.send_command_timing ('delete interfaces ge-0/0/0 unit 0 family inet filter input routeleak')
                            print(b12)
                            b8 = net_connect.send_command_timing ('commit and-quit')
                            time.sleep(60)
                            print(b8)
                            b7 = net_connect.send_command_timing ('show firewall')
                            print(b7)
                            b9 = net_connect.send_command_timing ('show policy-options')
                            print(b9)
func1()