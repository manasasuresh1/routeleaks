import datetime
from ipaddress import ip_network
import requests
import re
from email.mime.base import MIMEBase
import smtplib
from email import encoders
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
import datetime
import psycopg2
import pprint
from collections import Counter
from numpy.core.fromnumeric import transpose
from netmiko import Netmiko
import netmiko
import os
import json
from flask import Markup
from flask import Flask, render_template, request, flash
app = Flask(__name__)

#conn = psycopg2.connect(host="172.16.2.104",database="openbmp", user="openbmp", password="openbmp")			#Connect to the Database and fetch records
#cursor = conn.cursor()		
#cursor.execute("SELECT isipv4, origin_as, prefix,  timestamp,first_added_timestamp, iswithdrawn FROM ip_rib")	#Obtain origin_as, prefix, timestamp and iswithdrawn info from database
#records = cursor.fetchall()
#pprint.pprint(records)

records =[																													#Manual records for testing purposes 
(True, 3, '20.20.20.20', datetime.datetime(2019, 3, 10, 22, 7, 7), datetime.datetime(2019, 2, 23, 23, 52, 30, 316734), True),
(True, 2, '130.0.0.0/24', datetime.datetime(2019, 2, 24, 0, 4, 6), datetime.datetime(2019, 2, 23, 23, 52, 30, 316734), False),
(True, 2, '20.20.20.0/26', datetime.datetime(2019, 3, 10, 22, 14, 46), datetime.datetime(2019, 3, 10, 21, 45, 20, 742457), False),
(True, 3, '20.20.20.0/24', datetime.datetime(2019, 3, 10, 22, 9, 4), datetime.datetime(2019, 3, 10, 21, 39, 38, 697183), False),
]
######
p={}
list1=[]
list2 = []
route_leak = {}
###########
#def send_alert(ip_add):
#    currentDT = datetime.datetime.now()
#    print (str(currentDT))
    #leak_cor(ip_add)

def send_alert(ip_add):									#To send email when route leak occurs 
    msg = MIMEMultipart()

    msg['Subject'] = 'Route leak'
    msg['From'] = 'umailsandy@gmail.com'
    msg['To'] = 'sasu4625@colorado.edu'
    url = "http://127.0.0.1:9900/alert"					#Link to the flask webpage that allows user to take corrective action
    text = MIMEText(str(ip_add)+" is a possible Route leak. Please click on this link to take action: "+str(url))
    msg.attach(text)

    s = smtplib.SMTP('smtp.gmail.com', '587')
    s.ehlo()
    s.starttls()
    s.ehlo()
    s.login('umailsandy@gmail.com', 'inspire1245')     # PLACE PASSWORD
    s.sendmail('umailsandy@gmail.com', 'sasu4625@colorado.edu', msg.as_string())
    s.quit()
    print ('Email sent')

def leak_det():							#To detect route leak
    for ele in records:
        list1 = ele[2].split('/')
        if(len(list1)<2):
            list1.append('32')
        list2 = [ele[1], ele[4], ele[5], list1[1]] # AS, First-added timestamp, is_withdrawn, subnet
        p[str(list1[0])+'_'+str(list1[1])+'_'+str(ele[1])] = list2
    sorted_p = sorted(p.items() , key=lambda t : t[1][3]) #sort based on subnet_mask
    #print(sorted_p)

    j = 0
    for key, elem in sorted_p:
        if(key != '0'):
            as_no = key.split('_')[2]
            if((int(as_no) > 64511) and (int(as_no) < 65537)):				#Check for private ASs
                sorted_p[j] = ('0','0')
                print("route leak")
                #send_alert()
            network_id = key.split('_')[0]+'/'+key.split('_')[1]
            a = ip_network(network_id)
            sanity = ip_network("10.0.0.0/8")				#Check for private IPs
            if(a.subnet_of(sanity)):
                sorted_p[j] = ('0','0')
                print("route leak")
                #send_alert()
            sanity = ip_network("192.168.0.0/16")
            if(a.subnet_of(sanity)):
                sorted_p[j] = ('0','0')
                print("route leak")
            sanity = ip_network("172.16.0.0/12")
            if(a.subnet_of(sanity)):
                sorted_p[j] = ('0','0')
                print("route leak")
                #send_alert()
            route_leak[key] = {"ip" : [network_id], "as" : [elem[0]],
                               "timestamp" : [elem[1]], "withdrawn" : [elem[2]]}
            i = 0
            for key1,elem1 in sorted_p:
                if(key1 != key and str(key1) != '0'):
                    network_id1 = key1.split('_')[0]+'/'+key1.split('_')[1]
                    b = ip_network(network_id1)
                    bool_verify = b.subnet_of(a)				#Check if IP address is a subnet of another network (To get the most specific prefix entry)
                    if(bool_verify):
                        for leak_key, leak_value in route_leak.items():
                            if(key == leak_key):
                                leak_value.setdefault("ip", []).append(network_id1)
                                leak_value.setdefault("as", []).append(elem1[0])
                                leak_value.setdefault("timestamp", []).append(elem1[1])
                                leak_value.setdefault("withdrawn", []).append(elem1[2])
                        sorted_p[i] = ('0','0')
                i = i+1
        j = j+1
    print(route_leak)			#Most specific prefix wrongly advertised from a different AS
    ############################################
    headers = {
        'Accept': 'application/json',
    }
    try:
        response = requests.get('https://rpki-validator.ripe.net/api/export.json', headers=headers)			#Validate against RPKI records from the internet (Second level of validation)
        regex1 = []
        rpki_list = re.findall(r'\d{1,3}.\d{1,3}\.\d{1,3}\.\d{1,3}',str(response.content))
        print(rpki_list)
    except:
        rpki_list = []
    ############################################
    for key, elem in route_leak.items():
        least_ip = elem["ip"][0]
        least_sub =elem["ip"][0].split("/")[1]
        least_as = elem["as"][0]
        least_time = elem["timestamp"][0]

        rpki_flag = 0
        for i in range(0, len(elem["ip"])):
            if elem["ip"][i] in rpki_list:
                rpki_flag = 1
                legit_ip = elem["ip"][i]
                if(legit_ip == least_ip):
                    print("least_ip is the valid IP")
                    pass
                else:
                    print("least_ip is not the valid IP")
                    least_ip = legit_ip
                    least_sub = elem["ip"][i].split("/")[1]
                    least_as = elem["as"][i]

        if(rpki_flag == 0):
            past = datetime.datetime.now() - datetime.timedelta(days=1)
            for i in range(0, len(elem["timestamp"])):
                if (past > elem["timestamp"][i]):
                    record_i = i
                    break
            if(i == 0):
                pass
            else:
                least_ip = elem["ip"][i]
                least_sub = elem["ip"][i].split("/")[1]
                least_as = elem["as"][i]

        for ip_add,as_no in zip(elem["ip"],elem["as"]):
            if(ip_add != least_ip):
                sub = ip_add.split('/')[1]
                if(sub > least_sub):
                    if(least_as != as_no):
                        print(str(ip_add)+" is a route_leak")
                        send_alert(ip_add)
#while True:
leak_det()
#    time.sleep(300)

@app.route('/alert123', methods=['POST'])
def leak_corr():									#Correction in case of route leak
    if request.method == 'POST':
        if request.form['submit_button'] == 'YES':				#Obtain response from flask webpage
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
            prefix = prefix_ip
            for go in password:						#Login to the Edge device and configure prefix list and firewall rule to block out a particular network traffic

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
                                b2 = net_connect.send_command_timing ('set policy-options prefix-list bgplist '+prefix)
                                print (b2)
                                b3 = net_connect.send_command_timing ('commit and-quit')
                                print(b3)
                                b10 = net_connect.send_command_timing('configure')
                                print(b10)
                                b4 = net_connect.send_command_timing ('set firewall filter routeleak term blockroute from source-prefix-list bgplist'+'\n'+'set firewall filter routeleak term blockroute then discard'+'\n'+'set firewall filter routeleak term all then accept'+'\n'+'set interfaces ge-0/0/0 unit 0 family inet filter input routeleak' + '\n')
                                print(b4)
                                b8 = net_connect.send_command_timing ('commit and-quit')
                                time.sleep(60)
                                print("B8",b8)
                                b7 = net_connect.send_command_timing ('show firewall log')
                                print("B7",b7)
            print("Route leak correction action completed")
            bodyText = Markup("<h1>Route leak correction action completed</h1>")
        if request.form['submit_button'] == 'NO':
            print("Route leak correction action IGNORED")
            bodyText = Markup("<h1>Route leak correction action IGNORED</h1>")
        return render_template('alert123.html', bodyText=bodyText)

@app.route('/alert')
def alert():
    return render_template('alert.html')

if __name__ == '__main__':
    app.debug = True
    app.run(host='127.0.0.1', port=9900)
