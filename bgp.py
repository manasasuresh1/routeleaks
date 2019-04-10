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

conn = psycopg2.connect(host="172.16.2.104",database="openbmp", user="openbmp", password="openbmp")
cursor = conn.cursor()
cursor.execute("SELECT isipv4, origin_as, prefix,  timestamp,first_added_timestamp, iswithdrawn FROM ip_rib")
records = cursor.fetchall()
pprint.pprint(records)

'''records =[
(True, 3, '20.20.20.20', datetime.datetime(2019, 3, 10, 22, 7, 7), datetime.datetime(2019, 2, 23, 23, 52, 30, 316734), True),
(True, 2, '130.0.0.0/24', datetime.datetime(2019, 2, 24, 0, 4, 6), datetime.datetime(2019, 2, 23, 23, 52, 30, 316734), False),
(True, 2, '20.20.20.0/26', datetime.datetime(2019, 3, 10, 22, 14, 46), datetime.datetime(2019, 3, 10, 21, 45, 20, 742457), False),
(True, 3, '20.20.20.0/24', datetime.datetime(2019, 3, 10, 22, 9, 4), datetime.datetime(2019, 3, 10, 21, 39, 38, 697183), False),
]'''
######
p={}
list1=[]
list2 = []
route_leak = {}
###########
def send_alert():
    currentDT = datetime.datetime.now()
    print (str(currentDT))
'''def send_alert():
    msg = MIMEMultipart()

    msg['Subject'] = 'Capstone'
    msg['From'] = 'umailsandy@gmail.com'
    msg['To'] = 'sasu4625@colorado.edu'

    text = MIMEText("The link is as show: \n\n www.google.com")
    msg.attach(text)

    s = smtplib.SMTP('smtp.gmail.com', '587')
    s.ehlo()
    s.starttls()
    s.ehlo()
    s.login('umailsandy@gmail.com', 'inspire1245')     # PLACE PASSWORD
    s.sendmail('umailsandy@gmail.com', 'sasu4625@colorado.edu', msg.as_string())
    s.quit()
    print ('Email sent')'''

def leak_det():
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
            if((int(as_no) > 64511) and (int(as_no) < 65537)):
                sorted_p[j] = ('0','0')
                print("route leak")
                #send_alert()
            network_id = key.split('_')[0]+'/'+key.split('_')[1]
            a = ip_network(network_id)
            sanity = ip_network("10.0.0.0/8")
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
                    bool_verify = b.subnet_of(a)
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
    print(route_leak)
    ############################################
    headers = {
        'Accept': 'application/json',
    }
    try:
        response = requests.get('https://rpki-validator.ripe.net/api/export.json', headers=headers)
        regex1 = []
        rpki_list = re.findall(r'\d{1,3}.\d{1,3}\.\d{1,3}\.\d{1,3}',str(response.content))
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
                        send_alert()
while True:
    leak_det()
    time.sleep(300)

#def leak_cor():
