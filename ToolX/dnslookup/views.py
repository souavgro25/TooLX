from concurrent.futures import process
from os import read
import readline
from subprocess import PIPE
import shlex
from django.shortcuts import render
import dns.resolver
import subprocess
import nmap
from django.http import HttpResponse, JsonResponse

from dnslookup.models import Ping, Tools

def nslookup(request,host,type):
    host = host.replace(" ", "").replace(
			"(", "").replace(")", "").replace("+", "").replace("-", "").replace("/","")
    try:
        result = dns.resolver.query(host,type)
    except:
        context={"records":["no data found"],'host':host,'type':type}
        return JsonResponse({"data":context ,"error":'1'})
    records = []
    for val in result:
        
        records.append(val.to_text())
    context={ 'records': records ,'host':host,'type':type}
    return JsonResponse({"data":context ,"error":"0"})
    

def index(request):
    tool= Tools.objects.filter(Toolname='Dns')
    print(tool)
    context ={
        'Tool':tool
    }
    return render(request,'index.html',context)
   


def nmapscanner(request,host, port,command):
    
    nmScan = nmap.PortScanner()
    try:
        scan = nmScan.scan(host,arguments=command+port)
        host=nmScan.all_hosts() 
        context={'host':host,'scaninfo':scan}
            # if (type==1):
        #     scan = nmScan.scan(host,arguments='-sV  -p'+port)
        # elif(type==2):
        #     scan = nmScan.scan(host,arguments='-sC -p'+port)
        # elif(type==3):
        #     scan = nmScan.scan(host,arguments='--privileged -sU -p'+port)
        # elif(type==4):
        #     scan = nmScan.scan(host,arguments=' --privileged -sN -p'+port)

        return JsonResponse({'data':context,"error":"0"})
    except:
        return JsonResponse({'data':"failed to scan this host ","error":"1"})

def about(request):
    context={ 'records': "hello i am about page " }
    return render(request,'about.html',context)

def indexnmap(request):
    tool= Tools.objects.filter(Toolname='Nmap')
    context ={
        'Tool':tool
    }
    return render(request,'nmap.html',context)

#Ping
#function made for ping
def ping(request):
    tool="Ping"
    if request.method == 'POST':
        tool="Ping"
        ip = request.POST.get('ip')
        p= subprocess.run(['ping', '-c4', ip], capture_output=True, text=True)
        #if there is any eror output to catch that
        if p.stderr:
            p1= p.stderr
        #else it will catch the output
        elif p.stdout:
            p1= p.stdout
        else:
            p1= 'Provide the Valid input'
        return render(request, 'home.html',{'p1': p1,'tool':tool})
    else:
        return render(request, 'home.html',{'tool':tool})


#Traceroute
#function made for traceroute
def traceroute (request):
    tool="Traceroute"
    if request.method == 'POST':
        ip = request.POST.get('ip')
        tool="Traceroute"
        p= subprocess.run(['traceroute', ip], capture_output=True, text=True)
        if p.stderr:
            p1= p.stderr
        elif p.stdout:
            p1= p.stdout
        else:
            p1='provide the valid input'
        return render(request, 'home.html', {'p1': p1,'tool':tool})
    else:
        return render(request, 'home.html',{'tool':tool})


#AES Decrypter CBC mode


#Hping3
#function made for hping3
def hping3(request):
    tool="hping3"
    if request.method== 'POST':
        tool="hping3"
        ip= request.POST.get('ip')
        try:
            option= request.Post.get('option') 
        except:
            option= 1      
        if (option==1):
            p= subprocess.run(['hping3', '','--c', '4', ip], capture_output=True, text= True)
        elif(option==2):
            p= subprocess.run(['hping3', '-1','--c', '4', ip], capture_output=True, text= True)
        elif(option==3):
            p= subprocess.run(['hping3', '-2','--c', '4', ip], capture_output=True, text= True)

        if p.stderr:
            p1= p.stderr
        elif p.stdout:
            p1= p.stdout
        else:
            p1= 'provide the valid input'
        return render(request, 'home.html', {'p1':p1,'tool':tool})
    else:
        return render(request, 'home.html',{'tool':tool})

