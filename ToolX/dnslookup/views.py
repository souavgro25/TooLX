
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from .models import Tools
import dns.resolver
import subprocess
import nmap

def ping(request,):
    if request.method == 'POST':
        ip = request.POST.get('ip')
        p= subprocess.run(['ping', '-c4', ip], capture_output=True, text=True)
        p1= p.stdout
        return render(request, 'home.html',{'p1':p1})
    else:
        return render(request, 'home.html')

def nslookup(request,host,type):
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
   


def nmapscanner(request,host, port,id):
    tool= Tools.objects.filter(id=id)
    nmScan = nmap.PortScanner()
    try:
        scan = nmScan.scan(host,arguments=tool.command+port)
        # if (type==1):
        #     scan = nmScan.scan(host,arguments='-sV  -p'+port)
        # elif(type==2):
        #     scan = nmScan.scan(host,arguments='-sC -p'+port)
        # elif(type==3):
        #     scan = nmScan.scan(host,arguments='--privileged -sU -p'+port)
        # elif(type==4):
        #     scan = nmScan.scan(host,arguments=' --privileged -sN -p'+port)
        return JsonResponse({'data':scan,"error":"0"})
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

