from curses.ascii import HT
from json import tool
from Crypto.Cipher import AES  #import AES from library
from django.shortcuts import render, redirect
import dns.resolver
import subprocess
import nmap
from django.http import JsonResponse
from dnslookup.models import Tools
from Crypto.Util.Padding import unpad, pad #import pad unpad from library

#######################################################################################################################
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
    try:
        if request.method == 'POST':
            ip = request.POST.get('ip')
            p= subprocess.run(['ping', '-c4', ip], capture_output=True, text=True)#subprocess run command from command line
            #if there is any eror output to catch that
            if p.stderr:
                p1= p.stderr
            #else it will catch the output
            elif p.stdout:
                p1= p.stdout
            else:
                p1= 'Provide the Valid input'
            return render(request, 'home.html',{'p1': p1})
        else:
            return render(request, 'home.html')
    except:
        return redirect('ping')


#Traceroute
#function made for traceroute
def traceroute (request):
    try:
        if request.method == 'POST':
            ip = request.POST.get('ip')
            p= subprocess.run(['traceroute', ip], capture_output=True, text=True)#subprocess run command from command line
            #if there is any eror output to catch that
            if p.stderr:
                p1= p.stderr
            #else it will catch the output
            elif p.stdout:
                p1= p.stdout
            else:
                p1='provide the valid input'
            return render(request, 'home.html', {'p1': p1})
        else:
            return render(request, 'home.html')
    except:
        return redirect('traceroute')


#AES Decrypter CBC mode
def aesencrypt(request):
    tool = "aesencryp"
    try:
        if request.method == 'POST':
            #encrypt
            plaintext= request.POST.get('plaintext')#take textas input from user
            key= request.POST.get('key')# take key as input from user
            iv= request.POST.get('iv')#take iv from user which is bydefault 0000000000000000
            #converting input to bytes
            bplaintext= bytes(plaintext, 'utf-8')
            bkey= bytes(key, 'utf-8')
            biv= bytes(iv, 'utf-8')
            cipher= AES.new(bkey,AES.MODE_CBC, iv= biv)
            ciphertext= cipher.encrypt(pad(bplaintext,AES.block_size))
            #converting the cipher text and key to hex values
            hextext= ciphertext.hex()
            hexkey= bkey.hex()
            return render(request, 'aes.html', {'ciphertext': hextext, 'tool': tool, 'hexkey': hexkey})
        else:
            return render(request, 'aes.html', {'tool': tool})
    except (ValueError, KeyError):
        message= "Enter valid key size and value"
        return render(request, 'aes.html', {'messages': message, 'tool': tool})

def aesdecrypt(request):
    tool= "aesdecryp"
    try:
        if request.method == 'POST':
            #decrypt
            ciphertext=request.POST.get('ciphertext')#take ciphertext as input from user
            key= request.POST.get('key')#take key as input from user
            iv= request.POST.get('iv')#take iv fro user as input
            #converting hex values to byte
            bciphertext= bytes.fromhex(ciphertext)
            bkey= bytes.fromhex(key)
            biv= bytes(iv, 'utf-8')
            plain= AES.new(bkey, AES.MODE_CBC, biv)
            bplaintext= unpad(plain.decrypt(bciphertext),AES.block_size)
            plaintext= bplaintext.decode()
            return render(request, 'aes.html', {'plaintext':plaintext, 'tool': tool})
        else:
            return render(request, 'aes.html', {'tool':tool})
    except (ValueError, KeyError):
        message= "Enter valid key size and value"
        return render(request, 'aes.html', {'messages': message, 'tool': tool})

#Hping3
#function made for hping3
def hping3(request):
    tool="hping3"
    try:
        if request.method== 'POST':
            tool="hping3"
            ip= request.POST.get('ip')
            try:
                option= request.Post.get('option') 
            except:
                option= 1      
            if (option==1):
                p= subprocess.run(['hping3', '-S', '--c', '4', ip], capture_output=True, text= True)
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
    except:
        return redirect('hping3')

