from multiprocessing import context
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import dns.resolver



def nslookup(request,host,type):
    result = dns.resolver.query(host,type)
    records = []
    for val in result:
        print('A Record : ', val.to_text())
        records.append(val.to_text())
    context={ 'records': records ,'host':host,'type':type}
    return JsonResponse({"data":context})
    

def index(request):
    return render(request,'index.html')
   