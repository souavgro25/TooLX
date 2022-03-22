from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('ab/<str:host>/<str:type>', views.nslookup, name='dnslookup'),
   
    path('nmap/<str:host>/<str:port>/<str:command>',views.nmapscanner,name='portscanner'),

    path('about',views.about,name='about'),
    path('index_nmap',views.indexnmap,name="nmap"),
    path('ping', views.ping, name='ping'),
    path('traceroute', views.traceroute, name='traceroute'),
    path('hping3', views.hping3, name='hping3'),
    path('aesencrypt', views.aesencrypt, name='aesencrypt'),
    path('aesdecrypt', views.aesdecrypt, name='aesdecrypt'),
]