from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('ab/<str:host>/<str:type>', views.nslookup, name='dnslookup'),
   
    path('nmap/<str:host>/<str:port>/<str:id>',views.nmapscanner,name='portscanner'),

    path('about',views.about,name='about'),
    path('index_nmap',views.indexnmap,name="nmap"),
    path('ping',views.ping, name='ping'),
    path('traceroute', views.traceroute, name='traceroute'),

]