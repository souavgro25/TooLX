from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('ab/<str:host>/<str:type>', views.nslookup, name='dnslookup'),
    path('about',views.about,name='about'),
    path('nmap/<str:host>/<str:port>/<int:type>',views.portscanner,name='portscanner')
]