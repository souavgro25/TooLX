from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('ab/<str:host>/<str:type>', views.nslookup, name='dnslookup'),

]