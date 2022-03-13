from django.db import models
# Create your models here.
class Tools(models.Model):
    id = models.AutoField(primary_key=True)
    Name = models.CharField(max_length=50)
    Tool_choices = (
        ('Dns', 'Dns'),
        ('Nmap', 'Nmap'),
        ('ping', 'ping'),
        ('Hping','Hping'),
        
    )
    Toolname = models.CharField( max_length=50 ,choices=Tool_choices)
    command= models.CharField(max_length=100)


# ping model
class Ping(models.Model):
    definition= models.CharField(max_length=50, null= False)
    query= models.CharField(max_length= 35)