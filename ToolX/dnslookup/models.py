from statistics import mode
from click import command
from django.db import models

# Create your models here.
class Tools(models.Model):
    id = models.AutoField(primary_key=True)
    Name = models.CharField(max_length=50)
    Toolname = models.CharField( max_length=50)
    command= models.CharField(max_length=100)
    

