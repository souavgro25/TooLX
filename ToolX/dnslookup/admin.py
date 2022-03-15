from django.contrib import admin
from .models import Ping, Tools
# Register your models here.
class Tool(admin.ModelAdmin):
    fields = ['Name', 'Toolname','command']

admin.site.register(Tools,Tool)
admin.site.register(Ping)