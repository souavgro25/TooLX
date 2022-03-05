from django.contrib import admin
from .models import Tools
# Register your models here.
class Tool(admin.ModelAdmin):
    fields = ['Name', 'Toolname','command']

admin.site.register(Tools,Tool)