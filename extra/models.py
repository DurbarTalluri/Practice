from django.db import models

# Create your models here.
class Details(models.Model):
    user= models.CharField(max_length=50)
    domain=models.CharField(max_length=50)

    def __str__(self):
        return self.user