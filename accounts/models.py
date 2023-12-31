from django.db import models
from django.conf import settings


class Document(models.Model):
    document = models.FileField(upload_to='documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.document)

SIMULATION = [
    ('alya', 'Alya'),
]
SAMPLER = [
    ('morris', 'Morris'),
    ('saltelli', 'Saltelli')
]

SENSITIVITY = [
    ('morris', 'Morris'),
    ('saltelli', 'Saltelli')
]

INTEGER_CHOICES= [tuple([x,x]) for x in range(1,10)]

class WorkFlow(models.Model):
    samplerName = models.CharField(max_length=255,choices=SAMPLER, default='morris')
    samplerParameters = models.CharField(max_length=255,  null=False)

    simulation = models.CharField(max_length=255,choices=SIMULATION, default='alya')
    mesh = models.CharField(max_length=255, null=False)
    templateSim= models.CharField(max_length=255, null=False)

    sensitivity = models.CharField(max_length=255,choices=SENSITIVITY, default='morris')
    sensitivityOutput = models.CharField(max_length=255,  null=False)

    outputs= models.CharField(max_length=255,  null=False)

    numVarproblem = models.IntegerField(choices=INTEGER_CHOICES, default='3')
    variablesSampler= models.CharField(max_length=500,  null=False)
    variablesFixed= models.CharField(max_length=1000,  null=False)

class Execution(models.Model):
    jobID= models.IntegerField(null=False)
    user= models.CharField(max_length=255,null=False)
    author = models.ForeignKey(settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        to_field='username',
        null=True)
    nodes = models.IntegerField(null=False)
    status = models.CharField(max_length=255, null=False)
    time = models.CharField(max_length=255,null=False)
    execution_time= models.IntegerField(null=False)
    qos=models.CharField(max_length=255,null=False)
    name_workflow=models.CharField(max_length=255,null=False)
    checkpoint=models.IntegerField(null=False, default=0)
    wdir= models.CharField(max_length=500,null=False)
    workflow_path= models.CharField(max_length=500,null=False)


class Key_Gen(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL,
                               on_delete=models.CASCADE,
                               to_field='username',
                               null=True, blank=True)
    machine=models.ForeignKey("Machine",
                               on_delete=models.CASCADE,
                               to_field='id',
                               null=True, blank=True)
    public_key=models.CharField(max_length=2048,null=False)
    private_key=models.CharField(max_length=2048,null=False)


class Machine(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL,
                               on_delete=models.CASCADE,
                               to_field='username',
                               null=True, blank=True)
    user = models.CharField(max_length=255, null=False)
    fqdn=models.CharField(max_length=255,null=False)
    wdir = models.CharField(max_length=2048, null=False)

