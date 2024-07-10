from django.db import models
from django.conf import settings
import random
import string


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

INTEGER_CHOICES = [tuple([x, x]) for x in range(1, 10)]


class WorkFlow(models.Model):
    samplerName = models.CharField(max_length=255, choices=SAMPLER, default='morris')
    samplerParameters = models.CharField(max_length=255, null=False)

    simulation = models.CharField(max_length=255, choices=SIMULATION, default='alya')
    mesh = models.CharField(max_length=255, null=False)
    templateSim = models.CharField(max_length=255, null=False)

    sensitivity = models.CharField(max_length=255, choices=SENSITIVITY, default='morris')
    sensitivityOutput = models.CharField(max_length=255, null=False)

    outputs = models.CharField(max_length=255, null=False)

    numVarproblem = models.IntegerField(choices=INTEGER_CHOICES, default='3')
    variablesSampler = models.CharField(max_length=500, null=False)
    variablesFixed = models.CharField(max_length=1000, null=False)


class Execution(models.Model):
    eID = models.CharField(max_length=255, null=False)
    jobID = models.IntegerField(null=False)
    user = models.CharField(max_length=255, null=False)
    author = models.ForeignKey(settings.AUTH_USER_MODEL,
                               on_delete=models.CASCADE,
                               to_field='username',
                               null=True)
    nodes = models.IntegerField(null=False)
    status = models.CharField(max_length=255, null=False)
    time = models.CharField(max_length=255, null=False)
    execution_time = models.IntegerField(null=False)
    qos = models.CharField(max_length=255, null=False)
    name_workflow = models.CharField(max_length=255, null=False)
    checkpoint = models.IntegerField(null=False, default=0)
    checkpointBool = models.BooleanField(default=False)
    wdir = models.CharField(max_length=500, null=False)
    workflow_path = models.CharField(max_length=500, null=False)
    autorestart = models.BooleanField(default=False)
    name_sim = models.CharField(max_length=255, null=False)
    machine=  models.ForeignKey("Machine",
                                on_delete=models.CASCADE,
                                to_field='id',
                                null=True, blank=True)
    results_ftp_path = models.CharField(max_length=255, null=False)
    branch=models.CharField(max_length=255, null=False, default="main")
    g_bool = models.CharField(max_length=255, null=False, default="false")
    d_bool = models.CharField(max_length=255, null=False, default="false")
    t_bool = models.CharField(max_length=255, null=False, default="false")
    project_name = models.CharField(max_length=255, null=False, default="bsc19")


class Key_Gen(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL,
                               on_delete=models.CASCADE,
                               to_field='username',
                               null=True, blank=True)
    machine = models.ForeignKey("Machine",
                                on_delete=models.CASCADE,
                                to_field='id',
                                null=True, blank=True)
    public_key = models.CharField(max_length=3000, null=False)
    private_key = models.CharField(max_length=3000, null=False)


class Machine(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL,
                               on_delete=models.CASCADE,
                               to_field='username',
                               null=True, blank=True)
    user = models.CharField(max_length=255, null=False)
    fqdn = models.CharField(max_length=255, null=False)
    wdir = models.CharField(max_length=2048, null=False)
    installDir= models.CharField(max_length=2048, null=False)
    dataDir=models.CharField(max_length=2048, null=False)


STATUS_CONN = [
    ('Active', 'Active'),
    ('Disconnect', 'Disconnect'),
    ('Timeout', 'Timeout')
]


class Connection(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE,
                             to_field='username',
                             null=True, blank=True)
    idConn_id = models.AutoField(primary_key=True)
    status = models.CharField(max_length=30, choices=STATUS_CONN, default='Disconnect')

class Mesh(models.Model):
    mesh_id = models.AutoField(primary_key=True)
    name= models.CharField(max_length=512, null=False)
    pathFTP = models.CharField(max_length=2048, null=False)
    description = models.CharField(max_length=4096, null=False)
    dateLastUpdate= models.DateTimeField(null=True)

class userMesh(models.Model):
    downloadMesh_id=models.AutoField(primary_key=True)
    user= models.ForeignKey(settings.AUTH_USER_MODEL,
                               on_delete=models.CASCADE,
                               to_field='username',
                               null=True, blank=True)
    mesh= models.ForeignKey("Mesh",
                                on_delete=models.CASCADE,
                                to_field='mesh_id',
                                null=True, blank=True)
    pathCluster= models.CharField(max_length=512, null=False)
    dateDownload = models.DateTimeField(null=True)

