# Generated by Django 4.1.7 on 2024-02-29 13:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_execution_checkpointbool'),
    ]

    operations = [
        migrations.AddField(
            model_name='execution',
            name='branch',
            field=models.CharField(default='main', max_length=255),
        ),
        migrations.AddField(
            model_name='execution',
            name='d_bool',
            field=models.CharField(default='false', max_length=255),
        ),
        migrations.AddField(
            model_name='execution',
            name='g_bool',
            field=models.CharField(default='false', max_length=255),
        ),
        migrations.AddField(
            model_name='execution',
            name='t_bool',
            field=models.CharField(default='false', max_length=255),
        ),
    ]
