# Generated by Django 4.1.7 on 2024-02-29 10:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_execution_results_ftp_path'),
    ]

    operations = [
        migrations.AlterField(
            model_name='execution',
            name='checkpoint',
            field=models.BooleanField(default=False),
        ),
    ]
