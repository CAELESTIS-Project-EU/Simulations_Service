# Generated by Django 4.1.7 on 2023-10-30 17:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='execution',
            name='eID',
            field=models.CharField(default=1, max_length=255),
            preserve_default=False,
        ),
    ]
