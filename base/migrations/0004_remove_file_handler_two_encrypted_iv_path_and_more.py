# Generated by Django 5.0.7 on 2024-07-26 04:58

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0003_file_handler_two_tag_path'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='file_handler_two',
            name='encrypted_iv_path',
        ),
        migrations.RemoveField(
            model_name='file_handler_two',
            name='encrypted_sym_key_path',
        ),
        migrations.RemoveField(
            model_name='file_handler_two',
            name='public_key_path',
        ),
        migrations.RemoveField(
            model_name='file_handler_two',
            name='tag_path',
        ),
        migrations.AddField(
            model_name='file_handler_two',
            name='fernetkeyl1',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='file_handler_two',
            name='fernetkeyl2',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='file_handler_two',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
