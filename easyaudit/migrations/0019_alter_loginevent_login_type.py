# Generated by Django 4.1.3 on 2023-03-28 11:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('easyaudit', '0018_crudevent_easyaudit_c_object__a12edd_idx_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='loginevent',
            name='login_type',
            field=models.SmallIntegerField(choices=[(0, 'Login'), (1, 'Logout'), (2, 'Failed login'), (3, 'Login mobile')], verbose_name='Event type'),
        ),
    ]