# Generated by Django 4.1.3 on 2023-05-16 23:17

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("tasktrack_api", "0003_rename_lista_task_list"),
    ]

    operations = [
        migrations.AlterField(
            model_name="task",
            name="group",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="tasktrack_api.group",
            ),
        ),
        migrations.AlterField(
            model_name="task",
            name="list",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="tasktrack_api.list",
            ),
        ),
    ]
