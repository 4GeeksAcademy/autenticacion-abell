import os
from flask_admin import Admin, BaseView, expose
from api.models import db, User, Task, Group, AssignedTask
from flask_admin.contrib.sqla import ModelView
from flask import render_template


class SecureModelView(ModelView):
    column_display_pk = True
    can_export = True
    can_view_details = True


def setup_admin(app):
    app.secret_key = os.environ.get('FLASK_APP_KEY', 'sample key')
    admin = Admin(app, name='TaskFlow Admin', template_mode='bootstrap3')

    class DevToolsView(BaseView):
        @expose('/')
        def index(self):
            return render_template('dev_tools_admin.html')

    class AssignedTaskView(SecureModelView):
        column_list = ('id', 'user_email', 'task_title')
        column_labels = {'user_email': 'Usuario', 'task_title': 'Tarea'}

    admin.add_view(SecureModelView(User, db.session, name='User'))
    admin.add_view(SecureModelView(Task, db.session, name='Task'))
    admin.add_view(SecureModelView(Group, db.session, name='Group'))
    admin.add_view(AssignedTaskView(
        AssignedTask, db.session, name='AssignedTask'))
    admin.add_view(DevToolsView(name='Dev Tools', endpoint='devtools'))
