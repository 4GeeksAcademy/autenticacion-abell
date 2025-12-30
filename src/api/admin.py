import os
from flask_admin import Admin, BaseView, expose, AdminIndexView
from api.models import db, User
from flask_admin.contrib.sqla import ModelView
from flask import render_template, redirect

class SecureModelView(ModelView):
    column_display_pk = True
    can_export = True
    can_view_details = True

def setup_admin(app):
    app.secret_key = os.environ.get('FLASK_APP_KEY', 'sample key')

    class MyAdminIndexView(AdminIndexView):
        is_default = True

        @expose()
        def index(self):
            return redirect('/admin/user/')

    admin = Admin(
        app,
        name='Autenticacion Admin',
        index_view=MyAdminIndexView()
    )

    admin.add_view(SecureModelView(User, db.session, name='User'))
