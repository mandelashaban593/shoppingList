from flask import flash, redirect, render_template, url_for
from flask_login import login_required, login_user, logout_user

from . import auth
from forms import LoginForm, RegistrationForm,AddListForm
from .. import db
from ..models import User, Shoplist
from flask_login import current_user



def check_username():
    # prevent non-admins from accessing the page
    if current_user.username:
        print current_user.id



@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                            username=form.username.data,
                            first_name=form.first_name.data,
                            last_name=form.last_name.data,
                            password=form.password.data)

        # add employee to the database
        db.session.add(user)
        db.session.commit()
        flash('You have successfully registered! You may now login.')

        # redirect to the login page
        return redirect(url_for('auth.login'))

    # load registration template
    return render_template('auth/register.html', form=form, title='Register')



@auth.route('/addlist', methods=['GET', 'POST'])
@login_required
def addlist():
    """
    Add a department to the database
    """
   

    add_shoplist = True

    form = AddListForm()
    if form.validate_on_submit():
        shoplist = Shoplist(title=form.title.data,
                            items=form.items.data,
                            user=current_user.id,
                            )
        try:
            # add department to the database
            db.session.add(shoplist)
            db.session.commit()
            flash('You have successfully added shoping list.')
        except:
            # in case department name already exists
            flash('Error: Adding shoping list.')

        # redirect to departments page
        return redirect(url_for('auth.list_shoplist'))

    # load department template
    return render_template('auth/addlist.html', action="Add",
                           add_shoplist=add_shoplist, form=form,
                           title="Add Shoplist")


@auth.route('/shoplist', methods=['GET', 'POST'])
@login_required
def list_shoplist():
    """
    List all departments
    """
    check_username()

    shoplist = Shoplist.query.filter_by(user=current_user.id)

    return render_template('auth/shoplist.html',
                           shoplist=shoplist, title="Shoplist")


@auth.route('/addlist/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_shoplist(id):
    """
    Edit a shoplist
    """
    

    add_shoplist = False

    shoplist = Shoplist.query.get_or_404(id)
    form = AddListForm(obj=shoplist)
    if form.validate_on_submit():
        shoplist.title = form.title.data
        shoplist.items = form.items.data
        db.session.commit()
        flash('You have successfully edited the shoplist.')

        # redirect to the departments page
        return redirect(url_for('auth.list_shoplist'))

    form.items.data = shoplist.items
    form.title.data = shoplist.title
    return render_template('auth/shoplist2.html', action="Edit",
                           add_shoplist=add_shoplist, form=form,
                           shoplist=shoplist, title="Edit Shoplist")




@auth.route('/addlist/delete/<int:id_del>', methods=['GET', 'POST'])
@login_required
def delete_shoplist(id_del):
    """
    Delete a department from the database
    """


    shoplist = Shoplist.query.get_or_404(id_del)
    db.session.delete(shoplist)
    db.session.commit()
    flash('You have successfully deleted the Shoplist.')

    # redirect to the departments page
    return redirect(url_for('auth.list_shoplist'))

    return render_template(title="Delete Shoplist")



@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        # check whether employee exists in the database and whether
        # the password entered matches the password in the database
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(
                form.password.data):
            # log employee in
            login_user(user)

            # redirect to the appropriate dashboard page
            if not user.is_admin:
                return redirect(url_for('home.admin_dashboard'))
            
        # when login details are incorrect
        else:
            flash('Invalid email or password.')

    # load login template
    return render_template('auth/login.html', form=form, title='Login')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully been logged out.')

    # redirect to the login page
    return redirect(url_for('auth.login'))
