from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Instance of Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    # __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), index=True, unique=False)
    email = db.Column(db.String(150), index=True, unique=True)
    hashed_password = db.Column(db.String(150), index=False, unique=False)
    # posts = relationship('BlogPost', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

    def check_password(self, submitted_password):
        return check_password_hash(pwhash=self.hashed_password, password=submitted_password)


db.create_all()

# user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# check if the user is an admin decorator
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if int(current_user.get_id()) != 1:
            abort(403, description='Unauthorized access')
        return func(*args, **kwargs)
    return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    is_admin = False
    try:
        if current_user and int(current_user.get_id()) == 1:
            is_admin = True
    except TypeError:
        pass
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, is_admin=is_admin)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']

        # check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists!')
            return redirect(url_for('login'))

        # create new user
        new_user = User(name=name, email=email)

        # set password
        new_user.set_password(password)

        # add new user to db
        db.session.add(new_user)

        # commit
        try:
            db.session.commit()
        except:
            flash('Network error')
            db.session.rollback()

        # redirect to login page
        return redirect(url_for('login'))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        submitted_email = request.form['email']
        submitted_pass = request.form['password']

        # check for user
        user = User.query.filter_by(email=submitted_email).first()
        if not user:
            flash('Email does not match')
            return redirect(url_for('login'))

        # user exists; check password
        if not user.check_password(submitted_pass):
            flash('password is incorrect')
            return redirect(url_for('login'))

        # email and pass are good; login user
        login_user(user)
        flash('successfully login')
        return redirect(url_for('get_all_posts'))
    return render_template("login.html")


@app.route('/logout')
def logout():
    logout_user()
    if not current_user.is_authenticated:
        flash('Successfully logged out')
        return redirect(url_for('login'))
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, logged_in=current_user.is_authenticated))
    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
