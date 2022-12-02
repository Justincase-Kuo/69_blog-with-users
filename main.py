from flask import Flask, render_template, redirect, url_for, flash, request, abort, send_from_directory
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from weather_api import Weather
import os
from flask_ckeditor import upload_success, upload_fail

##################################################################
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField, CKEditor


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")
##################################################################

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '8BYkEfBA6O6donzWlSihBXox7C0sKR6b')
ckeditor = CKEditor(app)
Bootstrap(app)
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'




gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


Base = declarative_base()
##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    posts = relationship('BlogPost', back_populates="author")
    comments = relationship('Comment', back_populates="comment_author")

    email = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = Column(db.Integer, ForeignKey('user.id'))
    author = relationship('User', back_populates="posts")
    comments = relationship('Comment', back_populates="parent_posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_author = relationship('User', back_populates="comments")
    author_id = Column(db.Integer, ForeignKey('user.id'))
    parent_posts = relationship('BlogPost', back_populates="comments")
    post_id = Column(db.Integer, ForeignKey('blog_posts.id'))
    text = db.Column(db.Text, nullable=False)

db.create_all()


login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    weather_list = Weather().get_weather_data()
    return render_template("index.html", all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           user=current_user,
                           weather_list=weather_list)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    print("hello")
    if form.validate_on_submit():
        name = request.form['name']
        email = request.form['email']
        if User.query.filter_by(email=email) is True:
            flash("Email already registered. Please log in.")
        else:
            password = request.form['password']
            hashed_pw = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
            new_user = User(name=name, email=email, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    print('hi')
    if form.validate_on_submit():
        input_email = request.form['email']
        input_password = request.form['password']
        user = User.query.filter_by(email=input_email).first()
        print('hello')
        if user is not None:
            if check_password_hash(user.password, input_password):
                login_user(user, remember=True)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect. Please enter again.')
                return redirect(url_for('login'))

        else:
            flash('Cannot find user. Please register.')
            print("cannot find user")
            return redirect(url_for('register'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = request.form['comment']
            comment_to_add = Comment(author_id=current_user.id, post_id=post_id, text=new_comment)
            db.session.add(comment_to_add)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('You need to login to comment.')
            return redirect(url_for('login'))

    return render_template("post.html", post=requested_post, user=current_user, form=comment_form, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    print('oh')
    if form.validate_on_submit():
        print(form)
        print('hi')
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/files/<path:filename>')
def uploaded_files(filename):
    path = 'static/uploads'
    return send_from_directory(path, filename)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('upload')
    # Add more validations here
    extension = f.filename.split('.')[1].lower()
    if extension not in ['jpg', 'gif', 'png', 'jpeg']:  # 验证文件类型示例
        return upload_fail(message='Image only!')  # 返回upload_fail调用
    f.save(os.path.join('static/uploads', f.filename))
    url = url_for('uploaded_files', filename=f.filename)
    return upload_success(url=url)






if __name__ == "__main__":
    app.run(debug=True)
