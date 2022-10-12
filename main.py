import os
from datetime import date
from functools import wraps

# from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, url_for
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy

# from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash

from forms import CommentForm, CreatePostForm, CreateRegisterForm, LoginForm

# load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

# print(os.getenv("SECRET_KEY"))

# Gravatar
gravatar = Gravatar(
    app,
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)

# Login Manager
# Used YT tutorial for better understanding: https://www.youtube.com/watch?v=2dEM-s3mRLE
login_manager = LoginManager()
login_manager.init_app(app=app)


@login_manager.user_loader
def user_loader(user_id):
    # print("user_id Type:", type(user_id))
    # Need to convert user_id since login manager passes in id as string type
    return User.query.get(int(user_id))


# CONNECT TO DB
# Update the app config to use "DATABASE_URL" environment variable if provided, but if
# it's None (e.g. when running locally) then we can provide sqlite:///blog.db as the alternative.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
# app.config[
#     "SQLALCHEMY_DATABASE_URI"
# ] = "postgresql://qrvdzcuhltvvll:396c0c8891bc82fd86e597bec28e5a3647fc088de0110453c1a94cfa37f67882@ec2-54-147-36-107.compute-1.amazonaws.com:5432/db800hp7k23dm8"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), nullable=False)

    # Parent relataionship with BlogPost table
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")

    # Parent relataionship with Comment table
    # "comment_author" refers to the comment_author property in the Comment class.
    # My note: I can use the same name "author" like in BlogPost table as reference to relationship.
    # It will not cause conflict with BlogPost as far as I tested, so keeping the same name for demonstration purposes.
    # it's still a good idea to name relationship reference uniquely in the future across tables
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Child relationship with User table
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Parent relataionship with Comment table
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # Child Relationship with User Table
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")

    # Child Relationship with BlogPost Table
    # My note: I can use the same name "comments" in this Comment table since it references two separate tables.
    # One for User, and one for BlogPost
    # It will not cause conflict as far as I know, so keeping the same name for demonstration purposes.
    # it's still a good idea to "comments" back_populates name relationship reference uniquely in the future across tables
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


db.create_all()


# Decorators
def admin_only(f):
    """Check if current user's id is equal to 1. Abort if not"""

    @wraps(f)
    def decorated_func(*args, **kwargs):
        print("Current User Authentication status:", current_user.is_authenticated)
        # Added not current_user.is_authenticated to catch users not logged in and
        # avoid error current_user.id not available since no user is logged in
        # Alternatively, just use @login_required decorator which might be better. this way,
        # admin_only decorator's job is to only check for user id and confirm admin.
        # Just put @login_required first before admin_only so it's executed first

        # if not current_user.is_authenticated or current_user.id != 1:
        if current_user.id != 1:
            print("User ID:", current_user.id)
            print("User denied/Abort!")
            return abort(403)
        return f(*args, **kwargs)

    return decorated_func


# I could also just include this in the login route, but decided to create decorator for practice
def login_check(f):
    """Check if current user is logged in. Redirect to index page if user is already logged in."""

    @wraps(f)
    def decorated_func(*args, **kwargs):
        print("Current User Authentication status:", current_user.is_authenticated)
        # Added not current_user.is_authenticated to catch users not logged in and
        # avoid error current_user.id not available since no user is logged in
        # Alternatively, just use @login_required decorator which might be better. this way,
        # admin_only decorator's job is to only check for user id and confirm admin.
        # Just put @login_required first before admin_only so it's executed first

        # if not current_user.is_authenticated or current_user.id != 1:
        if current_user.is_authenticated:
            print("Already logged in. Redirect to index")
            return redirect(url_for("get_all_posts"))
        return f(*args, **kwargs)

    return decorated_func


@app.route("/")
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


# Rewritten this route as I was receiving error when migrated to Postgres
# integrityerror check won't work since it's no longer using sqlite db
@app.route("/register", methods=["GET", "POST"])
def register():
    form = CreateRegisterForm()
    if form.validate_on_submit():
        # print("validated")

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first().email)
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        hash_and_salted_pw = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8)
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hash_and_salted_pw,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


# Old register route using integrityerror as check
# @app.route("/register", methods=["GET", "POST"])
# def register():
#     form = CreateRegisterForm()
#     if form.validate_on_submit():
#         print("validated")
#         hash_and_salted_pw = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8)
#         # Error handling for SQLAlchemy found in https://www.youtube.com/watch?v=P-Z1wXFW4Is
#         # Also check day 63 project
#         # Checks if email already exists in database
#         try:
#             new_user = User(
#                 name=form.name.data,
#                 email=form.email.data,
#                 password=hash_and_salted_pw,
#             )
#             db.session.add(new_user)
#             db.session.commit()
#         # Check if duplicate email exists in db
#         except IntegrityError:
#             flash("You've already signed up with that email address. Log in instead.")
#             return redirect(url_for("login"))
#         else:
#             login_user(new_user)
#             return redirect(url_for("get_all_posts"))

#     return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@login_check
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user = User.query.filter_by(email=user_email).first()
        print("User:", user)
        if user and check_password_hash(user.password, form.password.data):
            print("Email/Password Validated")
            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("Invalid Credentials. Please try again.")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to log in or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(text=form.comment.data, author=current_user, parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    # comment = Comment.query.get(1)
    # print("Comment Author:", comment.author.name)
    print(gravatar)
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    # print("Author Name:", post.author.name)
    edit_form = CreatePostForm(title=post.title, subtitle=post.subtitle, img_url=post.img_url, body=post.body)
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # Commented this out since author name is linked to the signed in user's name from Users table.
        # Removed author field from CreatePostForm as well
        # User doesn't need to manually edit this
        # post.author = post.author.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
