from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, NumberRange, Email, Optional, EqualTo, ValidationError
from flask_wtf import FlaskForm
from model import User


class LoginForm(FlaskForm):
    """Login form."""

    username = StringField("Username", validators=[InputRequired(), Length(min=1, max=20)],)
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=55)],)


class RegisterForm(FlaskForm):
    """User registration form."""

    username = StringField("Username", validators=[InputRequired(), Length(min=1, max=20)],)
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=55)],)
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=50)],)
    first_name = StringField("First Name", validators=[InputRequired(), Length(max=30)],)
    last_name = StringField("Last Name", validators=[InputRequired(), Length(max=30)],)


class FeedbackForm(FlaskForm):
    """Add feedback form."""

    title = StringField("Title", validators=[InputRequired(), Length(max=100)],)
    content = StringField("Content", validators=[InputRequired()],)


class DeleteForm(FlaskForm):
    """To delete feedback"""



class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[InputRequired(), Email()])
    submit = SubmitField('Request Password Reset')
 

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(), EqualTo('password')])
    