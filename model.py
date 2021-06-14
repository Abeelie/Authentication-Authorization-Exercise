from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


bcrypt = Bcrypt()
db = SQLAlchemy()


class User(db.Model):
    """Site user."""

    __tablename__ = "users"

    username = db.Column(db.String(20), nullable=False, unique=True, primary_key=True,)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)

    feedback = db.relationship("Feedback", backref="user", cascade="all,delete")


    @classmethod
    def register(cls, username, password, first_name, last_name, email):
        """Register a user, hashing their password."""

        hashed = bcrypt.generate_password_hash(password)
        hashed_utf8 = hashed.decode("utf8")
        user = cls(
            username=username,
            password=hashed_utf8,
            first_name=first_name,
            last_name=last_name,
            email=email
        )

        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Validate that user exists & password is correct."""

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            return user
        else:
            return False


    def get_reset_token(self, expires_sec=1800):
        s = Serializer('SECRET_KEY', expires_sec)
        return s.dumps('user_id').decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer('SECRET_KEY')
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)




class Feedback(db.Model):
    """Feedback."""

    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    username = db.Column(
        db.String(20),
        db.ForeignKey('users.username'),
        nullable=False,
    )


def connect_db(app):
    db.app = app
    db.init_app(app)