from flask.views import MethodView
from flask_smorest import Blueprint, abort
from passlib.hash import pbkdf2_sha256
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from db import db
from models import UserModel
from schemas import UserSchema, UserRegisterSchema
from blocklist import BLOCKLIST
from flask_jwt_extended import create_access_token, get_jwt, jwt_required, create_refresh_token, get_jwt_identity

blp = Blueprint("users",__name__,description="Operations on Users")

@blp.route('/register')
class UserRegister(MethodView):
    @blp.arguments(UserRegisterSchema)
    def post(self,user_data):
        user = UserModel(
            username=user_data["username"], 
            email=user_data["email"],
            password=pbkdf2_sha256.hash(user_data["password"])
        )
        if UserModel.query.filter((UserModel.username == user_data["username"])).first() \
            or UserModel.query.filter((UserModel.email == user_data["email"])).first() :
            abort(409, message="A user with that username or email already exists.")
        db.session.add(user)
        db.session.commit()
        return {"message" : "User Created Successfully"},201

@blp.route('/user/<int:user_id>')
class User(MethodView):
    @blp.response(200,UserSchema)
    def get(self,user_id):
        user = UserModel.query.get_or_404(user_id)
        return user
    
    @blp.response(202, description="User deleted")
    @blp.alt_response(404, description="User not found.")
    def delete(self,user_id):
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message" : "User Deleted"}
        
@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {"access_token": access_token, "refresh_token": refresh_token}, 200
        abort(401, message="Invalid credentials.")

@blp.route('/logout')
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        BLOCKLIST.add(jti)
        return {"message": "Successfully logged out"}, 200

@blp.route('/refresh')
class TokenRefresh(MethodView):
    @jwt_required(fresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        jti = get_jwt()['jti']
        BLOCKLIST.add(jti)
        return {"access token": new_token},200