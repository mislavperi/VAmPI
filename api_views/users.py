import re
import jsonschema

from config import db
from api_views.json_schemas import register_user_schema, login_user_schema, update_email_schema
from flask import jsonify, Response, request, json
from models.user_model import User

APPLICATION_JSON="application/json"

def error_message_helper(msg):
    return '{ "status": "fail", "message": "' + msg + '"}'


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def debug():
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value


def get_by_username(username):
    if User.get_user(username):
        return Response(str(User.get_user(username)), 200, mimetype=APPLICATION_JSON)
    else:
        return Response(error_message_helper("User not found"), 404, mimetype=APPLICATION_JSON)


def register_user():
    request_data = request.get_json()
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        try:
            # validate the data are in the correct form
            jsonschema.validate(request_data, register_user_schema)
            if 'admin' in request_data:  # User is possible to define if she/he wants to be an admin !!
                if request_data['admin']:
                    admin = True
                else:
                    admin = False
                user = User(username=request_data['username'], password=request_data['password'],
                            email=request_data['email'], admin=admin)
            else:
                user = User(username=request_data['username'], password=request_data['password'],
                            email=request_data['email'])
            db.session.add(user)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': 'Successfully registered. Login to receive an auth token.'
            }

            return Response(json.dumps(responseObject), 200, mimetype=APPLICATION_JSON)
        except jsonschema.exceptions.ValidationError as exc:
            return Response(error_message_helper(exc.message), 400, mimetype=APPLICATION_JSON)
    else:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype=APPLICATION_JSON)


def login_user():
    request_data = request.get_json()

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and request_data.get('password') == user.password:
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype=APPLICATION_JSON)
        if user and request_data.get('password') != user.password:
            return Response(error_message_helper("Password is not correct for the given username."), 200, mimetype=APPLICATION_JSON)
        elif not user:  # User enumeration
            return Response(error_message_helper("Username does not exist"), 200, mimetype=APPLICATION_JSON)
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype=APPLICATION_JSON)
    except:
        return Response(error_message_helper("An error occurred!"), 200, mimetype=APPLICATION_JSON)


def token_validator(auth_header):
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except:
            auth_token = ""
    else:
        auth_token = ""
    if auth_token:
        # if auth_token is valid we get back the username of the user
        return User.decode_auth_token(auth_token)
    else:
        return "Invalid token"


def update_email(username):
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, update_email_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype=APPLICATION_JSON)
    resp = token_validator(request.headers.get('Authorization'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    elif "Invalid token" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    else:
        user = User.query.filter_by(username=resp).first()
        match = re.search(
                r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$',
                str(request_data.get('email')))
        if match:
            user.email = request_data.get('email')
            db.session.commit()
            responseObject = {
                    'status': 'success',
                    'data': {
                        'username': user.username,
                        'email': user.email
                    }
                }
            return Response(json.dumps(responseObject), 204, mimetype=APPLICATION_JSON)
        else:
             return Response(error_message_helper("Please Provide a valid email address."), 400, mimetype=APPLICATION_JSON)


def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    elif "Invalid token" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    else:
        if request_data.get('password'):
            user = User.query.filter_by(username=username).first()
            if user:
                user.password = request_data.get('password')
                db.session.commit()
            else:
                return Response(error_message_helper("User Not Found"), 400, mimetype=APPLICATION_JSON)
        else:
            return Response(error_message_helper("Malformed Data"), 400, mimetype=APPLICATION_JSON)




def delete_user(username):
    resp = token_validator(request.headers.get('Authorization'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    elif "Invalid token" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    else:
        user = User.query.filter_by(username=resp).first()
        if user.admin:
            if bool(User.delete_user(username)):
                responseObject = {
                    'status': 'success',
                    'message': 'User deleted.'
                }
                return Response(json.dumps(responseObject), 200, mimetype=APPLICATION_JSON)
            else:
                return Response(error_message_helper("User not found!"), 404, mimetype=APPLICATION_JSON)
        else:
            return Response(error_message_helper("Only Admins may delete users!"), 401, mimetype=APPLICATION_JSON)
