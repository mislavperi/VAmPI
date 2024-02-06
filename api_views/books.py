import jsonschema

from api_views.users import token_validator
from api_views.cache import SimpleCache
from config import db
from api_views.json_schemas import add_book_schema
from flask import jsonify, Response, request, json
from models.user_model import User
from models.books_model import Book
import pickle

# Initialize the cache
cache = SimpleCache()


def error_message_helper(msg):
    return '{ "status": "fail", "message": "' + msg + '"}'


def get_all_books():
    return_value = jsonify({'Books': Book.get_all_books()})
    return return_value


def add_new_book():
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, add_book_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'), request.headers.get('Refresh'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    elif "Invalid token" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp).first()

        book = Book.query.filter_by(user=user, book_title=request_data.get('book_title')).first()
        if book:
            return Response(error_message_helper("Book Already exists!"), 400, mimetype="application/json")
        else:
            newBook = Book(book_title=request_data.get('book_title'), secret_content=request_data.get('secret'),
                           user_id=user.id)
            db.session.add(newBook)
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Book has been added.'
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")

def get_by_title(book_title):
    resp = token_validator(request.headers.get('Authorization'), request.headers.get('Refresh'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    elif "Invalid token" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        serialized_book = cache.get(book_title)
        if serialized_book:
            try:
                loaded_object = pickle.loads(serialized_book, fix_imports=True, encoding="ASCII", errors="strict") 
                if not isinstance(loaded_object, Book):
                    raise ValueError(f"Unauthorized deserialization attempt: {type(loaded_object).__name__}")
                book = loaded_object 
            except (pickle.UnpicklingError, ValueError) as e:
                return Response(error_message_helper(f"Error in deserialization: {e}"), 500, mimetype="application/json")
        else:
            user = User.query.filter_by(username=resp).first()
            book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
            if book:
                serialized_book = pickle.dumps(book)
                cache.set(book_title, serialized_book)
        if book:
            responseObject = {
                'book_title': book.book_title,
                'secret': book.secret_content,
                'owner': book.user.username
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        else:
            return Response(error_message_helper("Book not found!"), 404, mimetype="application/json")
