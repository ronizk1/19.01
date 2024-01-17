# from collections import UserDict
# import datetime 
# import json,time,os
# from functools import wraps
# from flask import Flask, jsonify, request, send_from_directory, url_for
# from flask_sqlalchemy import SQLAlchemy
# from flask_cors import CORS, cross_origin
# # from sqlalchemy.orm import class_mapper
# # from werkzeug.utils import secure_filename
# import jwt
# from flask_bcrypt import Bcrypt
# from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
# from flask import Flask, request, jsonify
# from flask_cors import CORS
# from flask_sqlalchemy import SQLAlchemy
# from flask_bcrypt import Bcrypt
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from datetime import datetime, timedelta
from collections import UserDict
from datetime import datetime, timedelta  # Add this line
from datetime import timedelta

import json, time, os
from functools import wraps
from flask import Flask, Request, jsonify, request, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
import jwt
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_jwt_extended import jwt_required, get_jwt_identity
import requests




app = Flask(__name__)
CORS(app)

# SQLite database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Keep this as is
app.config['JWT_SECRET_KEY'] = 'secret_secret_key'  # Keep this as is
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Define Customer class (serving as both user and customer)
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(255), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    book_type = db.Column(db.Integer, nullable=False)

class Loan(db.Model):
    cust_id = db.Column(db.Integer, db.ForeignKey('customer.id'), primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), primary_key=True)
    loan_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    return_date = db.Column(db.DateTime)

# Create tables in the database
with app.app_context():
    db.create_all()

# Routes for the RESTful API

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    city = data.get('city')
    age = data.get('age')

    # Check if the username is already taken
    existing_user = Customer.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username is already taken'}), 400

    # Hash and salt the password using Bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new customer and add to the database
    new_customer = Customer(username=username, password=hashed_password, name=name, city=city, age=age)
    db.session.add(new_customer)
    db.session.commit()

    return jsonify({'message': 'Customer registered successfully'}), 201

# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()

#     username = data.get('username')
#     password = data.get('password')

#     # Check if the user exists
#     user = Customer.query.filter_by(username=username).first()

#     if user and bcrypt.check_password_hash(user.password, password):
#         # Generate an access token with an expiration time
#         expires = timedelta(hours=1)  # Use timedelta directly
#         access_token = create_access_token(identity=user.id, expires_delta=expires)
#         print(access_token)
#         return jsonify({'access_token': access_token}), 200
#     else:
#         return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    # Check if the user exists
    user = Customer.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Generate an access token with an expiration time
        expires = timedelta(hours=1)
        access_token = create_access_token(identity=user.id, expires_delta=expires)
        print(access_token)
        return jsonify({
            'message': 'Login successful',
            'user_id': user.id,
            'username': user.username,
            'access_token': access_token
        }), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401




# Remaining routes for the library app (your existing code)





# @app.route('/add_book', methods=['POST'])
# @jwt_required()
# def add_book():
#     current_user_id = get_jwt_identity()
    
#     # Access the current user's information if needed
#     current_user = Customer.query.get(current_user_id)
#     print(f"User {current_user.username} is adding a book.")

#     data = request.get_json()
#     name = data.get('name')
#     author = data.get('author')
#     year_published = data.get('year_published')
#     book_type = data.get('book_type')

#     new_book = Book(name=name, author=author, year_published=year_published, book_type=book_type)
#     db.session.add(new_book)
#     db.session.commit()

#     return jsonify({'message': 'Book added successfully'})

@app.route('/add_book', methods=['POST'])
@jwt_required()
def add_book():
    current_user_id = get_jwt_identity()
    
    # Access the current user's information if needed
    current_user = Customer.query.get(current_user_id)
    print(f"User {current_user.username} is adding a book.")

    try:
        data = request.get_json()

        name = data.get('name')
        author = data.get('author')
        year_published = data.get('year_published')
        book_type = data.get('book_type')

        new_book = Book(name=name, author=author, year_published=year_published, book_type=book_type)
        db.session.add(new_book)
        db.session.commit()

        return jsonify({'message': 'Book added successfully'})
    except Exception as e:
        print(f"Error adding book: {e}")
        return jsonify({'error': 'Failed to add book'}), 500

# Add other routes...

# Protected routes requiring JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify({'message': f'Hello, User {current_user_id}!'}), 200

# Loan a book
@app.route('/loan_book', methods=['POST'])
@jwt_required()
def loan_book():
    current_user = get_jwt_identity()

    # Assuming that the user information is stored in the 'customers' table
    user = Customer.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'error': 'User not found'})

    data = request.get_json()
    book_name = data.get('book_name')

    # Search for the book by name in the database
    book = Book.query.filter_by(name=book_name).first()

    if book:
        # Check if the book is already on loan
        existing_loan = Loan.query.filter_by(cust_id=user.id, book_id=book.id, return_date=None).first()
        if existing_loan:
            return jsonify({'error': 'This book is already on loan'})

        # Perform necessary operations (e.g., update database)
        new_loan = Loan(cust_id=user.id, book_id=book.id)
        db.session.add(new_loan)
        db.session.commit()

        return jsonify({'message': 'Book loaned successfully'})
    else:
        return jsonify({'error': 'Book not found'})


@app.route('/return_book', methods=['POST'])
@jwt_required()
def return_book():
    data = request.get_json()

    customer_name_return = data.get('customer_name_return')
    book_name_return = data.get('book_name_return')

    # Your existing code for returning a book
    # ...
    
# @app.route('/test_add_book', methods=['GET'])
# def test_add_book():
#     # Simulate a user login
#     login_data = {
#         'username': 'your_username',
#         'password': 'your_password'
#     }

#     login_response = requests.post('http://127.0.0.1:5000/login', json=login_data)
#     login_token = login_response.json().get('access_token')

#     # Use the obtained token to make a request to add_book
#     book_data = {
#         'name': 'Sample Book',
#         'author': 'John Doe',
#         'year_published': 2022,
#         'book_type': 'Fiction'
#     }

#     headers = {
#         'Authorization': f'Bearer {login_token}',
#         'Content-Type': 'application/json'
#     }

#     add_book_response = requests.post('http://127.0.0.1:5000/add_book', json=book_data, headers=headers)

#     return jsonify({
#         'login_status': login_response.status_code,
#         'add_book_status': add_book_response.status_code,
#         'add_book_response': add_book_response.json()
#     })

# Remaining routes...

# Run the application
if __name__ == '__main__':
    app.run(debug=True)