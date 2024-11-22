#!/usr/bin/env python3
""" This module defines a basic Flask application. """
from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/')
def welcome():
    return jsonify({'message': 'Bienvenue'})


@app.post('/users')
def users():
    try:
        data = request.form
        if not data or not data['email'] or not data['password']:
            return jsonify({'error': 'email and password are required'}), 400

        email = data['email']
        password = data['password']
        user = AUTH.register_user(email, password)
        return jsonify({'email': user.email, 'message': 'user created'})
    except ValueError:
        return jsonify({'message': 'email already registered'}), 400


@app.post('/sessions')
def login():
    data = request.form
    if not data or not data['email'] or not data['password']:
        return make_response(
            jsonify({'error': 'email and password are required'}), 400)

    email = data['email']
    password = data['password']

    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({'email': email, 'message': 'logged in'})
    response.set_cookie('session_id', session_id)
    return response


@app.delete('/sessions')
def logout():
    if not request.cookies.get('session_id'):
        abort(403)

    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)

    if not user:
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect('/')


@app.get('/profile')
def profile():
    if not request.cookies.get('session_id'):
        abort(403)

    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        return jsonify(
            {'email': user.email}
        ), 200
    else:
        abort(403)


@app.post('/reset_password')
def get_reset_password_token():
    try:
        data = request.form
        if not data or not data['email']:
            return jsonify({'error': 'email is required'}), 400

        email = data['email']
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({'email': email, 'reset_token': reset_token}), 200
    except ValueError:
        abort(403)


@app.put('/reset_password')
def update_password():
    data = request.form
    if not data or not data['email'] or not data['reset_token'] \
            or not data['new_password']:
        return jsonify(
            {'error': 'email, reset_token and new_password are required'}
        ), 400

    email = data['email']
    reset_token = data['reset_token']
    new_password = data['new_password']
    updated = False

    try:
        AUTH.update_password(reset_token, new_password)
        updated = True
    except ValueError:
        updated = False

    if not updated:
        abort(403)

    return jsonify({'email': email, 'message': 'Password updated'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
