import requests

from flask import Flask, url_for, session, redirect, jsonify, render_template
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = 'secret'
app.OAUTH2_ACCESS_TOKEN_GENERATOR = True
oauth = OAuth(app)
github = oauth.register('github',
                        client_id='69ba8ba4e8ccd432f528',
                        client_secret='19ebfc6dc2297acf6891c4c2527436f048cf8c92',
                        access_token_url='https://github.com/login/oauth/access_token',
                        access_token_params=None,
                        authorize_url='https://github.com/login/oauth/authorize',
                        authorize_params=None,
                        api_base_url='https://api.github.com/',
                        client_kwargs={'scope': 'read:user'},
                        )


@app.route('/')
# def hello_world():
#     return f'Hello, stranger'
def index():
    auth_token = session.get('access_token')
    if "access_token" in session:
        headers = {
            "Authorization": f"token {auth_token.get('access_token')}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "Github OAuth 2.0 Client"
        }
        response = requests.get("https://api.github.com/user", headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            name=user_data["name"]
            return render_template('home.html', user=name)
    else:
        return render_template('home.html', user='')


@app.route('/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    return github.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorized():
    token = github.authorize_access_token()
    session['access_token'] = token
    return redirect(url_for('index'))


@app.route("/profile")
def profile():
    auth_token = session.get('access_token')
    # Check if access token is present in the session
    if "access_token" in session:
        # Fetch user information from GitHub API
        headers = {
            "Authorization": f"token {auth_token.get('access_token')}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "Github OAuth 2.0 Client"
        }
        response = requests.get("https://api.github.com/user", headers=headers)
        user_data = response.json()

        # Display user information
        # return f"Hello {user_data['login']}! Your GitHub ID is {user_data['id']}"
        return jsonify(user_data)
        # return auth_token
    else:
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    # Clear session data
    session.clear()
    return redirect(url_for("index"))
