# Standard library imports
import datetime
import os
import re
from functools import wraps

# Third-party imports
import bleach
import jwt
import requests
from dotenv import load_dotenv
from flask import (Flask, flash, jsonify, redirect, render_template, request,session, url_for)
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Local imports
from DB import *

# === Application Initialization ===
app = Flask(__name__)
load_dotenv()
bcrypt = Bcrypt(app)

# === Configuration Constants ===
JELLYFIN_URL = os.getenv("JELLYFIN_URL")
API_KEY = os.getenv("API_KEY")
USER_ID = os.getenv("USER_ID")
app.secret_key = os.getenv("SECRET_KEY")
hashed_password = os.getenv("PASSWORD_HASH")

# === Security Configuration ===
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# === Security Headers ===
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# === Authentication Functions ===
def authenticate_user(password):
    if bcrypt.check_password_hash(hashed_password, password):
        token = jwt.encode({
            'password': password,
            'timestamp': datetime.datetime.utcnow().timestamp()
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return token
    return None

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        timestamp = payload['timestamp']
        if datetime.datetime.utcnow().timestamp() - timestamp > 300:  # 5 minutes
            return False
        return True
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return False

# === Decorator Functions ===
def check_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('user_token')
        if not token:
            flash('You must be logged in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))

        try:
            jwt.decode(token, app.secret_key, algorithms=['HS256'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            session.clear()
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            session.clear()
            flash('Invalid session. Please log in again.', 'error')
            return redirect(url_for('login'))
    return decorated_function

# === Jellyfin API Functions ===
def get_jellyfin_headers():
    return {
        'X-MediaBrowser-Token': API_KEY,
        'Content-Type': 'application/json'
    }

def get_movies():
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items/"
    params = {
        'IncludeItemTypes': 'Movie',
        'Recursive': 'true',
        'SortBy': 'SortName',
        'SortOrder': 'Ascending'
    }
    response = requests.get(url, headers=get_jellyfin_headers(), params=params)
    return response.json().get('Items', [])

def get_tv_shows():
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items"
    params = {
        'IncludeItemTypes': 'Series',
        'Recursive': 'true',
        'SortBy': 'SortName',
        'SortOrder': 'Ascending'
    }
    try:
        response = requests.get(url, headers=get_jellyfin_headers(), params=params)
        response.raise_for_status()
        return response.json().get('Items', [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching TV shows: {e}")
        return []

def get_latest_movies():
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items/Latest?IncludeItemTypes=Movie&Limit=6"
    headers = {'X-Emby-Token': API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        movies = response.json()
        return [{
            "title": movie['Name'],
            "poster_url": f"{JELLYFIN_URL}/Items/{movie['Id']}/Images/Primary?maxWidth=300"
        } for movie in movies]
    return []

def get_latest_tvshows():
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items/Latest?IncludeItemTypes=Series&Limit=6"
    headers = {'X-Emby-Token': API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        tvshows = response.json()
        return [{
            "title": tvshow['Name'],
            "poster_url": f"{JELLYFIN_URL}/Items/{tvshow['Id']}/Images/Primary?maxWidth=300"
        } for tvshow in tvshows]
    return []

# === Utility Functions ===
def sanitize_input(text):
    if not text:
        return ""
    cleaned = bleach.clean(text, tags=[], strip=True)
    return cleaned[:500]

# === Route Handlers ===

@app.route('/blacklist/<name>', methods=['POST'])
@check_token
def blacklist_movie(name):
    # Add to blacklist

    add_to_blacklist(name)

    # Delete the movie

    movie_id = get_movie_id_by_name(name)

    if movie_id:
        delete_movie_by_id(movie_id)

    return redirect(url_for('admin'))
@app.route('/', methods=["GET", "POST"])
def index():
    latest_movies = get_latest_movies()
    latest_tvshows = get_latest_tvshows()
    movies = get_top_10_movies()

    return render_template('index.html',latest_tvshows=latest_tvshows, latest_movies=latest_movies, movies=movies)

@app.route('/current_movies')
def current_movies():
    movies = get_movies()
    tv_shows = get_tv_shows()
    return render_template('jellyfin_guide.html', movies=movies, tv_shows=tv_shows)

@app.route('/all_movies')
def list_all_movies_with_index():
    movies = list_all_movies()
    return render_template('list_all_movies_with_index.html', movies=movies)

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    token = session.get('user_token')
    page = request.args.get('page', 1, type=int)
    request_data = get_current_account_requests(page)
    movies = list_all_diff_movies()

    if token:
        if verify_token(token):
            return render_template('index_Admin.html', movies=movies, request=request_data, page=page)
        else:
            # Session has expired, try to authenticate with the current password
            password = sanitize_input(request.form.get('password'))
            if password:
                new_token = authenticate_user(password)
                if new_token:
                    session['user_token'] = new_token
                    return render_template('index_Admin.html', movies=movies, request=request_data, page=page)
                else:
                    flash('Invalid password', 'error')
                    return redirect('/login')
            else:
                flash('Your session has expired. Please log in again.', 'error')
                return redirect('/login')
    else:
        password = sanitize_input(request.form.get('password'))
        if password:
            token = authenticate_user(password)
            if token:
                session['user_token'] = token
                return render_template('index_Admin.html', movies=movies, request=request_data, page=page)
            else:
                flash('Invalid password', 'error')
                return redirect('/login')
        else:
            return redirect('/login')

@app.route('/next-request/<int:page>')
@check_token
def next_request(page):
    return redirect(url_for('admin', page=page + 1))

# Route to navigate to the previous request
@app.route('/prev-request/<int:page>')
@check_token
def prev_request(page):
    return redirect(url_for('admin', page=max(page - 1, 1)))

@app.route('/approve/<int:request_id>', methods=['POST'])
@check_token
def approve_request(request_id):

    delete_account_request(request_id)

    return redirect(url_for('admin'))



@app.route('/delete/<int:movie_id>', methods=['GET', 'POST'])
@check_token
def delete_movie_id(movie_id):

    # Check if the movie with the given ID exists
    movie = get_movie_by_id(movie_id)
    if not movie:
        return redirect('/failure')

    # Delete the movie by ID
    delete_movie_by_id(movie_id)
    return redirect(url_for('admin'))

@app.route('/request-account', methods=['POST'])
@limiter.limit("3 per hour")  # Strict rate limit for account requests
def submit_account():
    try:
        username = sanitize_input(request.form.get('username'))
        contact = sanitize_input(request.form.get('contact'))
        description = sanitize_input(request.form.get('description'))

        if not all([username, contact, description]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            return jsonify({'success': False, 'message': 'Invalid username format'}), 400

        add_account_request(username, contact, description)
        return jsonify({'success': True, 'message': 'Account request submitted successfully'}), 200
    except Exception as e:
        app.logger.error(f"Error in submit_account: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500


@app.route('/failure')
def failure():
    return "?? Something Went wrong"


@app.route('/submit', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit submissions
def submit():
    if not request.form.get('Movie'):
        flash('No movie name provided', 'error')
        return redirect(url_for('index'))

    movie_name = sanitize_input(request.form.get('Movie'))
    if not movie_name:
        flash('Invalid movie name', 'error')
        return redirect(url_for('index'))

    # Store the original search query in case we need to display it
    original_query = movie_name

    # Parse movie name and year if provided
    requested_year = None
    if '(' in movie_name and ')' in movie_name:
        try:
            requested_year = movie_name[movie_name.rindex('(') + 1:movie_name.rindex(')')]
            if requested_year.isdigit() and len(requested_year) == 4:
                movie_name = movie_name[:movie_name.rindex('(')].strip()
            else:
                requested_year = None
        except ValueError:
            requested_year = None

    api_key = os.getenv('OMDB_API_KEY')
    if not api_key:
        flash('API key not configured', 'error')
        return redirect("/")

    search_url = f'http://www.omdbapi.com/?apikey={api_key}&s={movie_name}&type=movie'

    try:
        search_response = requests.get(search_url)
        search_response.raise_for_status()
        search_data = search_response.json()

        if search_data.get('Response') == 'True':
            movies = search_data['Search']

            # If there's only one version, add it directly
            if len(movies) == 1:
                movie_id = movies[0]['imdbID']
                detail_url = f'http://www.omdbapi.com/?apikey={api_key}&i={movie_id}'
                detail_response = requests.get(detail_url)
                movie_data = detail_response.json()

                if movie_data.get('Response') == 'True':
                    formatted_title = f"{movie_data['Title']} ({movie_data['Year'].split('–')[0]})"
                    if is_blacklisted(formatted_title):
                        flash(f'"{formatted_title}" is blacklisted and cannot be added', 'error')
                    else:
                        add_movie(formatted_title)
                        flash(f'Successfully added "{formatted_title}"', 'success')
                    return redirect("/")

            # For multiple versions, store them in session and redirect to selection page
            movie_versions = []
            for movie in movies:
                movie_id = movie['imdbID']
                detail_url = f'http://www.omdbapi.com/?apikey={api_key}&i={movie_id}'
                detail_response = requests.get(detail_url)
                movie_detail = detail_response.json()

                if movie_detail.get('Response') == 'True':
                    movie_versions.append({
                        'id': movie_id,
                        'title': movie_detail['Title'],
                        'year': movie_detail['Year'].split('–')[0],
                        'poster': movie_detail.get('Poster', 'N/A'),
                        'plot': movie_detail.get('Plot', 'No plot available'),
                        'director': movie_detail.get('Director', 'Unknown'),
                        'actors': movie_detail.get('Actors', 'Unknown')
                    })

            # Sort by year, most recent first
            movie_versions.sort(key=lambda x: x['year'], reverse=True)

            # Store in session and redirect to selection page
            session['movie_versions'] = movie_versions
            session['original_query'] = original_query
            return redirect(url_for('select_version'))
        else:
            flash(f'Movie "{movie_name}" not found. Check spelling?', 'error')

    except requests.RequestException as e:
        flash(f'Error checking movie: {str(e)}', 'error')

    return redirect("/")


@app.route('/select_version')
def select_version():
    movie_versions = session.get('movie_versions', [])
    original_query = session.get('original_query', '')
    if not movie_versions:
        flash('No movie versions found', 'error')
        return redirect('/')
    return render_template('select_version.html', movies=movie_versions, original_query=original_query)


@app.route('/add_version', methods=['POST'])
def add_version():
    movie_versions = session.get('movie_versions', [])
    selected_id = sanitize_input(request.form.get('movie_id'))

    selected_movie = next((movie for movie in movie_versions if movie['id'] == selected_id), None)

    if selected_movie:
        formatted_title = f"{selected_movie['title']} ({selected_movie['year']})"

        # Check if movie is blacklisted before adding
        if is_blacklisted(formatted_title):
            flash(f'"{formatted_title}" is blacklisted and cannot be added', 'error')
        else:
            add_movie(formatted_title)
            flash(f'Successfully added "{formatted_title}"', 'success')
    else:
        flash('Selected movie version not found', 'error')

    # Clear the session data
    session.pop('movie_versions', None)
    session.pop('original_query', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)


