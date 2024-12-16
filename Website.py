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

def get_movies(timeout=10):
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items/"
    params = {
        'IncludeItemTypes': 'Movie',
        'Recursive': 'true',
        'SortBy': 'SortName',
        'SortOrder': 'Ascending'
    }
    try:
        response = requests.get(url, headers=get_jellyfin_headers(), params=params, timeout=timeout)
        response.raise_for_status()
        return response.json().get('Items', [])
    except requests.Timeout:
        print(f"Request timed out after {timeout} seconds while fetching movies")
        return []
    except requests.RequestException as e:
        print(f"Error fetching movies: {e}")
        return []

def get_tv_shows(timeout=10):
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items"
    params = {
        'IncludeItemTypes': 'Series',
        'Recursive': 'true',
        'SortBy': 'SortName',
        'SortOrder': 'Ascending'
    }
    try:
        response = requests.get(url, headers=get_jellyfin_headers(), params=params, timeout=timeout)
        response.raise_for_status()
        return response.json().get('Items', [])
    except requests.Timeout:
        print(f"Request timed out after {timeout} seconds while fetching TV shows")
        return []
    except requests.RequestException as e:
        print(f"Error fetching TV shows: {e}")
        return []

def get_latest_movies(timeout=10):
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items/Latest?IncludeItemTypes=Movie&Limit=6"
    headers = {'X-Emby-Token': API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        movies = response.json()
        return [{
            "title": movie['Name'],
            "poster_url": f"{JELLYFIN_URL}/Items/{movie['Id']}/Images/Primary?maxWidth=300"
        } for movie in movies]
    except requests.Timeout:
        print(f"Request timed out after {timeout} seconds while fetching latest movies")
        return []
    except requests.RequestException as e:
        print(f"Error fetching latest movies: {e}")
        return []

def get_latest_tvshows(timeout=10):
    url = f"{JELLYFIN_URL}/Users/{USER_ID}/Items/Latest?IncludeItemTypes=Series&Limit=6"
    headers = {'X-Emby-Token': API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        tvshows = response.json()
        return [{
            "title": tvshow['Name'],
            "poster_url": f"{JELLYFIN_URL}/Items/{tvshow['Id']}/Images/Primary?maxWidth=300"
        } for tvshow in tvshows]
    except requests.Timeout:
        print(f"Request timed out after {timeout} seconds while fetching latest TV shows")
        return []
    except requests.RequestException as e:
        print(f"Error fetching latest TV shows: {e}")
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
    if not request.form.get('media_title'):
        flash('No title provided', 'error')
        return redirect(url_for('index'))

    media_title = request.form.get('media_title')
    media_type = request.form.get('media_type')  # Default to movie if not specified
    print(media_title, media_type)
    if not media_title:
        flash('Invalid title', 'error')
        return redirect(url_for('index'))

    # Store the original search query
    original_query = media_title

    # Parse title and year if provided
    requested_year = None
    if '(' in media_title and ')' in media_title:
        try:
            requested_year = media_title[media_title.rindex('(') + 1:media_title.rindex(')')]
            if requested_year.isdigit() and len(requested_year) == 4:
                media_title = media_title[:media_title.rindex('(')].strip()
            else:
                requested_year = None
        except ValueError:
            requested_year = None

    api_key = os.getenv('OMDB_API_KEY')
    if not api_key:
        flash('API key not configured', 'error')
        return redirect("/")

    # Include type in search query
    search_url = f'http://www.omdbapi.com/?apikey={api_key}&s={media_title}&type={media_type}'

    try:
        search_response = requests.get(search_url)
        search_response.raise_for_status()
        search_data = search_response.json()

        if search_data.get('Response') == 'True':
            results = search_data['Search']

            # If there's only one version, add it directly
            if len(results) == 1:
                media_id = results[0]['imdbID']
                detail_url = f'http://www.omdbapi.com/?apikey={api_key}&i={media_id}'
                detail_response = requests.get(detail_url)
                media_data = detail_response.json()

                if media_data.get('Response') == 'True':
                    # Handle different year formats for movies vs TV shows
                    year = media_data['Year'].split('–')[0] if '–' in media_data['Year'] else media_data['Year']
                    formatted_title = f"{media_data['Title']} ({year})"

                    if is_blacklisted(formatted_title):
                        flash(f'"{formatted_title}" is blacklisted and cannot be added', 'error')
                    else:
                        if media_type == 'series':
                            add_movie(formatted_title)  # You'll need to create this function
                            flash(f'Successfully added TV show "{formatted_title}"', 'success')
                        else:
                            add_movie(formatted_title)
                            flash(f'Successfully added movie "{formatted_title}"', 'success')
                    return redirect("/")

            # For multiple versions, store them in session and redirect to selection page
            media_versions = []
            for item in results:
                media_id = item['imdbID']
                detail_url = f'http://www.omdbapi.com/?apikey={api_key}&i={media_id}'
                detail_response = requests.get(detail_url)
                media_detail = detail_response.json()

                if media_detail.get('Response') == 'True':
                    # Handle different year formats
                    year = media_detail['Year'].split('–')[0] if '–' in media_detail['Year'] else media_detail['Year']

                    media_versions.append({
                        'id': media_id,
                        'title': media_detail['Title'],
                        'year': year,
                        'poster': media_detail.get('Poster', 'N/A'),
                        'plot': media_detail.get('Plot', 'No plot available'),
                        'director': media_detail.get('Director', 'Unknown'),
                        'actors': media_detail.get('Actors', 'Unknown'),
                        'type': media_detail.get('Type', media_type),
                        'total_seasons': media_detail.get('totalSeasons', 'N/A') if media_type == 'series' else None
                    })

            # Sort by year, most recent first
            media_versions.sort(key=lambda x: x['year'], reverse=True)
            print(media_versions)
            # Store in session and redirect to selection page
            session['media_versions'] = media_versions
            session['original_query'] = original_query
            session['media_type'] = media_type
            return redirect(url_for('select_version'))
        else:
            media_type_str = 'TV show' if media_type == 'series' else 'movie'
            flash(f'{media_type_str} "{media_title}" not found. Check spelling?', 'error')

    except requests.RequestException as e:
        flash(f'Error checking media: {str(e)}', 'error')

    return redirect("/")


@app.route('/select_version')
def select_version():
    movie_versions = session.get('media_versions', [])
    original_query = session.get('original_query', '')
    if not movie_versions:
        flash('No movie versions found', 'error')
        return redirect('/')
    return render_template('select_version.html', movies=movie_versions, original_query=original_query)


@app.route('/add_version', methods=['POST'])
def add_version():
    movie_versions = session.get('media_versions', [])
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
    session.pop('media_versions', None)
    session.pop('original_query', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)


