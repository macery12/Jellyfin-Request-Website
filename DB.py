import sqlite3
import logging
from os.path import exists

# Configure logging to output to a log.txt file
logging.basicConfig(
    filename="log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Function to log messages
def log_message(message):
    logging.info(message)

# Function to open the database connection
def open_db():
    conn = sqlite3.connect('movies.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS movies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
    )
    ''')
    conn.commit()
    return conn, cursor

def open_account_db():
    account_conn = sqlite3.connect('accounts.db')
    account_cursor = account_conn.cursor()
    account_cursor.execute('''
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    contact TEXT NOT NULL,
                    description TEXT NOT NULL
                )
            ''')
    account_conn.commit()
    return account_conn, account_cursor

def add_account_request(username, contact, description):
    account_conn, account_cursor = open_account_db()
    account_cursor.execute('''INSERT INTO requests (username, contact, description) VALUES (?, ?, ?)''', (username, contact, description))
    account_conn.commit()
    account_conn.close()
    log_message('account request Added')
    return

def get_current_account_requests(page):
    account_conn, account_cursor = open_account_db()
    offset = (page - 1) * 1  # Only 1 request per page
    limit = 1
    account_cursor.execute('''SELECT * FROM requests LIMIT ? OFFSET ?''', (limit, offset))
    request_data = account_cursor.fetchone()
    account_conn.close()
    return request_data

def delete_account_request(request_id):
    account_conn, account_cursor = open_account_db()
    account_cursor.execute('DELETE FROM requests WHERE id = ?', (request_id,))
    account_conn.commit()
    account_conn.close()
    return 

def list_all_diff_movies():
    conn, cursor = open_db()
    cursor.execute("SELECT id, name FROM movies ORDER BY id ASC")
    movies = cursor.fetchall()
    conn.close()
    return movies

# Function to add a movie
def add_movie(name):
    if not name:  # Check if name is empty or None
        log_message("Error: Movie name cannot be empty.")
        return

    try:
        conn, cursor = open_db()
        cursor.execute('''INSERT INTO movies (name) VALUES (?)''', (name,))
        conn.commit()
        log_message(f"Movie '{name}' added successfully.")
    except sqlite3.Error as e:
        log_message(f"Error adding movie '{name}': {e}")
    finally:
        conn.close()
        reorder_movies()

# Function to retrieve all movies
def list_all_movies():
    try:
        conn, cursor = open_db()
        cursor.execute('SELECT name FROM movies')
        movies = [row[0] for row in cursor.fetchall()]
        conn.close()

        if not movies:
            log_message("No movies found in the database.")
            return []

        log_message(f"Retrieved all movies")
        return movies
    except sqlite3.Error as e:
        log_message(f"Error retrieving movies: {e}")
        return []

# Function to retrieve the top 10 movies
def get_top_10_movies(limit=10):
    try:
        conn, cursor = open_db()
        cursor.execute('SELECT name FROM movies LIMIT ?', (limit,))
        movies = [row[0] for row in cursor.fetchall()]
        conn.close()

        if not movies:
            log_message("No movies found in the top list or list is empty.")
            return []


        return movies
    except sqlite3.Error as e:
        log_message(f"Error retrieving top movies: {e}")
        return []




def get_movie_by_id(movie_id):
    """
    Retrieves a movie by its ID.

    Args:
        movie_id (int): The ID of the movie to retrieve.

    Returns:
        The movie name if found, or None if not found.
    """
    try:
        conn, cursor = open_db()
        cursor.execute('SELECT name FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        conn.close()
        return movie[0] if movie else None
    except sqlite3.Error as e:
        log_message(f"Error retrieving movie by ID {movie_id}: {e}")
        return None


def delete_movie_by_id(movie_id):
    """
    Deletes a movie from the database based on its ID.

    Args:
        movie_id (int): The ID of the movie to be deleted.
    """
    try:
        conn, cursor = open_db()

        # Attempt to delete the movie with the given ID
        cursor.execute('DELETE FROM movies WHERE id = ?', (movie_id,))
        conn.commit()

        if cursor.rowcount > 0:
            log_message(f"Movie with ID {movie_id} deleted successfully.")
        else:
            log_message(f"No movie found with ID {movie_id}.")
    except sqlite3.Error as e:
        log_message(f"Error deleting movie with ID {movie_id}: {e}")
    finally:
        conn.close()


def get_movie_id_by_name(name):
    """
    Retrieves a movie's ID based on its name.

    Args:
        name (str): The exact name of the movie to search for

    Returns:
        int: The movie ID if found, None if not found
    """
    try:
        conn, cursor = open_db()
        cursor.execute('SELECT id FROM movies WHERE name = ?', (name,))
        result = cursor.fetchone()

        if result:
            return result[0]
        else:
            log_message(f"No movie found with name: {name}")
            return None

    except sqlite3.Error as e:
        log_message(f"Error retrieving movie ID for '{name}': {e}")
        return None
    finally:
        conn.close()

def reorder_movies():
    """
    Reorders the movies in the database so that their IDs are sequential (1, 2, 3, etc.)
    based on the order of the current IDs.
    """
    try:
        conn, cursor = open_db()

        # Retrieve all movies ordered by their current IDs
        cursor.execute('SELECT id, name FROM movies ORDER BY id')
        movies = cursor.fetchall()

        # If no movies are found, log and return
        if not movies:
            log_message("No movies found to reorder.")
            return

        # Clear the table to reset IDs
        cursor.execute('DELETE FROM movies')
        conn.commit()

        # Reinsert the movies with sequential IDs
        for new_id, (_, name) in enumerate(movies, start=1):
            cursor.execute('INSERT INTO movies (id, name) VALUES (?, ?)', (new_id, name))
        conn.commit()

        log_message("Movies reordered successfully.")
    except sqlite3.Error as e:
        log_message(f"Error reordering movies: {e}")
    finally:
        conn.close()


def open_blacklist_db():
    """
    Opens a connection to the blacklist database and creates the table if it doesn't exist.
    """
    blacklist_conn = sqlite3.connect('blacklist.db')
    blacklist_cursor = blacklist_conn.cursor()
    blacklist_cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    blacklist_conn.commit()
    return blacklist_conn, blacklist_cursor


def add_to_blacklist(name):
    """
    Adds a name to the blacklist.

    Args:
        name (str): The name to add to the blacklist

    Returns:
        bool: True if successful, False if the name already exists or there's an error
    """
    if not name:
        logging.info("Error: Name cannot be empty.")
        return False

    try:
        conn, cursor = open_blacklist_db()
        cursor.execute('INSERT INTO blacklist (name) VALUES (?)', (name,))
        conn.commit()
        logging.info(f"Name '{name}' added to blacklist successfully.")
        return True
    except sqlite3.IntegrityError:
        logging.info(f"Name '{name}' already exists in blacklist.")
        return False
    except sqlite3.Error as e:
        logging.info(f"Error adding name to blacklist: {e}")
        return False
    finally:
        conn.close()


def is_blacklisted(name):
    """
    Checks if a name exists in the blacklist.

    Args:
        name (str): The name to check

    Returns:
        bool: True if the name is blacklisted, False otherwise
    """
    try:
        conn, cursor = open_blacklist_db()
        cursor.execute('SELECT EXISTS(SELECT 1 FROM blacklist WHERE name = ? LIMIT 1)', (name,))
        exists = cursor.fetchone()[0]
        return bool(exists)

    except sqlite3.Error as e:
        logging.info(f"Error checking blacklist: {e}")
        return False
    finally:
        conn.close()


def remove_from_blacklist(name):
    """
    Removes a name from the blacklist.

    Args:
        name (str): The name to remove from the blacklist

    Returns:
        bool: True if successful, False if the name doesn't exist or there's an error
    """
    try:
        conn, cursor = open_blacklist_db()
        cursor.execute('DELETE FROM blacklist WHERE name = ?', (name,))
        conn.commit()
        if cursor.rowcount > 0:
            logging.info(f"Name '{name}' removed from blacklist successfully.")
            return True
        else:
            logging.info(f"Name '{name}' not found in blacklist.")
            return False
    except sqlite3.Error as e:
        logging.info(f"Error removing name from blacklist: {e}")
        return False
    finally:
        conn.close()


def list_blacklist():
    """
    Returns all names in the blacklist.

    Returns:
        list: List of tuples containing (id, name, date_added)
    """
    try:
        conn, cursor = open_blacklist_db()
        cursor.execute('SELECT * FROM blacklist ORDER BY date_added DESC')
        return cursor.fetchall()
    except sqlite3.Error as e:
        logging.info(f"Error retrieving blacklist: {e}")
        return []
    finally:
        conn.close()