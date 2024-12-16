# Jellyfin Request Handler

Jellyfin Request Handler is a simple website that enables users to request movies or TV shows for your Jellyfin server. It centralizes and organizes requests, making it easy to track and manage them.

## Features
- Submit movie or TV show requests to your Jellyfin server.
- Centralized location to track all user requests.
- Integrated with OMDB for movie data.
- Secure API and user access.

---

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd jellyfin-request-handler
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the `.env` file with the following variables:
   ```env
   JELLYFIN_URL=your-jellyfin-url
   API_KEY=your-api-key
   USER_ID=your-admin-user-id
   AGENT_NAME=your-agent-name
   SECRET_KEY=your-secret-key
   PASSWORD_HASH=your-password-hash
   OMDB_API_KEY=your-omdb-api-key
   ```
   ### Environment Variable Descriptions:
   - **JELLYFIN_URL**: The URL to your Jellyfin homepage (e.g., `jellyfin.example.com/`).
   - **API_KEY**: API key for your Jellyfin server.
   - **USER_ID**: Admin user ID to retrieve information from the Jellyfin server using the API.
   - **AGENT_NAME**: The agent name you choose for the API.
   - **SECRET_KEY**: A custom key to secure your website.
   - **PASSWORD_HASH**: A hashed password generated using bcrypt for user authentication.
   - **OMDB_API_KEY**: API key for OMDB to request movie and TV show data.

4. Generate your password hash using bcrypt:
   ```python
   from bcrypt import generate_password_hash
   print(generate_password_hash("your-password"))
   ```
   Copy and paste the generated hash into your `.env` file under `PASSWORD_HASH`.

5. Run the application:
   ```bash
   python app.py
   ```

---

## Usage

1. Open your browser and navigate to your website URL (e.g., `http://localhost:5000`).
2. Submit movie or TV show requests through the form.
3. Admins can review and manage submitted requests through the centralized interface.

---

## Technologies Used
- **Python**: Core programming language.
- **Flask**: Web framework for serving the website.
- **SQLite**: Database to store request information.
- **bcrypt**: Password hashing for secure user authentication.
- **OMDB API**: Fetch movie and TV show data.

---

## Contributing
Contributions are welcome! Feel free to fork the repository, make changes, and submit a pull request. Suggestions and improvements are highly appreciated.

---

## Contact
For questions, support, or feedback, feel free to reach out:
- Email: [contact@macery12.xyz](mailto:contact@macery12.xyz)

