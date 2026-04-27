"""
Photo Slideshow App - Enhanced Version
A feature-rich Flask application for creating photo slideshows with background audio
"""

from flask import Flask, render_template, flash, redirect, url_for, request, session, jsonify
import bcrypt
import mysql.connector
from mysql.connector import Error
import jwt
import time
import base64
from functools import wraps

# Configuration
app = Flask(__name__)
app.secret_key = "!@#$%^adsfmnv"
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

salt_hash = bcrypt.gensalt()

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_db_connection():
    """Create and return a new database connection"""
    try:
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="Alamanda@15",
            database="ISIS_DB"
        )
    except Error as e:
        print(f"Database connection error: {e}")
        return None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def allowed_image(filename):
    """Check if file has an allowed image extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('jwt_token')
        if not token:
            flash('Please log in first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_jwt_token(username):
    """Generate JWT token for user session"""
    payload = {'username': username}
    secret_key = '@#23$%^'
    expiration_time = 36000  # 10 hours
    token = jwt.encode(
        {'exp': time.time() + expiration_time, **payload},
        secret_key,
        algorithm='HS256'
    )
    session['jwt_token'] = token
    session['user_details'] = {'username': username}
    return {'username': username, 'token': token}

def verify_jwt_token(token):
    """Verify JWT token validity"""
    secret_key = '@#23$%^'
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def find_user_details(user_id):
    """Find user details from database"""
    db = get_db_connection()
    if not db:
        return None
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM accounts WHERE username = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return {
                'username': user_data[1],
                'email': user_data[2],
                'password': user_data[3]
            }
    except Error as e:
        print(f"Database error: {e}")
    finally:
        cursor.close()
        db.close()
    return None

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/', methods=['GET', 'POST'])
@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    """Welcome page after login"""
    token = session.get('jwt_token')
    if not token:
        return redirect(url_for('login'))
    
    payload = verify_jwt_token(token)
    if payload:
        username = payload['username']
        user_data = find_user_details(username)
        return render_template('confirmation.html', data=user_data, token=token)
    else:
        session.pop('jwt_token', None)
        return render_template('login.html', err="Session expired. Please log in again.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    token = session.get('jwt_token')
    if token:
        return redirect(url_for('welcome'))
    
    if request.method == 'POST':
        username = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        
        # Validate input
        if not username or not password:
            return render_template('login.html', err="Username and password are required")
        
        db = get_db_connection()
        if not db:
            flash('Database connection error. Please try again.', 'error')
            return render_template('login.html')
        
        try:
            cursor = db.cursor()
            # Using parameterized query to prevent SQL injection
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            data = cursor.fetchone()
            
            if data and bcrypt.checkpw(password.encode(), data[2].encode()):
                generate_jwt_token(username)
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('welcome'))
            else:
                return render_template('login.html', err="Invalid username or password")
        except Error as e:
            print(f"Login error: {e}")
            return render_template('login.html', err="An error occurred. Please try again.")
        finally:
            cursor.close()
            db.close()
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration page"""
    token = session.get('jwt_token')
    if token:
        return redirect(url_for('welcome'))
    
    if request.method == 'POST':
        username = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('Signup.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return render_template('Signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('Signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('Signup.html')
        
        db = get_db_connection()
        if not db:
            flash('Database connection error', 'error')
            return render_template('Signup.html')
        
        try:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                flash('Username already exists. Choose a different one.', 'error')
                return render_template('Signup.html')
            
            hash_password = bcrypt.hashpw(password.encode(), salt_hash)
            cursor.execute(
                "INSERT INTO accounts (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hash_password)
            )
            db.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        
        except Error as e:
            print(f"Signup error: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('Signup.html')
        finally:
            cursor.close()
            db.close()
    
    return render_template('Signup.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """User logout"""
    session.pop('jwt_token', None)
    session.pop('user_details', None)
    session.pop('selected_image_ids', None)
    session.pop('selected_audio', None)
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

# ============================================================================
# MAIN APP ROUTES
# ============================================================================

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    """Home page - upload and manage images"""
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Handle image uploads"""
    if request.method == 'POST':
        username = session['user_details']['username']
        files = request.files.getlist('files[]')
        
        if not files or files[0].filename == '':
            flash('No files selected', 'error')
            return redirect(url_for('home'))
        
        db = get_db_connection()
        if not db:
            flash('Database connection error', 'error')
            return redirect(url_for('home'))
        
        try:
            cursor = db.cursor()
            uploaded_count = 0
            
            for file in files:
                if file and allowed_image(file.filename):
                    img_data = file.read()
                    
                    # Check file size (50MB limit)
                    if len(img_data) > 50 * 1024 * 1024:
                        flash(f'File {file.filename} is too large (max 50MB)', 'warning')
                        continue
                    
                    query = "INSERT INTO images (username, image, timestamp) VALUES (%s, %s, %s)"
                    cursor.execute(query, (username, img_data, time.time()))
                    uploaded_count += 1
            
            db.commit()
            if uploaded_count > 0:
                flash(f'✓ {uploaded_count} image(s) uploaded successfully!', 'success')
            else:
                flash('No valid images to upload (PNG, JPG, GIF, WEBP only)', 'error')
        
        except Error as e:
            print(f"Upload error: {e}")
            flash('Error uploading images', 'error')
        finally:
            cursor.close()
            db.close()
        
        return redirect(url_for('home'))
    
    return render_template('home.html')

@app.route('/preview', methods=['GET', 'POST'])
@login_required
def preview():
    """Preview and play slideshow"""
    audio_choice = session.get('selected_audio', 'chipichipi.mp3')
    return render_template('preview.html', audio_choice=audio_choice)

@app.route('/play_slideshow', methods=['POST'])
@login_required
def play_slideshow():
    """Prepare slideshow with selected images and audio"""
    selected_ids = request.form.getlist('selected_images[]')
    audio_choice = request.form.get('audio_choice', 'chipichipi.mp3')
    
    if not selected_ids:
        flash('Please select at least one image', 'error')
        return redirect(url_for('home'))
    
    session['selected_image_ids'] = selected_ids
    session['selected_audio'] = audio_choice
    
    return redirect(url_for('preview'))

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/get_images')
@login_required
def get_images():
    """Get all uploaded images for current user"""
    username = session['user_details']['username']
    db = get_db_connection()
    if not db:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, image FROM images WHERE username = %s ORDER BY timestamp DESC",
            (username,)
        )
        images = cursor.fetchall()
        
        image_list = []
        for img_id, img_data in images:
            img_base64 = base64.b64encode(img_data).decode('utf-8')
            image_list.append({
                'id': img_id,
                'data': f'data:image/jpeg;base64,{img_base64}'
            })
        
        return jsonify({'images': image_list})
    except Error as e:
        print(f"Get images error: {e}")
        return jsonify({'error': 'Error retrieving images'}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/get_selected_images')
@login_required
def get_selected_images():
    """Get selected images in specified order"""
    selected_ids = session.get('selected_image_ids', [])
    
    if not selected_ids:
        return jsonify({'images': []})
    
    username = session['user_details']['username']
    db = get_db_connection()
    if not db:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = db.cursor()
        # Convert and validate selected_ids
        selected_ids = [int(id) for id in selected_ids if str(id).isdigit()]
        
        if not selected_ids:
            return jsonify({'images': []})
        
        # Build dynamic query with proper parameterization
        placeholders = ','.join(['%s'] * len(selected_ids))
        query = f"SELECT id, image FROM images WHERE username = %s AND id IN ({placeholders})"
        cursor.execute(query, [username] + selected_ids)
        
        images = cursor.fetchall()
        
        # Create dictionary and maintain selection order
        image_dict = {}
        for img_id, img_data in images:
            img_base64 = base64.b64encode(img_data).decode('utf-8')
            image_dict[img_id] = {
                'id': img_id,
                'data': f'data:image/jpeg;base64,{img_base64}'
            }
        
        # Reorder according to selected_ids
        image_list = [image_dict[id] for id in selected_ids if id in image_dict]
        
        return jsonify({'images': image_list})
    except Error as e:
        print(f"Get selected images error: {e}")
        return jsonify({'error': 'Error retrieving images'}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/delete_image/<int:image_id>', methods=['POST', 'DELETE'])
@login_required
def delete_image(image_id):
    """Delete an image"""
    username = session['user_details']['username']
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute(
            "DELETE FROM images WHERE id = %s AND username = %s",
            (image_id, username)
        )
        db.commit()
        
        if cursor.rowcount > 0:
            return jsonify({'success': True, 'message': 'Image deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Image not found'}), 404
    except Error as e:
        print(f"Delete error: {e}")
        return jsonify({'success': False, 'message': 'Error deleting image'}), 500
    finally:
        cursor.close()
        db.close()

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    flash('File is too large. Maximum size is 50MB', 'error')
    return redirect(url_for('home')), 413

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    flash('Page not found', 'error')
    return redirect(url_for('login')), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    print(f"Internal error: {error}")
    flash('An internal server error occurred', 'error')
    return redirect(url_for('login')), 500

# ============================================================================
# RUN APP
# ============================================================================

if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)
