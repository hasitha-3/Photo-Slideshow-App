from flask import Flask, render_template, flash, redirect, url_for, request, session, jsonify
import bcrypt
import mysql.connector
from mysql.connector import Error
import jwt
import time
import base64
import os
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "!@#$%^adsfmnv"
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_AUDIO = {'mp3', 'wav', 'ogg'}

salt_hash = bcrypt.gensalt()

def get_db_connection():
    """Create a new database connection"""
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

def allowed_image(filename):
    """Check if file is allowed image"""
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

# Update the generate_jwt_token function
def generate_jwt_token(username):
    payload = {'username': username}
    secret_key = '@#23$%^'
    expiration_time = 36000  # Set your desired expiration time in seconds
    token = jwt.encode({'exp': time.time() + expiration_time, **payload}, secret_key, algorithm='HS256')

    # Store token and user details in the session
    session['jwt_token'] = token
    session['user_details'] = {'username': username}

    return {'username': username, 'token': token}

def verify_jwt_token(token):
    secret_key = '@#23$%^'  # Replace with the same key used for encoding
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
    
# Add a protected route that requires a valid JWT token
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
            return {'username': user_data[1], 'email': user_data[2], 'password': user_data[3]}
    except Error as e:
        print(f"Database error: {e}")
    finally:
        cursor.close()
        db.close()
    return None

@app.route('/', methods=['GET', 'POST'])
@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    token = session.get('jwt_token')
    if not token:
        return redirect(url_for('login'))
    user_data = None
    if token:
        payload = verify_jwt_token(token)
        if payload:
            # Token is valid, get user details from payload
            username = payload['username']
            user_data = find_user_details(username)
        else :
            return render_template('login.html')
    else :
        return render_template('login.html')
    return render_template('confirmation.html', data=user_data, token=token)


@app.route('/home', methods=['GET', 'POST'])
def home():
    token = session.get('jwt_token')
    if not token:
        return redirect(url_for('login'))
    return render_template('home.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    token = session.get('jwt_token')
    if not token:
        return redirect(url_for('login'))

    username = session['user_details']['username']
    if username != 'admin':
        return redirect(url_for('home'))

    cursor.execute("SELECT * FROM accounts")
    data = cursor.fetchall()
    print(data)
    return render_template('admin.html', accounts=data)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
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
                    img = file.read()
                    if len(img) > 50 * 1024 * 1024:  # 50MB limit
                        flash(f'File {file.filename} is too large (max 50MB)', 'error')
                        continue
                    
                    query = "INSERT INTO images (username, image, timestamp) VALUES (%s, %s, %s)"
                    cursor.execute(query, (username, img, time.time()))
                    uploaded_count += 1
            
            db.commit()
            if uploaded_count > 0:
                flash(f'{uploaded_count} image(s) uploaded successfully', 'success')
            else:
                flash('No valid images to upload', 'error')
        
        except Error as e:
            print(f"Upload error: {e}")
            flash('Error uploading images', 'error')
        finally:
            cursor.close()
            db.close()
        
        return redirect(url_for('home'))
    
    return render_template('home.html')

@app.route('/play_slideshow', methods=['POST'])
@login_required
def play_slideshow():
    selected_ids = request.form.getlist('selected_images[]')
    audio_choice = request.form.get('audio_choice', 'chipichipi.mp3')
    
    if not selected_ids:
        flash('Please select at least one image', 'error')
        return redirect(url_for('home'))
    
    session['selected_image_ids'] = selected_ids
    session['selected_audio'] = audio_choice
    
    return redirect(url_for('preview'))

@app.route('/preview', methods=['GET', 'POST'])
@login_required
def preview():
    audio_choice = session.get('selected_audio', 'chipichipi.mp3')
    return render_template('preview.html', audio_choice=audio_choice)

@app.route('/get_images')
@login_required
def get_images():
    username = session['user_details']['username']
    db = get_db_connection()
    if not db:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT id, image FROM images WHERE username = %s ORDER BY timestamp DESC", (username,))
        images = cursor.fetchall()
        
        image_list = []
        for img_id, img_data in images:
            img_base64 = base64.b64encode(img_data).decode('utf-8')
            image_list.append({'id': img_id, 'data': f'data:image/jpeg;base64,{img_base64}'})
        
        return jsonify({'images': image_list})
    except Error as e:
        print(f"Get images error: {e}")
        return jsonify({'error': 'Error retrieving images'}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/get_selected_images')
def get_selected_images():
    token = session.get('jwt_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    
    selected_ids = session.get('selected_image_ids', [])
    
    if not selected_ids:
        return jsonify({'images': []})
    
    username = session['user_details']['username']
    
    # Convert selected_ids to integers for comparison
    selected_ids = [int(id) for id in selected_ids if id.isdigit()]
    
    cursor.execute("SELECT id, image FROM images WHERE username = %s AND id IN ({})".format(
        ','.join(['%s'] * len(selected_ids))
    ), [username] + selected_ids)
    
    images = cursor.fetchall()
    
    # Sort images in the same order as selected_ids
    image_dict = {}
    for img_id, img_data in images:
        img_base64 = base64.b64encode(img_data).decode('utf-8')
        image_dict[img_id] = {'id': img_id, 'data': f'data:image/jpeg;base64,{img_base64}'}
    
    # Reorder according to selected_ids
    image_list = [image_dict[id] for id in selected_ids if id in image_dict]
    
    return jsonify({'images': image_list})

@app.route('/login', methods=['GET', 'POST'])
def login():
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
            return render_template('login.html', err="Database connection error")
        
        try:
            cursor = db.cursor()
            query = 'SELECT * FROM accounts WHERE username = %s'
            cursor.execute(query, (username,))
            data = cursor.fetchone()
            
            if data and bcrypt.checkpw(password.encode(), data[2].encode()):
                token = generate_jwt_token(username)
                session['user_details'] = {'username': username}
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
    token = session.get('jwt_token')
    if token:
        return redirect(url_for('welcome'))
    
    if request.method == 'POST':
        username = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate input
        if not username or not email or not password:
            return render_template('Signup.html', msg="All fields are required")
        
        if len(username) < 3:
            return render_template('Signup.html', msg="Username must be at least 3 characters")
        
        if len(password) < 6:
            return render_template('Signup.html', msg="Password must be at least 6 characters")
        
        if password != confirm_password:
            return render_template('Signup.html', msg="Passwords do not match")
        
        db = get_db_connection()
        if not db:
            return render_template('Signup.html', msg="Database connection error")
        
        try:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                return render_template('Signup.html', msg="Username already exists. Choose a different one.")
            
            hash_password = bcrypt.hashpw(password.encode(), salt_hash)
            cursor.execute("INSERT INTO accounts (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, hash_password))
            db.commit()
            
            cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
            data1 = cursor.fetchone()
            user_data = {'username': data1[1], 'email': data1[2], 'password': data1[3]}

            # Generate JWT token for the user information
            token = generate_jwt_token(username)
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Error as e:
            print(f"Signup error: {e}")
            return render_template('Signup.html', msg="An error occurred. Please try again.")
        finally:
            cursor.close()
            db.close()
    
    return render_template('Signup.html')

# @app.route('/', methods=['GET', 'POST'])


# @app.route('/', methods=['GET', 'POST'])


@app.route('/delete_image/<int:image_id>', methods=['POST'])
@login_required
def delete_image(image_id):
    username = session['user_details']['username']
    db = get_db_connection()
    if not db:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM images WHERE id = %s AND username = %s", (image_id, username))
        db.commit()
        
        if cursor.rowcount > 0:
            return jsonify({'success': True, 'message': 'Image deleted'})
        else:
            return jsonify({'error': 'Image not found'}), 404
    except Error as e:
        print(f"Delete error: {e}")
        return jsonify({'error': 'Error deleting image'}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('jwt_token', None)
    session.pop('user_details', None)
    session.pop('selected_image_ids', None)
    session.pop('selected_audio', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File is too large. Maximum size is 50MB', 'error')
    return redirect(url_for('home')), 413

@app.errorhandler(500)
def internal_error(error):
    print(f"Internal error: {error}")
    flash('An internal server error occurred', 'error')
    return redirect(url_for('home')), 500

if __name__ == "__main__":
    app.run(debug=True)
