from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import io
from datetime import datetime
from flask_socketio import SocketIO

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SECRET_KEY'] = 'YourSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
socketio = SocketIO(app)

db = SQLAlchemy(app)

conversation_participants = db.Table('conversation_participants',
    db.Column('conversation_id', db.Integer, db.ForeignKey('conversation.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# Define models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    sent_files = db.relationship('FileTransfer', foreign_keys='FileTransfer.sender_id', cascade="all, delete-orphan", backref='sender_user', lazy='dynamic')
    received_files = db.relationship('FileTransfer', foreign_keys='FileTransfer.recipient_id', cascade="all, delete-orphan", backref='recipient_user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
# Define Conversation and Message models correctly
class Conversation(db.Model):
    __tablename__ = 'conversation'
    id = db.Column(db.Integer, primary_key=True)
    participants = db.relationship('User', secondary=conversation_participants, backref=db.backref('conversations', lazy='dynamic'))
    messages = db.relationship('Message', backref='conversation', lazy='dynamic')

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(1000))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

@app.route('/messages')
def messages():
    if 'user_id' not in session:
        flash("Please log in to view messages.")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('messages.html', conversations=user.conversations)

@app.route('/conversation/<int:conversation_id>')
def conversation(conversation_id):
    if 'user_id' not in session:
        flash("Please log in to view this conversation.")
        return redirect(url_for('login'))
    
    conversation = Conversation.query.get(conversation_id)
    if not conversation:
        flash("Conversation not found.")
        return redirect(url_for('messages'))
    
    # Sort messages by timestamp
    messages = sorted(conversation.messages, key=lambda x: x.timestamp)
    return render_template('conversation.html', conversation=conversation, messages=messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        flash("Please log in to send messages.")
        return redirect(url_for('login'))

    recipient_username = request.form['recipient']
    message_text = request.form['message']
    sender_id = session['user_id']
    recipient = User.query.filter_by(username=recipient_username).first()

    if not recipient:
        flash("Recipient not found.")
        return redirect(url_for('messages'))

    # Check if conversation already exists
    conversation = Conversation.query.filter(
        Conversation.participants.any(id=sender_id),
        Conversation.participants.any(id=recipient.id)
    ).first()

    if not conversation:
        # Create new conversation if it does not exist
        conversation = Conversation(participants=[User.query.get(sender_id), recipient])
        db.session.add(conversation)

    # Add new message to the conversation
    new_message = Message(body=message_text, sender_id=sender_id, conversation=conversation)
    db.session.add(new_message)
    db.session.commit()

    flash("Message sent successfully.")
    return redirect(url_for('conversation', conversation_id=conversation.id))

@app.route('/send_message_to_conversation/<int:conversation_id>', methods=['POST'])
def send_message_to_conversation(conversation_id):
    if 'user_id' not in session:
        flash("Please log in to send messages.")
        return redirect(url_for('login'))

    # Fetch the conversation
    conversation = db.session.get(Conversation, conversation_id)
    if not conversation:
        flash("Conversation not found.")
        return redirect(url_for('messages'))

    # Add the new message to the conversation
    new_message = Message(
        body=request.form['message'],
        sender_id=session['user_id'],
        conversation_id=conversation_id
    )
    db.session.add(new_message)
    db.session.commit()
    flash("Message sent.")
    return redirect(url_for('conversation', conversation_id=conversation_id))

class FileTransfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    encryption_key = db.Column(db.String(200), nullable=False)

# Generate a new encryption key
def generate_encryption_key():
    return Fernet.generate_key().decode('utf-8')

# Encrypt file data
def encrypt_file(file_data, encryption_key):
    fernet = Fernet(encryption_key.encode('utf-8'))
    encrypted_data = fernet.encrypt(file_data)
    return encrypted_data

# Decrypt file data
def decrypt_file(encrypted_data, encryption_key):
    fernet = Fernet(encryption_key.encode('utf-8'))
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    sent_files = user.sent_files.all()
    received_files = user.received_files.all()
    return render_template('dashboard.html', sent_files=sent_files, received_files=received_files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('This username is already taken. Please choose another one.')
            return redirect(url_for('register'))

        # If username is not taken, proceed to create a new user
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Login Failed')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # Clearing all data from the session
    flash('You have successfully logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/update_username', methods=['POST'])
def update_username():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    new_username = request.form['new_username']
    user = User.query.get(session['user_id'])
    if user:
        user.username = new_username
        db.session.commit()
        flash('Username updated successfully.')
    return redirect(url_for('settings'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user:
        db.session.delete(user)
        db.session.commit()
        session.pop('user_id', None)
        flash('Account deleted successfully.')
        return redirect(url_for('register'))
    return redirect(url_for('settings'))

# Define a route example
@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        flash("Please log in to delete files.")
        return redirect(url_for('login'))
    file = FileTransfer.query.get(file_id)
    if file and file.recipient_id == session['user_id']:
        db.session.delete(file)
        db.session.commit()
        flash('File deleted successfully')
    else:
        flash('File not found or unauthorized')
    return redirect(url_for('dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        flash("Please log in to upload files.")
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        recipient_username = request.form['recipient']
        recipient = User.query.filter_by(username=recipient_username).first()
        if not recipient:
            flash('Recipient username not found. Please check the username and try again.', 'error')
            return redirect(request.url)
        if 'file' not in request.files or file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        file_data = file.read()
        encryption_key = generate_encryption_key()
        encrypted_data = encrypt_file(file_data, encryption_key)
        new_file = FileTransfer(filename=file.filename, file_data=encrypted_data, sender_id=session['user_id'], recipient_id=recipient.id, encryption_key=encryption_key)
        db.session.add(new_file)
        db.session.commit()
        flash('File successfully uploaded, encrypted, and sent', 'success')
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        flash("Please log in to download files.")
        return redirect(url_for('login'))
    file = FileTransfer.query.get(file_id)
    if file and file.recipient_id == session['user_id']:
        decrypted_data = decrypt_file(file.file_data, file.encryption_key)
        return send_file(io.BytesIO(decrypted_data), download_name=file.filename, as_attachment=True)
    else:
        flash('File not found or unauthorized')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create new tables with the updated schema
    app.run(debug=True, host='0.0.0.0', port=5000)
