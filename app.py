import streamlit as st
import cv2
import mediapipe as mp
import os
from skimage.metrics import structural_similarity as ssim
import numpy as np
from datetime import datetime
import re
from PIL import Image
import csv
import bcrypt
import time
import secrets
from datetime import datetime, timedelta
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Constants
USER_FILE = 'users.csv'
RESET_TOKENS_FILE = 'reset_tokens.csv'
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$")

# Custom CSS
def load_css():
    st.markdown("""
    <style>
    .stApp {
        background-color: #f7f9fa; /* Light grey background */
        font-family: 'Helvetica', sans-serif;
    }
    .big-font {
        font-size: 2.5rem !important;
        font-weight: 700;
        color: #00796b; /* Teal */
        text-align: center;
    }
    .subtitle {
        font-size: 1.2rem;
        color: #424242; /* Dark grey */
        text-align: center;
        margin-bottom: 1rem;
    }
    .date-time {
        font-size: 1rem;
        color: #757575; /* Medium grey */
        text-align: center;
        margin-bottom: 2rem;
    }
    .stButton>button {
        color: #ffffff;
        background-color: #009688; /* Teal */
        padding: 0.5rem 1rem;
        font-size: 1rem;
        font-weight: 600;
        border-radius: 0.375rem;
        border: none;
        cursor: pointer;
        transition: background-color 0.3s ease;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #00796b; /* Darker teal on hover */
    }
    .sign-up {
        background-color: #4caf50 !important; /* Green */
    }
    .sign-up:hover {
        background-color: #388e3c !important; /* Darker green on hover */
    }
    .feature-box {
        background-color: #ffffff; /* White */
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
    }
    .feature-icon {
        font-size: 2rem;
        margin-bottom: 0.5rem;
    }
    .logo-container {
        display: flex;
        justify-content: center;
        margin-bottom: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

# User management functions
def load_users():
    users = {}
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r', newline='') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for row in reader:
                users[row[0]] = {
                    'password': row[1],
                    'email': row[2],
                    'created_at': row[3],
                    'last_login': row[4]
                }
    return users

def save_users(users):
    with open(USER_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['username', 'password', 'email', 'created_at', 'last_login'])
        for username, data in users.items():
            writer.writerow([username, data['password'], data['email'], data['created_at'], data['last_login']])

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

def sanitize_input(input_string):
    return re.sub(r'[<>&\'"]/g', '', input_string)

def validate_email(email):
    return EMAIL_REGEX.match(email)

def validate_username(username):
    return USERNAME_REGEX.match(username)

def validate_password(password):
    return PASSWORD_REGEX.match(password)

def create_user(username, password, email):
    users = load_users()
    if username not in users:
        if not validate_username(username):
            return False, "Invalid username format. Use 3-20 alphanumeric characters or underscores."
        if not validate_email(email):
            return False, "Invalid email format."
        if not validate_password(password):
            return False, "Password must be at least 8 characters long and contain both letters and numbers."
        
        hashed_password = hash_password(password)
        current_time = datetime.now().isoformat()
        users[username] = {
            'password': hashed_password,
            'email': email,
            'created_at': current_time,
            'last_login': ''
        }
        save_users(users)
        return True, "Account created successfully!"
    return False, "Username already exists."

def authenticate_user(username, password):
    users = load_users()
    if username in users and verify_password(users[username]['password'], password):
        users[username]['last_login'] = datetime.now().isoformat()
        save_users(users)
        return True
    return False

def change_password(username, current_password, new_password):
    users = load_users()
    if username in users and verify_password(users[username]['password'], current_password):
        if not validate_password(new_password):
            return False, "New password must be at least 8 characters long and contain both letters and numbers."
        users[username]['password'] = hash_password(new_password)
        save_users(users)
        return True, "Password changed successfully!"
    return False, "Current password is incorrect."

# Reset token management
def load_reset_tokens():
    tokens = {}
    if os.path.exists(RESET_TOKENS_FILE):
        with open(RESET_TOKENS_FILE, 'r', newline='') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for row in reader:
                tokens[row[0]] = {'username': row[1], 'expiry': datetime.fromisoformat(row[2])}
    return tokens

def save_reset_tokens(tokens):
    with open(RESET_TOKENS_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['token', 'username', 'expiry'])
        for token, data in tokens.items():
            writer.writerow([token, data['username'], data['expiry'].isoformat()])

def generate_reset_token(email):
    users = load_users()
    tokens = load_reset_tokens()
    for username, data in users.items():
        if data['email'] == email:
            token = secrets.token_urlsafe()
            expiry = datetime.now() + timedelta(hours=1)
            tokens[token] = {'username': username, 'expiry': expiry}
            save_reset_tokens(tokens)
            return token
    return None

def send_reset_email(email, token):
    sender_email = "your-email@example.com"  # Configure this
    sender_password = "your-email-password"  # Configure this

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["Subject"] = "Password Reset for KIP SAFE"

    body = f"Click the following link to reset your password: http://your-app-url/reset?token={token}"
    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())

def reset_password(token, new_password):
    tokens = load_reset_tokens()
    users = load_users()
    if token in tokens and datetime.now() < tokens[token]['expiry']:
        username = tokens[token]['username']
        if not validate_password(new_password):
            return False, "New password must be at least 8 characters long and contain both letters and numbers."
        users[username]['password'] = hash_password(new_password)
        save_users(users)
        del tokens[token]
        save_reset_tokens(tokens)
        return True, "Password reset successfully!"
    return False, "Invalid or expired reset token."

# KIP SAFE APP functionality
def kip_safe_app():
    # Initialize MediaPipe
    mp_hands = mp.solutions.hands
    mp_drawing_hands = mp.solutions.drawing_utils
    mp_face_detection = mp.solutions.face_detection
    mp_drawing_faces = mp.solutions.drawing_utils

    # Directory for saving known faces
    known_faces_dir = 'known_faces'
    os.makedirs(known_faces_dir, exist_ok=True)

    def compare_faces(image1, image2):
        """Compare two images and return the similarity score."""
        image1 = cv2.cvtColor(image1, cv2.COLOR_BGR2GRAY)
        image2 = cv2.cvtColor(image2, cv2.COLOR_BGR2GRAY)

        # Resize images to the same size
        image1 = cv2.resize(image1, (100, 100))
        image2 = cv2.resize(image2, (100, 100))

        # Compute SSIM between two images
        score = ssim(image1, image2)
        return score

    def detect_hands():
        """Detect and display hands, and identify amputee hands."""
        st.write("Place your hand in front of the camera.")
        cap = cv2.VideoCapture(0)

        if not cap.isOpened():
            st.error("Could not open webcam.")
            return

        with mp_hands.Hands(max_num_hands=2, min_detection_confidence=0.3) as hands:
            while True:
                ret, frame = cap.read()
                if not ret:
                    st.error("Failed to capture image.")
                    break

                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                results = hands.process(rgb_frame)

                if results.multi_hand_landmarks:
                    for hand_landmarks in results.multi_hand_landmarks:
                        mp_drawing_hands.draw_landmarks(frame, hand_landmarks, mp_hands.HAND_CONNECTIONS)

                    st.image(frame, channels="BGR", use_column_width=True)

                    # Check how many hands are detected
                    num_hands_detected = len(results.multi_hand_landmarks)
                    if num_hands_detected == 2:
                        st.success("Both hands detected.")
                    elif num_hands_detected == 1:
                        st.warning("One hand detected. Possible amputee.")
                    else:
                        st.warning("No hands detected. Make sure your hands are visible to the camera.")
                else:
                    st.warning("No hands detected.")

                if st.button("Stop Detection", key=f"stop_detection_{time.time()}"):
                    break

                time.sleep(0.1)

        cap.release()

    def capture_face():
        """Capture a face image and save it to the known_faces directory."""
        st.write("Adjust your position before capturing.")
        cap = cv2.VideoCapture(0)

        with mp_face_detection.FaceDetection(min_detection_confidence=0.5) as face_detection:
            ret, frame = cap.read()
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            results = face_detection.process(rgb_frame)

            if results.detections:
                for detection in results.detections:
                    mp_drawing_faces.draw_detection(frame, detection)
                st.image(frame, channels="BGR")

                if st.button("Capture Face", key="capture_face"):
                    img_path = os.path.join(known_faces_dir, 'captured_face.jpg')
                    cv2.imwrite(img_path, frame)
                    st.success(f"Face captured and saved as {img_path}")

            else:
                st.warning("No face detected.")

        cap.release()

    def verify_face():
        """Verify the captured face against the saved known face."""
        known_image_path = os.path.join(known_faces_dir, 'captured_face.jpg')
        if not os.path.exists(known_image_path):
            st.warning("No known face found. Please capture an image first.")
            return

        cap = cv2.VideoCapture(0)
        st.write("Press 'Verify' to check your face.")

        with mp_face_detection.FaceDetection(min_detection_confidence=0.5) as face_detection:
            ret, frame = cap.read()
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            results = face_detection.process(rgb_frame)

            if results.detections:
                for detection in results.detections:
                    mp_drawing_faces.draw_detection(frame, detection)
                st.image(frame, channels="BGR")

                if st.button("Verify Face", key="verify_face"):
                    known_face = cv2.imread(known_image_path)
                    similarity_score = compare_faces(known_face, frame)

                    if similarity_score > 0.9:  # Threshold for similarity
                        st.success("Face verified successfully!")
                    else:
                        st.warning("Face verification failed. Not a match.")

            else:
                st.warning("No face detected.")

        cap.release()

    st.title("DATAGRITY APP - Data Capturing and Verification")

    # Add a default option to the selectbox
    option = st.selectbox("Choose an action:", 
                          ("Select an action", "Hand Detection", "Capture Face", "Verify Face"))
    
    # Only execute functions if a valid option is selected
    if option == "Hand Detection":
        detect_hands()
    elif option == "Capture Face":
        capture_face()
    elif option == "Verify Face":
        verify_face()

    if st.button("Sign Out"):
        del st.session_state.user
        st.session_state.page = 'home'
        st.success("Signed out successfully!")

# Streamlit UI functions
def main():
    load_css()
    
    col1, col2, col3 = st.columns([1,3,1])
    
    with col2:
        # Display logo
        st.markdown('<div class="logo-container">', unsafe_allow_html=True)
        logo = Image.open("logo.png")
        st.image(logo, use_column_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<p class="big-font">Welcome</p>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">Secured Data Capturing and Verification App</p>', unsafe_allow_html=True)
        
        # Display current date and time
        now = datetime.now()
        st.markdown(f'<p class="date-time">{now.strftime("%B %d")}</p>', unsafe_allow_html=True)
        
        if 'page' not in st.session_state:
            st.session_state.page = 'home'

        # Call the appropriate page function based on the session state
        if st.session_state.page == 'home':
            home_page()
        elif st.session_state.page == 'signin':
            signin_page()
        elif st.session_state.page == 'signup':
            signup_page()
        elif st.session_state.page == 'forgot_password':
            forgot_password_page()
        elif st.session_state.page == 'reset_password':
            reset_password_page()
        elif 'user' in st.session_state:
            if st.session_state.page == 'kip_safe_app':
                kip_safe_app()  # Call the KIP SAFE APP functionality
            else:
                user_dashboard()
        elif st.session_state.page == 'change_password':
            change_password_page()

def home_page():
    col_btn1, col_btn2 = st.columns(2)
    
    with col_btn1:
        if st.button("Sign In"):
            st.session_state.page = 'signin'
    
    with col_btn2:
        if st.button("Sign Up", key="sign_up"):
            st.session_state.page = 'signup'

    st.write("")
    st.write("")
    
    # Feature highlights
    st.subheader("Why Choose DATAGRITY APP?")
    
    col_feat1, col_feat2 = st.columns(2)
    
    with col_feat1:
        st.markdown('<div class="feature-box"><span class="feature-icon">🔒</span><br><strong>Secured Data Capturing and Verification</strong><br>Integration of artificial intelligence into national identity database management to ensure integrity and maximum security on data capturing and verification </div>', unsafe_allow_html=True)
       
   # with col_feat2:
             
def signin_page():
    st.subheader("Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Sign In", key="signin_button"):
        if authenticate_user(sanitize_input(username), password):
            st.success("Signed in successfully!")
            st.session_state.user = username
            st.session_state.page = 'user_dashboard'  # Redirect to dashboard
        else:
            st.error("Invalid username or password")
    if st.button("Forgot Password"):
        st.session_state.page = 'forgot_password'
    if st.button("Back to Home"):
        st.session_state.page = 'home'

def signup_page():
    st.subheader("Sign Up")
    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Sign Up"):
        if password != confirm_password:
            st.error("Passwords do not match")
        else:
            success, message = create_user(sanitize_input(username), password, sanitize_input(email))
            if success:
                st.success(message)
                st.session_state.page = 'dashboard'  # Redirect to dashboard
            else:
                st.error(message)
    if st.button("Back to Home"):
        st.session_state.page = 'home'

def forgot_password_page():
    st.subheader("Forgot Password")
    email = st.text_input("Enter your email")
    if st.button("Reset Password"):
        token = generate_reset_token(sanitize_input(email))
        if token:
            send_reset_email(email, token)
            st.success("Password reset link sent to your email")
        else:
            st.error("Email not found")
    if st.button("Back to Sign In"):
        st.session_state.page = 'signin'

def reset_password_page():
    st.subheader("Reset Password")
    token = st.experimental_get_query_params().get("token", [""])[0]
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm New Password", type="password")
    if st.button("Reset Password"):
        if new_password != confirm_password:
            st.error("Passwords do not match")
        else:
            success, message = reset_password(token, new_password)
            if success:
                st.success(message)
                st.session_state.page = 'signin'
            else:
                st.error(message)

def change_password_page():
    st.subheader("Change Password")
    current_password = st.text_input("Current Password", type="password")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm New Password", type="password")
    if st.button("Change Password"):
        if new_password != confirm_password:
            st.error("New passwords do not match")
        else:
            success, message = change_password(st.session_state.user, current_password, new_password)
            if success:
                st.success(message)
                st.session_state.page = 'dashboard'  # Redirect to dashboard
    if st.button("Back to Dashboard"):
        st.session_state.page = 'dashboard'

def user_dashboard():
    st.subheader(f"Welcome, {st.session_state.user}!")
    st.markdown("Click to lunch DATAGRITY APP:")
    
     # Add a link to the KIP SAFE APP
    if st.button("Access DATAGRITY APP"):
       st.session_state.page = 'kip_safe_app'
       #st.session_state.page = '#'

    if st.button("Change Password"):
        st.session_state.page = 'change_password'
    if st.button("Sign Out"):
        del st.session_state.user
        st.session_state.page = 'home'
        st.success("Signed out successfully!")

    # Placeholder for user dashboard content
    st.write("DATEGRITY APP")

if __name__ == "__main__":
    main()