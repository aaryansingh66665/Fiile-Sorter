# Flask File Upload and User Authentication System

This project is a Flask-based web application that allows users to register, log in, upload, view, and download files securely. It includes user authentication, file management, and access control, making it suitable for personal or small-scale use cases.

Features
✅ User registration and login (Flask-Login, Flask-Bcrypt, SQLAlchemy)
✅ Secure file upload with allowed file extensions
✅ User-specific directories for storing files
✅ File download functionality
✅ Flash messages for user notifications

Tech Stack
Flask (Backend)
SQLite (Database)
Flask-Login (User Authentication)
Flask-Bcrypt (Password Hashing)
HTML/CSS (Frontend Templates)

Installation
Clone the repository:
bash
Copy
Edit
git clone https://github.com/yourusername/flask-file-upload.git
cd flask-file-upload
Create a virtual environment and activate it:
bash
Copy
Edit
python -m venv venv  
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate  # On Windows
Install dependencies:
bash
Copy
Edit
pip install -r requirements.txt
Run the Flask app:

bash
Copy
Edit
python app.py
Open the application in your browser:

cpp
Copy
Edit
http://127.0.0.1:5000/
File Upload
Allowed file types: jpg, png, gif, pdf, docx, xlsx, pptx, mp4, mp3, zip, rar
Each user has their own directory inside the uploads/ folder

Usage
Register an account on /register
Log in on /login
Upload files on the dashboard
View and download files from /file_access

Author
Aryan Singh
📧 Email: aaryansingh66661@gmail.com
🔗 LinkedIn: https://www.linkedin.com/in/aryan-singh-02a449340/

