from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from datetime import datetime, timedelta
from functools import wraps
import csv
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production

# Constants
DOCTORS = ['Dr. Smith', 'Dr. Johnson', 'Dr. Williams']
TIME_SLOTS = [
    f"{hour:02d}:{minute:02d}"
    for hour in range(9, 17)
    for minute in range(0, 60, 30)
]

# File paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
USERS_CSV = os.path.join(BASE_DIR, 'users.csv')
APPOINTMENTS_CSV = os.path.join(BASE_DIR, 'appointments.csv')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_file_permissions():
    """Check if necessary files are accessible and have correct permissions"""
    files = [USERS_CSV, APPOINTMENTS_CSV]
    for file_path in files:
        dir_path = os.path.dirname(file_path)
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            if not os.path.exists(file_path):
                open(file_path, 'a').close()
            if not os.access(file_path, os.R_OK | os.W_OK):
                logger.error(f"Permission denied for {file_path}")
                return False
        except Exception as e:
            logger.error(f"Error checking permissions: {e}")
            return False
    return True

def initialize_csv_files():
    """Initialize CSV files with headers if they don't exist"""
    try:
        # Create users.csv if it doesn't exist
        if not os.path.exists(USERS_CSV):
            with open(USERS_CSV, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Email', 'Password', 'First_Name', 'Last_Name',
                               'Mobile_Number', 'Address', 'DOB', 'Sex'])  # Added DOB and Sex
            logger.info(f"Created users.csv at {USERS_CSV}")


        # Create appointments.csv if it doesn't exist
        if not os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Doctor', 'Date', 'Time', 'Patient_Email',
                               'Patient_Name', 'Booking_Time'])
            logger.info(f"Created appointments.csv at {APPOINTMENTS_CSV}")
    except Exception as e:
        logger.error(f"Error initializing CSV files: {e}")
        raise

def get_user_details(email):
    """Get user details from users.csv"""
    try:
        with open(USERS_CSV, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['Email'].strip() == email.strip():
                    return {k: v.strip() for k, v in row.items()}
        logger.warning(f"User not found: {email}")
    except Exception as e:
        logger.error(f"Error reading user details: {e}")
    return None

def update_user_details(email, details):
    """Update user details in users.csv"""
    try:
        rows = []
        updated = False
        with open(USERS_CSV, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            for row in reader:
                if row['Email'].strip() == email.strip():
                    row.update(details)
                    updated = True
                rows.append(row)

        if updated:
            with open(USERS_CSV, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
            logger.info(f"Updated details for user: {email}")
            return True
        logger.warning(f"No user found to update: {email}")
    except Exception as e:
        logger.error(f"Error updating user details: {e}")
    return False

def get_user_appointments(email):
    """Get appointments for a specific user"""
    appointments = []
    try:
        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['Patient_Email'].strip() == email.strip():
                        appointments.append(row)
    except Exception as e:
        logger.error(f"Error getting appointments: {e}")
    return appointments

def is_time_slot_available(doctor, date, time_slot):
    """Check if a time slot is available for a doctor on a specific date"""
    try:
        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if (row['Doctor'] == doctor and
                        row['Date'] == date and
                        row['Time'] == time_slot):
                        return False
    except Exception as e:
        logger.error(f"Error checking time slot: {e}")
    return True

def get_available_dates():
    """Return available dates starting from tomorrow up to 30 days"""
    dates = []
    start_date = datetime.now().date() + timedelta(days=1)
    for i in range(30):
        current_date = start_date + timedelta(days=i)
        # Exclude weekends (5 = Saturday, 6 = Sunday)
        if current_date.weekday() not in [5, 6]:
            dates.append(current_date.strftime('%Y-%m-%d'))
    return dates

def book_appointment_helper(doctor, date, time_slot, user_email, user_name):
    """Helper function to handle appointment booking"""
    try:
        if not is_time_slot_available(doctor, date, time_slot):
            return False, "Time slot no longer available"

        appointments = []
        headers = ['Doctor', 'Date', 'Time', 'Patient_Email',
                  'Patient_Name', 'Booking_Time']

        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                appointments = list(reader)

        new_appointment = {
            'Doctor': doctor,
            'Date': date,
            'Time': time_slot,
            'Patient_Email': user_email,
            'Patient_Name': user_name,
            'Booking_Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        appointments.append(new_appointment)

        with open(APPOINTMENTS_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(appointments)

        return True, "Appointment booked successfully"
    except Exception as e:
        logger.error(f"Error in book_appointment_helper: {e}")
        return False, str(e)

# Routes
@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if get_user_details(email):
            flash('Email already registered')
            return redirect(url_for('signup'))

        try:
            is_empty = True
            if os.path.exists(USERS_CSV):
                with open(USERS_CSV, 'r', encoding='utf-8') as f:
                    is_empty = len(f.readlines()) <= 1

            if is_empty:
                with open(USERS_CSV, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Email', 'Password', 'First_Name', 'Last_Name',
                                   'Mobile_Number', 'Address', 'DOB', 'Sex'])
                    writer.writerow([
                        email,
                        password,
                        request.form['first_name'].strip(),
                        request.form['last_name'].strip(),
                        request.form['mobile'].strip(),
                        request.form['address'].strip(),
                        request.form['dob'].strip(),
                        request.form['sex'].strip()
                    ])
            else:
                with open(USERS_CSV, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        email,
                        password,
                        request.form['first_name'].strip(),
                        request.form['last_name'].strip(),
                        request.form['mobile'].strip(),
                        request.form['address'].strip(),
                        request.form['dob'].strip(),
                        request.form['sex'].strip()
                    ])

            logger.info(f"New user registered: {email}")
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in signup: {e}")
            flash('Registration failed. Please try again.')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        try:
            user = get_user_details(email)
            if user and user['Password'] == password:
                session['user_email'] = email
                logger.info(f"Successful login for user: {email}")
                flash('Logged in successfully!')
                return redirect(url_for('dashboard'))
            else:
                logger.warning(f"Invalid credentials for email: {email}")
                flash('Invalid email or password')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login. Please try again.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash('Logged out successfully!')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_details(session['user_email'])
    if user:
        appointments = get_user_appointments(session['user_email'])
        available_dates = get_available_dates()
        return render_template('dashboard.html',
                             user=user,
                             appointments=appointments,
                             doctors=DOCTORS,
                             time_slots=TIME_SLOTS,
                             available_dates=available_dates)
    return redirect(url_for('logout'))

@app.route('/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    doctor = request.form['doctor']
    date = request.form['appointment_date']
    time_slot = request.form['time_slot']
    user = get_user_details(session['user_email'])

    if not user:
        flash('User details not found.')
        return redirect(url_for('dashboard'))

    success, message = book_appointment_helper(
        doctor,
        date,
        time_slot,
        session['user_email'],
        f"{user['First_Name']} {user['Last_Name']}"
    )

    flash(message)
    if success:
        logger.info(f"Appointment booked for {session['user_email']}")
    else:
        logger.error(f"Failed to book appointment: {message}")

    return redirect(url_for('dashboard'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    details = {
        'First_Name': request.form['first_name'].strip(),
        'Last_Name': request.form['last_name'].strip(),
        'Mobile_Number': request.form['mobile'].strip(),
        'Address': request.form['address'].strip(),
        'DOB': request.form['dob'].strip(),
        'Sex': request.form['sex'].strip()
    }

    if update_user_details(session['user_email'], details):
        flash('Profile updated successfully!')
    else:
        flash('Failed to update profile')

    return redirect(url_for('dashboard'))


@app.route('/get_available_slots/<doctor>/<date>')
def available_slots(doctor, date):
    slots = [slot for slot in TIME_SLOTS
             if is_time_slot_available(doctor, date, slot)]
    return jsonify({'slots': slots})


@app.route('/api/appointments')
def get_appointments_api():
    try:
        appointments = []
        if os.path.exists(APPOINTMENTS_CSV):
            with open(APPOINTMENTS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                appointments = list(reader)

        # Get all appointments with patient details
        enhanced_appointments = []
        for app in appointments:
            # Get patient details including DOB and Sex
            patient_details = get_user_details(app['Patient_Email'])

            enhanced_appointment = {
                'id': len(enhanced_appointments) + 1,
                'doctor': app['Doctor'],
                'date': app['Date'],
                'time': app['Time'],
                'patient': {
                    'email': app['Patient_Email'],
                    'name': app['Patient_Name'],
                    'dob': patient_details.get('DOB', '') if patient_details else '',
                    'sex': patient_details.get('Sex', '') if patient_details else '',
                    'mobile': patient_details.get('Mobile_Number', '') if patient_details else '',
                    'address': patient_details.get('Address', '') if patient_details else ''
                },
                'booking_time': app.get('Booking_Time', ''),
                'status': 'scheduled'
            }
            enhanced_appointments.append(enhanced_appointment)

        response = {
            'status': 'success',
            'data': {
                'appointments': enhanced_appointments,
                'meta': {
                    'total': len(enhanced_appointments),
                    'timestamp': datetime.now().isoformat()
                }
            }
        }

        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in API: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'data': None
        }), 500


@app.before_request
def startup_check():
    if not getattr(app, '_got_first_request', False):
        if not check_file_permissions():
            logger.error("File permission check failed!")
            raise PermissionError("Cannot access required files")
        initialize_csv_files()
        app._got_first_request = True

if __name__ == '__main__':
    app.run(debug=True)
