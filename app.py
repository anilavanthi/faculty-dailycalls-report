from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3
import os
import pandas as pd

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'calls.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student TEXT,
        phone_number TEXT,
        status TEXT,
        notes TEXT,
        call_date TEXT,
        exam_type TEXT,
        hall_ticket_no TEXT,
        rank TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def get_db():
    return sqlite3.connect(DATABASE)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        return 'Please enter both username and password.'

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['is_admin'] = user[3]
        return redirect('/adminpanel' if user[3] == 1 else '/dashboard')
    
    return 'Invalid credentials'

@app.route('/register', methods=['GET', 'POST'])
def register_faculty():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 0  # Faculty
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                  (username, password, is_admin))
        conn.commit()
        conn.close()
        return redirect('/')
    return render_template('register.html', role='Faculty')

@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 1  # Admin
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                  (username, password, is_admin))
        conn.commit()
        conn.close()
        return redirect('/')
    return render_template('register.html', role='Admin')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin') == 1:
        return redirect('/')

    if request.method == "POST":
        student = request.form.get('student', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        hall_ticket_no = request.form.get('hall_ticket_no', '').strip()
        rank = request.form.get('rank', '').strip()
        status = request.form.get('status', '').strip()
        notes = request.form.get('notes', '').strip()
        call_date = request.form.get('call_date', '').strip()
        exam_type = request.form.get('exam_type', '').strip()

        if student:
            conn = get_db()
            c = conn.cursor()
            c.execute('''INSERT INTO calls (user_id, student, phone_number, hall_ticket_no, rank, status, notes, call_date, exam_type)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (session['user_id'], student, phone_number, hall_ticket_no, rank, status, notes, call_date, exam_type))
            conn.commit()
            conn.close()

    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT u.username, c.student, c.phone_number, c.hall_ticket_no, c.rank, c.status, c.notes, c.call_date, c.exam_type
                 FROM calls c JOIN users u ON c.user_id = u.id
                 WHERE u.id=? 
                 AND (c.exam_type = "EAPCET" OR c.exam_type = "POLYCET" OR c.exam_type = "General")
                 ORDER BY c.call_date DESC''', (session['user_id'],))
    calls = c.fetchall()
    conn.close()
    return render_template('dashboard.html', username=session['username'], calls=calls)

@app.route('/adminpanel', methods=['GET', 'POST'])
def adminpanel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/')

    conn = get_db()
    c = conn.cursor()
    
    # Get faculty list (non-admin users)
    c.execute('''SELECT DISTINCT u.id, u.username FROM users u
                 JOIN calls c ON u.id = c.user_id WHERE u.is_admin = 0''')
    faculty_list = c.fetchall()

    # Get the selected faculty filter from the form
    faculty_filter = request.args.get('faculty', '')

    # Modify the query to filter reports by faculty if selected
    if faculty_filter:
        c.execute('''SELECT u.username, c.student, c.phone_number, c.status, c.notes, c.call_date, c.exam_type, c.hall_ticket_no, c.rank
                     FROM calls c JOIN users u ON c.user_id = u.id
                     WHERE u.id = ?
                     ORDER BY c.call_date DESC''', (faculty_filter,))
    else:
        c.execute('''SELECT u.username, c.student, c.phone_number, c.status, c.notes, c.call_date, c.exam_type, c.hall_ticket_no, c.rank
                     FROM calls c JOIN users u ON c.user_id = u.id
                     ORDER BY c.call_date DESC''')

    reports = c.fetchall()
    conn.close()

    return render_template('report.html', reports=reports, faculty_list=faculty_list, selected_user=faculty_filter)

@app.route('/export_excel')
def export_excel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/')

    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT u.username, c.student, c.phone_number, c.hall_ticket_no, c.rank, c.status, c.notes, c.call_date, c.exam_type
                 FROM calls c JOIN users u ON c.user_id = u.id
                 ORDER BY c.call_date DESC''')
    data = c.fetchall()
    conn.close()

    df = pd.DataFrame(data, columns=["Faculty", "Student", "Phone Number", "Hall Ticket No", "Rank", "Status", "Notes", "Date", "Exam Type"])
    file_path = 'faculty_call_reports.xlsx'
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/export_my_excel')
def export_my_excel():
    if 'user_id' not in session or session.get('is_admin') == 1:
        return redirect('/')

    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT student, phone_number, hall_ticket_no, rank, status, notes, call_date, exam_type
                 FROM calls WHERE user_id=? ORDER BY call_date DESC''', (session['user_id'],))
    data = c.fetchall()
    conn.close()

    df = pd.DataFrame(data, columns=["Student", "Phone Number", "Hall Ticket No", "Rank", "Status", "Notes", "Date", "Exam Type"])
    file_path = f"{session['username']}_call_report.xlsx"
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)






























































































































































