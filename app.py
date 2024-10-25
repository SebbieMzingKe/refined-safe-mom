from flask import Flask, render_template, url_for,flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

from functools import wraps
from werkzeug.security import check_password_hash

from forms import RegistrationForm, LoginForm

import mysql.connector
from mysql.connector import Error
import json
import email_validator
import pandas as pd
import joblib
import xgboost
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)
app.config['SECRET_KEY']='a5cd36c715058bf2c9057169b7134a4d'

app.config['SQLALCHEMY_DATABASEURI'] = 'sqlite:///siste.db'
# db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

db_config = {
    "host": "localhost",
    "user":"root",
    "password":"Seb#@Evayo1",
    "database":"refined-safe-mom"
}

#mysql connection
def get_db_connection():
    connection = None
    try:
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            return connection
    except Error as e:
        print("Error: '{e}'")
    return connection

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next = request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/", methods=['POST', 'GET'])
@app.route("/login", methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT id, password, role FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[1], password):
            
            session['user_id'] = user[0]
            session['role'] = user[2]
            if user[2] == "doctor":
                flash(f'Login successful! Welcome, {email}', 'success')
                return redirect(url_for("doctor_dashboard"))
            
            
            elif user[2] == "patient":
                flash(f'Login successful! Welcome, {email}', 'success')
                return redirect(url_for("patient_dashboard"))
            
            else:
                
                flash("Access denied. Only authorized roles are allowed.", "danger")
            # next_page = request.args.get('next')
            return redirect(url_for('login'))

        flash(f'Login Failed. Please check your email and password.', 'danger')

        cursor.close()
        connection.close()

    return render_template('login.html', title = 'Login', form = form)
    # if form.validate_on_submit():
    #     flash(f'Login Succesfull Welcome', 'success')
    #     return redirect(url_for('hello_world'))
    # return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', "info")
    return redirect(url_for('login'))


@app.route("/register", methods=['POST', 'GET'])

def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
         

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                       (form.username.data, form.email.data, hashed_password))
        connection.commit()
        cursor.close()
        connection.close()

        flash(f'Account Successfully Created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)



@app.route("/home",methods=["GET","POST"])
@login_required
def hello_world():
    return render_template('home.html')

@app.route("/about")
def jambo():
    return render_template('about.html', title='about')


@app.route("/contact")
def contact():
    return render_template("contact.html", title = "contact")



@app.route("/doctor_dashboard", methods=['GET', 'POST'])
@login_required
def doctor_dashboard():
    if session.get("role") != "doctor":
        return redirect(url_for("login"))
    
    form = RegistrationForm()
    if form.validate_on_submit():
       hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
       connection = get_db_connection()
       cursor = connection.cursor()
       cursor.execute('INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
                    (form.username.data, form.email.data, hashed_password, 'patient'))
       connection.commit()
       cursor.close()
       connection.close()

       flash(f'Patient account created for {form.username.data}!', 'success')
       return redirect(url_for('doctor_dashboard'))

    return render_template('doctor_dashboard.html', title='Doctor Dashboard', form=form) 



@app.route("/patient_dashboard")
@login_required
def patient_dashboard():
    if 'patient_id' not in session:
        flash("No patient is logged in.", 'danger')
        return redirect(url_for('hello_world'))

    return render_template('patient_dashboard.html', title='Patient Dashboard')



@app.route("/predict", methods = ["GET", "POST"])
def predict():
    if request.method == "POST":
        to_predict_list = request.form.to_dict()
        
        user_id = session.get('user_id')
        if not user_id:
            return "User Not logged in"

        connection = get_db_connection()
        cursor = connection.cursor()
        # cursor.execute('INSERT INTO patient_data (patient_data) VALUES (%s)', (str(to_predict_list),))
        
        insert_query = '''
        INSERT INTO patient_data (
        age, height, weight, bmi, sysbp, diabp, hb, pcv, platelet, creatinine, plgf_sflt, SEng, cysC, pp_13, glycerides, htn, diabetes, fam_htn, sp_art, occupation, diet, activity, sleep
        ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        '''
        values = (
            to_predict_list.get('age'),
            to_predict_list.get('height'),
            to_predict_list.get('weight'),
            to_predict_list.get('bmi'),
            to_predict_list.get('sysbp'),
            to_predict_list.get('diabp'),
            to_predict_list.get('hb'),
            to_predict_list.get('pcv'),
            to_predict_list.get('platelet'),
            to_predict_list.get('creatinine'),
            to_predict_list.get('plgf_sflt'),
            to_predict_list.get('SEng'),
            to_predict_list.get('cysC'),
            to_predict_list.get('pp_13'),
            to_predict_list.get('glycerides'),
            to_predict_list.get('htn'),
            to_predict_list.get('diabetes'),
            to_predict_list.get('fam_htn'),
            to_predict_list.get('sp_art'),
            to_predict_list.get('occupation'),
            to_predict_list.get('diet'),
            to_predict_list.get('activity'),
            to_predict_list.get('sleep'),
            user_id
        )
        
        cursor.execute(insert_query, values)
        
        connection.commit()

        cursor.close()
        connection.close()
        
        json_data = json.dumps(to_predict_list)
        
        # try:
        prediction = preprocessDataAndPredict(json_data)
        return render_template('/predict.html', prediction = prediction)
        
        
        # except ValueError:
        #     return "Please Enter Valid Values"
        

    return "Method not allowed"


def preprocessDataAndPredict(json_data):
    feature_dict = json.loads(json_data)
    test_data = {k: [v] for k, v in feature_dict.items()}
    test_data = pd.DataFrame(test_data)
    
    # Convert columns to appropriate numeric types
    cols_to_numeric = ['age', 'gest_age', 'height', 'weight', 'bmi', 'sysbp', 'diabp', 'hb',
       'pcv', 'tsh', 'platelet', 'creatinine', 'plgf:sflt', 'SEng', 'cysC',
       'pp_13', 'glycerides', 'htn', 'diabetes', 'fam_htn', 'sp_art',
       'occupation', 'diet', 'activity', 'sleep']

    for col in cols_to_numeric:
        test_data[col] = pd.to_numeric(test_data[col], errors='coerce')  # Converts non-numeric values to NaN

    
    if 'occupation' in test_data.columns:
    
        label_encoder = LabelEncoder()
        test_data['occupation'] = label_encoder.fit_transform(test_data['occupation'].astype(str))


    if 'next' in test_data.columns:
        test_data.drop('next', axis=1, inplace=True) 
    
    test_data.fillna(0, inplace=True)

    file = open("safe_mom_model_1.pkl", "rb")
    trained_model = joblib.load(file)
    
    prediction = trained_model.predict(test_data)
    
    return prediction



if __name__ == '__main__':
    app.run(debug=True)


# @app.route("/register", methods=['POST', 'GET'])

# def register():
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
         

#         connection = get_db_connection()
#         cursor = connection.cursor()
#         cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
#                        (form.username.data, form.email.data, hashed_password))
#         connection.commit()
#         cursor.close()
#         connection.close()

#         flash(f'Account Successfully Created for {form.username.data}!', 'success')
#         return redirect(url_for('login'))
    
#     return render_template('register.html', title='Register', form=form)



# def preprocessDataAndPredict(feature_dict):
#     test_data = {k:[v] for k, v in feature_dict.items()}
#     test_data = pd.DataFrame(test_data) 
    
#     file = open("safe_mom_model_1.pkl", "rb")
    
#     trained_model = joblib.load(file)
    
#     predict = trained_model.predict(test_data)

#     return predict