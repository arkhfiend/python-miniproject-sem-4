from flask import Flask, render_template,request,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from bs4 import BeautifulSoup
from models import db,User,MutualFund
from auth import login_manager
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from admin import admin_bp  # Import the admin blueprint
#from auth import User
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import requests
app = Flask(__name__)

# Set the secret key
app.config['SECRET_KEY'] = 'c5064ddd7c72e2b528a770ff179e4d42'

# Replace 'mysql://username:password@localhost/dbname' with your MySQL connection details
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Aarya%401971@localhost/mfdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.register_blueprint(admin_bp)
login_manager= LoginManager(app)
bcrypt = Bcrypt(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# Initialize db with the Flask app
db.init_app(app)
migrate = Migrate(app, db)
with app.app_context():
    #db.drop_all()
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mfinfo')
def mf_info():
    # You can pass any necessary data to mfinfo.html if needed
    return render_template('mfinfo.html')

@app.route('/data_entry')
def data_entry():
    return render_template('data_entry.html')

@app.route('/mutual_funds')
def mutual_funds():
    mutual_funds_list = MutualFund.query.all()
    return render_template('mutual_funds.html', mutual_funds=mutual_funds_list)

@app.route('/submit_data', methods=['POST'])
def submit_data():
    name = request.form.get('name')
    fund_type = request.form.get('fund_type')
    nav = float(request.form.get('nav'))
    returns = float(request.form.get('returns'))
    risk_tolerance = request.form.get('risk_tolerance')
    new_fund = MutualFund(name=name, fund_type=fund_type, nav=nav, returns=returns,risk_tolerance=risk_tolerance)
    db.session.add(new_fund)
    db.session.commit()

    return redirect(url_for('mutual_funds'))

# Add a new route for filtering funds
@app.route('/filter_funds', methods=['GET', 'POST'])
def filter_funds():
    if request.method == 'POST':
        # Get the selected risk tolerance and fund type from the form
        risk_tolerance = request.form.get('risk_tolerance')
        
        fund_category = request.form.get('fund_category')
        
        # Query the database to filter funds based on risk tolerance and fund type
        filtered_funds = MutualFund.query.filter_by(risk_tolerance=risk_tolerance, fund_type=fund_category).all()
        
        return render_template('filter_funds.html', filtered_funds=filtered_funds)

    # If it's a GET request, render the page with the form
    return render_template('filter_funds.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Implement login logic
    if request.method == 'POST':
        # Validate user credentials and log them in
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin.admin_dashboard'))
            else:
                return redirect(url_for('index'))
    return render_template('admin/login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Implement the signup logic here
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        #is_admin = request.form.get('is_admin') == 'on'
        # Check if the 'is_admin' checkbox is selected
        is_admin = 'is_admin' in request.form
        # Validate the form data (e.g., check if passwords match)

        # Create a new user and add it to the database
        if password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password_hash=hashed_password,is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()

            # Redirect to the login page after successful signup
            return redirect(url_for('login'))
        else:
            # Handle the case where passwords don't match
            return render_template('admin/signup.html', message="Passwords do not match.")


    return render_template('admin/signup.html')

def get_financial_news():
    #api_key = 'H9D3T215Q1U9UUAM'
    url = f'https://financialmodelingprep.com/api/v3/stock_news?apikey=a5b58d816a52512f11d38eac14796b22'


    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        news_data = response.json()
        return news_data
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None


@app.route('/daily_news')
def daily_news():
    news_data = get_financial_news()
    print('News Data:', news_data)
    if news_data is not None:
        return render_template('daily_news.html', news_data=news_data)
    else:
        # Handle the case where news_data is None (e.g., API request failed)
        return render_template('daily_news.html', news_data=[])

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)