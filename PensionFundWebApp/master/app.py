from urllib import response
from gnewsclient import gnewsclient
import base64
import json,random
import sqlite3
from flask import Flask, render_template, request, url_for, redirect, flash,send_from_directory,send_file,make_response,session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager,current_user,login_user, login_required, logout_user
import os, pdfkit
from chatterbot import ChatBot
from chatterbot.trainers import ListTrainer
from flask_mail import Mail, Message


app = Flask(__name__)
app.secret_key = 'romeo'
mail= Mail(app)
app.config['SECRET_KEY'] = "ADD YOUR KEY"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pension.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER']='\static'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'ADD YOUR MAIL ID'
app.config['MAIL_PASSWORD'] = 'ADD YOUR PASSWORD'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

db = SQLAlchemy(app)

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    firstName = db.Column(db.String(1000))
    lastName = db.Column(db.String(1000))
    ni = db.Column(db.String(9), unique=True)
    mobile = db.Column(db.String(15))
    gender = db.Column(db.String(10))
    date = db.Column(db.String(10))
    image=db.Column(db.BLOB)
    userType=db.Column(db.String(15))

def get_db_connection():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, "pension.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn
def convertToBinaryData(filename):
    # Convert digital data to binary format
    with open(filename, 'rb') as file:
        blobData = file.read()
    return blobData


def generateOTP():
    return random.randrange(100000,999999)    
'''
new_user = User(
            firstName='Nanda',
            lastName='Kishore',
            email='10015639',
            password=generate_password_hash('UOL@12345', method='pbkdf2:sha256', salt_length=6),
            ni = '',
            mobile = '',
            gender = '',
            date = '',
            image=convertToBinaryData('static/profileImage.png'),
            userType='admin')
db.session.add(new_user)
db.session.commit()

'''

with open('file.txt','r') as file:
    chatbotConvo = file.read()
'''
Chat Bot Code
'''
chatbot = ChatBot('LPF')

trainer = ListTrainer(chatbot)
content_list = chatbotConvo.split("\n")
trainer.train(content_list)

@app.route("/getChatBot")
def getChatBotresponse():
	userMessageInput = request.args.get('userMessageInput')
	return str(chatbot.get_response(userMessageInput))

@app.route("/generatePDF", methods=["GET", "POST"])
def generatePDF():
    userMessageInput = request.form.get('userMessageInput') #request.args.get('userMessageInput')
    config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
    pdfkit.from_string(userMessageInput, 'static/files/payments.pdf',configuration=config)
    
    dir = os.path.abspath(os.getcwd())
    filepath = dir + '\\static\\files'
    return send_from_directory(directory=filepath,path=filepath,
                           filename='payments.pdf',
                           mimetype='application/pdf',as_attachment=True)        

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# The line below is used only once for creating the database
#db.create_all()

#Start of the application: the main page
@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(email=request.form.get('email')).first():
            # If email already exists
            flash('Email already exist. Please try logging in with it.')
            return redirect(url_for('login'))
        if User.query.filter_by(ni=request.form.get('ni')).first():
            # If ni already exists
            flash('NI already exist. Please check and try again.')
            return redirect(url_for('login'))
        new_user = User(
            firstName=request.form.get('fname'),
            lastName=request.form.get('lname'),
            email=request.form.get('email'),
            password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=6),
            ni = request.form.get('ni'),
            mobile = request.form.get('mobile'),
            gender = request.form.get('gender'),
            date = request.form.get('dob'),
            image=convertToBinaryData('static/profileImage.png'),
            userType='user'
            )
        db.session.add(new_user)
        db.session.commit()
        conn = get_db_connection()
        policyName='Leicester Workplace Pension'
        policyNumber='L'+str(random.randint(10000, 99999))+'/'+str(random.randint(1000, 9999))
        pensionFund='0.00'
        employeeContribution='5'
        employerContribution='3'
        retirementAge='68'
        login_user(new_user)
        msg = Message('Registration Successful', sender = app.config['MAIL_USERNAME'], recipients = [current_user.email])
        msg.body = "Your registration was successful."
        mail.send(msg)
        conn.execute('INSERT into pensionDetails (userID,policyName,policyNumber,pensionFund,employeeContribution,employerContribution,retirementAge) VALUES (?,?,?,?,?,?,?)',
                            (current_user.id,policyName,policyNumber,pensionFund,employeeContribution,employerContribution,retirementAge)).fetchall()
        conn.commit() 
        # Log in and authenticate user after adding details to database
        
        flash('Successfully registered!')
        return redirect(url_for('login'))
    return render_template("register.html", logged_in=current_user.is_authenticated)

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # The below is used to find the user by email from the DB.
        user = User.query.filter_by(email=email).first()
        # If the entered email doesnt exists.
        if not user or user.userType != 'user':
            flash("Incorect credentials, please try again!")            
            return redirect(url_for('login'))
        # If the entered password is incorrect
        elif not check_password_hash(user.password, password):
            flash("Incorrect credentials, please try again!")
            msg = Message('Invalid Login', sender = app.config['MAIL_USERNAME'], recipients = [email])
            msg.body = "Invalid Login attempt."
            mail.send(msg)
            return redirect(url_for('login'))
        # If the login credentials are correct.
        else:            
            login_user(user)
            return redirect(url_for("getOTP"))
    return render_template("login.html", logged_in=current_user.is_authenticated)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))




@app.route('/getOTP')
def getOTP():
    otp = generateOTP()
    session['response'] = str(otp)
    msg = Message('OTP for Login', sender = app.config['MAIL_USERNAME'], recipients = [current_user.email])
    msg.body = "Your OTP is:"+str(otp)
    mail.send(msg)
    return render_template("otp.html", logged_in=current_user.is_authenticated)

@app.route('/validateOTP',methods=["GET","POST"])
def validateOTP():
    if request.method == "POST":        
        otpEntered=request.form.get('otp')
        if 'response' in session:
            s=session['response']            
            if s== otpEntered:
                session.pop('response',None)
                return redirect(url_for("dashboard"))
            else:
                flash("Incorrect OTP. Please enter again.")
                return render_template("otp.html", logged_in=current_user.is_authenticated)

@app.route('/dashboard')
@login_required
def dashboard():  

    news_client = gnewsclient.NewsClient(language='english',
                                location='United Kingdom',
                                topic='Business',
                                max_results=5)
    news_list = news_client.get_news()
    for item in news_list:
        item['title'] = item['title'].replace("\'","")        

    conn = get_db_connection()
    pensionDetails = conn.execute('SELECT * FROM pensionDetails WHERE userID = ?',
                        (current_user.id,)).fetchall()
    conn.close()  
    if len(pensionDetails)>0:
        userPensionDetails={}
        userPensionDetails['policyName']=pensionDetails[0][1]
        userPensionDetails['policyNumber']=pensionDetails[0][2]
        userPensionDetails['pensionFund']=pensionDetails[0][3]    
        return render_template("dashboard.html",menuItem="menu-home", 
        lastName=current_user.lastName,
        firstName=current_user.firstName, 
        userPensionDetails=json.dumps(userPensionDetails),
        news_list=json.dumps(news_list),
        logged_in=True)
    else:
        flash("Your account is being setup. Please wait until you get a notification.")
        return redirect(url_for('login'))


@app.route('/pensionDetails')
@login_required
def pensionDetails():  
    conn = get_db_connection()
    pensionDetails = conn.execute('SELECT * FROM pensionDetails WHERE userID = ?',
                        (current_user.id,)).fetchall()
    conn.close()  
    userPensionDetails={}
    userPensionDetails['policyName']=pensionDetails[0][1]
    userPensionDetails['policyNumber']=pensionDetails[0][2]
    userPensionDetails['pensionFund']=pensionDetails[0][3]
    userPensionDetails['employeeContribution']=pensionDetails[0][4]
    userPensionDetails['employerContribution']=pensionDetails[0][5]
    userPensionDetails['retirementAge']=pensionDetails[0][6] 
    return render_template("pensionDetails.html",menuItem="menu-pension", 
    lastName=current_user.lastName,
    firstName=current_user.firstName, 
    userPensionDetails=json.dumps(userPensionDetails),
    logged_in=True)

@app.route('/payments')
@login_required
def payments():  
    conn = get_db_connection()
    transactions = conn.execute('SELECT * FROM transactions WHERE userId = ?',
                        (current_user.id,)).fetchall()
    conn.close()
    payments = []
    for i in range(0,len(transactions)):
        payment={}
        payment['referenceNumber']=transactions[i][1]
        payment['description']=transactions[i][2]
        payment['from']=transactions[i][3]
        payment['amount']=transactions[i][4]
        payment['transactionDate']=transactions[i][5]
        payment['currency']=transactions[i][6]
        payment['transactionType']=transactions[i][7]
        payments.append(payment)
    
    
    return render_template("payments.html",menuItem="menu-payments", 
    lastName=current_user.lastName,
    firstName=current_user.firstName, 
    payments=json.dumps(payments),
    logged_in=True)

@app.route('/beneficiaries', methods=["GET", "POST"])
@login_required
def beneficiaries():
    conn = get_db_connection()
    if request.method == "POST":  
        newBen = request.get_json()
        if newBen['flowType']=="editBen":
            name = newBen['benName2']
            relation = newBen['benRelation2']
            percentage = newBen['benPercentage2']
            benId =newBen['benId2']
            conn.execute('UPDATE beneficiaries set name = ?,relation = ?,percentage = ? WHERE userId = ? AND benId = ?',
                            (name,relation,percentage,current_user.id,benId)).fetchall()
            conn.commit()
            msg = Message('Changes to your beneficiary', sender = app.config['MAIL_USERNAME'], recipients = [current_user.email])
            msg.body = "Updates to beneficiary details were successful."
            mail.send(msg)
        
        if newBen['flowType']=="Delete":            
            benId =newBen['benId2']
            conn.execute('DELETE from beneficiaries WHERE userId = ? AND benId = ?',
                            (current_user.id,benId)).fetchall()
            conn.commit()
            msg = Message('Changes to your beneficiary', sender = app.config['MAIL_USERNAME'], recipients = [current_user.email])
            msg.body = "Delete beneficiary was successful."
            mail.send(msg)
                   
        
        if newBen['flowType']=="addBen":
            
            name = newBen['benName1']
            relation = newBen['benRelation1']
            percentage = newBen['benPercentage1']
            benId = "BT"+str(random.randint(1000, 9999))
            conn.execute('INSERT into beneficiaries (name,relation,percentage,benId,userId) VALUES (?,?,?,?,?)',
                            (name,relation,percentage,benId,current_user.id)).fetchall()
            conn.commit()
            msg = Message('Added a new beneficiary', sender = app.config['MAIL_USERNAME'], recipients = [current_user.email])
            msg.body = "A new beneficiary was addedd succesfully."
            mail.send(msg) 
    
    beneficiariesList = conn.execute('SELECT * FROM beneficiaries WHERE userId = ?',
                        (current_user.id,)).fetchall()
    conn.close()
    beneficiaries = []
    for i in range(0,len(beneficiariesList)):
        beneficiary={}
        beneficiary['name']=beneficiariesList[i][0]
        beneficiary['relation']=beneficiariesList[i][1]
        beneficiary['percentage']=beneficiariesList[i][2]
        beneficiary['benId']=beneficiariesList[i][3]
        beneficiary['userId']=beneficiariesList[i][4]
        beneficiaries.append(beneficiary)
    
    
    return render_template("beneficiaries.html",menuItem="menu-ben", 
    lastName=current_user.lastName,
    firstName=current_user.firstName, 
    beneficiaries=json.dumps(beneficiaries),
    logged_in=True)

@app.route('/profile',methods=["GET", "POST"])
@login_required
def profile():    
    
    if request.method == "POST":
        conn = get_db_connection()
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        ni = request.form.get('ni')
        mobile = request.form.get('mobile')
        date = request.form.get('dob')
        image=request.files['image1'].read()
        if image!=b'':
            conn.execute("UPDATE user SET firstName=?,lastName=?,email=?,ni=?,mobile=?,date=?,image=? WHERE id=?", 
            (fname,lname,email,ni,mobile,date,image,current_user.id))
        else:
            conn.execute("UPDATE user SET firstName=?,lastName=?,email=?,ni=?,mobile=?,date=? WHERE id=?", 
            (fname,lname,email,ni,mobile,date,current_user.id))
        conn.commit() 
        conn.close()
        return redirect(url_for("profile"))
    
    return render_template("profile.html",menuItem="menu-profile", 
    firstName=current_user.firstName,
    lastName=current_user.lastName,
    email=current_user.email,
    ni=current_user.ni,
    mobile=current_user.mobile,
    dob=current_user.date,
    image=(base64.b64encode(current_user.image)).decode("UTF-8"),
    logged_in=True)


@app.route('/pensionCal',methods=["GET", "POST"])
@login_required
def pensionCal():   
    return render_template("pensionCal.html",menuItem="menu-cal", 
    logged_in=True)

@app.route('/supportPrivacy',methods=["GET", "POST"])
@login_required
def supportPrivacy():   
    conn = get_db_connection()
    supportData = conn.execute('SELECT privacyPolicy FROM support',
                        ()).fetchall()
    conn.close()
    
    
    return render_template("support.html",menuItem="menu-support",supportType="privacyPolicy", supportData=supportData[0][0],
    logged_in=True)

@app.route('/supportCookie',methods=["GET", "POST"])
@login_required
def supportCookie():   
    conn = get_db_connection()
    supportData = conn.execute('SELECT coockiePolicy FROM support',
                        ()).fetchall()
    conn.close()
    return render_template("support.html",menuItem="menu-support",supportType="cookiePolicy", supportData=supportData[0][0],
    logged_in=True)

@app.route('/supportTerms',methods=["GET", "POST"])
@login_required
def supportTerms():   
    conn = get_db_connection()
    supportData = conn.execute('SELECT termsAndConditions FROM support',
                        ()).fetchall()
    conn.close()
    return render_template("support.html",menuItem="menu-support",supportType="Terms", supportData=supportData[0][0],
    logged_in=True)

@app.route('/support',methods=["GET", "POST"])
@login_required
def support():   
    conn = get_db_connection()
    supportData = conn.execute('SELECT termsAndConditions FROM support',
                        ()).fetchall()
    conn.close()
    return render_template("support.html",menuItem="menu-support",supportType="", supportData="",
    logged_in=True)


@app.route('/supportContactInfo', methods=["GET", "POST"])
@login_required
def supportContactInfo(): 
    conn = get_db_connection()
    
    contactDetails = conn.execute("select * from support",()).fetchall()
    conn.close() 
    contactUsInfo = []
    contactUsJson = {}
    contactUsJson['email1'] = contactDetails[0][3]
    contactUsJson['email2'] = contactDetails[0][4]
    contactUsJson['phone1'] = contactDetails[0][5]
    contactUsJson['phone2'] = contactDetails[0][6]
    contactUsJson['address'] = contactDetails[0][7]
    contactUsInfo.append(contactUsJson)
    return render_template("supportContactInfo.html",menuItem="menu-support",contactUsInfo  =json.dumps(contactUsInfo))

@app.route('/supportFAQ', methods=["GET", "POST"])
@login_required
def supportFAQ(): 
    conn = get_db_connection()
    
    faqs = conn.execute("select * from faqs",()).fetchall()
    conn.close() 
    faqsJson = {}
    for i in range(0,len(faqs)): 
        jsonQ = {}
        jsonQ["question"] = faqs[i][1]
        jsonQ["answer"] = faqs[i][2]       
        if faqs[i][0] not in faqsJson:
            faqsJson[faqs[i][0]] = []
            faqsJson[faqs[i][0]].append(jsonQ)
        else:            
            faqsJson[faqs[i][0]].append(jsonQ)
    print("========faqsJson: ",json.dumps(faqsJson))
    return render_template("supportFAQ.html",menuItem="menu-support",faqsJson  =json.dumps(faqsJson))


@app.route('/schemes', methods=["GET", "POST"])
@login_required
def schemes(): 
    conn = get_db_connection()
    
    schemes = conn.execute("select * from schemes",()).fetchall()
    conn.close() 
    schemesJson = []
    for i in range(0,len(schemes)): 
        jsonQ = {}
        jsonQ["schemeHeading"] = schemes[i][0]
        jsonQ["schemeDescription"] = schemes[i][1]
        jsonQ["schemePhoto"] = (base64.b64encode(schemes[i][3])).decode("UTF-8") 
        schemesJson.append(jsonQ)
    return render_template("schemes.html",menuItem="menu-schemes",schemesJson  =json.dumps(schemesJson))




'''
Admin Functions
'''
@app.route('/adminlogin', methods=["GET", "POST"])
def adminlogin():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        # The below is used to find the user by email from the DB.
        user = User.query.filter_by(email=username).first()
        # If the email doesnt exists.
        if not user or user.userType != 'admin':
            flash("Incorect email, please try again!")
            return redirect(url_for('adminlogin'))
        # If the password is incorrect
        elif not check_password_hash(user.password, password):
            flash("Incorrect password, please try again!")
            return redirect(url_for('adminlogin'))
        # If the login credentials are correct.
        else:
            login_user(user)
        return redirect(url_for("adminDashboard"))
    return render_template("adminlogin.html", logged_in=current_user.is_authenticated)


@app.route('/adminDashboard', methods=["GET", "POST"])
@login_required
def adminDashboard():  
    if request.method == "POST":
        if request.form.get('flowType')=='search':
            searchKey = request.form.get('userKey')
            conn = get_db_connection()
            userDetails = conn.execute('SELECT * FROM user WHERE email = ?',
                            (searchKey,)).fetchall()
            conn.close()
            if len(userDetails)>0:        
                return render_template("adminDashboard.html",
                flowType = request.form.get('flowType'),
                id=userDetails[0][0],
                firstName=userDetails[0][3],
                lastName=userDetails[0][4],
                email=userDetails[0][1],
                ni=userDetails[0][5],
                mobile=userDetails[0][6],
                dob=userDetails[0][8],
                menuItem='menu-userDetails',
                searchKey=searchKey)
            else:
                flash("User not found.")
                return render_template("adminDashboard.html",flowType='dashboard',menuItem='menu-userDetails')
            
        if request.form.get('flowType')=='update':
            fname=request.form.get('fname')
            lname=request.form.get('lname')
            email=request.form.get('email')
            ni = request.form.get('ni')
            mobile = request.form.get('mobile')
            date = request.form.get('dob')
            id = request.form.get('userId')
            conn = get_db_connection()
            conn.execute("UPDATE user SET firstName=?,lastName=?,email=?,ni=?,mobile=?,date=? WHERE id=?", 
            (fname,lname,email,ni,mobile,date,id))
            conn.commit() 
            conn.close()
            flash("User details updated successfully.")
            return render_template("adminDashboard.html",flowType='dashboard',menuItem='menu-userDetails')
    return render_template("adminDashboard.html",flowType='dashboard',menuItem='menu-userDetails')

@app.route('/adminPension', methods=["GET", "POST"])
@login_required
def adminPension():
    if request.method == "POST":
        if request.form.get('flowType')=='search':
            searchKey = request.form.get('userKey')
            conn = get_db_connection()
            checkUser = conn.execute('select count(*) from user where user.email=?',
                            (searchKey,)).fetchall()
            if checkUser[0][0]>0  :
                userDetails = conn.execute('SELECT * FROM pensionDetails WHERE pensionDetails.userID = ( select user.id from user where user.email=?)',
                                (searchKey,)).fetchall()
                conn.close()        
                return render_template("adminPension.html",
                flowType = request.form.get('flowType'),
                id=userDetails[0][0],
                policyName=userDetails[0][1],
                policyNumber=userDetails[0][2],
                pensionFund=userDetails[0][3],
                employeeContribution=userDetails[0][4],
                employerContribution=userDetails[0][5],
                retirementAge=userDetails[0][6],
                menuItem='menu-pensionDetails',
                searchKey=searchKey)
            else:
                flash("User not found.")
                return render_template("adminPension.html",flowType='main',menuItem='menu-pensionDetails')    
            
        if request.form.get('flowType')=='update':
            policyName=request.form.get('policyName')
            policyNumber=request.form.get('policyNumber')
            pensionFund=request.form.get('pensionFund')
            employeeContribution = request.form.get('employeeContribution')
            employerContribution = request.form.get('employerContribution')
            retirementAge = request.form.get('retirementAge')
            id = request.form.get('userId')
            conn = get_db_connection()
            conn.execute("UPDATE pensionDetails SET policyName=?,policyNumber=?,pensionFund=?,employeeContribution=?,employerContribution=?,retirementAge=? WHERE userId=?", 
            (policyName,policyNumber,pensionFund,employeeContribution,employerContribution,retirementAge,id))
            conn.commit() 
            conn.close()
            flash("User details updated successfully.")
            return render_template("adminPension.html",flowType='main',menuItem='menu-pensionDetails')
    return render_template("adminPension.html",flowType='main',menuItem='menu-pensionDetails')

@app.route('/adminBen', methods=["GET", "POST"])
@login_required
def adminBen():
    if request.method == "POST":
        if request.data!=b'':
            deleteBen = request.get_json()
        if request.form.get('flowType')=='search':
            searchKey = request.form.get('userKey')
            conn = get_db_connection()
            checkUser = conn.execute('select count(*) from user where user.email=?',
                            (searchKey,)).fetchall()
            if checkUser[0][0]>0  :
                beneficiariesList = conn.execute('SELECT * FROM beneficiaries WHERE beneficiaries.userId = ( select user.id from user where user.email=?)',
                                (searchKey,)).fetchall()
                conn.close()  
                beneficiaries = []
                for i in range(0,len(beneficiariesList)):
                    beneficiary={}
                    beneficiary['name']=beneficiariesList[i][0]
                    beneficiary['relation']=beneficiariesList[i][1]
                    beneficiary['percentage']=beneficiariesList[i][2]
                    beneficiary['benId']=beneficiariesList[i][3]
                    beneficiary['userId']=beneficiariesList[i][4]
                    beneficiaries.append(beneficiary)      
                return render_template("adminBen.html",
                flowType = request.form.get('flowType'),
                beneficiaries=json.dumps(beneficiaries),
                menuItem='menu-beneficiary',
                searchKey=searchKey)   
            else:
                flash("User not found.")
                return render_template("adminBen.html",flowType='main',menuItem='menu-beneficiary')

        if request.form.get('flowType')=='update':
            benId=request.form.get('benId')
            userId=request.form.get('userId')            
            conn = get_db_connection()
            conn.execute("DELETE from beneficiaries WHERE userId=? and benId=?", 
            (userId,benId))
            conn.commit() 
            conn.close()
            flash("Beneficiary deleted successfully.")
            return render_template("adminBen.html",flowType='main',menuItem='menu-beneficiary')
        if deleteBen['flowType']=='notify':
            searchKey=deleteBen['searchKey']
            msg = Message('Manage You Beneficiaries', sender = app.config['MAIL_USERNAME'], recipients = [searchKey])
            msg.body = "You still have a proportion of fund that can be assigned to a beneficiary. Please login and add at your convenience."
            mail.send(msg)
            return 'Notification was sent successfully.'
    return render_template("adminBen.html",flowType='main',menuItem='menu-beneficiary')

@app.route('/adminTandC', methods=["GET", "POST"])
@login_required
def adminTandC(): 
    conn = get_db_connection()
    if request.method == "POST":
        tAndCText=request.form.get('tAndCText')
        conn.execute("UPDATE support SET termsAndConditions=? ", (tAndCText,))
        conn.commit() 
        
        termsAndConditions = conn.execute("select termsAndConditions from support",()).fetchall()
        conn.close()
        return render_template("adminTandC.html",flowType='main',menuItem='menu-tAndC',termsAndConditions = termsAndConditions[0][0])
    termsAndConditions = conn.execute("select termsAndConditions from support",()).fetchall()
    return render_template("adminTandC.html",flowType='main',menuItem='menu-tAndC',termsAndConditions = termsAndConditions[0][0])

@app.route('/adminPrivacy', methods=["GET", "POST"])
@login_required
def adminPrivacy(): 
    conn = get_db_connection()
    if request.method == "POST":
        privacyText=request.form.get('privacyText')
        conn.execute("UPDATE support SET privacyPolicy=? ", (privacyText,))
        conn.commit() 
        
        privacyPolicy = conn.execute("select privacyPolicy from support",()).fetchall()
        conn.close()
        return render_template("adminPrivacy.html",flowType='main',menuItem='menu-privacy',privacyPolicy = privacyPolicy[0][0])
    privacyPolicy = conn.execute("select privacyPolicy from support",()).fetchall()
    return render_template("adminPrivacy.html",flowType='main',menuItem='menu-privacy',privacyPolicy = privacyPolicy[0][0])

@app.route('/adminCookie', methods=["GET", "POST"])
@login_required
def adminCookie(): 
    conn = get_db_connection()
    if request.method == "POST":
        cookieText=request.form.get('cookieText')
        conn.execute("UPDATE support SET coockiePolicy=? ", (cookieText,))
        conn.commit() 
        
        cookiePolicy = conn.execute("select coockiePolicy from support",()).fetchall()
        conn.close()
        return render_template("adminCookie.html",flowType='main',menuItem='menu-cookie',cookiePolicy = cookiePolicy[0][0])
    cookiePolicy = conn.execute("select coockiePolicy from support",()).fetchall()
    return render_template("adminCookie.html",flowType='main',menuItem='menu-cookie',cookiePolicy = cookiePolicy[0][0])


@app.route('/adminContactUs', methods=["GET", "POST"])
@login_required
def adminContactUs(): 
    conn = get_db_connection()
    if request.method == "POST":
        email1=request.form.get('email1')
        email2=request.form.get('email2')
        phone1=request.form.get('phone1')
        phone2=request.form.get('phone2')
        address=request.form.get('address')
        conn.execute("UPDATE support SET email1=?,email2=?,phone1=?,phone2=?,address=? ", (email1,email2,phone1,phone2,address,))
        conn.commit() 
        
               
    contactDetails = conn.execute("select * from support",()).fetchall()
    conn.close() 
    contactUsInfo = []
    contactUsJson = {}
    contactUsJson['email1'] = contactDetails[0][3]
    contactUsJson['email2'] = contactDetails[0][4]
    contactUsJson['phone1'] = contactDetails[0][5]
    contactUsJson['phone2'] = contactDetails[0][6]
    contactUsJson['address'] = contactDetails[0][7]
    contactUsInfo.append(contactUsJson)
    return render_template("adminContactUs.html",flowType='main',menuItem='menu-contact',contactUsInfo  =json.dumps(contactUsInfo))

@app.route('/adminFAQ', methods=["GET", "POST"])
@login_required
def adminFAQ(): 
    conn = get_db_connection()
    if request.method == "POST":
        if request.form.get('flowType') == "edit":
            question=request.form.get('question')
            answer=request.form.get('answer')
            FAQId=request.form.get('FAQId')
            
            conn.execute("UPDATE faqs SET question=?,answer=? WHERE FAQId=? ", (question,answer,FAQId,))
            conn.commit() 
        if request.form.get('flowType') == "delete":
            FAQId=request.form.get('FAQId')
            print(FAQId)
            conn.execute("DELETE from faqs WHERE FAQId=?", (FAQId))
            conn.commit()
        if request.form.get('flowType') == "add":
            question=request.form.get('question')
            answer=request.form.get('answer')
            module= request.form.get('module')
            FAQId=request.form.get('FAQId')
            print(FAQId)
            conn.execute('INSERT into faqs (question,answer,module) VALUES (?,?,?)',
                            (question,answer,module)).fetchall()            
            conn.commit()

    faqs = conn.execute("select * from faqs",()).fetchall()
    conn.close() 
    faqsJson = {}
    for i in range(0,len(faqs)): 
        jsonQ = {}
        jsonQ["question"] = faqs[i][1]
        jsonQ["answer"] = faqs[i][2]
        jsonQ["FAQId"] = faqs[i][3]       
        if faqs[i][0] not in faqsJson:
            faqsJson[faqs[i][0]] = []
            faqsJson[faqs[i][0]].append(jsonQ)
        else:            
            faqsJson[faqs[i][0]].append(jsonQ)
    return render_template("adminFAQ.html",flowType='main',menuItem='menu-FAQ',faqsJson  =json.dumps(faqsJson))


@app.route('/adminSchemes', methods=["GET", "POST"])
@login_required
def adminSchemes(): 
    conn = get_db_connection()
    if request.method == "POST":
        if request.form.get('flowType') == "edit":
            schemeHeading=request.form.get('schemeHeading')
            schemeDescription=request.form.get('schemeDescription')
            schemePhoto=request.files['schemePhotoEdit'].read()
            schemeId=request.form.get('schemeId')
            if schemePhoto!=b'':
                conn.execute("UPDATE schemes SET schemeHeading=?,schemeDescription=?,schemePhoto=? WHERE schemeId=? ", (schemeHeading,schemeDescription,schemePhoto,schemeId,))
            else:
                conn.execute("UPDATE schemes SET schemeHeading=?,schemeDescription=? WHERE schemeId=? ", (schemeHeading,schemeDescription,schemeId,))
            conn.commit() 
        if request.form.get('flowType') == "delete":
            schemeId=request.form.get('schemeId')
            print(schemeId)
            conn.execute("DELETE from schemes WHERE schemeId=?", (schemeId))
            conn.commit()
        if request.form.get('flowType') == "add":
            schemeHeading=request.form.get('schemeHeading')
            schemeDescription=request.form.get('schemeDescription')
            schemePhoto=request.files['schemePhoto'].read()
            conn.execute('INSERT into schemes (schemeHeading,schemeDescription,schemePhoto) VALUES (?,?,?)',
                            (schemeHeading,schemeDescription,schemePhoto)).fetchall()            
            conn.commit()

    schemes = conn.execute("select * from schemes",()).fetchall()
    conn.close() 
    schemesJson = []
    for i in range(0,len(schemes)): 
        jsonQ = {}
        jsonQ["schemeHeading"] = schemes[i][0]
        jsonQ["schemeDescription"] = schemes[i][1]
        jsonQ["schemeId"] = schemes[i][2]   
        jsonQ["schemePhoto"] = (base64.b64encode(schemes[i][3])).decode("UTF-8")      
        schemesJson.append(jsonQ)
        
    return render_template("adminSchemes.html",flowType='main',menuItem='menu-schemes',schemesJson  =json.dumps(schemesJson))
if __name__ == "__main__":
    app.run(host="0.0.0.0")
