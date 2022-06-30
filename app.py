from flask import Flask,Response,request,json,render_template,jsonify
from datetime import datetime,timedelta
from flask import *
import hashlib
from flask_cors import CORS
import pymongo
import requests
import jwt
from flask_authorize import Authorize
from flask_login import LoginManager

app = Flask(__name__,template_folder="../fe/")
cors = CORS(app, resources={r"/api/*": {"origin": "*"}})
client = pymongo.MongoClient('localhost', 27017)
#client = pymongo.MongoClient("mongodb+srv://diabeo2k:cuong08082000@internweb.p9kqja0.mongodb.net/?retryWrites=true&w=majority",connect=False)
db = client.dataSource
isLogin = False
token = None
# login = LoginManager(app)
# authorize = Authorize(app)
@app.route("/")
def index():
    return render_template('index.html')
@app.route("/register")
def register_template():
    return render_template('register.html')
@app.route("/login")
def login_template():
    return render_template('login.html')
@app.route("/admin")
def admin_template():
    return render_template('admin.html')
def goto_home():
    return render_template('index.html')
def goto__admin():
    return render_template('admin.html')
@app.route("/api/register",methods=['POST'])
def register():
    idUser= datetime.now().microsecond
    username =request.form['username']
    password = request.form['password']
    Fname =request.form['Fname']
    gtint = request.form['gt']
    if gtint == '0' :
        gt = 'nam' 
    else: 
        gt = 'nu'
    datebirth =request.form['datebirth']
    email =request.form['email']
    sdt =request.form['sdt']
    address =request.form['address']
    timecreated = datetime.now()
    isAvalid = False
    for user in db.user.find():
        if username == user['username']:
            isAvalid = True
        else: isAvalid = False
    if not isAvalid:
        user ={"_id":idUser,"username":username,"password":hash_password(password),"Fname":Fname,"gt":gt,"dateofbirth":datebirth,"email":email,"sdt":sdt,"address":address,"timecreated":timecreated}
        db.user.insert_one(user)
    index()
    return Response(
        response ="Successfully registered with username: " + username,
        status= 200,
        mimetype = "application/json"
    )
@app.route("/api/login",methods=["POST"])
def login():
    global token
    global isLogin
    username = request.form['username']
    password = request.form['password']
    for item in db.user.find({"username":username}):
        if item['password'] == hash_password(password):
            islogin = True
            # print("dayy")
            # print(islogin)
            # print(token)
            token = generate_token(username)
            response = json.dumps({"status":"Successfully logged","token": token,},default=vars)
            status = 200   
        else:
            response = "password is incorrect"
            status = 401
    if isLogin and decode_auth_token(token) == "admin":
        goto__admin()
    else:
        goto_home()
    return Response(
        response = response,
        status = status,
        mimetype="application/json"
    )
    
@app.route("/api/getallusers/<string:username>",methods=["GET", "POST"])
# @login.logged_in
# @authorize.getall
def getallusers(username):
    if username == 'admin':
        list = []
        # if isLogin:
        for item in  db.user.find():
            list.append(item)
        status = 200
        response = json.dumps({'data': list})
        # else:
        #     response = "Must be logged"
        #     status = 401
    else:
        response = "Must be adminstrator"
        status = 401
    return Response(
        response= response,
        status= status,
        mimetype="application/json"   
    )
@app.route("/api/deleteuser/<string:username>",methods=["GET"])
def deleteuser(username):
    if db.user.find({'username':username}):
        db.user.delete_one({'username':username})
        response = "Successfully deleted"
        status = 200
    else:
        response =  "Can't Find user with username: "   + username
        status = 404
    return Response(
        response= response,
        status= status,
        mimetype="application/json" 
    )
    
    
@app.route("/api/edituser/<string:username>",methods=["GET","POST"])
def edituser(username):
    email = request.form['email']
    sdt = request.form['sdt']
    newpassword = request.form['newpassword']
    rs = db.user.update_one({'username':username},{"$set":{'email':email, 'newpassword':hash_password(newpassword),'sdt':sdt}})
    if rs:
        reponse = "Successfully updated"
        status = 200
    else:
        response = "Error updating user"
        status = 404
    return Response(
        response= response,
        status= status,
        mimetype="application/json"
    )
def generate_token(username):
    SECRET_KEY="""\xf9'\xe4p(\xa9\x12\x1a!\x94\x8d\x1c\x99l\xc7\xb7e\xc7c\x86\x02MJ\xa0"""
    try:
        payload = {
            'exp': datetime.now() + timedelta(days=0, seconds=5),
            'iat': datetime.now(),
            'sub': username
        }
        return jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
    except Exception as e:
        return e
#decode token
def decode_auth_token(auth_token):
    SECRET_KEY="""\xf9'\xe4p(\xa9\x12\x1a!\x94\x8d\x1c\x99l\xc7\xb7e\xc7c\x86\x02MJ\xa0"""
    try:
        payload = jwt.decode(auth_token, options={"verify_signature": False})
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
def hash_password(password):
    return hashlib.sha256(password.encode("utf8")).hexdigest()
if __name__ == "__main__":
    app.run(debug=True)
    