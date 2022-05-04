
import flask as fk
import sqlite3
import re
import logging
from random import randint
import hashlib
import hmac
from cryptography.fernet import Fernet
import base64

###-----How Authentication Works
# When a user is first created its password is hashed 
# using its unique id and stored in the database.
# A cookie is created containing the user's username and a 
# encrypted form (type wip) of the hash. The encrypt/decrypt key
# is the user's id, which is never shared externally.

###-----SETUP-----###

#https://stackoverflow.com/a/57234760
logging.basicConfig(level = logging.INFO)

app = fk.Flask(
  __name__,
  static_folder="static",
  template_folder="templates",
)
#Will auto apply all changes but will not open in an external window
#app.run(debug=True)


database = sqlite3.connect("database.db", check_same_thread = False)
cursor = database.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, usertype TEXT, username TEXT, password TEXT)")
cursor.execute("CREATE TABLE IF NOT EXISTS requests (ownerid INTEGER PRIMARY KEY, location TEXT, description TEXT)")

USERNAME_RE = re.compile(r"^[\w-]{3,20}$")
#PASSWORD_RE = re.compile(r"^[.]{3,20}$")
PASSWORD_RE = re.compile(r"^[\w-]{3,20}$")

###-----HELPER FUNCTIONS-----###

#Currently using https://stackoverflow.com/a/55147077
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)

def createCookieStringHash(text,idVal):
    #Must be 32 characters long
    paddedKey = str(idVal) + ("~" * (32 - len(str(idVal))))

    b64Key = base64.urlsafe_b64encode(paddedKey.encode("utf-8"))
    bText = bytes(text,encoding="utf-8")
    
    return encrypt(bText,b64Key).decode("utf-8")
    
#Creates a new request in the database
def createRequest(idVal,loc,desc):

    sql = ''' INSERT INTO requests(ownerid, location, description) VALUES(?,?,?) '''
    
    cursor.execute(sql, (idVal,loc,desc))
    cursor.commit()

#Creates a new user in the database
def createUser(userType,username,password):
    idVal = randint(10000000000,100000000000)
    hashedPassword = hash_str(password,idVal)
    
    sql = ''' INSERT INTO users(id, usertype, username, password) VALUES(?,?,?,?) '''
    
    cursor.execute(sql, (idVal,userType,username,hashedPassword))
    database.commit()
    
    return username + "|" + createCookieStringHash(hashedPassword,idVal)

def checkUserLogin(cookieText):
    if userid := getUserIDFromCookie(cookieText):
        userid = int(userid[0])
    
        cursor.execute("SELECT password FROM users WHERE id = ?", (userid,))
        passHash = cursor.fetchone()[0]
        cookieHash = str(cookieText.split("|")[1])
        
        paddedKey = str(userid) + ("~" * (32 - len(str(userid))))

        b64Key = base64.urlsafe_b64encode(paddedKey.encode("utf-8"))

        bText = bytes(cookieHash,encoding="utf-8")
        
        attemptPass = decrypt(bText,b64Key).decode("utf-8")
        
        if passHash == attemptPass:
            return True
        return False
        
    else:
        return False
    
def getUserIDFromCookie(cookieText):
    cookieText = cookieText.split("|")
    username = cookieText[0]
    encPass = cookieText[1]
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if userid := cursor.fetchone():
        return userid
    else:
        return False

#Hash will be used in the database for passwords
def hash_str(s,key): 
  return hmac.new(str(key).encode('utf-8'),str(s).encode('utf-8'),digestmod=hashlib.sha256).hexdigest()
    
#Returns a string of the current database entires
def debugDatabaseStrUsers():
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    string = ""
    for user in users:
        string += f"{user[0]}  {user[1]}  {user[2]}  {user[3]} <br>"
        
    #logging.info(string)
    return string

@app.route('/mainpage')
def mainpage():
    if "userinfo" not in fk.request.cookies:
        return fk.make_response(fk.redirect(fk.url_for("loginpage"), code=302))

    cookie = fk.request.cookies.get("userinfo")
    
    if not checkUserLogin(cookie):
        return fk.make_response(fk.redirect(fk.url_for("loginpage"), code=302))

    
    
    return fk.render_template('mainpage.html', allUser = debugDatabaseStrUsers(),username = cookie.split("|")[0]) 
    
###-----WEBPAGE LOGIC-----###

@app.route('/')
@app.route('/attemptLogin',methods = ['POST', 'GET'])
def loginpage() :
    if "userinfo" in fk.request.cookies:
        if checkUserLogin(fk.request.cookies.get("userinfo")):
            logging.info("Cookie found and valid, redirecting")
            return fk.redirect(fk.url_for("mainpage"), code=302)
        else:
            logging.info("Cookie found but not valid, proceed to login")
    else:
        logging.info("No cookie found, proceed to login")
    
    method = fk.request.method
        
    if method == "GET":
        return fk.render_template('login.html')
    else:
        username = fk.request.form["user"]
        password = fk.request.form["pass"]
        if (USERNAME_RE.search(username) and PASSWORD_RE.search(password)):
            cursor.execute("SELECT id,password FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            logging.info("Result " + str(result))
            #If the user exists
            if result:
                #Valid credentials
                if hash_str(password,int(result[0])) == result[1]:
                    cText = username + "|" + createCookieStringHash(result[1],result[0])
                    resp = fk.make_response(fk.redirect(fk.url_for("mainpage"), code=302))
                    resp.set_cookie("userinfo", cText)
                    return resp
                #Invalid credentials
                else:
                    return fk.render_template('login.html', username = username, password = "", logerror = "Please enter valid username and password!")
                    
            #Create a new user
            #Probable want to make this its own page
            else:
                cText = createUser("stu",username,password)
                resp = fk.make_response(fk.redirect(fk.url_for("mainpage"), code=302))
                resp.set_cookie("userinfo", cText)
                return resp
            
            
        return fk.render_template('login.html', username = username, password = "", logerror = "Please enter valid username and password!")

#@app.route('/createNew', methods)
def createNewAcc() :
  pass

app.run(host='0.0.0.0', port=8080)