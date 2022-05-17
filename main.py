
import flask as fk
import sqlite3
import re
import logging
from random import randint
import hashlib
import hmac
from cryptography.fernet import Fernet
import base64
from datetime import datetime

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
#cursor.row_factory = dict_factory

#connectionP = sqlite3.connect("helpposts.db", check_same_thread = False)
#cursorP = connectionP.cursor()
#cursorP.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, name TEXT, position TEXT, room TEXT, content TEXT, dueDate TEXT)")
#cursor.execute("DROP TABLE signups")
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, usertype TEXT, username TEXT, password TEXT, nickname TEXT)")

cursor.execute("CREATE TABLE IF NOT EXISTS requests (ownerid INTEGER, name TEXT, location TEXT, position TEXT, description TEXT, dueDate TEXT, timemade REAL, requestid INTEGER)")

cursor.execute("CREATE TABLE IF NOT EXISTS signups (requestid INTEGER, userid INTEGER)")

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
def getUserIDFromCookie(cookieText):
    cookieText = cookieText.split("|")
    username = cookieText[0]
    encPass = cookieText[1]
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if userid := cursor.fetchone():
        return int(userid[0])
    else:
        return False

def getUserNicknameFromCookie(cookieText):
    cursor.execute("SELECT nickname FROM users WHERE username = ?",(cookieText.split("|")[0],))
    return cursor.fetchone()[0]
    
#Hash will be used in the database for passwords
def hash_str(s,key): 
  return hmac.new(str(key).encode('utf-8'),str(s).encode('utf-8'),digestmod=hashlib.sha256).hexdigest()

def checkUserLogin(cookieText):
    if userid := getUserIDFromCookie(cookieText):
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

def createRequest(idVal,name,loc,desc,due):

    sql = ''' INSERT INTO requests(ownerid, name, position, location, description, dueDate, timemade, requestid) VALUES(?,?,?,?,?,?,?,?) '''
    
    current = datetime.now().timestamp()

    cursor.execute("SELECT usertype FROM users WHERE id = ?", (idVal,))
    position = cursor.fetchone()[0]
    requestid = randint(10**10,10**11)
    
    cursor.execute(sql, (idVal,name,position,loc,desc,due,current,requestid))
    database.commit()

#Creates a new user in the database
def createUser(userType,username,password):
    idVal = randint(10**10,10**11)
    hashedPassword = hash_str(password,idVal)
    
    sql = ''' INSERT INTO users(id, usertype, username, password, nickname) VALUES(?,?,?,?,?) '''
    
    cursor.execute(sql, (idVal,userType,username,hashedPassword,username))
    database.commit()
    
    return username + "|" + createCookieStringHash(hashedPassword,idVal)

def getSignups(cookietext):
    p = cursor.execute("SELECT requestid FROM signups WHERE userid = ?",(getUserIDFromCookie(cookietext),)).fetchall()
    posts = []
    #logging.info(p)
    for s in range(len(p)):
        cursor.execute("SELECT * FROM requests WHERE requestid = ?", (p[s][0],))
        posts.append(cursor.fetchone())
    return posts
    
#Returns a string of the current database entires
def debugDatabaseStrUsers():
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    string = ""
    for user in users:
        string += f"{user[0]}  {user[1]}  {user[2]}  {user[3]} {user[4]} <br>"
        
    #logging.info(string)
    return string
    


def getPosts(startPage,numPerPage):
    p = cursor.execute(f"SELECT * FROM requests ORDER BY timemade DESC LIMIT {numPerPage} OFFSET {startPage * numPerPage}")
    posts = [x for x in p]
    return posts

    ###-----WEBPAGE LOGIC-----###
    
@app.route('/settingspage',methods = ['POST', 'GET'])
def settings():
    if "userinfo" not in fk.request.cookies:
        return fk.make_response(fk.redirect(fk.url_for("loginpage"), code=302))

    cookie = fk.request.cookies.get("userinfo")
    
    if not checkUserLogin(cookie):
        return fk.make_response(fk.redirect(fk.url_for("loginpage"), code=302))
    
    userid = getUserIDFromCookie(cookie)
    
    method = fk.request.method
    
    if method == "POST":
      
        newnick = fk.request.form["nickname"]
        cursor.execute("UPDATE users SET nickname = ? WHERE id =?",(newnick,userid))
        database.commit()
    
    nick = getUserNicknameFromCookie(cookie)
    
    return fk.render_template('settingspage.html',currentname = nick)
    
    
@app.route('/mainpage',methods = ['POST','GET'])
def mainpage():
    method = fk.request.method
    if "userinfo" not in fk.request.cookies:
        return fk.make_response(fk.redirect(fk.url_for("loginpage"), code=302))

    cookie = fk.request.cookies.get("userinfo")

    if not checkUserLogin(cookie):
        return fk.make_response(fk.redirect(fk.url_for("loginpage"), code=302))


    if method == "POST":
        attemptsignupid = (list(fk.request.form.keys())[0])
        if attemptsignupid[-6:] == 'remove':
            cursor.execute("DELETE FROM signups WHERE requestid = ?",(int(attemptsignupid[:-6]),))
        else:    
            cursor.execute("INSERT INTO signups(requestid,userid) VALUES(?,?)", (int(attemptsignupid),getUserIDFromCookie(cookie)))
        database.commit()
    
    return fk.render_template('mainpage.html', signups=getSignups(cookie), posts=getPosts(0,10),name = getUserNicknameFromCookie(cookie)) 
        

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
                #Valid credentials. A new cookie is created
                if hash_str(password,int(result[0])) == result[1]:
                    cText = username + "|" + createCookieStringHash(result[1],result[0])
                    resp = fk.make_response(fk.redirect(fk.url_for("mainpage"), code=302))
                    resp.set_cookie("userinfo", cText)
                    return resp
                #Invalid credentials
                else:
                    return fk.render_template('login.html', username = username, password = "", logerror = "Please enter valid username and password!")
                    
            #User does not exist
            else:
                return fk.render_template('login.html', username = username, password = "", logerror = "Please enter valid username and password!")
            
        return fk.render_template('login.html', username = username, password = "", logerror = "Please enter valid username and password!")

@app.route('/createNew', methods = ['POST', 'GET'])
def createNew() :
  method = fk.request.method
  if method == "GET" :
    return fk.render_template('createNew.html')
  else :
    username=fk.request.form["user"]
    password=fk.request.form["pass"]
    password2=fk.request.form["passConf"]
    role=fk.request.form["roles"] #student, teacher, or admin
    if (password == password2 and (USERNAME_RE.search(username) and PASSWORD_RE.search(password))):
      cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
      if cursor.fetchone() :
        return fk.render_template('createNew.html', username="", password="", password2="", logerror = "Username or Password already exists!")
      else :
        cText = createUser(role,username,password)
        resp = fk.make_response(fk.redirect(fk.url_for("mainpage"), code=302))
        resp.set_cookie("userinfo", cText)
        return resp
    else:
      return fk.render_template('createNew.html', username=username, password="", password2="", logerror = "Please enter valid username and matching passwords!")

@app.route('/createPost', methods=['POST', 'GET'])
def createPost() :
  method= fk.request.method
  cookie = fk.request.cookies.get("userinfo")
    
  if method == "GET" :
    nick = getUserNicknameFromCookie(cookie)
      
    return fk.render_template('createPost.html',name=nick)
  else :
    name = fk.request.form["name"]
    room = fk.request.form["room"]
    description = fk.request.form["description"]
    dueDat = fk.request.form["dueDate"]
    cookie = fk.request.cookies.get("userinfo")
      
    createRequest(getUserIDFromCookie(cookie),name,room,description,dueDat)

    return fk.make_response(fk.redirect(fk.url_for("mainpage"), code=302))
    #s = cursorP.execute("SELECT * FROM posts")
    #posts = [x for x in s]
    #return fk.render_template("mainpage.html", posts=posts)

app.run(host='0.0.0.0', port=8080)