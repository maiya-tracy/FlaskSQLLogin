from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
import re
import socket
import datetime
from mysql import connectToMySQL
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "This is my secret key"


def validateEmail(emailaddress):
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    if not EMAIL_REGEX.match(emailaddress):
        flash("Invalid Email Address!", "email")
        return False
    else:
        mysql = connectToMySQL("loginandregistration")
        query = "SELECT COUNT(*) as doesExist FROM loginandregistrations where email = %(email)s;"
        data = { "email": emailaddress }
        if (mysql.query_db(query,data)[0]['doesExist'] == 0):
            return True
        else:
            flash("Email already in system", "email")
            return False


def validateFirstName(firstname):
    if not len(firstname) >= 2:
        flash("Invalid First Name! - Must be 2 characters long", "firstname")
        return False
    else:
        if not str.isalpha(firstname) == True:
            flash(
                "Invalid First Name! - Can only contain alphabetic characters", "firstname")
            return False
        else:
            return True


def validateLastName(lastname):
    if not len(lastname) >= 2:
        flash("Invalid Last Name! - Must be 2 characters long", "lastname")
        return False
    else:
        if not str.isalpha(lastname) == True:
            flash(
                "Invalid Last Name! - Can only contain alphabetic characters", "lastname")
            return False
        else:
            return True


def validatePassword(pw):
    if not len(pw) >= 8:
        flash("Invalid Password! - Must be at least 8 characters long", "password")
        return False
    else:
        if not str.isalnum(pw) == True:
            flash("Invalid Password! - Must be alphanumeric", "password")
            return False
        else:
            return True


def validateConfirmPW(pw, conpw):
    if not (pw == conpw):
        flash("Password and Confirm Password must match", "confirmpw")
        return False
    else:
        return True

def validateLoginEmail(emailaddress):
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    if not EMAIL_REGEX.match(emailaddress):
        flash("Invalid Email Address!", "loginemail")
        return False
    else:
        return True

def checkEmailInDB(email):
    mysql = connectToMySQL("loginandregistration")
    query = "SELECT * FROM loginandregistrations where email = %(email)s;"
    data = { "email": email}
    query_check = "SELECT COUNT(*) as doesExist FROM loginandregistrations where email = %(email)s;"
    if mysql.query_db(query_check,data)[0]['doesExist'] == 0:
        result = False
    else:
        mysql = connectToMySQL("loginandregistration")
        result = mysql.query_db(query,data)
    return result

#This function will bring in a list of all available users to send messages to and list their names alphabtically in a drop down that will allow you to choose any other user to send a message to.
def allUsersReturn():
    mysql = connectToMySQL("loginandregistration")
    query = "SELECT *  FROM loginandregistrations ;"
    all_users = mysql.query_db(query)
    return all_users

def get_host_ip():
    host_name = socket.gethostname()
    host_ip = socket.gethostbyname(host_name)
    ip_info = {
        'ip': host_ip,
        'comp_name': host_name
    }
    print(ip_info)
    return ip_info

@app.route("/")
def index():
    session["isLoggedIn"] = False
    return render_template("index.html")


@app.route('/wall')
def success():
    if session["isLoggedIn"] == False:
        return redirect("/")
    else:
        user = checkEmailInDB(session['email_address'])
        mysql = connectToMySQL('loginandregistration')
        query = "SELECT concat(Sender.FirstName, ' ', Sender.LastName) as who_sent_me, messages.id as message_id, messages.sent_to_user_id AS sent_to_user_id, messages.sending_user_id AS sending_user_id, messages.message as message, messages.sent_at AS timestamp, timediff(now(), messages.sent_at) AS timepassed from messages join loginandregistrations as Sender on messages.sending_user_id = Sender.id join loginandregistrations as SentTo on messages.sent_to_user_id = SentTo.id where sent_to_user_id = %(user_id)s;"
        data = {
            "user_id": user[0]['id']
        }
        received_messages = mysql.query_db(query,data)
        if received_messages == False:
            received_messages = []
        all_users = allUsersReturn()
    return render_template("success.html", all_users=all_users, user=user, received_messages=received_messages)

@app.route('/wall/send', methods = ['POST'])
def send_msg():
    if len(request.form['message_text']) < 5:
        flash('Your message must be at least 5 characters long', 'message_send')
        return redirect('/wall')
    mysql = connectToMySQL('loginandregistration')
    query = 'INSERT INTO messages (sending_user_id, sent_to_user_id, message, sent_at) VALUES ( %(sender)s, %(receiver)s, %(message)s, NOW() )'
    data = {
        'sender': session['user_id'],
        'receiver': request.form['message_to'],
        'message': request.form['message_text']
    }
    print(session['user_id'])
    print(request.form['message_to'])
    print(request.form['message_text'])
    mysql.query_db(query, data)
    return redirect('/wall')

@app.route('/wall/delete', methods=["POST"])
def delete_msg():
    mysql = connectToMySQL('loginandregistration')
    query = "SELECT sent_to_user_id from messages where id = %(message_id)s;"
    data = {
        "message_id": request.form['message_id']
    }
    # print(mysql.query_db(query,data))
    # print("*!*!*!**!*!")
    if mysql.query_db(query,data)[0]['sent_to_user_id'] != str(session['user_id']):
        return redirect('/terribleperson')
    else:
        mysql = connectToMySQL('loginandregistration')
        queryDelete = "DELETE from messages where id = %(message_id)s;"
        data = {
            "message_id": request.form['message_id']
        }
    mysql.query_db(queryDelete,data)
    return redirect('/wall')

@app.route('/terribleperson')
def terribleperson():
    ip_info = get_host_ip()
    if 'hacker' in session:
        session.clear()
        return redirect('/')
    else:
        session['hacker'] = 1
        return render_template('terribleperson.html', ip_info = ip_info)

@app.route("/register", methods=["POST"])
def register():
    current_form = request.form
    isTrue = True
    if validateEmail(request.form["email"]) == False:
        isTrue = False
    if validateFirstName(request.form["first_name"]) == False:
        isTrue = False
    if validateLastName(request.form["last_name"]) == False:
        isTrue = False
    if validatePassword(request.form["password"]) == False:
        isTrue = False
    if validateConfirmPW(request.form["password"], request.form["pwconfirm"]) == False:
        isTrue = False
    if isTrue == False:
        flash(request.form["first_name"], "holdFName")
        flash(request.form["last_name"], "holdLName")
        flash(request.form["email"], "holdEmail")
        return redirect('/')
    elif isTrue == True:
        mysql = connectToMySQL('loginandregistration')
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        query = "INSERT INTO loginandregistrations (FirstName, LastName, Email, Password, created_at, updated_at) VALUES (%(firstname)s, %(lastname)s, %(email)s, %(password)s, NOW(), NOW());"
        data = {
            "firstname": request.form["first_name"],
            "lastname": request.form["last_name"],
            "email": request.form["email"],
            "password": pw_hash
        }
        id = mysql.query_db(query, data)
        session["isLoggedIn"] = True
        session["user_id"] = id
        session["email_address"] = request.form["email"]
        return redirect("/wall")


@app.route("/login", methods={'POST'})
def log_in():
    if validateLoginEmail(request.form['emailLogin']) == True:
        user = checkEmailInDB(request.form['emailLogin'])
        print(user)
        print("***********")
        if user == False:
            flash("Login Failed", "loginemail")
            flash(request.form["emailLogin"], "holdLoginEmail")
            return redirect("/")
        elif len(request.form['passwordLogin']) >= 8:
            if bcrypt.check_password_hash(user[0]['Password'], request.form['passwordLogin']):
                session["isLoggedIn"] = True
                session["user_id"] = user[0]['id']
                session["email_address"] = user[0]['Email']
                return redirect("/wall")
            else:
                return redirect("/")
        else:
            return redirect("/")
    else:
        return redirect("/")


@app.route("/logout")
def log_out():
    session.clear()
    session["isLoggedIn"] = False
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
