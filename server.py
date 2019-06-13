from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
import re
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
        query = "SELECT * from messages join loginandregistrations as Sender on messages.sending_user_id = Sender.id join loginandregistrations as SentTo on messages.sent_to_user_id = SentTo.id where sent_to_user_id = %(user_id)s;"
        data = {
            "user_id": user[0]['id']
        }
        received_messages = mysql.query_db(query,data)
        if received_messages == False:
            received_messages = []
        print("***********")
        print(received_messages)
        print("***********")
    return render_template("success.html", user=user, received_messages=received_messages)


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
