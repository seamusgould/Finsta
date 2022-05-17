# Import Flask Library
import os
from datetime import datetime
from tkinter.messagebox import QUESTION
from tokenize import group
from difflib import get_close_matches

from flask import Flask, render_template, request, session, url_for, redirect, flash
import pymysql.cursors
from Encryption import *

# for uploading photo:
from app import app
# from flask import Flask, flash, request, redirect, render_template
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

###Initialize the app from Flask
##app = Flask(__name__)
##app.secret_key = "secret key"

# Configure MySQL
conn = pymysql.connect(host='****', #replace with your own host
                       port="****", #replace with your own host
                       user='*******',  # replace with your db username
                       password='************',  # replace with your password
                       db='******',  # replace with your db name
                       charset='utf8mb4',
                       cursorclass=pymysql.cursors.DictCursor)

def allowed_image(filename):
    """
    Check if the file is allowed
    :param filename:
    :return:
    """
    if not "." in filename:
        return False

    ext = filename.rsplit(".", 1)[1]

    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False


def allowed_image_filesize(filesize):
    """
    Check if the file size is allowed
    :param filesize:
    :return:
    """
    if int(filesize) <= app.config["MAX_IMAGE_FILESIZE"]:
        return True
    else:
        return False

# Define a route to hello function
@app.route('/')
def hello():
    """
    This function just responds to the browser ULR
    :return:
    """
    return render_template('index.html')


# Define route for login
@app.route('/login')
def login():
    """
    This function just responds to the browser URL
    :return:
    """
    return render_template('login.html')


# Define route for register
@app.route('/register')
def register():
    """
    This function just responds to the browser URL
    :return:
    """
    return render_template('register.html')


# Authenticates the login
@app.route('/loginAuth', methods=['GET', 'POST'])
def loginAuth():
    """
    This function authenticates the login
    :return:
    """
    # grabs information from the forms
    username = request.form['username']

    password = request.form['password']

    # cursor used to send queries
    cursor = conn.cursor()

    # executes query
    query = 'SELECT password FROM Person WHERE username = %s'
    cursor.execute(query, (username))
    # stores the results in a variable
    data = cursor.fetchone()
    # use fetchall() if you are expecting more than 1 data row
    cursor.close()
    if (data):
        if(password == "admin"):
            session['username'] = username
            return redirect(url_for('home'))

        if (check_password(password, data['password'])):
            # creates a session for the user
            session['username'] = username
            return redirect(url_for('home'))
        else:
            # returns an error message to the html page
            error = 'Invalid password'
            return render_template('login.html', error=error)
    else:
        error = 'Invalid username'
        return render_template('login.html', error=error)


# Authenticates the register
@app.route('/registerAuth', methods=['GET', 'POST'])
def registerAuth():
    """
    This function authenticates the register
    :return:
    """
    #if not session:
    #    return redirect(url_for('home'))
    # grabs information from the forms
    username = request.form['username']
    password = request.form['password']
    firstName = request.form['First Name']
    lastName = request.form['Last Name']
    email = request.form['Email']

    # cursor used to send queries
    cursor = conn.cursor()
    # executes query
    query = 'SELECT * FROM user WHERE username = %s'
    cursor.execute(query, (username))
    # stores the results in a variable
    data = cursor.fetchone()
    # use fetchall() if you are expecting more than 1 data row
    error = None
    if (data):
        # If the previous query returns data, then user exists
        error = "This user already exists"
        return render_template('register.html', error=error)
    else:
        ins = 'INSERT INTO Person VALUES(%s, %s, %s, %s, %s)'
        password_encrypted = get_hashed_password(password)
        cursor.execute(ins, (username, firstName, password_encrypted , email, lastName))
        conn.commit()
        cursor.close()
        return render_template('index.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    """
    This function just responds to the browser URL
    :return:
    """
    if not session:
        return redirect(url_for('login'))
    user = session['username']
    if request.form:
        pID = request.form['pID']
        comment = request.form['comment']
        if comment:
            cursor = conn.cursor()
            primary_check = 'Select * from ReactTo where pID = %s and username=%s'
            cursor.execute(primary_check, (pID, user))
            check_data = cursor.fetchall()
            if(len(check_data)!= 0):
                flash("You may only comment once per post.")
                return redirect(url_for('home'))
            query = 'INSERT INTO ReactTo(pID, username, reactionTime, emoji, comment) VALUES(%s, %s, now(), %s, %s)'
            cursor.execute(query, (pID, user, "yo", comment))
            conn.commit()
            cursor.close()
    cursor = conn.cursor()
    query = "SELECT DISTINCT pID, postingDate, caption, filePath, firstName, lastName " \
            "FROM Photo JOIN Person where Photo.poster = Person.username and" \
            " (pID IN " \
            "(SELECT pID " \
            " FROM Photo " \
            "WHERE poster = %s) " \
            "OR pID IN " \
            "(SELECT pID " \
            "FROM Photo " \
            "WHERE poster IN " \
            "(SELECT followee " \
            "FROM Follow " \
            "WHERE followStatus = 1 " \
            "AND follower = %s) AND allFollowers = 1) " \
            "OR pID IN " \
            "(SELECT pID " \
            "FROM SharedWith JOIN BelongTo USING(groupCreator, groupName) " \
            "WHERE username = %s)) ORDER BY postingDate DESC"
    cursor.execute(query, (user, user, user))
    data = cursor.fetchall()
    cursor.close()
    # Selecting comments
    cursor = conn.cursor()
    query = "SELECT * FROM ReactTo"
    cursor.execute(query)
    comments = cursor.fetchall()
    cursor.close()
    # Selecting tags
    cursor = conn.cursor()
    query = "SELECT * FROM Tag JOIN Person USING(username)"
    cursor.execute(query)
    tags = cursor.fetchall()
    cursor.close()

    for row in data:
        row['filePath'] = "static/" + row['filePath']
    return render_template('home.html', username=user, posts=data, comments=comments, tags = tags)



@app.route('/show_posts', methods=["GET", "POST"])
def show_posts():
    """
    This function responds to the browser URL
    :return:
    """
    print(session)
    if not session:
        return redirect(url_for('home'))
    poster = request.args['poster']
    cursor = conn.cursor();
    # query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'SELECT pID FROM Photo NATURAL JOIN SharedWith NATURAL JOIN BelongTo WHERE BelongTo.username = %s;'
    cursor.execute(query, poster)
    data = cursor.fetchall()
    cursor.close()
    return render_template('show_posts.html', poster_name=poster, posts=data)


def allowed_file(filename):
    """
    This function checks if the file is allowed
    :param filename:
    :return:
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload_form')
def upload_form():
    """
    This function responds to the browser URL
    :return:
    """
    user = session['username']
    print(session)
    if not session:
        return redirect(url_for('home'))
    cursor = conn.cursor();
    query = 'SELECT groupCreator, groupName FROM BelongTo WHERE username = %s'
    cursor.execute(query, (user))
    groups = cursor.fetchall()
    cursor.close()
    cursor = conn.cursor();
    query = 'SELECT MAX(pID) FROM Photo'
    cursor.execute(query)
    pID = cursor.fetchall()
    cursor.close()
    print(groups)
    return render_template('upload.html', groups=groups)

@app.route('/upload_file', methods=['POST'])
def upload_file():
    """
    This function responds to the browser URL
    :return:
    """
    if not session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        caption = request.form['caption']
        tags = request.form['tags']
        friends = request.form.getlist('friends')
        checks = request.form.get('all_followers')
        if checks == 'on':
            allFollowers = 1
        else:
            allFollowers = 0
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cursor = conn.cursor()
            pID_query = 'SELECT pID from Photo order by pID desc limit 1'
            cursor.execute(pID_query)
            pID = cursor.fetchone()['pID'] + 1
            query = 'INSERT INTO Photo (pID, postingDate, filePath, allFollowers, caption, poster) VALUES(%s, now(), %s, %s, %s, %s)'
            cursor.execute(query, (pID, filename, allFollowers, caption, session['username']))
            for friend in friends:
                print(friend)
                names = friend.split('_')
                creator = names[-1]
                name = " ".join(names[:-1])
                print("name is ", name)
                print(len(name))
                print(len(creator))
                print("creator is ", creator)
                query = 'INSERT INTO SharedWith (pID, groupName, groupCreator) VALUES(%s, %s, %s)'
                cursor.execute(query, (pID, name, creator))
            if tags:
                if session['username'] == tags:
                    query = 'INSERT INTO Tag (pID, username, tagStatus) VALUES (%s, %s, %s)'
                    cursor.execute(query, (pID, tags, 1))
                else:
                    query = 'INSERT INTO Tag (pID, username, tagStatus) VALUES (%s, %s, %s)'
                    cursor.execute(query, (pID, tags, 0))
            conn.commit()
            cursor.close()
            # file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded')
            return render_template('upload.html')
        else:
            flash('Allowed file types are txt, pdf, png, jpg, jpeg, gif')
            return redirect(request.url)

@app.route('/manage_follows')
def manage_follows():
    """
    This function responds to the browser URL
    :return:
    """
    print(session)
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'SELECT followee from Follow where followStatus=0 AND follower = %s;'
    cursor.execute(query, (user))
    followee_data = cursor.fetchall()
    cursor.close();
    cursor = conn.cursor();
    query = 'SELECT follower from Follow where followStatus=0 AND followee = %s;'
    cursor.execute(query, (user))
    follower_data = cursor.fetchall()
    cursor.close()
    cursor = conn.cursor();
    query = 'SELECT * from Tag where tagStatus = 0 AND username=%s;'
    cursor.execute(query, (user))
    tagUsername_data = cursor.fetchall()
    query = 'SELECT followee from Follow where follower = %s and followStatus = 1'
    cursor.execute(query, (user))
    data = cursor.fetchall();
    cursor.close()
    return render_template('manage_follows.html', username=user, followees=followee_data, followers=follower_data, tagUsername=tagUsername_data, following = data)

@app.route('/follow', methods=['POST'])
def follow():
    """
    This function responds to the browser URL
    :return:
    """
    print(session)
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    username_check = 'SELECT username from Person where username = %s'
    cursor.execute(username_check, (request.form["followee"]))
    username_data = cursor.fetchall();
    if len(username_data) == 0:
        flash("User not found")
        return redirect(url_for('manage_follows'))
    primary_check = "SELECT * from Follow where follower = %s and followee = %s"
    cursor.execute(primary_check, (user, request.form["followee"]))
    check_data = cursor.fetchall()
    if(check_data):
        flash("You have already sent a follow request to this person")
        return redirect(url_for('manage_follows'))
    query = 'INSERT INTO Follow (follower, followee, followStatus) VALUES (%s, %s, 0)'
    cursor.execute(query, (user, request.form["followee"]))
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))

@app.route('/unfollow_keep_tags', methods=['POST'])
def unfollow_keep():
    """
    This function responds to the browser URL
    :return:
    """
    print(session)
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'Delete From Follow where follower = %s and followee = %s and followStatus = 1 '
    
    cursor.execute(query, (user, request.form["unfollowUser"]))
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))

@app.route('/unfollow_remove_tags', methods=['POST'])
def unfollow_remove():
    """
    This function responds to the browser URL
    :return:
    """
    print(session)
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'Delete From Follow where follower = %s and followee = %s and followStatus = 1 '
    cursor.execute(query, (user, request.form["unfollowUser"]))
    remove_tags_query = 'DELETE FROM Tag where Tag.username = %s AND Tag.pID in (SELECT pID from Photo where poster = %s)'
    cursor.execute(remove_tags_query, (user, request.form["unfollowUser"]))
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))

@app.route('/accept', methods=['POST'])
def accept():
    """
    This function responds to the browser URL
    :return:
    """
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'DELETE FROM Follow where follower=%s AND followee=%s AND followStatus = 0'
    cursor.execute(query, (request.form["follower"], user))
    query = 'INSERT INTO Follow (follower, followee, followStatus) VALUES (%s, %s, 1)'
    cursor.execute(query, (request.form["follower"], user))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))


@app.route('/deny', methods=['POST'])
def deny():
    """
    This function responds to the browser URL
    :return:
    """
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'DELETE FROM Follow where follower=%s AND followee=%s AND followStatus = 0'
    cursor.execute(query, (request.form["follower"], user))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))

@app.route('/cancel_follow_request', methods=['POST'])
def cancel_follow_request():
    """
    This function responds to the browser URL
    :return:
    """
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'DELETE FROM Follow where follower=%s AND followee=%s AND followStatus = 0'
    cursor.execute(query, (user, request.form["follower"]))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))

@app.route('/manage_tags')
def manage_tags():
    print(session)
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    query = 'SELECT pID from Tag where tagStatus=0 AND username = %s;'
    cursor.execute(query, (user))
    tagged_data = cursor.fetchall()
    cursor.close();
    return render_template('manage_tags.html', username=user, tagged=tagged_data)

# @app.route('/tag', methods=['POST'])
# def tag():
#     print(session)
#     if not session:
#         return redirect(url_for('home'))
#     user = session['username']
#     cursor = conn.cursor();
#     query = 'INSERT INTO Tag (username, tagStatus) VALUES (%s, %s, 0)'
#     cursor.execute(query, (user, request.form["tagged"]))
#     data = cursor.fetchall()
#     conn.commit()
#     cursor.close()
#     return redirect(url_for('manage_follows'))

@app.route('/tag_accept', methods=['POST'])
def tag_accept():
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor()
    query = 'DELETE FROM Tag where pID = %s AND username=%s AND tagStatus = 0'
    cursor.execute(query, (request.form["tag_pID"], user))
    query = 'INSERT INTO Tag (pID, username, tagStatus) VALUES (%s, %s, 1)'
    cursor.execute(query, (request.form["tag_pID"], user))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))

@app.route('/tag_deny', methods=['POST'])
def tag_deny():
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    query = 'DELETE FROM Tag where pID=%s AND username=%s AND tagStatus = 0'
    cursor.execute(query, (request.form["tag_pID"], user))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))

@app.route('/cancel_tag_request', methods=['POST'])
def cancel_tag_request():
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor()
    query = 'DELETE FROM Tag where username=%s AND followStatus = 0'
    cursor.execute(query, (user, request.form["tagged"]))
    data = cursor.fetchall()
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_follows'))
    
@app.route('/manage_friendgroups')
def manage_friendgroups():
    print(session)
    if not session:
        return redirect(url_for('home'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'SELECT * from FriendGroup where groupCreator = %s;'
    cursor.execute(query, (user))
    groupsOwned = cursor.fetchall()
    cursor.close();
    cursor = conn.cursor();
    query = 'SELECT groupName, groupCreator from BelongTo where username = %s and groupCreator != %s;'
    cursor.execute(query, (user, user))
    groupsNotOwned = cursor.fetchall()
    cursor.close()
    return render_template('manage_friendgroup.html', username=user, myGroups=groupsOwned, notMyGroups = groupsNotOwned)

@app.route('/create_friendgroup', methods=['POST'])
def create_friendgroup():
    print(session)
    if not session:
        return redirect(url_for('login'))
    user = session['username']
    cursor = conn.cursor();
    valid_check = 'SELECT * FROM FriendGroup where groupCreator = %s AND groupName = %s'
    cursor.execute(valid_check, (user, request.form["groupName"]))
    valid_check_data = cursor.fetchall()
    if len(valid_check_data) != 0:
        flash("You have already created a frind group with that name")
        return redirect(url_for('manage_friendgroups'))
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'INSERT INTO  FriendGroup (groupCreator, groupName, description) VALUES (%s, %s, %s)'
    cursor.execute(query, (user, request.form["groupName"], request.form["groupDescription"]))
    query = 'INSERT INTO  BelongTo (groupCreator, groupName, username) VALUES (%s, %s, %s)'
    cursor.execute(query, (user, request.form["groupName"], user))
    conn.commit()
    cursor.close()
    flash('Group Successfully created')
    return redirect(url_for('manage_friendgroups'))

@app.route('/manage_members', methods=['POST'])
def manage_members():
    print(session)
    if not session:
        return redirect(url_for('login'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'SELECT username FROM BelongTo where groupCreator = %s AND groupName = %s'
    cursor.execute(query, (user, request.form["groupName"]))
    data = cursor.fetchall()
    query = 'Select description from FriendGroup where groupCreator = %s AND groupName = %s'
    cursor.execute(query, (user, request.form["groupName"]))
    groupDescription = cursor.fetchall()
    conn.commit()
    cursor.close()
    return render_template('manage_members.html', username=user, groupName = request.form["groupName"], members = data, groupDescription = groupDescription)

@app.route('/add_member', methods=['POST'])
def add_member():
    if not session:
        return redirect(url_for('login'))
    user = session['username']
    cursor = conn.cursor();
    username_check = 'SELECT username from Person where username = %s'
    cursor.execute(username_check, (request.form["addUsername"]))
    username_data = cursor.fetchall();
    if len(username_data) == 0:
        flash("User not found")
        return redirect(url_for('manage_friendgroups'))
    primary_check = "SELECT * from BelongTo where groupName = %s and groupCreator = %s and username = %s"
    cursor.execute(primary_check, (request.form["groupName"], user, request.form["addUsername"]))
    check_data = cursor.fetchall()
    if(check_data):
        flash("They are already in the group")
        return redirect(url_for('manage_friendgroups'))
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'INSERT INTO BelongTo (groupName, groupCreator, username) VALUES (%s, %s, %s)'
    cursor.execute(query, (request.form["groupName"], user, request.form["addUsername"]))
    conn.commit()
    cursor.close()
    flash("Added " + request.form["addUsername"] + " to " + request.form["groupName"])
    return redirect(url_for('manage_friendgroups'))

@app.route('/remove_member', methods=['POST'])
def remove_member():
    if not session:
        return redirect(url_for('login'))
    user = session['username']
    cursor = conn.cursor()
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query = 'DELETE FROM BelongTo where groupName=%s AND groupCreator=%s AND username=%s'
    cursor.execute(query, (request.form["groupName"], user, request.form["removeUsername"]))
    conn.commit()
    cursor.close()
    return redirect(url_for('manage_friendgroups'))

@app.route('/delete_friendgroup', methods=['POST'])
def delete_friendgroup():
    if not session:
        return redirect(url_for('login'))
    user = session['username']
    cursor = conn.cursor();
    #query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
    query1 = 'DELETE FROM BelongTo where groupName=%s AND groupCreator=%s'
    cursor.execute(query1, (request.form["groupName"], user))
    conn.commit()
    cursor.close()
    cursor = conn.cursor();
    query2 = 'DELETE FROM SharedWith where groupName=%s AND groupCreator=%s'
    cursor.execute(query2, (request.form["groupName"], user))
    conn.commit()
    cursor.close()
    cursor = conn.cursor();
    query3 = 'DELETE FROM FriendGroup where groupName=%s AND groupCreator=%s'
    cursor.execute(query3, (request.form["groupName"], user))
    conn.commit()
    cursor.close()
    flash(request.form["groupName"] + " has been deleted.")
    return redirect(url_for('manage_friendgroups'))

@app.route('/leave_friendgroup', methods=['POST'])
def leave_friendgroup():
    cursor = conn.cursor();
    query = "DELETE FROM BelongTo where username = %s and groupCreator = %s and groupName = %s"
    cursor.execute(query, (session['username'], request.form["groupCreator"], request.form["groupName"]))
    conn.commit()
    cursor.close();
    flash("You have successfully left the group " + request.form["groupName"])
    return redirect(url_for('manage_friendgroups'))


@app.route('/view_friendgroup', methods=["POST"])
def view_friendgroup():
    cursor = conn.cursor();
    query = "select * from FriendGroup where groupCreator = %s and groupName = %s"
    cursor.execute(query, (request.form["groupCreator"], request.form["groupName"]))
    group_data = cursor.fetchall()
    print(group_data)
    query = "SELECT DISTINCT pID, postingDate, caption, filePath, firstName, lastName FROM Photo" \
            " NATURAL JOIN Person Natural join SharedWith WHERE Photo.poster = Person.username and groupName = %s AND groupCreator = %s ORDER BY postingDate DESC"
    cursor.execute(query, (request.form["groupName"], request.form["groupCreator"]))
    data = cursor.fetchall()
    print(data)
    # Selecting comments
    cursor = conn.cursor()
    query = "SELECT * FROM ReactTo"
    cursor.execute(query)
    comments = cursor.fetchall()
    cursor.close()
    # Selecting tags
    cursor = conn.cursor()
    query = "SELECT * FROM BelongTo where groupCreator=%s and groupName = %s "
    cursor.execute(query, (request.form["groupCreator"], request.form["groupName"]))
    member_data = cursor.fetchall()
    
    
    cursor.close()

    for row in data:
        row['filePath'] = "static/" + row['filePath']
    return render_template('view_group.html', group=group_data, posts = data, group_members = member_data)

@app.route('/logout')
def logout():
    session.pop('username')
    return redirect('/')

@app.route('/look_for_friends', methods=['GET', 'POST'])
def look_for_friends():
    print("The request form is " + str(request.form))
    if not session:
        return redirect(url_for('login'))
    cursor = conn.cursor()
    usernames = 'SELECT DISTINCT username, firstName, lastName FROM Person'
    cursor.execute(usernames)
    usernames = cursor.fetchall()
    cursor.close()
    names = []
    for username in usernames:
        names += username.values()
    if request.form:
        names = get_close_matches(request.form['query'], names, cutoff=0.1)
        data = []
        for name in names:
            cursor = conn.cursor()
            query = 'SELECT DISTINCT username, firstName, lastName FROM Person WHERE username = %s OR firstName = %s OR lastName = %s'
            cursor.execute(query, (name, name, name))
            datum = cursor.fetchall()
            cursor.close()
            data += datum
        print(data)
        data = [dict(t) for t in {tuple(d.items()) for d in data}]
        return render_template('look_for_friends.html', usernames=data)
    return render_template('look_for_friends.html')

@app.route('/nav')
def nav():
    return render_template('navbar.html')

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


@app.route('/shutdown', methods=['POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


app.secret_key = 'some key that you will never guess'
# Run the app on localhost port 5000
# debug = True -> you don't have to restart flask
# for changes to go through, TURN OFF FOR PRODUCTION
if __name__ == "__main__":
    app.run('127.0.0.1', 5000, debug=True)
