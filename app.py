import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, session
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from bson import ObjectId
from bson.timestamp import Timestamp
import datetime
from azure.storage.blob import BlobServiceClient
#import certifi

#ca = certifi.where()

#Load ENV data
load_dotenv()
mongodb_connection_string = os.environ.get('MONGODB_CONNECTION_STRING')
app_secret = os.environ.get('APP_SECRET')

#Connect to MongoDB
mongo_client = MongoClient(mongodb_connection_string) #, tlsCAFile=ca)
db = mongo_client.get_database("videoapp")

#Storage
storage_connection_string = os.environ.get('STORAGE_CONNECTION_STRING')
storage_container_name = os.environ.get('STORAGE_CONTAINER_NAME')


#Initiating Flask
app = Flask(__name__, template_folder="templates2", static_folder= "templates2/assets")
app.secret_key = app_secret
bcrypt = Bcrypt(app)

#Routes
#Homepage - Index
@app.route('/', methods=['GET'])
def index():
        #Get method
        if request.method == 'GET':
                videos_collection = db.get_collection("videos")
                videos_without_email = list(videos_collection.find())
                videos = []
                
                users_collection = db.get_collection("users")
                users = list(users_collection.find())

                for video in videos_without_email:
                        for user in users:
                                if ObjectId(video['uploaded_by']) == ObjectId(user['_id']):
                                        v = dict(video)
                                        v['email'] = user['email']
                                        videos.append(v)
                
                if 'isSignedIn' in session.keys():
                        return render_template("index.html", videos = videos, email = session['email'], role = session['role'], uid= session['uid'])
                else:
                        return render_template("index.html", videos = videos)
        else:
                return redirect(url_for('index'))

#Sign Up
@app.route('/signup', methods = ['GET', 'POST'])
def signup():
        #Get method
        if request.method == 'GET':
                if 'isSignedIn' in session.keys():
                        return redirect(url_for("dashboard"))
                else:
                        return render_template("signup.html")
        #Post method
        elif request.method == 'POST':
                email_address = request.form.get('email')
                password = request.form.get('password')
                confirm_password = request.form.get('confirm_password')
                
                #If email is empty
                if email_address == "":
                        return render_template("signup.html", faliure="E-mail address cannot be empty.")
                #If password or confirm password is empty
                elif (password == "") or (confirm_password == ""):
                        return render_template("signup.html", faliure="Password cannot be empty.")
                #If password does not match
                elif not (password == confirm_password):
                        return render_template("signup.html", faliure="Password does not match.")
                #Create consumer accout by hashing the password
                else:
                        hashed_password = bcrypt.generate_password_hash(password)
                        users_collection = db.get_collection("users")
                        user = {"email": email_address, "password": hashed_password, "role": "consumer"}
                        users_collection.insert_one(user)

                        return render_template("signin.html", success= f"Sign up successful for {email_address}!")

#Sign In
@app.route('/signin', methods = ['GET', 'POST'])
def signin():
        #Get method
        if request.method == 'GET':
                if 'isSignedIn' in session.keys():
                        return redirect(url_for("dashboard"))
                else:
                        return render_template("signin.html")
        #Post method
        elif request.method == 'POST':
                email_address = request.form.get('email')
                password = request.form.get('password')

                #If email is empty
                if email_address == "":
                        return render_template("signin.html", faliure="E-mail address cannot be empty.")
                #If password or confirm password is empty
                elif (password == ""):
                        return render_template("signin.html", faliure="Password cannot be empty.")
                #Sign into the consumer accout by checking email & hashed password, redirect to the dashboard
                else:
                        users_collection = db.get_collection("users")
                        user = users_collection.find_one({"email": f"{email_address}"})

                        if user is None:
                                return render_template("signin.html", faliure="Wrong e-mail. Please Sign Up.")
                        elif bcrypt.check_password_hash(user['password'], password):
                                session['uid'] = str(user['_id'])
                                session['email'] = email_address
                                session['isSignedIn'] = True
                                session['role'] = user['role']
                                return redirect(url_for("dashboard"))
                        else:
                                return render_template("signin.html", faliure="Wrong password. Please try again.")

#Sign Out
@app.route('/signout', methods = ['GET'])
def signout():
        if request.method == 'GET':
                #If Signed In then clear the session and redirect to the Sign In page
                if 'isSignedIn' in session.keys():
                        session.clear()
                
                return redirect(url_for("signin"))
        else:
                return redirect(url_for('dashboard'))
        
#Dashboard
@app.route('/dashboard', methods = ['GET'])
def dashboard():
        #If Signed In then show Dashboard otherwise redirect to the Sign In page
        if request.method == 'GET':
                if 'isSignedIn' in session.keys():
                        
                        users_collection = db.get_collection("users")
                        videos_collection = db.get_collection("videos")

                        if session['role'] == "creator":
                                users = list(users_collection.find())
                                videos_without_email = list(videos_collection.find())
                                videos = []

                                for video in videos_without_email:
                                        for user in users:
                                                if ObjectId(video['uploaded_by']) == ObjectId(user['_id']):
                                                        v = dict(video)
                                                        v['email'] = user['email']
                                                        videos.append(v)

                                return render_template("dashboard-creator.html", users = users, videos = videos, email = session['email'], role = session['role'], uid= session['uid'])
                        elif session['role'] == "consumer":
                                #Show the Video Library
                                videos = videos_collection.find({"uploaded_by": ObjectId(session['uid'])})

                                return render_template("dashboard-consumer.html", videos = videos, email = session['email'], role = session['role'], uid= session['uid'])
                else:
                        return redirect(url_for("signin"))
        else:
                return redirect(url_for('dashboard'))
        
#Change Password
@app.route('/change_password', methods = ['GET', 'POST'])
def change_password():                
        if request.method == 'GET':
                return redirect(url_for("dashboard"))
        #If the old password is correct then update to new password
        elif request.method == 'POST':
                if 'isSignedIn' in session.keys() and 'email' in session.keys() and session['role'] == "consumer":
                        password = request.form.get('password')
                        confirm_password = request.form.get('confirm_password')

                        if (password is None or confirm_password is None) or (password == "" or confirm_password == ""):
                                return render_template("dashboard-consumer.html", failure = "Password cannot be empty", email = session['email'], role = session['role'], uid = session['uid'])
                        elif not (password == confirm_password):
                                return render_template("dashboard-consumer.html", failure = "Password does not match", email = session['email'], role = session['role'], uid = session['uid'])
                        #Change Passowrd
                        else:
                                users_collection = db.get_collection("users")
                                user = users_collection.find_one({"email": session['email']})
                                
                                if bcrypt.check_password_hash(user['password'], password):
                                        return render_template("dashboard-consumer.html", failure = "Cannot change to old password.", email = session['email'], role = session['role'], uid = session['uid'])
                                else:
                                        uid = user['_id']
                                        hashed_password = bcrypt.generate_password_hash(password)
                                        users_collection.update_one({"_id": ObjectId(uid)}, {"$set": {"password": hashed_password}})

                                        return render_template("dashboard-consumer.html", success = "Password changed successfully.", email = session['email'], role = session['role'], uid = session['uid'])
                else:
                        return redirect(url_for("dashboard"))

#Upload Video
@app.route('/upload', methods=['GET', 'POST'])         
def upload():
        if request.method == 'GET':
                return redirect(url_for("dashboard"))
        elif request.method == 'POST':
                if 'isSignedIn' in session.keys() and 'email' in session.keys() and session['role'] == "consumer":
                        title = request.form.get('title')
                        hashtag = request.form.get('hashtag')
                        video = request.files['video']
                        
                        
                        if (title is None or hashtag is None or video is None) or (title == "" or hashtag == "" or video.filename == ""):
                                return render_template("dashboard-consumer.html", failure = "Please provide proper info", email = session['email'], role = session['role'], uid = session['uid'])
                        #Upload Video
                        else:
                                #Transfer the video to the storage
                                try:
                                        blob_service_client = BlobServiceClient.from_connection_string(storage_connection_string)
                                        blob_client = blob_service_client.get_blob_client(container= storage_container_name, blob= video.filename)
                                        blob_client.upload_blob(video)
                                        video_url = blob_client.url
                                        blob_service_client.close()
                                except:
                                        return render_template("dashboard-consumer.html", failure = "File upload failed.", email = session['email'], role = session['role'], uid = session['uid'])

                                #Split and Trim the hashtags
                                list_of_hashtag = hashtag.split(',')
                                for i in range(0, len(list_of_hashtag)):
                                        list_of_hashtag[i] = str(list_of_hashtag[i]).strip()

                                videos_collection = db.get_collection("videos")                              
                                videos_collection.insert_one({
                                        "title": title, 
                                        "video_url": video_url,
                                        "filename": video.filename,
                                        "hashtag": list_of_hashtag,
                                        "uploaded_by": ObjectId(session['uid']),
                                        "uploaded_at": Timestamp(int(datetime.datetime.today().timestamp()), 1),
                                        })
                                
                                videos_collection = db.get_collection("videos")
                                videos = videos_collection.find({"uploaded_by": ObjectId(session['uid'])})

                                return render_template("dashboard-consumer.html", success = "Video uploaded successfully.", videos=videos, email = session['email'], role = session['role'], uid = session['uid'])
                else:
                        return redirect(url_for("dashboard"))

#Delete Video
@app.route('/delete_video/<vid>', methods=['GET'])
def delete_video(vid):
        #Check if the video exists and then delete the video
        if request.method == 'GET':
                if 'isSignedIn' in session.keys() and 'email' in session.keys() and 'role' in session.keys():
                        
                        videos_collection = db.get_collection('videos')
                        ratings_collection = db.get_collection('ratings')
                        comments_collection = db.get_collection('comments')

                        video = videos_collection.find_one({'_id' : ObjectId(vid)})
                        
                        if (ObjectId(video['uploaded_by']) == ObjectId(session['uid'])) or (session['role'] == 'creator'):
                                if video:
                                        #Remove video from the storage
                                        blob_service_client = BlobServiceClient.from_connection_string(storage_connection_string)
                                        blob_client = blob_service_client.get_blob_client(container= storage_container_name, blob= video['filename'])
                                        blob_client.delete_blob()
                                        blob_service_client.close()

                                        #Remove video related data from db
                                        videos_collection.delete_one({'_id': ObjectId(vid)})
                                        
                                        ratings = ratings_collection.find({'video_id' : ObjectId(vid)})
                                        for rating in ratings:
                                                ratings_collection.delete_one({'_id' : ObjectId(rating['_id'])})

                                        comments = comments_collection.find({'video_id' : ObjectId(vid)})
                                        for comment in comments:
                                                comments_collection.delete_one({'_id' : ObjectId(comment['_id'])})

                #Redirect to Dashboard
                return redirect(url_for("dashboard"))
        else:
                return redirect(url_for('dashboard'))
        
#Preview Video
@app.route('/video/<vid>', methods=['GET'])
def video(vid):
        if request.method == 'GET':      
                videos_collection = db.get_collection('videos')
                video_without_email = videos_collection.find_one({'_id' : ObjectId(vid)})
                video = {}

                users_collection = db.get_collection("users")
                users = users_collection.find()

                
                for user in users:
                        if ObjectId(video_without_email['uploaded_by']) == ObjectId(user['_id']):
                                v = dict(video_without_email)
                                v['email'] = user['email']
                                video = v
                
                comments_collection = db.get_collection('comments')
                comments = comments_collection.find({'video_id' : ObjectId(vid)})

                ratings_collection = db.get_collection('ratings')
                ratings = ratings_collection.find({'video_id' : ObjectId(vid)})
                
                rating = 0.0
                
                #If any rating does not exist then 0, otherwise go through the db and if there's 1 rating then show it directly
                #Otherwise go though all the ratings and show the average rating
                
                if ratings:
                        rating_list = []

                        for r in ratings:
                                rating_list.append(r['rating'])

                        
                        total_rating = 0

                        if len(rating_list) == 0:
                                pass
                        elif len(rating_list) == 1:
                                rating = float(rating_list[0])
                        else:
                                for r in rating_list:
                                        total_rating = total_rating + r
                                
                                rating = float(total_rating / len(rating_list))
                        
                if 'isSignedIn' in session.keys() and 'email' in session.keys() and 'role' in session.keys():
                        return render_template("video.html", vid=video['_id'], video=video, comments=comments, rating=rating, email = session['email'], role = session['role'], uid= session['uid'])
                else:
                        return render_template("video.html", vid=video['_id'], video=video, comments=comments, rating=rating)
        else:
                return redirect(url_for('dashboard'))

#Post Rating
@app.route('/post_rating/<vid>', methods=['POST'])
def post_rating(vid):
        if request.method == 'GET':
                return redirect(url_for("dashboard"))
               
        elif request.method == 'POST':
                if 'isSignedIn' in session.keys() and 'email' in session.keys() and session['role'] == "consumer":
                        #If a rating exists by the user then update otherwise insert new rating
                        ratings_collection = db.get_collection("ratings")
                        video_rating = ratings_collection.find_one({'video_id' : ObjectId(vid), 'user_id': ObjectId(session['uid'])})

                        rating = float(request.form.get('rating'))

                        if video_rating:
                                ratings_collection.update_one({'_id': ObjectId(video_rating['_id'])},{"$set": {"rating": rating}})
                        else:
                                ratings_collection.insert_one({
                                "video_id": ObjectId(vid), 
                                "user_id": ObjectId(session['uid']),
                                "rating": rating,
                                })
                                                
                        return redirect(url_for('video', vid = vid))

#Post Comment
@app.route('/post_comment/<vid>', methods=['POST'])
def post_comment(vid):
        if request.method == 'GET':
                return redirect(url_for("dashboard"))
        
        elif request.method == 'POST':
                if 'isSignedIn' in session.keys() and 'email' in session.keys() and session['role'] == "consumer":
                        
                        comment = request.form.get('comment')

                        comments_collection = db.get_collection("comments")                              
                        comments_collection.insert_one({
                                "video_id": ObjectId(vid), 
                                "user_id": ObjectId(session['uid']),
                                "email": session['email'],
                                "comment": comment,
                                })
                        
                        return redirect(url_for('video', vid = vid))
                
#Delete User
@app.route('/delete_user/<uid>', methods=['GET'])
def delete_user(uid):
        #Check if the user exists and then delete the user including all the videos, comments and rating posted by the user
        if request.method == 'GET':
                if 'isSignedIn' in session.keys() and 'email' in session.keys() and session['role'] == "creator":
                        #Remove user videos from the storage and db
                        videos_collection = db.get_collection('videos')
                        videos = videos_collection.find({"uploaded_by": ObjectId(uid)})
                                                
                        blob_service_client = BlobServiceClient.from_connection_string(storage_connection_string)
                        
                        for video in videos:
                                if video:
                                        blob_client = blob_service_client.get_blob_client(container= storage_container_name, blob= video['filename'])
                                        blob_client.delete_blob()
                                        
                                        videos_collection.delete_one({'_id': ObjectId(video['_id'])})

                        blob_service_client.close()

                        #Remove user comments from db
                        comments_collection = db.get_collection('comments')
                        comments = comments_collection.find({"user_id": ObjectId(uid)})

                        for comment in comments:
                                comments_collection.delete_one({'_id': ObjectId(comment['_id'])})

                        #Remove user ratings from db
                        ratings_collection = db.get_collection('ratings')
                        ratings = ratings_collection.find({"user_id": ObjectId(uid)})
                        for rating in ratings:
                                ratings_collection.delete_one({'_id' : ObjectId(rating['_id'])})

                        
                        #Remove user from db
                        users_collection = db.get_collection('users')
                        users_collection.delete_one({'_id': ObjectId(uid)})

                return redirect(url_for("dashboard"))
        else:
                return redirect(url_for('dashboard'))