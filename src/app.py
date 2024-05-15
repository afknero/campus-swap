#!/usr/bin/env python3

import os
import datetime
from flask import Flask, render_template, request, redirect, url_for

# from markupsafe import escape
import pymongo
from dotenv import load_dotenv
import flask_login  # this will be used for user authentication
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from bson.decimal128 import Decimal128
from bson.objectid import ObjectId  # used to search db using objec ids

# load credentials and configuration options from .env file
# if you do not yet have a file named .env, make one based on the template in env.example
load_dotenv()  # take environment variables from .env.

# instantiate the app
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)
# these 2 are for flask login
login_manager = LoginManager()
login_manager.init_app(app)

# if using Atlas database uncomment next line!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! and comment out the next four lines
client = pymongo.MongoClient(os.getenv("MONGO_URI"))
 
#if using containerized instance of mongo uncomment next 4 lines else comment them out
# root_username = os.environ["MONGO_INITDB_ROOT_USERNAME"]  #1
# root_password = os.environ["MONGO_INITDB_ROOT_PASSWORD"]  #2
# uri = f"mongodb://{root_username}:{root_password}@mongodb:27017/db?authSource=admin" #3
# client = pymongo.MongoClient(uri) #4

db = client['Cluster0']  # store a reference to the database

# the following try/except block is a way to verify that the database connection is alive (or not)
try:
    # verify the connection works by pinging the database
    client.admin.command("ping")  # The ping command is cheap and does not require auth.
    print(" *", "Connected to MongoDB!")  # if we get here, the connection worked!
except Exception as e:
    # the ping command failed, so the connection is not available.
    print(" * MongoDB connection error:", e)  # debug

# set up the routes


# # turn on debugging if in development mode
# if os.getenv("FLASK_ENV", "development") == "development":
#     # turn on debugging, if in development
#     app.debug = True  # debug mnode


# this is the class user which will be stored in a session
# i think the flask_login.Usermixin handles all of the methods needed
class User(flask_login.UserMixin):
    pass


# this callback is used to reload the user object from the user ID stored in the session.It should take the str ID of a user, and return the corresponding user object
@login_manager.user_loader
def user_loader(username):
    founduser = db.users.find_one({"username": username})
    if not founduser:
        return

    user = User()
    user.id = founduser["_id"]
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get("username")
    founduser = db.users.find_one({"username": username})
    if not founduser:
        return

    user = User()
    user.id = username
    return user


@app.route("/")
def home():
    """
    Route for the home page
    """
    sort_option = request.args.get("sort")

    if sort_option == "oldest":
        docs_cursor = db.items.find({"public": True}).sort("created_at", 1)
    elif sort_option == "lowest":
        docs_cursor = db.items.find({"public": True}).sort("price", 1)
    elif sort_option == "highest":
        docs_cursor = db.items.find({"public": True}).sort("price", -1)
    else:
        docs_cursor = db.items.find({"public": True}).sort("created_at", -1)

    docs = list(docs_cursor)
    return render_template("index.html", docs=docs)  # render the hone template


# route to accept the form submission to delete an existing post
@app.route("/signup", methods=["POST", "GET"])
def sign_up():
    """
    Route for GET AND POST for signup page
    """
    if request.method == "POST":
        username = request.form["fusername"]
        password = request.form["fpassword"]
        user = db.users.find_one({"username": username})
        if user:
            return render_template("signup.html", error="Username already in use.")
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = {
                "username": username,
                "password": hashed_password,
                "items": [],
                "bio": "",
                "pic": "https://i.imgur.com/xCvzudW.png",
                "friends": [],
            }
            db.users.insert_one(new_user)
            return redirect(url_for("log_in"))
    if flask_login.current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("signup.html")


@app.route("/login", methods=["POST", "GET"])
def log_in():
    """
    Route for GET AND POST for login page
    """
    if request.method == "POST":
        username = request.form["fusername"]
        password = request.form["fpassword"]
        found_user = db.users.find_one({"username": username})
        if not found_user:
            return render_template("login.html", error="User not found.")
        else:
            is_valid = bcrypt.check_password_hash(found_user["password"], password)
            if not is_valid:
                return render_template(
                    "login.html", error="Username or password is invalid."
                )
            user = User()
            user.id = username
            flask_login.login_user(user)
            return redirect(url_for("home"))
    if flask_login.current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/protected")
@flask_login.login_required
def protected():
    return render_template("protected.html")


@app.route("/logout")
def logout():
    flask_login.logout_user()
    return redirect(url_for("log_in"))


@app.route("/item/<item_id>")
@flask_login.login_required
def item(item_id):
    try:
        founditem = db.items.find_one({"_id": ObjectId(item_id)})
        userid = flask_login.current_user.id
        user = db.users.find_one({"_id": ObjectId(userid)})
        return render_template("item.html", founditem=founditem, user=user)
    except Exception as e:
        print(e)
        return redirect(url_for("home"))  # redirect to an error page ideally


# add item here
@app.route("/add")
@flask_login.login_required
def add():
    # TODO make this an actual userid fetch
    try:
        userid = flask_login.current_user.id
        return render_template("add.html", userid=userid)
    except:
        # error handle
        return redirect(url_for("home"))


@app.route("/add/<user_id>", methods=["GET", "POST"])
@flask_login.login_required
def create_item(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    print(user)
    username = user["username"]
    name = request.form["itemname"]
    desc = request.form["description"]
    price = Decimal128(request.form["price"])
    url = request.form["url"]
    item = {
        "name": name,
        "description": desc,
        "user": ObjectId(user_id),
        "username": username,
        "image_url": url,
        "price": price,
        "created_at": datetime.datetime.utcnow(),
        "public": True,
    }
    db.items.insert_one(item)
    return redirect(url_for("view_listings"))


# delete has no html but should be invoked later from the my listings page, pass the item id through
@app.route("/delete/<item_id>")
@flask_login.login_required
def delete(item_id):
    db.items.delete_one({"_id": ObjectId(item_id)})
    # TODO can redirect to the my listings page later
    return redirect(url_for("purge", item_id=item_id))


@app.route("/deleteoffer/<offer_id>")
@flask_login.login_required
def deleteoffer(offer_id):
    db.offers.delete_one({"_id": ObjectId(offer_id)})
    return redirect(url_for("sentoffers"))


@app.route("/edit/<item_id>")
@flask_login.login_required
def edit(item_id):
    founditem = db.items.find_one({"_id": ObjectId(item_id)})
    return render_template("edit.html", founditem=founditem, item_id=item_id)


@app.route("/update/<item_id>", methods=["GET", "POST"])
@flask_login.login_required
def update_item(item_id):
    name = request.form["itemname"]
    desc = request.form["description"]
    price = Decimal128(request.form["price"])
    url = request.form["url"]
    item = {"name": name, "description": desc, "image_url": url, "price": price}
    db.items.update_one({"_id": ObjectId(item_id)}, {"$set": item})
    return redirect(url_for("view_listings"))


@app.route("/viewListings")
@flask_login.login_required
def view_listings():
    user_to_find = flask_login.current_user.id
    print(user_to_find)
    items = list(db.items.find({"user": ObjectId(user_to_find)}))
    return render_template("viewlisting.html", docs=items)


@app.route("/setpublic/<item_id>")
@flask_login.login_required
def setpublic(item_id):
    item = {"public": True}
    db.items.update_one({"_id": ObjectId(item_id)}, {"$set": item})
    return redirect(url_for("view_listings"))


@app.route("/setprivate/<item_id>")
@flask_login.login_required
def setprivate(item_id):
    item = {"public": False}
    db.items.update_one({"_id": ObjectId(item_id)}, {"$set": item})
    return redirect(url_for("view_listings"))


@app.route("/offer/<item_id>")
@flask_login.login_required
def offer(item_id):
    founditem = db.items.find_one({"_id": ObjectId(item_id)})
    user_to_find = flask_login.current_user.id
    items = list(db.items.find({"user": ObjectId(user_to_find)}))
    return render_template(
        "offer.html", founditem=founditem, item_id=item_id, docs=items
    )


@app.route("/newoffer/<item_id>", methods=["GET", "POST"])
@flask_login.login_required
def new_offer(item_id):
    offered = request.form.getlist("mycheckbox")
    touser = db.items.find_one({"_id": ObjectId(item_id)}).get("user")

    curuser = flask_login.current_user.id
    offer = {
        "offerforid": item_id,
        "offereditems": offered,
        "sentby": ObjectId(curuser),
        "status": "sent",
        "sendtouser": touser,
    }
    db.offers.insert_one(offer)
    return redirect(url_for("sentoffers"))


@app.route("/sentoffers")
@flask_login.login_required
def sentoffers():
    """ """
    # find the current user's offers
    user = flask_login.current_user.id
    offers = list(db.offers.find({"sentby": ObjectId(user)}))

    # create a set of all item IDs
    item_ids = set()
    for offer in offers:
        item_ids.add(offer.get("offerforid"))
        item_ids.update(offer.get("offereditems", []))

    item_ids = [ObjectId(item_id) for item_id in item_ids]

    # find all items
    items_cursor = db.items.find(
        {"_id": {"$in": item_ids}},
        {"name": 1, "username": 1, "user": 1, "image_url": 1},
    )
    items = {str(item["_id"]): item for item in items_cursor}

    # populate item ids with item details
    for offer in offers:
        offerforid = offer.get("offerforid")
        if offerforid:
            offer["offerforid"] = items.get(str(offerforid))

        offereditems = offer.get("offereditems", [])
        offer["offereditems"] = [items.get(str(item_id)) for item_id in offereditems]
        print(offer)

    return render_template("sentoffers.html", offers=offers)


@app.route("/recievedoffers")
@flask_login.login_required
def recievedoffers():
    # find the current user's offers
    user = flask_login.current_user.id
    offers = list(db.offers.find({"sendtouser": ObjectId(user)}))

    # create a set of all item IDs
    item_ids = set()
    for offer in offers:
        item_ids.add(offer.get("offerforid"))
        item_ids.update(offer.get("offereditems", []))

    item_ids = [ObjectId(item_id) for item_id in item_ids]

    # find all items
    items_cursor = db.items.find(
        {"_id": {"$in": item_ids}},
        {"name": 1, "username": 1, "user": 1, "image_url": 1},
    )
    items = {str(item["_id"]): item for item in items_cursor}

    # populate item ids with item details
    for offer in offers:
        offerforid = offer.get("offerforid")
        if offerforid:
            offer["offerforid"] = items.get(str(offerforid))

        offereditems = offer.get("offereditems", [])
        offer["offereditems"] = [items.get(str(item_id)) for item_id in offereditems]
        print(offer)

    return render_template("recievedoffers.html", offers=offers)


@app.route("/acceptoffer/<offer_id>")
@flask_login.login_required
def acceptoffer(offer_id):
    item = {"status": "accepted"}
    db.offers.update_one({"_id": ObjectId(offer_id)}, {"$set": item})
    return redirect(url_for("recievedoffers"))


@app.route("/rejectoffer/<offer_id>")
@flask_login.login_required
def rejectoffer(offer_id):
    item = {"status": "rejected"}
    db.offers.update_one({"_id": ObjectId(offer_id)}, {"$set": item})
    return redirect(url_for("recievedoffers"))


@app.route("/purge/<item_id>")
@flask_login.login_required
def purge(item_id):
    query = {"offereditems": item_id}
    db.offers.delete_many(query)
    query2 = {"offerforid": item_id}
    db.offers.delete_many(query2)
    return redirect(url_for("view_listings"))


@app.route("/profile")
@flask_login.login_required
def profile():
    user_to_find = flask_login.current_user.id
    user = db.users.find_one({"_id": ObjectId(user_to_find)})

    user_profile = {
        "username": user["username"],
        "bio": user["bio"],
        "pic": user["pic"],
    }
    user_items = list(db.items.find({"user": ObjectId(user_to_find)}))
    return render_template("viewProfile.html", user=user_profile, docs=user_items)


@app.route("/viewUser/<user_name>", methods=["GET"])
@flask_login.login_required
def view_user(user_name):
    # gets the other user profile
    user = db.users.find_one({"username": user_name})
    if user["_id"] == flask_login.current_user.id:
        return redirect(url_for("profile"))
    user_profile = {
        "username": user["username"],
        "bio": user["bio"],
        "pic": user["pic"],
    }
    user_items = list(db.items.find({"user": ObjectId(user["_id"])}))
    # checks if user is in logged in user's friends
    logged_in_user = db.users.find_one({"_id": ObjectId(flask_login.current_user.id)})
    print(list(logged_in_user["friends"]))
    logged_in_user_friends = list(logged_in_user["friends"])
    if user["_id"] in logged_in_user_friends:
        friends = True
        print("true")
    else:
        friends = False
        print("false")

    return render_template(
        "viewUserProfile.html", user=user_profile, docs=user_items, friends=friends
    )


@app.route("/editProfile/", methods=["GET", "POST"])
@flask_login.login_required
def edit_profile():
    if request.method == "POST":
        bio = request.form["bio"]
        pic = request.form["pic"]
        db.users.update_one(
            {"_id": ObjectId(flask_login.current_user.id)},
            {"$set": {"bio": bio, "pic": pic}},
        )
        return redirect(url_for("profile"))
    user = db.users.find_one({"_id": ObjectId(flask_login.current_user.id)})
    return render_template("editProfile.html", user=user)


@app.route("/addFriend/<user_name>", methods=["GET"])
@flask_login.login_required
def add_friend(user_name):
    user = db.users.find_one({"username": user_name})
    logged_in_user = db.users.find_one({"_id": ObjectId(flask_login.current_user.id)})
    logged_in_user_friends = list(logged_in_user["friends"])
    if user["_id"] in logged_in_user_friends:
        return redirect(url_for("view_user", user_name=user_name))

    db.users.update_one(
        {"_id": ObjectId(flask_login.current_user.id)},
        {"$push": {"friends": user["_id"]}},
    )
    return redirect(url_for("view_user", user_name=user_name))


@app.route("/friends", methods=["GET"])
@flask_login.login_required
def friends():
    user = db.users.find_one({"_id": ObjectId(flask_login.current_user.id)})
    friends_list = list(user["friends"])
    print(friends_list)
    friends = []
    for friend in friends_list:
        current_friend = db.users.find_one({"_id": ObjectId(friend)})
        print(current_friend["username"])
        friend_info = {
            "pic": current_friend["pic"],
            "username": current_friend["username"],
        }
        friends.append(friend_info)
    print(friends)
    return render_template("friends.html", friends=friends)


@login_manager.unauthorized_handler
def unauthorized_handler():
    return redirect(url_for("log_in"))

# run the app
if __name__ == "__main__":
    # use the PORT environment variable, or default to 5000
    FLASK_PORT = os.getenv("FLASK_PORT", "5001")

    # import logging
    # logging.basicConfig(filename='/home/ak8257/error.log',level=logging.DEBUG)
    app.run(host="0.0.0.0", port=FLASK_PORT)
