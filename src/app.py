#!/usr/bin/env python3

import os
import datetime
from flask import Flask, render_template, request, redirect, url_for
import pymongo
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
import flask_login
from bson.decimal128 import Decimal128
from bson.objectid import ObjectId

# load credentials and configuration options from .env file
load_dotenv()

# instantiate the app
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

client = pymongo.MongoClient(os.getenv("MONGO_URI"))

# root_username = os.environ["MONGO_INITDB_ROOT_USERNAME"]  #1
# root_password = os.environ["MONGO_INITDB_ROOT_PASSWORD"]  #2
# uri = f"mongodb://{root_username}:{root_password}@mongodb:27017/db?authSource=admin" #3
# client = pymongo.MongoClient(uri) #4

db = client["Cluster0"]  # store a reference of the database


class User(flask_login.UserMixin):
    """
    User class that represents a user object.
    """

    def __init__(self, user_id, username):
        """
        Initializes a User object.
        """
        self.id = user_id
        self.username = username

    @property
    def is_authenticated(self):
        """
        Returns True if the user is authenticated (i.e. they have provided valid credentials).
        """
        return True

    @property
    def is_anonymous(self):
        """
        Returns False if this user is not anonymous.
        """
        return False

    def get_id(self):
        """
        Returns a string that uniquely identifies the user.
        """
        return str(self.id)


@login_manager.user_loader
def user_loader(user_id):
    """
    Callback to reload the user object from the user ID stored in the session.
    """
    found_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not found_user:
        return None

    user = User(user_id=found_user["_id"], username=found_user["username"])
    return user


@login_manager.request_loader
def request_loader(request):
    """
    Callback to load a user from a request.
    """
    username = request.form.get("username")
    if not username:
        return None

    found_user = db.users.find_one({"username": username})
    if not found_user:
        return None

    user = User(user_id=found_user["_id"], username=found_user["username"])
    return user


@login_manager.unauthorized_handler
def unauthorized_handler():
    """
    Redirects unauthorized users to the login page.
    """
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """
    GET and POST routes for signup page.
    """
    if request.method == "POST":
        username = request.form["fusername"]
        password = request.form["fpassword"]

        user = db.users.find_one({"username": username})
        if user:
            return render_template("signup.html", error="Username unavailable.")

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = {
            "username": username,
            "password": hashed_password,
            "bio": "",
            "pic": "https://i.imgur.com/xCvzudW.png",
            "items": [],
            "friends": [],
        }
        result = db.users.insert_one(new_user)

        user = User(user_id=result.inserted_id, username=username)
        flask_login.login_user(user)

        return redirect(url_for("home"))

    if flask_login.current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET and POST routes for login page.
    """
    if request.method == "POST":
        username = request.form["fusername"]
        password = request.form["fpassword"]

        found_user = db.users.find_one({"username": username})
        if not found_user:
            return render_template("login.html", error="User not found.")

        is_valid = bcrypt.check_password_hash(found_user["password"], password)
        if not is_valid:
            return render_template(
                "login.html", error="Username or password is invalid."
            )

        user = User(user_id=found_user["_id"], username=found_user["username"])
        flask_login.login_user(user)
        return redirect(url_for("home"))

    if flask_login.current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    """
    Logs out the current user.
    """
    flask_login.logout_user()
    return redirect(url_for("login"))


@app.route("/")
def home():
    """
    Route for the home page.
    """
    sort_option = request.args.get("sort")

    if sort_option == "lowest":
        docs_cursor = db.items.find({"public": True}).sort("price", 1)
    elif sort_option == "highest":
        docs_cursor = db.items.find({"public": True}).sort("price", -1)
    elif sort_option == "oldest":
        docs_cursor = db.items.find({"public": True}).sort("created_at", 1)
    else:
        docs_cursor = db.items.find({"public": True}).sort("created_at", -1)

    docs = list(docs_cursor)
    return render_template("index.html", docs=docs)


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
        return redirect(url_for("home"))


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


if __name__ == "__main__":
    # Verify the connection works by pinging the database.
    try:
        client.admin.command("ping")
        print(" * Connected to MongoDB!")
    except pymongo.errors.PyMongoError as error:
        print(" * MongoDB connection error:", error)

    FLASK_PORT = os.getenv("FLASK_PORT", "5000")
    # app.run(host="0.0.0.0", port=FLASK_PORT)
    app.run(port=FLASK_PORT)
