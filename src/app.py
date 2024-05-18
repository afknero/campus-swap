"""
This module defines a Flask application with routes and functionalities for managing user profiles, items, offers, and friends.
"""

#!/usr/bin/env python3

import os
from datetime import datetime, UTC
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
def request_loader(req):
    """
    Callback to load a user from a request.
    """
    username = req.form.get("username")
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
            return render_template("signup.html", error="Username Unavailable.")

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = {
            "username": username,
            "password": hashed_password,
            "bio": "",
            "pic": "https://i.imgur.com/xCvzudW.png",
            "items": [],
            "following": [],
            "followers": [],
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
            return render_template("login.html", error="User Not Found.")

        is_valid = bcrypt.check_password_hash(found_user["password"], password)
        if not is_valid:
            return render_template("login.html", error="Incorrect Password.")

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

    items = list(docs_cursor)
    return render_template("index.html", items=items)


@app.route("/add", methods=["GET", "POST"])
@flask_login.login_required
def create_item():
    """
    Route to handle the creation of a new listing.
    """
    if request.method == "POST":
        user_id = flask_login.current_user.get_id()
        user = db.users.find_one({"_id": ObjectId(user_id)})

        username = user["username"]
        name = request.form["itemname"]
        desc = request.form["description"]
        price = Decimal128(request.form["price"])
        url = request.form["url"]
        item = {
            "user_id": ObjectId(user_id),
            "username": username,
            "name": name,
            "description": desc,
            "image_url": url,
            "price": price,
            "public": True,
            "created_at": datetime.now(UTC),
        }
        db.items.insert_one(item)
        return redirect(url_for("view_profile"))

    return render_template("makeListing.html")


@app.route("/item/<item_id>")
@flask_login.login_required
def view_item(item_id):
    """
    View details of a specific item.
    """
    try:
        found_item = db.items.find_one({"_id": ObjectId(item_id)})
        if not found_item:
            return redirect(url_for("home"))

        return render_template("viewListing.html", item=found_item)
    except pymongo.errors.PyMongoError as e:
        print("MongoDB error:", e)
        return redirect(url_for("home"))


@app.route("/edit/<item_id>", methods=["GET", "POST"])
@flask_login.login_required
def edit_item(item_id):
    """
    Edit details of a specific item.
    """
    if request.method == "POST":
        try:
            name = request.form["name"]
            desc = request.form["desc"]
            price = Decimal128(request.form["price"])
            url = request.form["url"]

            item = {"name": name, "description": desc, "image_url": url, "price": price}
            db.items.update_one({"_id": ObjectId(item_id)}, {"$set": item})

            return redirect(url_for("view_profile"))
        except pymongo.errors.PyMongoError as e:
            print("MongoDB error:", e)
            return redirect(url_for("edit_item", item_id=item_id))

    found_item = db.items.find_one({"_id": ObjectId(item_id)})
    if not found_item:
        return redirect(url_for("view_profile"))

    return render_template("editListing.html", item=found_item)


@app.route("/delete/<item_id>")
@flask_login.login_required
def delete_item(item_id):
    """
    Delete a specific item.
    """
    # delete the specified item
    db.items.delete_one({"_id": ObjectId(item_id)})

    # purge related offers
    db.offers.delete_many({"offereditems": item_id})
    db.offers.delete_many({"offerforid": item_id})

    return redirect(url_for("view_profile"))


@app.route("/set-public/<item_id>")
@flask_login.login_required
def set_public(item_id):
    """
    Set the visibility of an item to public.
    """
    db.items.update_one({"_id": ObjectId(item_id)}, {"$set": {"public": True}})
    return redirect(url_for("view_profile"))


@app.route("/set-private/<item_id>")
@flask_login.login_required
def set_private(item_id):
    """
    Set the visibility of an item to private.
    """
    db.items.update_one({"_id": ObjectId(item_id)}, {"$set": {"public": False}})
    return redirect(url_for("view_profile"))


@app.route("/offer/<item_id>", methods=["GET", "POST"])
@flask_login.login_required
def make_offer(item_id):
    """
    Display the offer page for a specific item and handle creating a trade offer.
    """
    if request.method == "POST":
        offered = request.form.getlist("mycheckbox")
        receiver = db.items.find_one({"_id": ObjectId(item_id)}).get("user")
        sender = flask_login.current_user.get_id()

        offer = {
            "desired": item_id,
            "offered": offered,
            "sender": ObjectId(sender),
            "receiver": receiver,
            "status": "sent",
            "created_at": datetime.now(UTC),
        }
        db.offers.insert_one(offer)
        return redirect(url_for("offers_sent"))

    found_item = db.items.find_one({"_id": ObjectId(item_id)})
    if not found_item:
        return redirect(url_for("home"))

    user_id = flask_login.current_user.get_id()
    user_items = list(db.items.find({"user": ObjectId(user_id)}))

    return render_template("makeOffer.html", item=found_item, item=user_items)


@app.route("/delete-offer/<offer_id>")
@flask_login.login_required
def delete_offer(offer_id):
    """
    Delete a specific offer.
    """
    db.offers.delete_one({"_id": ObjectId(offer_id)})
    return redirect(url_for("offers_sent"))


@app.route("/accept-offer/<offer_id>")
@flask_login.login_required
def accept_offer(offer_id):
    """
    Accept an offer by updating its status to "accepted".
    """
    db.offers.update_one({"_id": ObjectId(offer_id)}, {"$set": {"status": "accepted"}})
    return redirect(url_for("offers_received"))


@app.route("/reject-offer/<offer_id>")
@flask_login.login_required
def reject_offer(offer_id):
    """
    Accept an offer by updating its status to "accepted".
    """
    db.offers.update_one({"_id": ObjectId(offer_id)}, {"$set": {"status": "rejected"}})
    return redirect(url_for("offers_received"))


@app.route("/offers-sent")
@flask_login.login_required
def offers_sent():
    """
    Retrieve and display the trade offers sent by the current user.
    """
    # find the current user's offers
    user = flask_login.current_user.get_id()
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

    return render_template("sentOffers.html", offers=offers)


@app.route("/offers-received")
@flask_login.login_required
def offers_received():
    """
    Retrieve and display the trade offers sent to the current user.
    """
    # find the current user's offers
    user = flask_login.current_user.get_id()
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

    return render_template("recievedOffers.html", offers=offers)


@app.route("/profile")
@flask_login.login_required
def view_profile():
    """
    Display the profile page of the current user.
    """
    user_to_find = flask_login.current_user.id
    user = db.users.find_one({"_id": ObjectId(user_to_find)})

    user = {
        "username": user["username"],
        "bio": user["bio"],
        "pic": user["pic"],
    }
    items = list(db.items.find({"user": ObjectId(user_to_find)}))
    # TODO: combine with view_listing
    # return render_template("viewlisting.html", docs=items)
    # TODO: append friend pic and username
    # friends_list = list(user["friends"])
    # friends = []
    # for friend in friends_list:
    #     current_friend = db.users.find_one({"_id": ObjectId(friend)})
    #     friend_info = {
    #         "pic": current_friend["pic"],
    #         "username": current_friend["username"],
    #     }
    #     friends.append(friend_info)
    # return render_template("friends.html", friends=friends)
    return render_template("viewProfile.html", user=user, items=items)


@app.route("/edit-profile/", methods=["GET", "POST"])
@flask_login.login_required
def edit_profile():
    """
    Allow the current user to edit their profile details.
    """
    if request.method == "POST":
        bio = request.form["bio"]
        pic = request.form["pic"]
        db.users.update_one(
            {"_id": ObjectId(flask_login.current_user.get_id())},
            {"$set": {"bio": bio, "pic": pic}},
        )
        return redirect(url_for("view_profile"))

    user_id = flask_login.current_user.id
    user = db.users.find_one({"_id": ObjectId(user_id)})

    user = {
        "username": user["username"],
        "bio": user["bio"],
        "pic": user["pic"],
    }

    return render_template("editProfile.html", user=user)


@app.route("/u/<username>", methods=["GET"])
@flask_login.login_required
def view_user(username):
    """
    Display the profile page of a specified user.
    """
    # gets the other user profile
    user = db.users.find_one({"username": username})
    if user["_id"] == flask_login.current_user.get_id():
        return redirect(url_for("profile"))

    user = {
        "username": user["username"],
        "bio": user["bio"],
        "pic": user["pic"],
    }
    items = list(db.items.find({"user": ObjectId(user["_id"])}))

    # checks if user is in logged in user's friends
    logged_in_user = db.users.find_one(
        {"_id": ObjectId(flask_login.current_user.get_id())}
    )
    print(list(logged_in_user["friends"]))
    logged_in_user_friends = list(logged_in_user["friends"])
    if user["_id"] in logged_in_user_friends:
        friends = True
        print("true")
    else:
        friends = False
        print("false")

    return render_template(
        "viewUserProfile.html", user=user, items=items, friends=friends
    )


@app.route("/add-follower/<username>", methods=["GET"])
@flask_login.login_required
def add_follower(username):
    """
    Add a user as a friend.
    """
    user = db.users.find_one({"username": username})

    follower = db.users.find_one({"_id": ObjectId(flask_login.current_user.get_id())})

    following = list(follower["friends"])
    if user["_id"] in following:
        return redirect(url_for("view_user", username=username))

    db.users.update_one(
        {"_id": ObjectId(flask_login.current_user.get_id())},
        {"$push": {"following": user["_id"]}},
    )
    return redirect(url_for("view_user", username=username))


if __name__ == "__main__":
    # verify the connection works by pinging the database
    try:
        client.admin.command("ping")
        print(" * Connected to MongoDB!")
    except pymongo.errors.PyMongoError as error:
        print(" * MongoDB connection error:", error)

    FLASK_PORT = os.getenv("FLASK_PORT", "5000")
    # app.run(host="0.0.0.0", port=FLASK_PORT)
    app.run(port=FLASK_PORT)
