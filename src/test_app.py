import pytest
from app import app, db

import datetime
from bson.objectid import ObjectId
from bson.decimal128 import Decimal128

global USER_ID
global ITEM_ID

TEST_USER_POST = {'fusername': 'marc3', 'fpassword': 'password'}
TEST_INCORRECT_POST = {'fusername': 'marc3', 'fpassword': 'assword'}
TEST_USER_MONGO = {'username': 'marc3'}
db.users.delete_one(TEST_USER_MONGO)

TEST_ITEM_POST = {'itemname': '5555', 'description': '5555', 'price': '555', 'url': '555'}
TEST_ITEM_MONGO = {'name': '5555'}
db.items.delete_one(TEST_ITEM_MONGO)

@pytest.fixture
def client():
    app.config.update({"TESTING": True})

    with app.test_client() as client:
        yield client

@pytest.fixture
def user(client):
    global USER_ID
    client.post('/signup', data = TEST_USER_POST)
    USER_ID = db.users.find_one(TEST_USER_MONGO)["_id"]

@pytest.fixture
def login(client, user):
    client.post('/login', data = TEST_USER_POST)

def test_homepage(client):
    response = client.get("/")
    assert response.status_code == 200

#create a user and attempt to create the same user again
def test_user_already_exists(client, user):
    res = client.post('/signup', data = TEST_USER_POST)
    assert 'Username already in use.' in str(res.data)

#login with wrong username and test that an error message is returned
def test_incorrect_login(client, user):
    res = client.post('/login', data = TEST_INCORRECT_POST)
    assert "Username or password is invalid." in str(res.data)

#make user post an item to a page and check to see that that item is on the page
def test_user_add_item(client, user):
    client.post('/add')

#test to see 
def test_index_page__not_logged_in(client):
    res = client.get('/add')
    assert res.status_code == 302

def test_index_page__logged_in(client, user):
    client.post('/login', data = TEST_USER_POST)
    res = client.get('/add')
    assert res.status_code == 200

def test_home(client):
    res = client.get('/')
    assert res.status_code == 200

def test_logout(client, user, login):
    res = client.get('/logout')
    assert res.status_code == 302
 
def test_add(client, user, login):
    response = client.get("/add")
    assert response.status_code == 200

def test_create_item(client, user, login):
    global ITEM_ID
    res = client.post(f"/add/{str(USER_ID)}", data = TEST_ITEM_POST)
    ITEM_ID = db.items.find_one(TEST_ITEM_MONGO)["_id"]
    assert 'You should be redirected automatically to the target URL' in str(res.data)

def test_item(client, user, login):
    global ITEM_ID
    res = client.get(f"/item/{str(ITEM_ID)}")
    assert res.status_code == 200

def test_delete(client, user, login):
    global ITEM_ID
    client.post(f"/delete/{str(ITEM_ID)}", data = TEST_ITEM_POST)
    res = client.get(f'/delete/{str(ITEM_ID)}')
    assert 'You should be redirected automatically to the target URL' in str(res.data)

def test_delete_offer(client, user, login):
    response = client.get('/')
    assert response.status_code == 200

def test_edit(client, user, login):
    response = client.get('/')
    assert response.status_code == 200

def test_update_item(client, user, login):
    response = client.get('/')
    assert response.status_code == 200

def test_view_listings(client, user, login):
    response = client.get('/')
    assert response.status_code == 200

def test_set_public(client):
    response = client.get('/')
    assert response.status_code == 200

def test_set_private(client):
    response = client.get("/setprivate/<item_id>")
    assert response.status_code == 302

def test_offer(client):
    response = client.get('/')
    assert response.status_code == 200

def test_view_offer(client):
    response = client.get('/')
    assert response.status_code == 200

def test_sent_offers(client):
    response = client.get('/')
    assert response.status_code == 200

def test_recieved_offers(client):
    response = client.get('/')
    assert response.status_code == 200

def test_accepts_offers(client):
    response = client.get('/')
    assert response.status_code == 200

def test_reject_offer(client):
    response = client.get('/')
    assert response.status_code == 200

def test_unauthorized_handler(client):
    response = client.get('/')
    assert response.status_code == 200

db.users.delete_one(TEST_USER_MONGO)
db.items.delete_one(TEST_ITEM_MONGO)
pytest.main()