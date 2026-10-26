"""Auth API tests. Fixtures (`app`, `client`) come from tests/conftest.py."""


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_register(client):
    r = client.post("/api/auth/register", json={
        "username": "analyst1",
        "email": "analyst1@example.com",
        "password": "securepass123",
    })
    assert r.status_code == 201
    data = r.get_json()
    assert "token" in data
    assert data["user"]["username"] == "analyst1"


def test_register_duplicate(client):
    payload = {"username": "dup", "email": "dup@example.com", "password": "pass1234"}
    client.post("/api/auth/register", json=payload)
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 409


def test_login(client):
    client.post("/api/auth/register", json={
        "username": "user2", "email": "user2@example.com", "password": "mypassword"
    })
    r = client.post("/api/auth/login", json={
        "email": "user2@example.com", "password": "mypassword"
    })
    assert r.status_code == 200
    assert "token" in r.get_json()


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={
        "username": "user3", "email": "user3@example.com", "password": "correct"
    })
    r = client.post("/api/auth/login", json={
        "email": "user3@example.com", "password": "wrong"
    })
    assert r.status_code == 401


def test_me_requires_auth(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401
