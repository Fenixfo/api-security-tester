"""
Suite de pruebas de seguridad de API — plantilla base.

Uso: copia este archivo, renombra a test_<nombre_api>_security.py,
y reemplaza los placeholders (ENDPOINT, PAYLOAD, aserciones) segun
la matriz de casos de prueba generada para el endpoint bajo prueba.

Requiere: pip install pytest requests

Variables de entorno esperadas (nunca hardcodear URLs/credenciales):
  API_BASE_URL     - URL base del entorno AUTORIZADO para pruebas (staging/sandbox)
  USER_TOKEN       - token valido de un usuario con rol normal
  OTHER_USER_TOKEN - token valido de OTRO usuario normal (para pruebas de BOLA)
  ADMIN_TOKEN      - token valido de un usuario con rol admin (para BFLA)
"""

import os
import time

import pytest
import requests

BASE_URL = os.environ["API_BASE_URL"]


@pytest.fixture(scope="session")
def user_session():
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {os.environ['USER_TOKEN']}"
    return s


@pytest.fixture(scope="session")
def other_user_session():
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {os.environ['OTHER_USER_TOKEN']}"
    return s


@pytest.fixture(scope="session")
def admin_session():
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {os.environ['ADMIN_TOKEN']}"
    return s


@pytest.fixture(scope="session")
def anon_session():
    return requests.Session()


# ---------------------------------------------------------------------------
# TC-01 / TC-02 — BOLA / IDOR
# Reemplaza /orders/{id} y OTHER_USER_RESOURCE_ID por los del endpoint real.
# ---------------------------------------------------------------------------

def test_TC01_bola_no_accede_a_recurso_de_otro_usuario(user_session):
    other_user_resource_id = os.environ.get("OTHER_USER_RESOURCE_ID", "REEMPLAZAR")
    resp = user_session.get(f"{BASE_URL}/orders/{other_user_resource_id}")
    assert resp.status_code in (403, 404), (
        f"BOLA: se esperaba 403/404 accediendo a recurso ajeno, se obtuvo {resp.status_code}"
    )


def test_TC02_bola_positivo_accede_a_recurso_propio(user_session):
    own_resource_id = os.environ.get("OWN_RESOURCE_ID", "REEMPLAZAR")
    resp = user_session.get(f"{BASE_URL}/orders/{own_resource_id}")
    assert resp.status_code == 200, "Falso positivo: el usuario no puede acceder a su propio recurso"


# ---------------------------------------------------------------------------
# TC-04 — Mass Assignment
# ---------------------------------------------------------------------------

def test_TC04_mass_assignment_role_ignorado(user_session):
    payload = {"name": "Ana Test", "role": "admin"}
    resp = user_session.patch(f"{BASE_URL}/users/me", json=payload)
    assert resp.status_code in (200, 422), f"Codigo inesperado: {resp.status_code}"
    if resp.status_code == 200:
        body = resp.json()
        assert body.get("role") != "admin", "Mass assignment: el campo 'role' fue aceptado"


# ---------------------------------------------------------------------------
# TC-06 / TC-07 — Broken Authentication (JWT)
# ---------------------------------------------------------------------------

def test_TC06_jwt_alg_none_rechazado(anon_session):
    forged_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
    resp = anon_session.get(
        f"{BASE_URL}/users/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert resp.status_code == 401, f"JWT alg=none deberia ser rechazado, se obtuvo {resp.status_code}"


def test_TC07_jwt_expirado_rechazado(anon_session):
    expired_token = os.environ.get("EXPIRED_TOKEN_FIXTURE", "REEMPLAZAR")
    resp = anon_session.get(
        f"{BASE_URL}/users/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TC-09 / TC-10 — BFLA
# ---------------------------------------------------------------------------

def test_TC09_bfla_ruta_admin_bloqueada_para_user(user_session):
    resp = user_session.get(f"{BASE_URL}/admin/users")
    assert resp.status_code == 403


def test_TC10_bfla_verbo_escritura_bloqueado_para_user(user_session):
    resource_id = os.environ.get("OWN_RESOURCE_ID", "REEMPLAZAR")
    resp = user_session.delete(f"{BASE_URL}/products/{resource_id}")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TC-11 / TC-12 — Unrestricted Resource Consumption
# ---------------------------------------------------------------------------

def test_TC11_limite_de_paginacion_aplicado(user_session):
    resp = user_session.get(f"{BASE_URL}/search", params={"limit": 999999})
    assert resp.status_code in (400, 422) or len(resp.json().get("results", [])) <= 200


@pytest.mark.slow
def test_TC12_rate_limit_aplicado(user_session):
    statuses = []
    for _ in range(100):
        r = user_session.get(f"{BASE_URL}/search", params={"q": "test"})
        statuses.append(r.status_code)
    assert 429 in statuses, "No se observo rate-limiting tras 100 requests rapidas"


# ---------------------------------------------------------------------------
# TC-13 — SQL Injection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND SLEEP(3)--",
])
def test_TC13_sql_injection_no_altera_query(user_session, payload):
    start = time.time()
    resp = user_session.get(f"{BASE_URL}/products", params={"category": payload})
    elapsed = time.time() - start
    assert elapsed < 2.5, f"Posible SQLi basado en tiempo: la respuesta tardo {elapsed:.2f}s"
    assert resp.status_code in (200, 400, 422)
    if resp.status_code == 200:
        assert len(resp.json().get("results", [])) == 0 or "products" in str(resp.json())


# ---------------------------------------------------------------------------
# TC-14 — NoSQL Injection
# ---------------------------------------------------------------------------

def test_TC14_nosql_injection_login_falla(anon_session):
    resp = anon_session.post(
        f"{BASE_URL}/login",
        json={"username": "admin", "password": {"$ne": None}},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TC-16 — XSS almacenado
# ---------------------------------------------------------------------------

def test_TC16_xss_almacenado_escapado_al_leer(user_session):
    payload = "<script>alert(1)</script>"
    create_resp = user_session.post(f"{BASE_URL}/comments", json={"body": payload})
    assert create_resp.status_code in (200, 201)
    comment_id = create_resp.json()["id"]

    read_resp = user_session.get(f"{BASE_URL}/comments/{comment_id}")
    body_returned = read_resp.json()["body"]
    assert "<script>" not in body_returned, "XSS: el payload se devolvio sin escapar"


# ---------------------------------------------------------------------------
# TC-17 — SSRF
# ---------------------------------------------------------------------------

def test_TC17_ssrf_url_interna_rechazada(user_session):
    resp = user_session.post(
        f"{BASE_URL}/webhooks",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert resp.status_code in (400, 422), (
        f"SSRF: la URL de metadata interna deberia ser rechazada, se obtuvo {resp.status_code}"
    )
