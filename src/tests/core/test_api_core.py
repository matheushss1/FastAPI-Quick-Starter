from fastapi import status
from fastapi.testclient import TestClient


def test_health_check_route(client: TestClient):
    response = client.get("/health-check")
    assert response.status_code == status.HTTP_200_OK
    assert response.json().get("data") == "Test API is working as expected"
