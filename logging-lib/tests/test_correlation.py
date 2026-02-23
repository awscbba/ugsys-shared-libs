"""Tests for CorrelationIdMiddleware."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.correlation import HEADER_NAME, CorrelationIdMiddleware, correlation_id_var


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CorrelationIdMiddleware)

    @app.get("/ping")
    def ping():
        return {"correlation_id": correlation_id_var.get()}

    return app


class TestCorrelationIdMiddleware:
    def setup_method(self):
        self.client = TestClient(_make_app())

    def test_generates_correlation_id_when_missing(self):
        resp = self.client.get("/ping")
        assert resp.status_code == 200
        assert HEADER_NAME in resp.headers
        cid = resp.headers[HEADER_NAME]
        assert len(cid) == 36  # UUID format

    def test_propagates_existing_correlation_id(self):
        cid = "my-trace-id-123"
        resp = self.client.get("/ping", headers={HEADER_NAME: cid})
        assert resp.headers[HEADER_NAME] == cid
        assert resp.json()["correlation_id"] == cid

    def test_correlation_id_in_response_header(self):
        resp = self.client.get("/ping")
        assert HEADER_NAME in resp.headers
