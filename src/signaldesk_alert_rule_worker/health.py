import httpx


def liveness(): return {"status": "ok"}


def readiness(urls, *, timeout, client: httpx.Client | None = None):
    owned_client = client is None
    try:
        current = client or httpx.Client(timeout=timeout)
        return all(current.get(url.rstrip("/") + "/readyz").is_success for url in urls)
    except httpx.HTTPError: return False
    finally:
        if owned_client and client is None:
            current.close()
