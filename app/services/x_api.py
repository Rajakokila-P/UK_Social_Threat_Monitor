import json
import os
import urllib.error
import urllib.parse
import urllib.request


X_API_BASE_URL = "https://api.x.com/2"


class XAPIError(Exception):
    """Raised when the X API request cannot be completed."""


def _get_bearer_token():
    """
    Read the X Bearer Token from the environment.

    The token must never be hard-coded in this file.
    """
    token = os.getenv("X_BEARER_TOKEN")

    if not token:
        raise XAPIError(
            "X Bearer Token is not configured. "
            "Set X_BEARER_TOKEN in the environment."
        )

    return token


def _make_request(endpoint, params=None):
    """
    Make an authenticated GET request to the X API.
    """

    token = _get_bearer_token()

    url = f"{X_API_BASE_URL}{endpoint}"

    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "UK-Social-Threat-Intelligence-Monitor",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as error:
        status_code = error.code

        try:
            response_body = error.read().decode("utf-8")
        except Exception:
            response_body = ""

        if status_code == 401:
            raise XAPIError(
                "X API authentication failed. Check the Bearer Token."
            )

        if status_code == 402:
            raise XAPIError(
                "X API credits are unavailable. "
                "The request requires API billing/credits."
            )

        if status_code == 403:
            raise XAPIError(
                "X API refused this request. "
                "The app may not have permission for this endpoint."
            )

        if status_code == 404:
            raise XAPIError(
                "The requested X resource was not found."
            )

        if status_code == 429:
            raise XAPIError(
                "X API rate limit reached. Try again later."
            )

        raise XAPIError(
            f"X API returned HTTP {status_code}. {response_body}"
        )

    except urllib.error.URLError as error:
        raise XAPIError(
            f"Could not connect to X API: {error.reason}"
        )

    except Exception as error:
        raise XAPIError(
            f"Unexpected X API error: {error}"
        )


def get_user_by_username(username):
    """
    Retrieve public X profile information for a username.
    """

    username = username.strip().lstrip("@")

    if not username:
        raise XAPIError("An X username is required.")

    return _make_request(
        f"/users/by/username/{urllib.parse.quote(username)}",
        {
            "user.fields": (
                "id,name,username,created_at,"
                "description,location,profile_image_url,"
                "public_metrics,verified"
            )
        },
    )


def get_user_posts(user_id, max_results=10):
    """
    Retrieve recent posts available through the X API
    for the supplied user ID.

    API availability depends on the X developer account,
    permissions and credits.
    """

    if not user_id:
        raise XAPIError("An X user ID is required.")

    max_results = max(5, min(int(max_results), 100))

    return _make_request(
        f"/users/{urllib.parse.quote(str(user_id))}/tweets",
        {
            "max_results": max_results,
            "tweet.fields": (
                "id,text,created_at,lang,"
                "public_metrics,conversation_id"
            ),
        },
    )


def test_x_connection(username="R2611K"):
    """
    Test the connector without exposing the Bearer Token.
    """

    try:
        result = get_user_by_username(username)

        return {
            "success": True,
            "message": "X API connection successful.",
            "data": result,
        }

    except XAPIError as error:
        return {
            "success": False,
            "message": str(error),
            "data": None,
        }