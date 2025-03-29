from typing import Annotated

import jwt
from fastapi import Cookie, Depends, HTTPException, status
from jwt.exceptions import InvalidTokenError
from sqlmodel import Session

from app.core.config import Settings, get_settings
from app.core.database import get_session
from app.core.security import TokenData, oauth2_scheme
from app.models.user import Session as UserSession
from app.models.user import User
from app.services.user_service import user_service

SettingsDep = Annotated[Settings, Depends(get_settings)]

# dependency to get DB sessions
SessionDep = Annotated[Session, Depends(get_session)]

# this dependency only ensures that a token exists in the request
TokenDep = Annotated[str, Depends(oauth2_scheme)]


# this dependency make sure that user is logged in
# it also returns the user info in database
async def get_current_user(
    token: TokenDep,
    session: SessionDep,
    settings: SettingsDep,
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )
    try:
        # expiration time is automatically verified in jwt.decode()
        payload = jwt.decode(
            token, settings.auth_token_secret_key, algorithms=[settings.auth_token_algorithm]
        )
        username = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError as err:
        raise credentials_exception from err

    user = user_service.get_user(session, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]


async def get_user_from_cookie(
    refresh_token: Annotated[str | None, Cookie()],
    session: SessionDep,
    settings: SettingsDep,
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
    )
    try:
        # expiration time is automatically verified in jwt.decode()
        payload = jwt.decode(
            refresh_token,
            settings.auth_token_secret_key,
            algorithms=[settings.auth_token_algorithm],
        )
        username = payload.get('sub')
        session_id = payload.get('session_id')
        if (username is None) or (session_id is None):
            raise credentials_exception
    except InvalidTokenError as err:
        raise credentials_exception from err

    user = user_service.get_user_with_sessions(session, username=username, session_id=session_id)
    if user is None:
        raise credentials_exception
    return user


UserFromCookiesDep = Annotated[tuple[User, UserSession], Depends(get_user_from_cookie)]
