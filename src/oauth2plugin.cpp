/*
 * This file is part of oauth2 plugin
 *
 * Copyright (C) 2010 Nokia Corporation.
 * Copyright (C) 2012 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "common.h"
#include "oauth2plugin.h"
#include "oauth2tokendata.h"

#include <QJsonDocument>
#include <QUrl>
#include <QUrlQuery>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QDateTime>


using namespace SignOn;
using namespace OAuth2PluginNS;

namespace OAuth2PluginNS {

const QString WEB_SERVER = QString("web_server");
const QString USER_AGENT = QString("user_agent");

const QString TOKEN = QString("Token");
const QString EXPIRY = QString("Expiry");
const QString SCOPES = QString("Scopes");

const int HTTP_STATUS_OK = 200;
const QString AUTH_CODE = QString("code");
const QString REDIRECT_URI = QString("redirect_uri");
const QString RESPONSE_TYPE = QString("response_type");
const QString STATE = QString("state");
const QString USERNAME = QString("username");
const QString PASSWORD = QString("password");
const QString ASSERTION_TYPE = QString("assertion_type");
const QString ASSERTION = QString("assertion");
const QString ACCESS_TOKEN = QString("access_token");
const QString DISPLAY = QString("display");
const QString EXPIRES_IN = QString("expires_in");
const QString SCOPE = QString("scope");
const QString TIMESTAMP = QString("timestamp");
const QString GRANT_TYPE = QString("grant_type");
const QString AUTHORIZATION_CODE = QString("authorization_code");
const QString USER_BASIC = QString("user_basic");
const QString CLIENT_ID = QString("client_id");
const QString CLIENT_SECRET = QString("client_secret");
const QString REFRESH_TOKEN = QString("refresh_token");
const QString AUTH_ERROR = QString("error");

const QByteArray CONTENT_TYPE = QByteArray("Content-Type");
const QByteArray CONTENT_APP_URLENCODED = QByteArray("application/x-www-form-urlencoded");
const QByteArray CONTENT_APP_JSON = QByteArray("application/json");
const QByteArray CONTENT_TEXT_PLAIN = QByteArray("text/plain");
const QByteArray CONTENT_TEXT_HTML = QByteArray("text/html");


class OAuth2PluginPrivate
{
public:
    OAuth2PluginPrivate():
        m_grantType(GrantType::Undefined)
    {
        TRACE();

        // Initialize randomizer
        qsrand(QTime::currentTime().msec());
    }

    ~OAuth2PluginPrivate()
    {
        TRACE();
    }

    QString m_mechanism;
    OAuth2PluginData m_oauth2Data;
    QVariantMap m_tokens;
    QString m_state;
    QString m_key;
    QString m_username;
    QString m_password;
    GrantType::e m_grantType;
}; //Private

} //namespace OAuth2PluginNS

OAuth2Plugin::OAuth2Plugin(QObject *parent):
    BasePlugin(parent),
    d_ptr(new OAuth2PluginPrivate())
{
    TRACE();
}

OAuth2Plugin::~OAuth2Plugin()
{
    TRACE();
    delete d_ptr;
    d_ptr = 0;
}

QStringList OAuth2Plugin::mechanisms()
{
    QStringList res = QStringList();
    res.append(WEB_SERVER);
    res.append(USER_AGENT);
    return res;
}

void OAuth2Plugin::sendOAuth2AuthRequest()
{
    Q_D(OAuth2Plugin);

    QUrl url(QString("https://%1/%2").arg(d->m_oauth2Data.Host()).arg(d->m_oauth2Data.AuthPath()));
    url.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
    url.addQueryItem(REDIRECT_URI, d->m_oauth2Data.RedirectUri());
    if (!d->m_oauth2Data.DisableStateParameter()) {
        d->m_state = QString::number(qrand());
        url.addQueryItem(STATE, d->m_state);
    }
    if (!d->m_oauth2Data.ResponseType().isEmpty()) {
        url.addQueryItem(RESPONSE_TYPE,
                         d->m_oauth2Data.ResponseType().join(" "));
    }
    if (!d->m_oauth2Data.Display().isEmpty()) {
        url.addQueryItem(DISPLAY, d->m_oauth2Data.Display());
    }
    if (!d->m_oauth2Data.Scope().empty()) {
        QString separator = QLatin1String(" ");

        /* The scopes separator defined in the OAuth 2.0 spec is a space;
         * unfortunately facebook accepts only a comma, so we have to treat
         * it as a special case. See:
         * http://bugs.developers.facebook.net/show_bug.cgi?id=11120
         */
        if (d->m_oauth2Data.Host().contains(QLatin1String("facebook.com"))) {
            separator = QLatin1String(",");
        }

        // Passing list of scopes
        url.addQueryItem(SCOPE, d->m_oauth2Data.Scope().join(separator));
    }
    TRACE() << "Url = " << url.toString();
    SignOn::UiSessionData uiSession;
    uiSession.setOpenUrl(url.toString());
    if (!d->m_oauth2Data.RedirectUri().isEmpty())
        uiSession.setFinalUrl(d->m_oauth2Data.RedirectUri());

    /* add username and password, for fields initialization (the
     * decision on whether to actually use them is up to the signon UI */
    uiSession.setUserName(d->m_username);
    uiSession.setSecret(d->m_password);

    emit userActionRequired(uiSession);
}

bool OAuth2Plugin::validateInput(const SignOn::SessionData &inData,
                                 const QString &mechanism)
{
    OAuth2PluginData input = inData.data<OAuth2PluginData>();
    if (input.Host().isEmpty()
        || input.ClientId().isEmpty()
        || input.RedirectUri().isEmpty()
        || input.AuthPath().isEmpty())
        return false;

    if (mechanism == WEB_SERVER) {
        /* According to the specs, the client secret is also required; however,
         * some services do not require it, see for instance point 8 from
         * http://msdn.microsoft.com/en-us/library/live/hh243647.aspx#authcodegrant
         */
        if (input.TokenPath().isEmpty())
            return false;
    }

    return true;
}

bool OAuth2Plugin::respondWithStoredToken(const QVariantMap &token,
                                          const QStringList &scopes)
{
    int timeToExpiry = 0;
    // if the token is expired, ignore it
    if (token.contains(EXPIRY)) {
        timeToExpiry =
            token.value(EXPIRY).toUInt() +
            token.value(TIMESTAMP).toUInt() -
            QDateTime::currentDateTime().toTime_t();
        if (timeToExpiry < 0) {
            TRACE() << "Stored token is expired";
            return false;
        }
    }

    /* if the stored token does not contain all the requested scopes,
     * we cannot use it now */
    if (!scopes.isEmpty()) {
        if (!token.contains(SCOPES)) return false;
        QSet<QString> cachedScopes =
            token.value(SCOPES).toStringList().toSet();
        if (!cachedScopes.contains(scopes.toSet())) return false;
    }

    if (token.contains(TOKEN)) {
        OAuth2PluginTokenData response;
        response.setAccessToken(token.value(TOKEN).toByteArray());
        if (token.contains(REFRESH_TOKEN)) {
            response.setRefreshToken(token.value(REFRESH_TOKEN).toByteArray());
        }
        if (token.contains(EXPIRY)) {
            response.setExpiresIn(timeToExpiry);
        }
        TRACE() << "Responding with stored token";
        emit result(response);
        return true;
    }

    return false;
}

void OAuth2Plugin::process(const SignOn::SessionData &inData,
                           const QString &mechanism)
{
    Q_D(OAuth2Plugin);

    if ((!mechanism.isEmpty()) && (!mechanisms().contains(mechanism))) {
        emit error(Error(Error::MechanismNotAvailable));
        return;
    }

    if (!validateInput(inData, mechanism)) {
        TRACE() << "Invalid parameters passed";
        emit error(Error(Error::MissingData));
        return;
    }

    d->m_mechanism = mechanism;
    d->m_oauth2Data = inData.data<OAuth2PluginData>();
    d->m_key = d->m_oauth2Data.ClientId();

    //get stored data
    OAuth2TokenData tokens = inData.data<OAuth2TokenData>();
    d->m_tokens = tokens.Tokens();
    if (inData.UiPolicy() == RequestPasswordPolicy) {
        //remove old token for given Key
        TRACE() << d->m_tokens;
        d->m_tokens.remove(d->m_key);
        OAuth2TokenData tokens;
        tokens.setTokens(d->m_tokens);
        emit store(tokens);
        TRACE() << d->m_tokens;
    } else if (d->m_oauth2Data.ForceTokenRefresh()) {
        // remove only the access token, not the refresh token
        QVariantMap storedData = d->m_tokens.value(d->m_key).toMap();
        storedData.remove(TOKEN);
        d->m_tokens.insert(d->m_key, storedData);
        OAuth2TokenData tokens;
        tokens.setTokens(d->m_tokens);
        Q_EMIT store(tokens);
        TRACE() << "Clearing access token" << d->m_tokens;
    }

    //get provided token data if specified
    if (!tokens.ProvidedTokens().isEmpty()) {
        //check that the provided tokens contain required values
        OAuth2PluginTokenData providedTokens =
                SignOn::SessionData(tokens.ProvidedTokens())
                .data<OAuth2PluginTokenData>();
        if (providedTokens.AccessToken().isEmpty() ||
            providedTokens.RefreshToken().isEmpty()) {
            //note: we don't check ExpiresIn as it might not be required
            TRACE() << "Invalid provided tokens data - continuing normal process flow";
        } else {
            TRACE() << "Storing provided tokens";
            OAuth2PluginTokenData storeTokens;
            storeTokens.setAccessToken(providedTokens.AccessToken());
            storeTokens.setRefreshToken(providedTokens.RefreshToken());
            storeTokens.setExpiresIn(providedTokens.ExpiresIn());
            storeResponse(storeTokens);
        }
    }

    QVariant tokenVar = d->m_tokens.value(d->m_key);
    QVariantMap storedData;
    if (tokenVar.canConvert<QVariantMap>()) {
        storedData = tokenVar.value<QVariantMap>();
        if (respondWithStoredToken(storedData, d->m_oauth2Data.Scope())) {
            return;
        }
    }

    /* Get username and password; the plugin doesn't use them, but forwards
     * them to the signon UI */
    d->m_username = inData.UserName();
    d->m_password = inData.Secret();

    if (mechanism == WEB_SERVER || mechanism == USER_AGENT) {
        if (mechanism == WEB_SERVER &&
            storedData.contains(REFRESH_TOKEN) &&
            !storedData[REFRESH_TOKEN].toString().isEmpty()) {
            /* If we have a refresh token, use it to get a renewed
             * access token */
            refreshOAuth2Token(storedData[REFRESH_TOKEN].toString());
        } else {
            sendOAuth2AuthRequest();
        }
    }
    else {
        emit error(Error(Error::MechanismNotAvailable));
    }
}

QString OAuth2Plugin::urlEncode(QString strData)
{
    return QUrl::toPercentEncoding(strData).constData();
}

void OAuth2Plugin::userActionFinished(const SignOn::UiSessionData &data)
{
    Q_D(OAuth2Plugin);

    if (handleUiErrors(data)) return;

    TRACE() << data.UrlResponse();

    // Checking if authorization server granted access
    QUrl url = QUrl(data.UrlResponse());
    if (url.hasQueryItem(AUTH_ERROR)) {
        TRACE() << "Server denied access permission";
        emit error(Error(Error::NotAuthorized, url.queryItemValue(AUTH_ERROR)));
        return;
    }

    if (d->m_mechanism == USER_AGENT) {
        // Response should contain the access token
        OAuth2PluginTokenData respData;
        if (url.hasFragment()) {
            QString state;
            respData.setScope(d->m_oauth2Data.Scope());
            QUrlQuery fragment(url.fragment());
            typedef QPair<QString, QString> StringPair;
            Q_FOREACH(const StringPair &pair, fragment.queryItems()) {
                if (pair.first == ACCESS_TOKEN) {
                    respData.setAccessToken(pair.second);
                } else if (pair.first == EXPIRES_IN) {
                    respData.setExpiresIn(pair.second.toInt());
                } else if (pair.first == REFRESH_TOKEN) {
                    respData.setRefreshToken(pair.second);
                } else if (pair.first == STATE) {
                    state = pair.second;
                } else if (pair.first == SCOPE) {
                    respData.setScope(pair.second.split(' ', QString::SkipEmptyParts));
                }
            }
            if (!d->m_oauth2Data.DisableStateParameter() &&
                state != d->m_state) {
                Q_EMIT error(Error(Error::NotAuthorized,
                                   QString("'state' parameter mismatch")));
                return;
            }

            if (respData.AccessToken().isEmpty()) {
                emit error(Error(Error::NotAuthorized, QString("Access token not present")));
            } else {
                storeResponse(respData);

                emit result(respData);
            }
        }
        else {
            emit error(Error(Error::NotAuthorized, QString("Access token not present")));
        }
    } else if (d->m_mechanism == WEB_SERVER) {
        // Access grant can be one of the floolwing types
        // 1. Authorization code (code, redirect_uri)
        // 2. Resource owner credentials (username, password)
        // 3. Assertion (assertion_type, assertion)
        // 4. Refresh Token (refresh_token)
        QUrl newUrl;
        if (url.hasQueryItem(AUTH_CODE)) {
            if (!d->m_oauth2Data.DisableStateParameter() &&
                d->m_state != url.queryItemValue(STATE)) {
                Q_EMIT error(Error(Error::NotAuthorized,
                                   QString("'state' parameter mismatch")));
                return;
            }
            QString code = url.queryItemValue(AUTH_CODE);
            newUrl.addQueryItem(GRANT_TYPE, AUTHORIZATION_CODE);
            newUrl.addQueryItem(AUTH_CODE, code);
            newUrl.addQueryItem(REDIRECT_URI, d->m_oauth2Data.RedirectUri());
            sendOAuth2PostRequest(newUrl,
                                  GrantType::AuthorizationCode);
        }
        else if (url.hasQueryItem(USERNAME) && url.hasQueryItem(PASSWORD)) {
            QString username = url.queryItemValue(USERNAME);
            QString password = url.queryItemValue(PASSWORD);
            newUrl.addQueryItem(GRANT_TYPE, USER_BASIC);
            newUrl.addQueryItem(USERNAME, username);
            newUrl.addQueryItem(PASSWORD, password);
            sendOAuth2PostRequest(newUrl,
                                  GrantType::UserBasic);
        }
        else if (url.hasQueryItem(ASSERTION_TYPE) && url.hasQueryItem(ASSERTION)) {
            QString assertion_type = url.queryItemValue(ASSERTION_TYPE);
            QString assertion = url.queryItemValue(ASSERTION);
            newUrl.addQueryItem(GRANT_TYPE, ASSERTION);
            newUrl.addQueryItem(ASSERTION_TYPE, assertion_type);
            newUrl.addQueryItem(ASSERTION, assertion);
            sendOAuth2PostRequest(newUrl,
                                  GrantType::Assertion);
        }
        else if (url.hasQueryItem(REFRESH_TOKEN)) {
            QString refresh_token = url.queryItemValue(REFRESH_TOKEN);
            refreshOAuth2Token(refresh_token);
        }
        else {
            emit error(Error(Error::NotAuthorized, QString("Access grant not present")));
        }
    }
}

QVariantMap OAuth2Plugin::parseReply(const QByteArray &contentType,
                                     const QByteArray &replyContent)
{
    typedef QVariantMap (OAuth2Plugin::*Parser)(const QByteArray &replyContent);
    Parser preferredParser;
    Parser fallbackParser;

    QVariantMap map;

    // Handling application/json content type
    if (contentType.startsWith(CONTENT_APP_JSON)) {
        TRACE() << "application/json content received";
        preferredParser = &OAuth2Plugin::parseJSONReply;
        fallbackParser = &OAuth2Plugin::parseTextReply;
    }
    // Added for facebook Graph API's (handling text/plain content type)
    else if (contentType.startsWith(CONTENT_TEXT_PLAIN) ||
             contentType.startsWith(CONTENT_TEXT_HTML) ||
               contentType.startsWith(CONTENT_APP_URLENCODED)) {
        TRACE() << contentType << "content received";
        preferredParser = &OAuth2Plugin::parseTextReply;
        fallbackParser = &OAuth2Plugin::parseJSONReply;
    } else {
        TRACE() << "Unsupported content type received: " << contentType;
        Q_EMIT error(Error(Error::OperationFailed,
                           QString("Unsupported content type received")));
        return map;
    }

    map = (this->*preferredParser)(replyContent);
    if (Q_UNLIKELY(map.isEmpty())) {
        TRACE() << "Parse failed, trying fallback parser";
        map = (this->*fallbackParser)(replyContent);
        if (Q_UNLIKELY(map.isEmpty())) {
            TRACE() << "Parse failed";
            Q_EMIT error(Error(Error::NotAuthorized,
                               QString("No access token found")));
        }
    }
    return map;
}

// Method to handle responses for OAuth 2.0 requests
void OAuth2Plugin::serverReply(QNetworkReply *reply)
{
    Q_D(OAuth2Plugin);

    QByteArray replyContent = reply->readAll();
    TRACE() << replyContent;

    // Handle error responses
    QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    TRACE() << statusCode;
    if (statusCode != HTTP_STATUS_OK) {
        handleOAuth2Error(replyContent);
        return;
    }

    // Handling 200 OK response (HTTP_STATUS_OK) WITH content
    if (reply->hasRawHeader(CONTENT_TYPE)) {
        QVariantMap map = parseReply(reply->rawHeader(CONTENT_TYPE), replyContent);
        if (Q_UNLIKELY(map.isEmpty())) {
            // The error has already been delivered
            return;
        }
        QByteArray accessToken = map["access_token"].toByteArray();
        int expiresIn = map["expires_in"].toInt();
        if (expiresIn == 0) {
            // Facebook uses just "expires" as key
            expiresIn = map["expires"].toInt();
        }
        QByteArray refreshToken = map["refresh_token"].toByteArray();

        QStringList scope;
        if (map.contains(SCOPE)) {
            QString rawScope = QString::fromUtf8(map[SCOPE].toByteArray());
            scope = rawScope.split(' ', QString::SkipEmptyParts);
        } else {
            scope = d->m_oauth2Data.Scope();
        }

        if (accessToken.isEmpty()) {
            TRACE()<< "Access token is empty";
            Q_EMIT error(Error(Error::NotAuthorized,
                               QString("Access token is empty")));
        } else {
            OAuth2PluginTokenData response;
            response.setAccessToken(accessToken);
            response.setRefreshToken(refreshToken);
            response.setExpiresIn(expiresIn);
            response.setScope(scope);
            storeResponse(response);
            emit result(response);
        }
    }
    // Handling 200 OK response (HTTP_STATUS_OK) WITHOUT content
    else {
        TRACE()<< "Content is not present";
        emit error(Error(Error::OperationFailed, QString("Content missing")));
    }
}

bool OAuth2Plugin::handleNetworkError(QNetworkReply *reply,
                                      QNetworkReply::NetworkError err)
{
    if (err >= QNetworkReply::ContentAccessDenied) {
        QByteArray replyContent = reply->readAll();
        TRACE() << replyContent;
        handleOAuth2Error(replyContent);
        return true;
    }
    return BasePlugin::handleNetworkError(reply, err);
}

void OAuth2Plugin::handleOAuth2Error(const QByteArray &reply)
{
    Q_D(OAuth2Plugin);

    TRACE();
    QVariantMap map = parseJSONReply(reply);
    QByteArray errorString = map["error"].toByteArray();
    if (!errorString.isEmpty()) {
        Error::ErrorType type = Error::OperationFailed;
        if (errorString == QByteArray("incorrect_client_credentials")) {
            type = Error::InvalidCredentials;
        }
        else if (errorString == QByteArray("redirect_uri_mismatch")) {
            type = Error::InvalidCredentials;
        }
        else if (errorString == QByteArray("bad_authorization_code")) {
            type = Error::InvalidCredentials;
        }
        else if (errorString == QByteArray("invalid_client_credentials")) {
            type = Error::InvalidCredentials;
        }
        else if (errorString == QByteArray("unauthorized_client")) {
            type = Error::NotAuthorized;
        }
        else if (errorString == QByteArray("invalid_assertion")) {
            type = Error::InvalidCredentials;
        }
        else if (errorString == QByteArray("unknown_format")) {
            type = Error::InvalidQuery;
        }
        else if (errorString == QByteArray("authorization_expired")) {
            type = Error::InvalidCredentials;
        }
        else if (errorString == QByteArray("multiple_credentials")) {
            type = Error::InvalidQuery;
        }
        else if (errorString == QByteArray("invalid_user_credentials")) {
            type = Error::InvalidCredentials;
        }
        else if (errorString == QByteArray("invalid_grant")) {
            if (d->m_grantType == GrantType::RefreshToken) {
                /* The refresh token has expired; try once more using
                 * the web-based authentication flow. */
                TRACE() << "Authenticating without refresh token";
                sendOAuth2AuthRequest();
                return;
            }
            type = Error::NotAuthorized;
        }
        TRACE() << "Error Emitted";
        emit error(Error(type, errorString));
        return;
    }

    // Added to work with facebook Graph API's
    errorString = map["message"].toByteArray();

    TRACE() << "Error Emitted";
    emit error(Error(Error::OperationFailed, errorString));
}

void OAuth2Plugin::refreshOAuth2Token(const QString &refreshToken)
{
    TRACE() << refreshToken;
    QUrl url;
    url.addQueryItem(GRANT_TYPE, REFRESH_TOKEN);
    url.addQueryItem(REFRESH_TOKEN, refreshToken);
    sendOAuth2PostRequest(url, GrantType::RefreshToken);
}

void OAuth2Plugin::sendOAuth2PostRequest(QUrl &postData,
                                         GrantType::e grantType)
{
    Q_D(OAuth2Plugin);

    TRACE();

    QUrl url(QString("https://%1/%2").arg(d->m_oauth2Data.Host())
             .arg(d->m_oauth2Data.TokenPath()));
    QNetworkRequest request(url);
    request.setRawHeader(CONTENT_TYPE, CONTENT_APP_URLENCODED);

    if (!d->m_oauth2Data.ClientSecret().isEmpty()) {
        if (d->m_oauth2Data.ForceClientAuthViaRequestBody()) {
            postData.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
            postData.addQueryItem(CLIENT_SECRET, d->m_oauth2Data.ClientSecret());
        } else {
            QByteArray authorization =
                QUrl::toPercentEncoding(d->m_oauth2Data.ClientId()) + ":" +
                QUrl::toPercentEncoding(d->m_oauth2Data.ClientSecret());
            QByteArray basicAuthorization =
                QByteArray("Basic ") + authorization.toBase64();
            request.setRawHeader("Authorization", basicAuthorization);
        }
    } else {
        postData.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
    }

    d->m_grantType = grantType;

    TRACE() << "Query string = " << postData;
    postRequest(request, postData.encodedQuery());
}

void OAuth2Plugin::storeResponse(const OAuth2PluginTokenData &response)
{
    Q_D(OAuth2Plugin);

    OAuth2TokenData tokens;
    QVariantMap token;
    token.insert(TOKEN, response.AccessToken());
    /* Do not overwrite the refresh token with an empty one: when using the
     * refresh token to obtain a new access token, the replie could not contain
     * a refresh token (or contain an empty one).
     * In such cases, we should re-store the old refresh token.
     */
    QString refreshToken;
    if (response.RefreshToken().isEmpty()) {
        QVariant tokenVar = d->m_tokens.value(d->m_key);
        QVariantMap storedData;
        if (tokenVar.canConvert<QVariantMap>()) {
            storedData = tokenVar.value<QVariantMap>();
            if (storedData.contains(REFRESH_TOKEN) &&
                !storedData[REFRESH_TOKEN].toString().isEmpty()) {
                refreshToken = storedData[REFRESH_TOKEN].toString();
            }
        }
    } else {
        refreshToken = response.RefreshToken();
    }
    token.insert(REFRESH_TOKEN, refreshToken);
    if (response.ExpiresIn() > 0) {
        token.insert(EXPIRY, response.ExpiresIn());
    }
    token.insert(TIMESTAMP, QDateTime::currentDateTime().toTime_t());
    token.insert(SCOPES, d->m_oauth2Data.Scope());
    d->m_tokens.insert(d->m_key, QVariant::fromValue(token));
    tokens.setTokens(d->m_tokens);
    Q_EMIT store(tokens);
    TRACE() << d->m_tokens;
}

QVariantMap OAuth2Plugin::parseJSONReply(const QByteArray &reply)
{
    TRACE();
    QJsonDocument doc = QJsonDocument::fromJson(reply);
    bool ok = !doc.isEmpty();
    QVariant tree = doc.toVariant();
    if (ok) {
        return tree.toMap();
    }
    return QVariantMap();
}

QVariantMap OAuth2Plugin::parseTextReply(const QByteArray &reply)
{
    TRACE();
    QVariantMap map;
    QList<QByteArray> items = reply.split('&');
    foreach (QByteArray item, items) {
        int idx = item.indexOf("=");
        if (idx > -1) {
            map.insert(item.left(idx),
                       QByteArray::fromPercentEncoding(item.mid(idx + 1)));
        }
    }
    return map;
}
