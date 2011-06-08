/*
 * This file is part of oauth2 plugin
 *
 * Copyright (C) 2010 Nokia Corporation.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@nokia.com>
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

#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkProxy>
#include <QDateTime>
#include <QCryptographicHash>

#include <qjson/parser.h>

#include "oauth2plugin.h"
#include "oauth2tokendata.h"

#ifdef TRACE
#undef TRACE
#endif
#define TRACE() qDebug() << __FILE__ << __LINE__ << __func__ << ":\t"

using namespace SignOn;

namespace OAuth2PluginNS {

    // Enum for OAuth 1.0 POST request type
    typedef enum {
        OAUTH1_POST_REQUEST_INVALID = 0,
        OAUTH1_POST_REQUEST_TOKEN,
        OAUTH1_POST_ACCESS_TOKEN
    } OAuth1RequestType;

    const QString WEB_SERVER = QString("web_server");
    const QString USER_AGENT = QString("user_agent");
    const QString HMAC_SHA1 = QString("HMAC-SHA1");
    const QString PLAINTEXT = QString("PLAINTEXT");
    const QString RSA_SHA1 = QString("RSA-SHA1");

    const int HTTP_STATUS_OK = 200;
    const QString AUTH_CODE = QString("code");
    const QString REDIRECT_URI = QString("redirect_uri");
    const QString USERNAME = QString("username");
    const QString PASSWORD = QString("password");
    const QString ASSERTION_TYPE = QString("assertion_type");
    const QString ASSERTION = QString("assertion");
    const QString ACCESS_TOKEN = QString("access_token");
    const QString EXPIRES_IN = QString("expires_in");
    const QString GRANT_TYPE = QString("grant_type");
    const QString AUTHORIZATION_CODE = QString("authorization_code");
    const QString USER_BASIC = QString("user_basic");
    const QString CLIENT_ID = QString("client_id");
    const QString CLIENT_SECRET = QString("client_secret");
    const QString REFRESH_TOKEN = QString("refresh_token");
    const QString AUTH_ERROR = QString("error");
    const QString USER_DENIED = QString("user_denied");

    const QString EQUAL = QString("=");
    const QString AMPERSAND = QString("&");
    const QString EQUAL_WITH_QUOTES = QString("%1=\"%2\"");
    const QString DELIMITER = QString(", ");
    const QString SPACE = QString(" ");
    const QString OAUTH = QString("OAuth");
    const QString OAUTH_REALM = QString("realm");
    const QString OAUTH_CALLBACK = QString("oauth_callback");
    const QString OAUTH_CONSUMERKEY = QString("oauth_consumer_key");
    const QString OAUTH_NONCE = QString("oauth_nonce");
    const QString OAUTH_TIMESTAMP = QString("oauth_timestamp");
    const QString OAUTH_SIGNATURE = QString("oauth_signature");
    const QString OAUTH_SIGNATURE_METHOD  = QString("oauth_signature_method");
    const QString OAUTH_VERSION = QString("oauth_version");
    const QString OAUTH_VERSION_1 = QString("1.0");
    const QString OAUTH_TOKEN = QString("oauth_token");
    const QString OAUTH_TOKEN_SECRET = QString("oauth_token_secret");
    const QString OAUTH_VERIFIER = QString("oauth_verifier");
    const QString OAUTH_PROBLEM = QString("oauth_problem");
    const QString OAUTH_USER_REFUSED = QString("user_refused");
    const QString OAUTH_PERMISSION_DENIED = QString("permission_denied");

    const QByteArray CONTENT_TYPE = QByteArray("Content-Type");
    const QByteArray CONTENT_APP_URLENCODED = QByteArray("application/x-www-form-urlencoded");
    const QByteArray CONTENT_APP_JSON = QByteArray("application/json");
    const QByteArray CONTENT_TEXT_PLAIN = QByteArray("text/plain");


    class OAuth2Plugin::Private
    {
    public:
        Private(OAuth2Plugin* parent) : m_parent(parent),
            m_manager(0), m_reply(0)
        {
            TRACE();
            m_networkProxy = QNetworkProxy::applicationProxy();
            m_oauth1Token.clear();
            m_oauth1TokenSecret.clear();
            m_oauth1TokenVerifier.clear();
            m_oauth1RequestType = OAUTH1_POST_REQUEST_INVALID;
        }

        ~Private()
        {
            TRACE();
            if (m_reply)
                m_reply->deleteLater();
            if (m_manager)
                m_manager->deleteLater();
        }

        OAuth2Plugin *m_parent;
        QNetworkAccessManager *m_manager;
        QNetworkProxy m_networkProxy;
        QNetworkReply *m_reply;
        QString m_mechanism;
        OAuth2PluginData m_oauth2Data;
        OAuth1PluginData m_oauth1Data;
        QByteArray m_oauth1Token;
        QByteArray m_oauth1TokenSecret;
        QString m_oauth1TokenVerifier;
        OAuth1RequestType m_oauth1RequestType;
        QVariantMap m_tokens;
        QString m_key;
    }; //Private

    OAuth2Plugin::OAuth2Plugin(QObject *parent)
            : AuthPluginInterface(parent), d(new Private(this))
    {
        TRACE();
    }

    OAuth2Plugin::~OAuth2Plugin()
    {
        TRACE();
        delete d;
        d = 0;
    }

    QString OAuth2Plugin::type() const
    {
        TRACE();
        return QString("oauth2");
    }

    QStringList OAuth2Plugin::mechanisms() const
    {
        TRACE();
        QStringList res = QStringList();
        res.append(WEB_SERVER);
        res.append(USER_AGENT);
        res.append(HMAC_SHA1);
        res.append(PLAINTEXT);
        return res;
    }

    void OAuth2Plugin::cancel()
    {
        TRACE();
        if (d->m_reply)
            d->m_reply->abort();
    }

    void OAuth2Plugin::sendOAuth2AuthRequest()
    {
        QUrl url(QString("https://%1/%2").arg(d->m_oauth2Data.Host()).arg(d->m_oauth2Data.AuthPath()));
        url.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
        url.addQueryItem(REDIRECT_URI, d->m_oauth2Data.RedirectUri());
        url.addQueryItem(QString("display"), QString("touch"));
        url.addQueryItem(QString("type"), d->m_mechanism);
        if (!d->m_oauth2Data.Scope().empty()) {
            // Passing comma de-limited list of scope
            url.addQueryItem(QString("scope"), d->m_oauth2Data.Scope().join(","));
        }
        TRACE() << "Url = " << url.toString();
        SignOn::UiSessionData uiSession;
        uiSession.setOpenUrl(url.toString());
        if (!d->m_oauth2Data.RedirectUri().isEmpty())
            uiSession.setFinalUrl(d->m_oauth2Data.RedirectUri());
        emit userActionRequired(uiSession);
    }

    void OAuth2Plugin::sendOAuth1AuthRequest(const QString &captchaUrl)
    {
        QUrl url(d->m_oauth1Data.AuthorizationEndpoint());
        url.addQueryItem(OAUTH_TOKEN, d->m_oauth1Token);
        TRACE() << "URL = " << url.toString();
        SignOn::UiSessionData uiSession;
        uiSession.setOpenUrl(url.toString());
        if (!captchaUrl.isEmpty()) {
            uiSession.setCaptchaUrl(captchaUrl);
        }
        emit userActionRequired(uiSession);
    }

    bool OAuth2Plugin::validateInput(const SignOn::SessionData &inData, const QString &mechanism)
    {
        if ((mechanism == WEB_SERVER) || (mechanism == USER_AGENT)) {
            OAuth2PluginData input = inData.data<OAuth2PluginData>();
            if (input.Host().isEmpty()
                || input.ClientId().isEmpty()
                || input.ClientSecret().isEmpty()
                || input.RedirectUri().isEmpty()
                || input.AuthPath().isEmpty()
                || ((mechanism == WEB_SERVER)
                    && (input.TokenPath().isEmpty()))) {
                return false;
            }
        }
        else {
            OAuth1PluginData input = inData.data<OAuth1PluginData>();
            if (input.AuthorizationEndpoint().isEmpty()
                || input.ConsumerKey().isEmpty()
                || input.ConsumerSecret().isEmpty()
                || input.Callback().isEmpty()
                || input.TokenEndpoint().isEmpty()
                || input.RequestEndpoint().isEmpty()){
                return false;
            }
        }
        return true;
    }

    void OAuth2Plugin::process(const SignOn::SessionData &inData,
                               const QString &mechanism)
    {
        TRACE();
        OAuth2PluginData input;

        if ((!mechanism.isEmpty()) && (!mechanisms().contains(mechanism))) {
            emit error(Error(Error::MechanismNotAvailable));
            return;
        }

        if (!validateInput(inData, mechanism)) {
            TRACE() << "Invalid parameters passed";
            emit error(Error(Error::InvalidQuery));
            return;
        }

        QString proxy = inData.NetworkProxy();
        //set proxy from params
        if (!proxy.isEmpty()) {
            QUrl proxyUrl(proxy);
            if (!proxyUrl.host().isEmpty()) {
                d->m_networkProxy = QNetworkProxy(
                        QNetworkProxy::HttpProxy,
                        proxyUrl.host(),
                        proxyUrl.port(),
                        proxyUrl.userName(),
                        proxyUrl.password());
                TRACE() << proxyUrl.host() << ":" <<  proxyUrl.port();
            }
        } else {
            d->m_networkProxy = QNetworkProxy::applicationProxy();
        }

        d->m_mechanism = mechanism;
        if (mechanism == WEB_SERVER || mechanism == USER_AGENT) {
            OAuth2PluginData data = inData.data<OAuth2PluginData>();
            d->m_key = data.ClientId();
        } else {
            OAuth1PluginData data = inData.data<OAuth1PluginData>();
            d->m_key = data.ConsumerKey();
        }
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
        }

        QVariant tokenVar = d->m_tokens.value(d->m_key);
        QVariantMap token;
        if (tokenVar.canConvert<QVariantMap>())
            token = tokenVar.value<QVariantMap>();
        //return stored session if it is valid
        if (token.value("Expiry").toUInt() > QDateTime::currentDateTime().toTime_t()) {
            if (mechanism == WEB_SERVER || mechanism == USER_AGENT) {
                OAuth2PluginTokenData response;
                response.setAccessToken(token.value("Token").toByteArray());
                response.setRefreshToken(token.value("Token2").toString());
                response.setExpiresIn(token.value("Expiry").toUInt());
                emit result(response);
                return;
            } else {
                OAuth1PluginTokenData response;
                response.setAccessToken(token.value("Token").toByteArray());
                emit result(response);
                return;
            }
        }
        if (mechanism == WEB_SERVER || mechanism == USER_AGENT) {
            d->m_oauth2Data = inData.data<OAuth2PluginData>();
            sendOAuth2AuthRequest();
        }
        else if (mechanism == HMAC_SHA1 ||mechanism == PLAINTEXT) {
            d->m_oauth1Data = inData.data<OAuth1PluginData>();
            d->m_oauth1RequestType = OAUTH1_POST_REQUEST_TOKEN;
            sendOAuth1PostRequest();
        }
        else {
            emit error(Error(Error::MechanismNotAvailable));
        }
    }

    QString OAuth2Plugin::urlEncode(QString strData)
    {
        return QUrl::toPercentEncoding(strData).constData();
    }

    // Create a HMAC-SHA1 signature
    QByteArray OAuth2Plugin::hashHMACSHA1(const QByteArray &baseSignatureString,
                                          const QByteArray &secret)
    {
        // The algorithm is defined in RFC 2104
        int blockSize = 64;
        QByteArray key(baseSignatureString);
        QByteArray opad(blockSize, 0x5c);
        QByteArray ipad(blockSize, 0x36);

        // If key size is too large, compute the hash
        if (key.size() > blockSize) {
            key = QCryptographicHash::hash(key, QCryptographicHash::Sha1);
        }

        // If too small, pad with 0x00
        if (key.size() < blockSize) {
            key += QByteArray(blockSize - key.size(), 0x00);
        }

        // Compute the XOR operations
        for (int i=0; i <= key.size() - 1; i++) {
            ipad[i] = (char) (ipad[i] ^ key[i]);
            opad[i] = (char) (opad[i] ^ key[i]);
        }

        // Append the data to ipad
        ipad += secret;

        // Hash sha1 of ipad and append the data to opad
        opad += QCryptographicHash::hash(ipad, QCryptographicHash::Sha1);

        // Return array contains the result of HMAC-SHA1
        return QCryptographicHash::hash(opad, QCryptographicHash::Sha1);
    }

    QByteArray OAuth2Plugin::constructSignatureBaseString(const QString &aUrl,
        const OAuth1PluginData &inData, const QString &timestamp,
        const QString &nonce)
    {
        QMap<QString, QString> oAuthHeaderMap;
        QUrl fullUrl(aUrl);

        // Constructing the base string as per RFC 5849. Sec 3.4.1
        QList<QPair<QString, QString> > queryItems = fullUrl.queryItems();
        QPair<QString, QString> queryItem;
        foreach (queryItem, queryItems) {
            oAuthHeaderMap[queryItem.first] = queryItem.second;
        }

        if (!inData.Callback().isEmpty()) {
            oAuthHeaderMap[OAUTH_CALLBACK] = inData.Callback();
        }
        oAuthHeaderMap[OAUTH_CONSUMERKEY]  = inData.ConsumerKey();
        oAuthHeaderMap[OAUTH_NONCE] = nonce;
        oAuthHeaderMap[OAUTH_SIGNATURE_METHOD] = d->m_mechanism;
        oAuthHeaderMap[OAUTH_TIMESTAMP] = timestamp;
        if (!d->m_oauth1Token.isEmpty()) {
            oAuthHeaderMap[OAUTH_TOKEN] = d->m_oauth1Token;
        }
        if (!d->m_oauth1TokenVerifier.isEmpty()) {
            oAuthHeaderMap[OAUTH_VERIFIER] = d->m_oauth1TokenVerifier;
        }
        oAuthHeaderMap[OAUTH_VERSION] = OAUTH_VERSION_1;

        QString oAuthHeaderString;
        QMap<QString, QString>::iterator i;
        bool first = true;
        for (i = oAuthHeaderMap.begin(); i != oAuthHeaderMap.end(); ++i) {
            if(!first) {
                oAuthHeaderString.append(AMPERSAND);
            } else {
                first = false;
            }
            oAuthHeaderString.append(urlEncode(i.key()) + EQUAL
                                     + urlEncode(i.value()));
        }
        QString urlWithHostAndPath = fullUrl.toString(QUrl::RemoveUserInfo | QUrl::RemoveQuery
                                                      | QUrl::RemoveFragment | QUrl::StripTrailingSlash);

        QByteArray signatureBase;
        signatureBase.append("POST");
        signatureBase.append(AMPERSAND);
        signatureBase.append(urlEncode(urlWithHostAndPath));
        signatureBase.append(AMPERSAND);
        signatureBase.append(urlEncode(oAuthHeaderString));
        return signatureBase;
    }

    // Method  to create the Authorization header
    QString OAuth2Plugin::createOAuth1Header(const QString &aUrl,
                                             OAuth1PluginData inData)
    {
        QString authHeader = OAUTH + SPACE;
        if (!inData.Realm().isEmpty()) {
            authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_REALM)
                              .arg(urlEncode(inData.Realm())));
            authHeader.append(DELIMITER);
        }
        if (!inData.Callback().isEmpty()) {
            authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_CALLBACK)
                              .arg(urlEncode(inData.Callback())));
            authHeader.append(DELIMITER);
        }
        authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_CONSUMERKEY)
                          .arg(urlEncode(inData.ConsumerKey())));
        authHeader.append(DELIMITER);
        // Nonce
        unsigned long nonce1 = (unsigned long) random();
        unsigned long nonce2 = (unsigned long) random();
        QString oauthNonce = QString("%1%2").arg(nonce1).arg(nonce2);
        authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_NONCE)
                          .arg(urlEncode(oauthNonce)));
        authHeader.append(DELIMITER);
        // Timestamp
        QString oauthTimestamp = QString("%1").arg(QDateTime::currentDateTime().toTime_t());
        authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_TIMESTAMP)
                          .arg(urlEncode(oauthTimestamp)));
        authHeader.append(DELIMITER);
        if (!d->m_oauth1Token.isEmpty()) {
            authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_TOKEN)
                              .arg(urlEncode(d->m_oauth1Token)));
            authHeader.append(DELIMITER);
        }

        authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_SIGNATURE_METHOD)
                          .arg(urlEncode(d->m_mechanism)));
        authHeader.append(DELIMITER);
        // Creating the signature
        // PLAINTEXT signature method
        QByteArray secretKey;
        secretKey.append(urlEncode(inData.ConsumerSecret()) + AMPERSAND +
                         urlEncode(d->m_oauth1TokenSecret));
        if (d->m_mechanism == PLAINTEXT) {
            TRACE() << "Signature = " << secretKey;
            authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_SIGNATURE)
                              .arg(urlEncode(secretKey)));
            authHeader.append(DELIMITER);
        }
        // HMAC-SHA1 signature method
        else if (d->m_mechanism == HMAC_SHA1) {
            QByteArray signatureBase = constructSignatureBaseString(aUrl,
                    inData, oauthTimestamp, oauthNonce);
            TRACE() << "Signature Base = " << signatureBase;
            QByteArray signature = hashHMACSHA1(secretKey, signatureBase);
            TRACE() << "Signature = " << signature;
            authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_SIGNATURE)
                              .arg(urlEncode(signature.toBase64())));
            authHeader.append(DELIMITER);
        }
        // TODO: RSA-SHA1 signature method should be implemented
        else {
            Q_ASSERT_X(false, __FUNCTION__, "Unsupported mechanism");
        }

        if (!d->m_oauth1TokenVerifier.isEmpty()) {
            authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_VERIFIER)
                              .arg(urlEncode(d->m_oauth1TokenVerifier)));
            authHeader.append(DELIMITER);
        }
        authHeader.append(EQUAL_WITH_QUOTES.arg(OAUTH_VERSION)
                          .arg(urlEncode(OAUTH_VERSION_1)));

        return authHeader;
    }

    void OAuth2Plugin::userActionFinished(const SignOn::UiSessionData &data)
    {
        TRACE();

        if (data.QueryErrorCode() != QUERY_ERROR_NONE) {
            TRACE() << "userActionFinished with error: " << data.QueryErrorCode();
            if (data.QueryErrorCode() == QUERY_ERROR_CANCELED)
                emit error(Error(Error::SessionCanceled, QLatin1String("Cancelled by user")));
            else
                emit error(Error(Error::UserInteraction,
                                 QString("userActionFinished error: ")
                                 + QString::number(data.QueryErrorCode())));
            return;
        }

        TRACE() << data.UrlResponse();

        // Checking if authorization server granted access
        QUrl url = QUrl(data.UrlResponse());
        if (url.hasQueryItem(AUTH_ERROR)) {
            TRACE() << "Server denied access permission";
            emit error(Error(Error::PermissionDenied, url.queryItemValue(AUTH_ERROR)));
            return;
        }

        if (d->m_mechanism == USER_AGENT) {
            // Response should contain the access token
            OAuth2PluginTokenData respData;
            QString fragment;
            if (url.hasFragment()) {
                fragment = url.fragment();
                QStringList list = fragment.split(QRegExp("&|="), QString::SkipEmptyParts);
                for (int i = 1; i < list.count(); i += 2) {
                    if (list.at(i - 1) == ACCESS_TOKEN) {
                        respData.setAccessToken(list.at(i));
                    }
                    else if (list.at(i - 1) == EXPIRES_IN) {
                        respData.setExpiresIn(QString(list.at(i)).toInt());
                    }
                    else if (list.at(i - 1) == REFRESH_TOKEN) {
                        respData.setRefreshToken(list.at(i));
                    }
                }
                if (respData.AccessToken().isEmpty()) {
                    emit error(Error(Error::Unknown, QString("Access token not present")));
                } else {
                    //store session key for later use
                    OAuth2TokenData tokens;
                    QVariantMap token;
                    token.insert("Token", respData.AccessToken());
                    token.insert("Token2", respData.RefreshToken());
                    token.insert("Expiry", respData.ExpiresIn());
                    d->m_tokens.insert(d->m_key, QVariant::fromValue(token));
                    tokens.setTokens(d->m_tokens);
                    emit store(tokens);
                    TRACE() << d->m_tokens;

                    emit result(respData);
                }
            }
            else {
                emit error(Error(Error::Unknown, QString("Access token not present")));
            }
        } else if (d->m_mechanism == WEB_SERVER) {
            // Access grant can be one of the floolwing types
            // 1. Authorization code (code, redirect_uri)
            // 2. Resource owner credentials (username, password)
            // 3. Assertion (assertion_type, assertion)
            // 4. Refresh Token (refresh_token)
            QUrl newUrl;
            if (url.hasQueryItem(AUTH_CODE)) {
                QString code = url.queryItemValue(AUTH_CODE);
                newUrl.addQueryItem(GRANT_TYPE, AUTHORIZATION_CODE);
                newUrl.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
                newUrl.addQueryItem(CLIENT_SECRET, d->m_oauth2Data.ClientSecret());
                newUrl.addQueryItem(AUTH_CODE, code);
                newUrl.addQueryItem(REDIRECT_URI, d->m_oauth2Data.RedirectUri());
                sendOAuth2PostRequest(newUrl.encodedQuery());
            }
            else if (url.hasQueryItem(USERNAME) && url.hasQueryItem(PASSWORD)) {
                QString username = url.queryItemValue(USERNAME);
                QString password = url.queryItemValue(PASSWORD);
                newUrl.addQueryItem(GRANT_TYPE, USER_BASIC);
                newUrl.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
                newUrl.addQueryItem(CLIENT_SECRET, d->m_oauth2Data.ClientSecret());
                newUrl.addQueryItem(USERNAME, username);
                newUrl.addQueryItem(PASSWORD, password);
                sendOAuth2PostRequest(newUrl.encodedQuery());
            }
            else if (url.hasQueryItem(ASSERTION_TYPE) && url.hasQueryItem(ASSERTION)) {
                QString assertion_type = url.queryItemValue(ASSERTION_TYPE);
                QString assertion = url.queryItemValue(ASSERTION);
                newUrl.addQueryItem(GRANT_TYPE, ASSERTION);
                newUrl.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
                newUrl.addQueryItem(CLIENT_SECRET, d->m_oauth2Data.ClientSecret());
                newUrl.addQueryItem(ASSERTION_TYPE, assertion_type);
                newUrl.addQueryItem(ASSERTION, assertion);
                sendOAuth2PostRequest(newUrl.encodedQuery());
            }
            else if (url.hasQueryItem(REFRESH_TOKEN)) {
                QString refresh_token = url.queryItemValue(REFRESH_TOKEN);
                newUrl.addQueryItem(GRANT_TYPE, REFRESH_TOKEN);
                newUrl.addQueryItem(CLIENT_ID, d->m_oauth2Data.ClientId());
                newUrl.addQueryItem(CLIENT_SECRET, d->m_oauth2Data.ClientSecret());
                newUrl.addQueryItem(REFRESH_TOKEN, refresh_token);
                sendOAuth2PostRequest(newUrl.encodedQuery());
            }
            else {
                emit error(Error(Error::Unknown, QString("Access grant not present")));
            }
        }
        else { // For all OAuth 1 mechanisms
            if (url.hasQueryItem(OAUTH_VERIFIER)) {
                d->m_oauth1TokenVerifier = url.queryItemValue(OAUTH_VERIFIER);
                d->m_oauth1Data.setCallback(QString());
                d->m_oauth1RequestType = OAUTH1_POST_ACCESS_TOKEN;
                sendOAuth1PostRequest();
            }
            else if (url.hasQueryItem(OAUTH_PROBLEM)) {
                handleOAuth1ProblemError(url.queryItemValue(OAUTH_PROBLEM).toAscii());
            }
            else {
                emit error(Error(Error::Unknown, QString("oauth_verifier missing")));
            }
        }
    }

    // Method to handle responses for OAuth 2.0 requests
    void OAuth2Plugin::replyOAuth2RequestFinished()
    {
        TRACE()<< "Finished signal received";
        QNetworkReply *reply = (QNetworkReply*)sender();
        QByteArray replyContent = reply->readAll();
        TRACE() << replyContent;
        if (reply->error() != QNetworkReply::NoError) {
            if (handleNetworkError(reply->error()))
                return;
        }

        // Handle error responses
        QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        TRACE() << statusCode;
        if (statusCode != HTTP_STATUS_OK) {
            handleOAuth2Error(replyContent);
            return;
        }

        // Handling 200 OK response (HTTP_STATUS_OK) WITH content
        if (reply->hasRawHeader(CONTENT_TYPE)) {

            // Handling application/json content type
            if (reply->rawHeader(CONTENT_TYPE).startsWith(CONTENT_APP_JSON)) {
                TRACE()<< "application/json content received";
                QVariantMap map = parseJSONReply(replyContent);
                QByteArray accessToken = map["access_token"].toByteArray();
                QVariant expiresIn = map["expires_in"];
                QByteArray refreshToken = map["refresh_token"].toByteArray();

                if (accessToken.isEmpty()) {
                    TRACE()<< "Access token is empty";
                    emit error(Error(Error::Unknown));
                }
                else {
                    OAuth2PluginTokenData response;
                    response.setAccessToken(accessToken);
                    response.setRefreshToken(refreshToken);
                    response.setExpiresIn(expiresIn.toInt());
                    emit result(response);
                }
            }
            // Added to test with facebook Graph API's (handling text/plain content type)
            else if (reply->rawHeader(CONTENT_TYPE).startsWith(CONTENT_TEXT_PLAIN)){
                TRACE()<< "text/plain content received";
                QMap<QString,QString> map = parseTextReply(replyContent);
                QByteArray accessToken = map["access_token"].toAscii();
                QByteArray expiresIn = map["expires"].toAscii();
                QByteArray refreshToken = map["refresh_token"].toAscii();

                if (accessToken.isEmpty()) {
                    TRACE()<< "Access token is empty";
                    emit error(Error(Error::Unknown));
                }
                else {
                    OAuth2PluginTokenData response;
                    response.setAccessToken(accessToken);
                    response.setRefreshToken(refreshToken);
                    response.setExpiresIn(expiresIn.toInt());
                    emit result(response);
                }
            }
            else {
                TRACE()<< "Unsupported content type received: " << reply->rawHeader(CONTENT_TYPE);
                emit error(Error(Error::OperationFailed, QString("Unsupported content type received")));
            }
        }
        // Handling 200 OK response (HTTP_STATUS_OK) WITHOUT content
        else {
            TRACE()<< "Content is not present";
            emit error(Error(Error::OperationFailed, QString("Content missing")));
        }
    }

    // Method to handle responses for OAuth 1.0a Request token request
    void OAuth2Plugin::replyOAuth1RequestFinished()
    {
        TRACE()<< "Finished signal received";
        QNetworkReply *reply = (QNetworkReply*)sender();
        QByteArray replyContent = reply->readAll();
        TRACE() << replyContent;
        if (reply->error() != QNetworkReply::NoError) {
            d->m_oauth1RequestType = OAUTH1_POST_REQUEST_INVALID;
            if (handleNetworkError(reply->error()))
                return;
        }

        // Handle error responses
        QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        TRACE() << statusCode;
        if (statusCode != HTTP_STATUS_OK) {
            handleOAuth1Error(replyContent);
            d->m_oauth1RequestType = OAUTH1_POST_REQUEST_INVALID;
            return;
        }

        // Handling 200 OK response (HTTP_STATUS_OK) WITH content
        if (reply->hasRawHeader(CONTENT_TYPE)) {

            // Checking if supported content type received
            if ((reply->rawHeader(CONTENT_TYPE).startsWith(CONTENT_APP_URLENCODED))
                || (reply->rawHeader(CONTENT_TYPE).startsWith(CONTENT_TEXT_PLAIN))) {

                QMap<QString,QString> map = parseTextReply(replyContent);
                if (d->m_oauth1RequestType == OAUTH1_POST_REQUEST_TOKEN) {
                    // Extracting the request token, token secret
                    d->m_oauth1Token = map[OAUTH_TOKEN].toAscii();
                    d->m_oauth1TokenSecret = map[OAUTH_TOKEN_SECRET].toAscii();
                    if (d->m_oauth1Token.isEmpty() || d->m_oauth1TokenSecret.isEmpty()) {
                        TRACE() << "OAuth token is empty";
                        emit error(Error(Error::Unknown, QString("Request token missing")));
                    }
                    else {
                        sendOAuth1AuthRequest();
                    }
                }
                else if (d->m_oauth1RequestType == OAUTH1_POST_ACCESS_TOKEN) {
                    // Extracting the access token
                    d->m_oauth1Token = map[OAUTH_TOKEN].toAscii();
                    if (d->m_oauth1Token.isEmpty()) {
                        TRACE()<< "OAuth token is empty";
                        emit error(Error(Error::Unknown, QString("Access token missing")));
                    }
                    else {
                        OAuth1PluginTokenData response;
                        response.setAccessToken(d->m_oauth1Token);
                        emit result(response);
                    }
                }
                else {
                    Q_ASSERT_X(false, __FUNCTION__, "Invalid OAuth1 POST request");
                }
            }
            else {
                TRACE()<< "Unsupported content type received: " << reply->rawHeader(CONTENT_TYPE);
                emit error(Error(Error::OperationFailed,
                                 QString("Unsupported content type received")));
            }
        }
        // Handling 200 OK response (HTTP_STATUS_OK) WITHOUT content
        else {
            TRACE()<< "Content is not present";
            emit error(Error(Error::OperationFailed, QString("Content missing")));
        }
        d->m_oauth1RequestType = OAUTH1_POST_REQUEST_INVALID;
    }

    void OAuth2Plugin::handleOAuth1ProblemError(const QByteArray &errorString)
    {
        TRACE();
        Error::ErrorType type = Error::Unknown;
        if (errorString == OAUTH_USER_REFUSED || errorString == OAUTH_PERMISSION_DENIED) {
            type = Error::PermissionDenied;
        }
        TRACE() << "Error Emitted";
        emit error(Error(type, errorString));
    }

    void OAuth2Plugin::handleOAuth1Error(const QByteArray &reply)
    {
        TRACE();
        if (d->m_reply) {
            d->m_reply->deleteLater();
            d->m_reply = 0;
        }
        QMap<QString,QString> map = parseTextReply(reply);
        QByteArray errorString = map[OAUTH_PROBLEM].toAscii();
        if (!errorString.isEmpty()) {
            handleOAuth1ProblemError(errorString);
            return;
        }

        TRACE() << "Error Emitted";
        emit error(Error(Error::Unknown, errorString));
    }

    void OAuth2Plugin::handleOAuth2Error(const QByteArray &reply)
    {
        TRACE();
        if (d->m_reply) {
            d->m_reply->deleteLater();
            d->m_reply = 0;
        }
        QVariantMap map = parseJSONReply(reply);
        QByteArray errorString = map["error"].toByteArray();
        if (!errorString.isEmpty()) {
            Error::ErrorType type = Error::Unknown;
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
            TRACE() << "Error Emitted";
            emit error(Error(type, errorString));
            return;
        }

        // Added to work with facebook Graph API's
        errorString = map["message"].toByteArray();
        if (!errorString.isEmpty()) {
            TRACE() << "Error Emitted";
            emit error(Error(Error::OperationFailed, errorString));
            return;
        }

        TRACE() << "Error Emitted";
        emit error(Error(Error::Unknown, errorString));
    }

    bool OAuth2Plugin::handleNetworkError(QNetworkReply::NetworkError err)
    {
        TRACE() << "error signal received:" << err;
        /* Has been handled by handleSslErrors already */
        if (err == QNetworkReply::SslHandshakeFailedError) {
            return true;
        }
        /* HTTP errors handled in slots attached to  signal */
        if ((err > QNetworkReply::UnknownProxyError)
            && (err <= QNetworkReply::UnknownContentError)) {
            return false;
        }
        Error::ErrorType type = Error::Network;
        if (err <= QNetworkReply::UnknownNetworkError)
            type = Error::NoConnection;
        QString errorString = "";
        if (d->m_reply) {
            errorString = d->m_reply->errorString();
            d->m_reply->deleteLater();
            d->m_reply = 0;
        }
        emit error(Error(type, errorString));
        return true;
    }

    void OAuth2Plugin::handleSslErrors(QList<QSslError> errorList)
    {
        TRACE() << "Error: " << errorList;
        QString errorString = "";
        foreach (QSslError error, errorList) {
            errorString += error.errorString() + ";";
        }
        if (d->m_reply) {
            d->m_reply->deleteLater();
            d->m_reply = 0;
        }
        emit error(Error(Error::Ssl, errorString));
    }

    void OAuth2Plugin::refresh(const SignOn::UiSessionData &data)
    {
        TRACE();
        emit refreshed(data);
    }

    void OAuth2Plugin::sendOAuth2PostRequest(const QByteArray &postData)
    {
        TRACE();

        if (!d->m_manager) {
            d->m_manager = new QNetworkAccessManager();
            d->m_manager->setProxy(d->m_networkProxy);
        }

        QUrl url(QString("https://%1/%2").arg(d->m_oauth2Data.Host())
                 .arg(d->m_oauth2Data.TokenPath()));
        QNetworkRequest request(url);
        request.setRawHeader(CONTENT_TYPE, CONTENT_APP_URLENCODED);

        TRACE() << "Query string = " << postData;
        d->m_reply = d->m_manager->post(request, postData);
        connect(d->m_reply, SIGNAL(finished()),
                this, SLOT(replyOAuth2RequestFinished()));
        connect(d->m_reply, SIGNAL(error(QNetworkReply::NetworkError)),
                this, SLOT(handleNetworkError(QNetworkReply::NetworkError)));
        connect(d->m_reply, SIGNAL(sslErrors(QList<QSslError>)),
                this, SLOT(handleSslErrors(QList<QSslError>)));
    }

    void OAuth2Plugin::sendOAuth1PostRequest()
    {
        TRACE();

        if (!d->m_manager) {
            d->m_manager = new QNetworkAccessManager();
            d->m_manager->setProxy(d->m_networkProxy);
        }

        QNetworkRequest request;
        request.setRawHeader(CONTENT_TYPE, CONTENT_APP_URLENCODED);
        QString authHeader;
        if (d->m_oauth1RequestType == OAUTH1_POST_REQUEST_TOKEN) {
            request.setUrl(d->m_oauth1Data.RequestEndpoint());
            authHeader = createOAuth1Header(d->m_oauth1Data.RequestEndpoint(),
                                            d->m_oauth1Data);
        }
        else if (d->m_oauth1RequestType == OAUTH1_POST_ACCESS_TOKEN) {
            request.setUrl(d->m_oauth1Data.TokenEndpoint());
            authHeader = createOAuth1Header(d->m_oauth1Data.TokenEndpoint(),
                                            d->m_oauth1Data);
        }
        else {
            Q_ASSERT_X(false, __FUNCTION__, "Invalid OAuth1 POST request");
        }
        request.setRawHeader(QByteArray("Authorization"), authHeader.toAscii());

        d->m_reply = d->m_manager->post(request, QByteArray());
        connect(d->m_reply, SIGNAL(finished()),
                this, SLOT(replyOAuth1RequestFinished()));
        connect(d->m_reply, SIGNAL(error(QNetworkReply::NetworkError)),
                this, SLOT(handleNetworkError(QNetworkReply::NetworkError)));
        connect(d->m_reply, SIGNAL(sslErrors(QList<QSslError>)),
                this, SLOT(handleSslErrors(QList<QSslError>)));
    }

    const QVariantMap OAuth2Plugin::parseJSONReply(const QByteArray &reply)
    {
        TRACE();
        QJson::Parser parser;
        bool ok;
        QVariant tree = parser.parse(reply, &ok);
        if (ok) {
            return tree.toMap();
        }
        return QVariantMap();
    }

    const QMap<QString, QString> OAuth2Plugin::parseTextReply(const QByteArray &reply)
    {
        TRACE();
        QMap<QString, QString> map;
        QList<QByteArray> items = reply.split('&');
        foreach (QByteArray item, items) {
            int idx = item.indexOf("=");
            if (idx > -1) {
                map.insert(item.left(idx), item.mid(idx + 1));
            }
        }
        return map;
    }

    SIGNON_DECL_AUTH_PLUGIN(OAuth2Plugin)
} //namespace OAuth2PluginNS
