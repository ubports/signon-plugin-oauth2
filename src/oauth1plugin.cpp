/*
 * This file is part of oauth2 plugin
 *
 * Copyright (C) 2010 Nokia Corporation.
 * Copyright (C) 2012-2016 Canonical Ltd.
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
#include "oauth1data.h"
#include "oauth1plugin.h"
#include "oauth2tokendata.h"

#include <QUrl>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QDateTime>
#include <QCryptographicHash>

using namespace SignOn;
using namespace OAuth2PluginNS;

namespace OAuth2PluginNS {

// Enum for OAuth 1.0 POST request type
typedef enum {
    OAUTH1_POST_REQUEST_INVALID = 0,
    OAUTH1_POST_REQUEST_TOKEN,
    OAUTH1_POST_ACCESS_TOKEN
} OAuth1RequestType;

const QString HMAC_SHA1 = QString("HMAC-SHA1");
const QString PLAINTEXT = QString("PLAINTEXT");
const QString RSA_SHA1 = QString("RSA-SHA1");

const QString EXPIRY = QString ("Expiry");
const QString USER_ID = QString("user_id");
const QString SCREEN_NAME = QString("screen_name");
const QString FORCE_LOGIN = QString("force_login");

const int HTTP_STATUS_OK = 200;
const QString TIMESTAMP = QString("timestamp");
const QString AUTH_ERROR = QString("error");

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
const QByteArray CONTENT_TEXT_PLAIN = QByteArray("text/plain");
const QByteArray CONTENT_TEXT_HTML = QByteArray("text/html");


class OAuth1PluginPrivate
{
public:
    OAuth1PluginPrivate()
    {
        TRACE();

        // Initialize randomizer
        qsrand(QTime::currentTime().msec());
    }

    ~OAuth1PluginPrivate()
    {
        TRACE();
    }

    QString m_mechanism;
    OAuth1PluginData m_oauth1Data;
    QByteArray m_oauth1Token;
    QByteArray m_oauth1TokenSecret;
    QString m_oauth1UserId;
    QString m_oauth1ScreenName;
    QString m_oauth1TokenVerifier;
    OAuth1RequestType m_oauth1RequestType;
    QVariantMap m_tokens;
    QString m_key;
    QString m_username;
    QString m_password;
}; //Private

} //namespace OAuth2PluginNS

OAuth1Plugin::OAuth1Plugin(QObject *parent):
    BasePlugin(parent),
    d_ptr(new OAuth1PluginPrivate())
{
    TRACE();
}

OAuth1Plugin::~OAuth1Plugin()
{
    TRACE();
    delete d_ptr;
    d_ptr = 0;
}

QStringList OAuth1Plugin::mechanisms()
{
    QStringList res = QStringList();
    res.append(HMAC_SHA1);
    res.append(PLAINTEXT);
    return res;
}

void OAuth1Plugin::sendOAuth1AuthRequest()
{
    Q_D(OAuth1Plugin);

    QUrl url(d->m_oauth1Data.AuthorizationEndpoint());
    url.addQueryItem(OAUTH_TOKEN, d->m_oauth1Token);
    if (!d->m_oauth1ScreenName.isEmpty()) {
        // Prefill username for Twitter
        url.addQueryItem(SCREEN_NAME, d->m_oauth1ScreenName);
        url.addQueryItem(FORCE_LOGIN, d->m_oauth1ScreenName);
    }
    TRACE() << "URL = " << url.toString();
    SignOn::UiSessionData uiSession;
    uiSession.setOpenUrl(url.toString());
    if (d->m_oauth1Data.Callback() != "oob")
        uiSession.setFinalUrl(d->m_oauth1Data.Callback());

    /* add username and password, for fields initialization (the
     * decision on whether to actually use them is up to the signon UI */
    uiSession.setUserName(d->m_username);
    uiSession.setSecret(d->m_password);

    emit userActionRequired(uiSession);
}

bool OAuth1Plugin::validateInput(const SignOn::SessionData &inData,
                                 const QString &mechanism)
{
    Q_UNUSED(mechanism);

    OAuth1PluginData input = inData.data<OAuth1PluginData>();
    if (input.AuthorizationEndpoint().isEmpty()
        || input.ConsumerKey().isEmpty()
        || input.ConsumerSecret().isEmpty()
        || input.Callback().isEmpty()
        || input.TokenEndpoint().isEmpty()
        || input.RequestEndpoint().isEmpty()){
        return false;
    }
    return true;
}

bool OAuth1Plugin::respondWithStoredToken(const QVariantMap &token,
                                          const QString &mechanism)
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

    if (mechanism == HMAC_SHA1 ||
        mechanism == RSA_SHA1 ||
        mechanism == PLAINTEXT) {
        if (token.contains(OAUTH_TOKEN) &&
            token.contains(OAUTH_TOKEN_SECRET)) {
            OAuth1PluginTokenData response = oauth1responseFromMap(token);

            emit result(response);
            return true;
        }
    }

    return false;
}

void OAuth1Plugin::process(const SignOn::SessionData &inData,
                           const QString &mechanism)
{
    Q_D(OAuth1Plugin);

    if (!validateInput(inData, mechanism)) {
        TRACE() << "Invalid parameters passed";
        emit error(Error(Error::MissingData));
        return;
    }

    d->m_mechanism = mechanism;
    d->m_oauth1Data = inData.data<OAuth1PluginData>();
    d->m_key = inData.data<OAuth1PluginData>().ConsumerKey();

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
    } else if (d->m_oauth1Data.ForceTokenRefresh()) {
        // remove only the access token, not the refresh token
        QVariantMap storedData = d->m_tokens.value(d->m_key).toMap();
        storedData.remove(OAUTH_TOKEN);
        d->m_tokens.insert(d->m_key, storedData);
        OAuth2TokenData tokens;
        tokens.setTokens(d->m_tokens);
        Q_EMIT store(tokens);
        TRACE() << "Clearing access token" << d->m_tokens;
    }

    //get provided token data if specified
    if (!tokens.ProvidedTokens().isEmpty()) {
        //check that the provided tokens contain required values
        OAuth1PluginTokenData providedTokens =
                SignOn::SessionData(tokens.ProvidedTokens())
                .data<OAuth1PluginTokenData>();
        if (providedTokens.AccessToken().isEmpty() ||
            providedTokens.TokenSecret().isEmpty()) {
            //note: we don't check UserId or ScreenName as it might not be required
            TRACE() << "Invalid provided tokens data - continuing normal process flow";
        } else {
            TRACE() << "Storing provided tokens";
            QVariantMap storeTokens;
            storeTokens.insert(OAUTH_TOKEN, providedTokens.AccessToken());
            storeTokens.insert(OAUTH_TOKEN_SECRET, providedTokens.TokenSecret());
            if (!providedTokens.UserId().isNull())
                storeTokens.insert(USER_ID, providedTokens.UserId());
            if (!providedTokens.ScreenName().isNull())
                storeTokens.insert(SCREEN_NAME, providedTokens.ScreenName());

            d->m_oauth1Token = providedTokens.AccessToken().toAscii();
            d->m_oauth1TokenSecret = providedTokens.TokenSecret().toAscii();
            d->m_oauth1UserId = providedTokens.UserId().toAscii();
            d->m_oauth1ScreenName = providedTokens.ScreenName().toAscii();

            OAuth2TokenData tokens;
            d->m_tokens.insert(d->m_key, QVariant::fromValue(storeTokens));
            tokens.setTokens(d->m_tokens);
            emit store(tokens);
        }
    }

    QVariant tokenVar = d->m_tokens.value(d->m_key);
    QVariantMap storedData;
    if (tokenVar.canConvert<QVariantMap>()) {
        storedData = tokenVar.value<QVariantMap>();
        if (respondWithStoredToken(storedData, mechanism)) {
            return;
        }
    }

    /* Get username and password; the plugin doesn't use them, but forwards
     * them to the signon UI */
    d->m_username = inData.UserName();
    d->m_password = inData.Secret();

    d->m_oauth1Token.clear();
    d->m_oauth1TokenSecret.clear();
    d->m_oauth1TokenVerifier.clear();
    d->m_oauth1RequestType = OAUTH1_POST_REQUEST_INVALID;
    d->m_oauth1RequestType = OAUTH1_POST_REQUEST_TOKEN;
    if (!d->m_oauth1Data.UserName().isEmpty()) {
        d->m_oauth1ScreenName = d->m_oauth1Data.UserName();
        //qDebug() << "Found username:" << d->m_oauth1ScreenName;
    }
    sendOAuth1PostRequest();
}

QString OAuth1Plugin::urlEncode(QString strData)
{
    return QUrl::toPercentEncoding(strData).constData();
}

// Create a HMAC-SHA1 signature
QByteArray OAuth1Plugin::hashHMACSHA1(const QByteArray &baseSignatureString,
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

QByteArray OAuth1Plugin::constructSignatureBaseString(const QString &aUrl,
    const OAuth1PluginData &inData, const QString &timestamp,
    const QString &nonce)
{
    Q_D(OAuth1Plugin);

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
QString OAuth1Plugin::createOAuth1Header(const QString &aUrl,
                                         OAuth1PluginData inData)
{
    Q_D(OAuth1Plugin);

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
    unsigned long nonce1 = (unsigned long) qrand();
    unsigned long nonce2 = (unsigned long) qrand();
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

void OAuth1Plugin::userActionFinished(const SignOn::UiSessionData &data)
{
    Q_D(OAuth1Plugin);

    if (handleUiErrors(data)) return;

    TRACE() << data.UrlResponse();

    // Checking if authorization server granted access
    QUrl url = QUrl(data.UrlResponse());
    if (url.hasQueryItem(AUTH_ERROR)) {
        TRACE() << "Server denied access permission";
        emit error(Error(Error::NotAuthorized, url.queryItemValue(AUTH_ERROR)));
        return;
    }

    if (url.hasQueryItem(OAUTH_VERIFIER)) {
        d->m_oauth1TokenVerifier = url.queryItemValue(OAUTH_VERIFIER);
        d->m_oauth1Data.setCallback(QString());
        d->m_oauth1RequestType = OAUTH1_POST_ACCESS_TOKEN;
        sendOAuth1PostRequest();
    }
    else if (url.hasQueryItem(OAUTH_PROBLEM)) {
        handleOAuth1ProblemError(url.queryItemValue(OAUTH_PROBLEM));
    }
    else {
        emit error(Error(Error::NotAuthorized, QString("oauth_verifier missing")));
    }
}

// Method to handle responses for OAuth 1.0a Request token request
void OAuth1Plugin::serverReply(QNetworkReply *reply)
{
    Q_D(OAuth1Plugin);

    QByteArray replyContent = reply->readAll();
    TRACE() << replyContent;
    if (reply->error() != QNetworkReply::NoError) {
        d->m_oauth1RequestType = OAUTH1_POST_REQUEST_INVALID;
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
            || (reply->rawHeader(CONTENT_TYPE).startsWith(CONTENT_TEXT_HTML))
            || (reply->rawHeader(CONTENT_TYPE).startsWith(CONTENT_TEXT_PLAIN))) {

            const QMap<QString,QString> map = parseTextReply(replyContent);
            if (d->m_oauth1RequestType == OAUTH1_POST_REQUEST_TOKEN) {
                // Extracting the request token, token secret
                d->m_oauth1Token = map.value(OAUTH_TOKEN).toAscii();
                d->m_oauth1TokenSecret = map.value(OAUTH_TOKEN_SECRET).toAscii();
                if (d->m_oauth1Token.isEmpty() ||
                    !map.contains(OAUTH_TOKEN_SECRET)) {
                    TRACE() << "OAuth request token is empty or secret is missing";
                    emit error(Error(Error::OperationFailed, QString("Request token or secret missing")));
                }
                else {
                    sendOAuth1AuthRequest();
                }
            }
            else if (d->m_oauth1RequestType == OAUTH1_POST_ACCESS_TOKEN) {
                // Extracting the access token
                d->m_oauth1Token = map.value(OAUTH_TOKEN).toAscii();
                d->m_oauth1TokenSecret = map.value(OAUTH_TOKEN_SECRET).toAscii();
                if (d->m_oauth1Token.isEmpty() ||
                    !map.contains(OAUTH_TOKEN_SECRET)) {
                    TRACE()<< "OAuth access token is empty or secret is missing";
                    emit error(Error(Error::OperationFailed, QString("Access token or secret missing")));
                }
                else {
                    QVariantMap siteResponse;
                    QMap<QString, QString>::const_iterator i;
                    for (i = map.begin(); i != map.end(); i++) {
                        siteResponse.insert(i.key(), i.value());
                    }
                    OAuth1PluginTokenData response =
                        oauth1responseFromMap(siteResponse);

                    // storing token and token secret for later use
                    OAuth2TokenData tokens;
                    d->m_tokens.insert(d->m_key,
                                       QVariant::fromValue(siteResponse));
                    tokens.setTokens(d->m_tokens);
                    emit store(tokens);

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

OAuth1PluginTokenData
OAuth1Plugin::oauth1responseFromMap(const QVariantMap &map)
{
    Q_D(OAuth1Plugin);

    TRACE() << "Response:" << map;
    OAuth1PluginTokenData response(map);
    response.setAccessToken(map[OAUTH_TOKEN].toString().toAscii());
    response.setTokenSecret(map[OAUTH_TOKEN_SECRET].toString().toAscii());

    // Store also (possible) user_id & screen_name
    if (map.contains(USER_ID)) {
        d->m_oauth1UserId = map[USER_ID].toString();
        response.setUserId(d->m_oauth1UserId);
    }
    if (map.contains(SCREEN_NAME)) {
        d->m_oauth1ScreenName = map[SCREEN_NAME].toString();
        response.setScreenName(d->m_oauth1ScreenName);
    }

    return response;
}

void OAuth1Plugin::handleOAuth1ProblemError(const QString &errorString)
{
    TRACE();
    Error::ErrorType type = Error::OperationFailed;
    if (errorString == OAUTH_USER_REFUSED || errorString == OAUTH_PERMISSION_DENIED) {
        type = Error::PermissionDenied;
    }
    TRACE() << "Error Emitted";
    emit error(Error(type, errorString));
}

void OAuth1Plugin::handleOAuth1Error(const QByteArray &reply)
{
    TRACE();
    QMap<QString,QString> map = parseTextReply(reply);
    QString errorString = map[OAUTH_PROBLEM];
    if (!errorString.isEmpty()) {
        handleOAuth1ProblemError(errorString);
        return;
    }

    TRACE() << "Error Emitted";
    emit error(Error(Error::OperationFailed, errorString));
}

void OAuth1Plugin::sendOAuth1PostRequest()
{
    Q_D(OAuth1Plugin);

    TRACE();

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

    postRequest(request, QByteArray());
}

const QMap<QString, QString> OAuth1Plugin::parseTextReply(const QByteArray &reply)
{
    TRACE();
    QMap<QString, QString> map;
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
