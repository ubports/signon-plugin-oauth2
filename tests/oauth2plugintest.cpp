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

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>
#include <QRegExp>
#include <QTimer>
#include <QtTest/QtTest>

#include "plugin.h"
#include "oauth1data.h"
#include "oauth2data.h"
#include "oauth2tokendata.h"

#include "oauth2plugintest.h"

using namespace OAuth2PluginNS;
using namespace SignOn;

static bool mapIsSubset(const QVariantMap &set, const QVariantMap &test)
{
    QMapIterator<QString, QVariant> it(set);
    while (it.hasNext()) {
        it.next();
        if (QMetaType::Type(it.value().type()) == QMetaType::QVariantMap) {
            if (!mapIsSubset(it.value().toMap(),
                             test.value(it.key()).toMap())) {
                return false;
            }
        } else if (test.value(it.key()) != it.value()) {
            qDebug() << "Maps differ: expected" << it.value() <<
                "but found" << test.value(it.key());
            return false;
        }
    }

    return true;
}

static QVariantMap parseAuthorizationHeader(const QStringList &parts, bool *ok)
{
    QVariantMap map;
    *ok = true;

    Q_FOREACH(const QString &part, parts) {
        int equalPos = part.indexOf("=");
        if (equalPos < 0) {
            qDebug() << "Invalid authorization header" << part;
            *ok = false;
            return map;
        }
        QString key = part.left(equalPos);
        QString escapedValue = part.mid(equalPos + 1);
        if (!escapedValue.startsWith('"') || !escapedValue.endsWith('"')) {
            qDebug() << "Authorization header string not quoted!" << part;
            *ok = false;
            return map;
        }

        QString value = escapedValue.mid(1, escapedValue.length() - 2);
        map.insert(key, value);
    }

    return map;
}

class TestNetworkReply: public QNetworkReply
{
    Q_OBJECT

public:
    TestNetworkReply(QObject *parent = 0):
        QNetworkReply(parent),
        m_offset(0)
    {}

    void setError(NetworkError errorCode, const QString &errorString) {
        QNetworkReply::setError(errorCode, errorString);
    }

    void setRawHeader(const QByteArray &headerName, const QByteArray &value) {
        QNetworkReply::setRawHeader(headerName, value);
    }

    void setContentType(const QString &contentType) {
        setRawHeader("Content-Type", contentType.toUtf8());
    }

    void setStatusCode(int statusCode) {
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, statusCode);
    }

    void setContent(const QByteArray &content) {
        m_content = content;
        m_offset = 0;

        open(ReadOnly | Unbuffered);
        setHeader(QNetworkRequest::ContentLengthHeader, QVariant(content.size()));

        QTimer::singleShot(0, this, SIGNAL(readyRead()));
        QTimer::singleShot(10, this, SLOT(finish()));
    }

public Q_SLOTS:
    void finish() { setFinished(true); Q_EMIT finished(); }

protected:
    void abort() Q_DECL_OVERRIDE {}
    qint64 bytesAvailable() const Q_DECL_OVERRIDE {
        return m_content.size() - m_offset + QIODevice::bytesAvailable();
    }

    bool isSequential() const Q_DECL_OVERRIDE { return true; }
    qint64 readData(char *data, qint64 maxSize) Q_DECL_OVERRIDE {
        if (m_offset >= m_content.size())
            return -1;
        qint64 number = qMin(maxSize, m_content.size() - m_offset);
        memcpy(data, m_content.constData() + m_offset, number);
        m_offset += number;
        return number;
    }

private:
    QByteArray m_content;
    qint64 m_offset;
};

class TestNetworkAccessManager: public QNetworkAccessManager
{
    Q_OBJECT

public:
    TestNetworkAccessManager(): QNetworkAccessManager() {}

    void setNextReply(TestNetworkReply *reply) { m_nextReply = reply; }

protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &request,
                                 QIODevice *outgoingData = 0) Q_DECL_OVERRIDE {
        Q_UNUSED(op);
        m_lastRequest = request;
        m_lastRequestData = outgoingData->readAll();
        return m_nextReply;
    }

public:
    QPointer<TestNetworkReply> m_nextReply;
    QNetworkRequest m_lastRequest;
    QByteArray m_lastRequestData;
};

void OAuth2PluginTest::initTestCase()
{
    qRegisterMetaType<SignOn::SessionData>();
    qRegisterMetaType<SignOn::UiSessionData>();
    qRegisterMetaType<SignOn::Error>();
}

void OAuth2PluginTest::cleanupTestCase()
{
}

//prepare each test by creating new plugin
void OAuth2PluginTest::init()
{
    m_testPlugin = new Plugin();
    m_stored = SignOn::SessionData();
    m_response = SignOn::SessionData();
    m_uiResponse = SignOn::UiSessionData();
    m_error = SignOn::Error(-1);
}

//finnish each test by deleting plugin
void OAuth2PluginTest::cleanup()
{
    delete m_testPlugin;
    m_testPlugin=NULL;
}

//slot for receiving result
void OAuth2PluginTest::result(const SignOn::SessionData& data)
{
    m_response = data;
    m_loop.exit();
}

//slot for receiving error
void OAuth2PluginTest::pluginError(const SignOn::Error &err)
{
    m_error = err;
    m_loop.exit();
}

//slot for receiving result
void OAuth2PluginTest::uiRequest(const SignOn::UiSessionData& data)
{
    Q_UNUSED(data);
    m_uiResponse.setUrlResponse(QString("UI request received"));
    m_loop.exit();
}

//slot for store
void OAuth2PluginTest::store(const SignOn::SessionData &data)
{
    m_stored = data;
}

void OAuth2PluginTest::aborted(QNetworkReply* reply)
{
    qDebug() << "aborted";
    //we should get error code if request was aborted
    qDebug() << reply->error();
    QVERIFY(reply->error());
    m_loop.exit();
}

// TEST CASES
void OAuth2PluginTest::testPlugin()
{
    QVERIFY(m_testPlugin);
}

void OAuth2PluginTest::testPluginType()
{
    QCOMPARE(m_testPlugin->type(), QString("oauth2"));
}

void OAuth2PluginTest::testPluginMechanisms()
{
    QStringList mechs = m_testPlugin->mechanisms();
    QVERIFY(!mechs.isEmpty());
    QVERIFY(mechs.contains(QString("user_agent")));
    QVERIFY(mechs.contains(QString("web_server")));
}

void OAuth2PluginTest::testPluginCancel()
{
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    //does nothing as no active connections
    m_testPlugin->cancel();

    //then real cancel
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error &)),
                     this, SLOT(pluginError(const SignOn::Error &)),
                     Qt::QueuedConnection);

    OAuth2PluginData userAgentData;
    userAgentData.setHost("https://localhost");
    userAgentData.setAuthPath("access_token");
    userAgentData.setClientId("104660106251471");
    userAgentData.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    userAgentData.setRedirectUri("http://localhost/connect/login_success.html");

    m_testPlugin->process(userAgentData, QString("user_agent"));
    m_testPlugin->cancel();
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::SessionCanceled));
}

void OAuth2PluginTest::testPluginProcess_data()
{
    QTest::addColumn<QString>("mechanism");
    QTest::addColumn<QVariantMap>("sessionData");
    QTest::addColumn<int>("errorCode");
    QTest::addColumn<QString>("urlResponse");
    QTest::addColumn<QVariantMap>("response");
    QTest::addColumn<QVariantMap>("stored");

    OAuth2PluginData userAgentData;
    userAgentData.setHost("https://localhost");
    userAgentData.setTokenPath("access_token");
    userAgentData.setClientId("104660106251471");
    userAgentData.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    userAgentData.setRedirectUri("http://localhost/connect/login_success.html");

    QTest::newRow("invalid mechanism") <<
        "ANONYMOUS" <<
        userAgentData.toMap() <<
        int(Error::MechanismNotAvailable) <<
        QString() << QVariantMap() << QVariantMap();

    QTest::newRow("without params, user_agent") <<
        "user_agent" <<
        userAgentData.toMap() <<
        int(Error::MissingData) <<
        QString() << QVariantMap() << QVariantMap();

    OAuth2PluginData webServerData;
    webServerData.setHost("https://localhost");
    webServerData.setAuthPath("authorize");
    webServerData.setClientId("104660106251471");
    webServerData.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    webServerData.setRedirectUri("http://localhost/connect/login_success.html");
    webServerData.setScope(QStringList() << "scope1" << "scope2");

    QTest::newRow("without params, web_server") <<
        "web_server" <<
        webServerData.toMap() <<
        int(Error::MissingData) <<
        QString() << QVariantMap() << QVariantMap();

    userAgentData.setAuthPath("authorize");
    QTest::newRow("ui-request, user_agent") <<
        "user_agent" <<
        userAgentData.toMap() <<
        -1 <<
        QString("UI request received") << QVariantMap() << QVariantMap();

    webServerData.setTokenPath("token");
    QTest::newRow("ui-request, web_server") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        QString("UI request received") << QVariantMap() << QVariantMap();

    QVariantMap tokens;
    QVariantMap token;
    token.insert("Token", QLatin1String("tokenfromtest"));
    token.insert("Token2", QLatin1String("token2fromtest"));
    token.insert("timestamp", QDateTime::currentDateTime().toTime_t());
    token.insert("Expiry", 10000);
    tokens.insert(QLatin1String("invalidid"), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);

    QTest::newRow("stored response, without params") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        QString("UI request received") << QVariantMap() << QVariantMap();

    tokens.insert(webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);

    QTest::newRow("stored response, missing cached scopes") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        QString("UI request received") << QVariantMap() << QVariantMap();

    token.insert("Scopes", QStringList("scope2"));
    tokens.insert(webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);

    QTest::newRow("stored response, incomplete cached scopes") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        QString("UI request received") << QVariantMap() << QVariantMap();

    token.insert("Scopes",
                 QStringList() << "scope1" << "scope3" << "scope2");
    tokens.insert(webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);
    QVariantMap response;
    response.insert("AccessToken", QLatin1String("tokenfromtest"));
    response.insert("ExpiresIn", int(10000));

    QTest::newRow("stored response, sufficient cached scopes") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        QString() << response << QVariantMap();

    /* test the ProvidedTokens semantics */
    OAuth2PluginData providedTokensWebServerData;
    providedTokensWebServerData.setHost("https://localhost");
    providedTokensWebServerData.setAuthPath("authorize");
    providedTokensWebServerData.setClientId("104660106251471");
    providedTokensWebServerData.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    providedTokensWebServerData.setRedirectUri("http://localhost/connect/login_success.html");
    providedTokensWebServerData.setTokenPath("token");
    providedTokensWebServerData.setScope(QStringList() << "scope1" << "scope3" << "scope2");
    QVariantMap providedTokens;
    providedTokens.insert("AccessToken", "providedtokenfromtest");
    providedTokens.insert("RefreshToken", "providedrefreshfromtest");
    providedTokens.insert("ExpiresIn", 12345);

    /* try providing tokens to be stored */
    providedTokensWebServerData.m_data.insert("ProvidedTokens", providedTokens);
    QVariantMap storedTokensForKey;
    storedTokensForKey.insert("Token", providedTokens.value("AccessToken"));
    storedTokensForKey.insert("refresh_token", providedTokens.value("RefreshToken"));
    QVariantMap storedTokens;
    storedTokens.insert(providedTokensWebServerData.ClientId(), storedTokensForKey);
    QVariantMap stored;
    stored.insert("Tokens", storedTokens);
    QTest::newRow("provided tokens") <<
        "web_server" <<
        providedTokensWebServerData.toMap() <<
        -1 <<
        QString() << providedTokens << stored;
}

void OAuth2PluginTest::testPluginProcess()
{
    QFETCH(QString, mechanism);
    QFETCH(QVariantMap, sessionData);
    QFETCH(int, errorCode);
    QFETCH(QString, urlResponse);
    QFETCH(QVariantMap, response);
    QFETCH(QVariantMap, stored);

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this,  SLOT(result(const SignOn::SessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this,  SLOT(pluginError(const SignOn::Error &)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this,  SLOT(uiRequest(const SignOn::UiSessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)),
                  this,  SLOT(store(const SignOn::SessionData&)),Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    m_testPlugin->process(sessionData, mechanism);
    m_loop.exec();
    QCOMPARE(m_error.type(), errorCode);
    if (errorCode < 0) {
        QCOMPARE(m_uiResponse.UrlResponse(), urlResponse);
        QCOMPARE(m_response.toMap(), response);
        QVERIFY(mapIsSubset(stored, m_stored.toMap()));
    }
}

void OAuth2PluginTest::testPluginHmacSha1Process_data()
{
    QTest::addColumn<QString>("mechanism");
    QTest::addColumn<QVariantMap>("sessionData");
    QTest::addColumn<int>("replyStatusCode");
    QTest::addColumn<QString>("replyContentType");
    QTest::addColumn<QString>("replyContents");
    QTest::addColumn<int>("errorCode");
    QTest::addColumn<QString>("urlResponse");
    QTest::addColumn<QVariantMap>("response");
    QTest::addColumn<QVariantMap>("stored");

    OAuth1PluginData hmacSha1Data;
    hmacSha1Data.setRequestEndpoint("https://localhost/oauth/request_token");
    hmacSha1Data.setTokenEndpoint("https://localhost/oauth/access_token");
    hmacSha1Data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    hmacSha1Data.setCallback("https://localhost/connect/login_success.html");
    hmacSha1Data.setConsumerKey("104660106251471");
    hmacSha1Data.setConsumerSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");

    QTest::newRow("invalid mechanism") <<
        "ANONYMOUS" <<
        hmacSha1Data.toMap() <<
        int(200) << "" << "" <<
        int(Error::MechanismNotAvailable) <<
        QString() << QVariantMap() << QVariantMap();

    // Try without params
    hmacSha1Data.setAuthorizationEndpoint(QString());
    QTest::newRow("without params, HMAC-SHA1") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "" << "" <<
        int(Error::MissingData) <<
        QString() << QVariantMap() << QVariantMap();

    // Check for signon UI request for HMAC-SHA1
    hmacSha1Data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    QTest::newRow("ui-request, HMAC-SHA1") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        -1 <<
        QString("UI request received") << QVariantMap() << QVariantMap();

    /* Now store some tokens and test the responses */
    hmacSha1Data.m_data.insert("UiPolicy", NoUserInteractionPolicy);
    QVariantMap tokens; // ConsumerKey to Token map
    QVariantMap token;
    token.insert("oauth_token", QLatin1String("hmactokenfromtest"));
    token.insert("oauth_token_secret", QLatin1String("hmacsecretfromtest"));
    token.insert("timestamp", QDateTime::currentDateTime().toTime_t());
    token.insert("Expiry", (uint)50000);
    tokens.insert(QLatin1String("invalidid"), QVariant::fromValue(token));
    hmacSha1Data.m_data.insert(QLatin1String("Tokens"), tokens);

    // Try without cached token for our ConsumerKey
    QTest::newRow("cached tokens, no ConsumerKey") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        -1 <<
        QString("UI request received") << QVariantMap() << QVariantMap();

    // Ensure that the cached token is returned as required
    tokens.insert(hmacSha1Data.ConsumerKey(), QVariant::fromValue(token));
    hmacSha1Data.m_data.insert(QLatin1String("Tokens"), tokens);
    QVariantMap response;
    response.insert("AccessToken", QLatin1String("hmactokenfromtest"));
    QTest::newRow("cached tokens, with ConsumerKey") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "" << "" <<
        -1 <<
        QString() << response << QVariantMap();

    /* test the ProvidedTokens semantics */
    OAuth1PluginData providedTokensHmacSha1Data;
    providedTokensHmacSha1Data.setRequestEndpoint("https://localhost/oauth/request_token");
    providedTokensHmacSha1Data.setTokenEndpoint("https://localhost/oauth/access_token");
    providedTokensHmacSha1Data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    providedTokensHmacSha1Data.setCallback("https://localhost/connect/login_success.html");
    providedTokensHmacSha1Data.setConsumerKey("104660106251471");
    providedTokensHmacSha1Data.setConsumerSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    QVariantMap providedTokens;
    providedTokens.insert("AccessToken", "providedhmactokenfromtest");
    providedTokens.insert("TokenSecret", "providedhmacsecretfromtest");
    providedTokens.insert("ScreenName", "providedhmacscreennamefromtest");

    // try providing tokens to be stored
    providedTokensHmacSha1Data.m_data.insert("ProvidedTokens", providedTokens);
    QVariantMap storedTokensForKey;
    storedTokensForKey.insert("oauth_token", providedTokens.value("AccessToken"));
    storedTokensForKey.insert("oauth_token_secret", providedTokens.value("TokenSecret"));
    QVariantMap storedTokens;
    storedTokens.insert(providedTokensHmacSha1Data.ConsumerKey(), storedTokensForKey);
    QVariantMap stored;
    stored.insert("Tokens", storedTokens);
    QTest::newRow("provided tokens") <<
        "HMAC-SHA1" <<
        providedTokensHmacSha1Data.toMap() <<
        int(200) << "" << "" <<
        -1 <<
        QString() << providedTokens << stored;
}

void OAuth2PluginTest::testPluginHmacSha1Process()
{
    QFETCH(QString, mechanism);
    QFETCH(QVariantMap, sessionData);
    QFETCH(int, replyStatusCode);
    QFETCH(QString, replyContentType);
    QFETCH(QString, replyContents);
    QFETCH(int, errorCode);
    QFETCH(QString, urlResponse);
    QFETCH(QVariantMap, response);
    QFETCH(QVariantMap, stored);

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this,  SLOT(result(const SignOn::SessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this,  SLOT(pluginError(const SignOn::Error &)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this,  SLOT(uiRequest(const SignOn::UiSessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)),
                  this,  SLOT(store(const SignOn::SessionData&)),Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(replyStatusCode);
    if (!replyContentType.isEmpty()) {
        reply->setContentType(replyContentType);
    }
    reply->setContent(replyContents.toUtf8());
    nam->setNextReply(reply);

    m_testPlugin->process(sessionData, mechanism);
    m_loop.exec();
    QCOMPARE(m_error.type(), errorCode);
    if (errorCode < 0) {
        /* We don't check the network request if a response was received,
         * because a response can only be received if a cached token was
         * found -- and that doesn't cause any network request to be made. */
        if (m_response.toMap().isEmpty()) {
            QCOMPARE(nam->m_lastRequest.url(),
                     sessionData.value("RequestEndpoint").toUrl());
            QVERIFY(nam->m_lastRequestData.isEmpty());

            /* Check the authorization header */
            QString authorizationHeader =
                QString::fromUtf8(nam->m_lastRequest.rawHeader("Authorization"));
            QStringList authorizationHeaderParts =
                authorizationHeader.split(QRegExp(",?\\s+"));
            QCOMPARE(authorizationHeaderParts[0], QString("OAuth"));

            /* The rest of the header should be a mapping, let's parse it */
            bool ok = true;
            QVariantMap authMap =
                parseAuthorizationHeader(authorizationHeaderParts.mid(1), &ok);
            QVERIFY(ok);
            QCOMPARE(authMap.value("oauth_signature_method").toString(), mechanism);
        }

        QCOMPARE(m_uiResponse.UrlResponse(), urlResponse);
        QVERIFY(mapIsSubset(response, m_response.toMap()));
        QVERIFY(mapIsSubset(stored, m_stored.toMap()));
    }
}

void OAuth2PluginTest::testPluginUseragentUserActionFinished()
{
    SignOn::UiSessionData info;
    OAuth2PluginData data;
    data.setHost("https://localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRedirectUri("http://localhost/connect/login_success.html");
    QStringList scopes = QStringList() << "scope1" << "scope2";
    data.setScope(scopes);

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this,  SLOT(result(const SignOn::SessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this,  SLOT(pluginError(const SignOn::Error &)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this,  SLOT(uiRequest(const SignOn::UiSessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)),
                     this,  SLOT(store(const SignOn::SessionData&)),
                     Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    m_testPlugin->process(data, QString("user_agent"));
    m_loop.exec();
    QCOMPARE(m_uiResponse.UrlResponse(), QString("UI request received"));

    //empty data
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));

    //invalid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html#access_token=&expires_in=4776"));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));

    //Invalid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html"));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));

    //valid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html#access_token=testtoken.&expires_in=4776"));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    OAuth2PluginTokenData *result = (OAuth2PluginTokenData*)&m_response;
    QCOMPARE(result->AccessToken(), QString("testtoken."));
    QCOMPARE(result->ExpiresIn(), 4776);
    QVariantMap storedTokenData = m_stored.data<OAuth2TokenData>().Tokens();
    QVariantMap storedClientData =
        storedTokenData.value(data.ClientId()).toMap();
    QVERIFY(!storedClientData.isEmpty());
    QCOMPARE(storedClientData["Scopes"].toStringList(), scopes);

    //valid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html#access_token=testtoken."));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    result = (OAuth2PluginTokenData*)&m_response;
    QCOMPARE(result->AccessToken(), QString("testtoken."));
    QCOMPARE(result->ExpiresIn(), 0);
    /* Check that the expiration time has not been stored, since the expiration
     * time was not given (https://bugs.launchpad.net/bugs/1316021)
     */
    storedTokenData = m_stored.data<OAuth2TokenData>().Tokens();
    storedClientData = storedTokenData.value(data.ClientId()).toMap();
    QVERIFY(!storedClientData.isEmpty());
    QCOMPARE(storedClientData["Token"].toString(), QString("testtoken."));
    QVERIFY(!storedClientData.contains("Expiry"));

    //Permission denied
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html?error=user_denied"));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));
}

void OAuth2PluginTest::testPluginWebserverUserActionFinished_data()
{
    QTest::addColumn<QString>("urlResponse");
    QTest::addColumn<int>("errorCode");
    QTest::addColumn<QString>("postUrl");
    QTest::addColumn<QString>("postContents");
    QTest::addColumn<int>("replyStatusCode");
    QTest::addColumn<QString>("replyContentType");
    QTest::addColumn<QString>("replyContents");
    QTest::addColumn<QVariantMap>("response");

    QVariantMap response;

    QTest::newRow("empty data") <<
        "" <<
        int(Error::NotAuthorized) <<
        "" << "" << 0 << "" << "" << QVariantMap();

    QTest::newRow("no query data") <<
        "http://localhost/resp.html" <<
        int(Error::NotAuthorized) <<
        "" << "" << 0 << "" << "" << QVariantMap();

    QTest::newRow("permission denied") <<
        "http://localhost/resp.html?error=user_denied" <<
        int(Error::NotAuthorized) <<
        "" << "" << 0 << "" << "" << QVariantMap();

    QTest::newRow("invalid data") <<
        "http://localhost/resp.html?sdsdsds=access.grant." <<
        int(Error::NotAuthorized) <<
        "" << "" << 0 << "" << "" << QVariantMap();

    QTest::newRow("reply code, http error 401") <<
        "http://localhost/resp.html?code=c0d3" <<
        int(Error::OperationFailed) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        int(401) <<
        "application/json" <<
        "something else" <<
        QVariantMap();

    QTest::newRow("reply code, empty reply") <<
        "http://localhost/resp.html?code=c0d3" <<
        int(Error::NotAuthorized) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        int(200) <<
        "application/json" <<
        "something else" <<
        QVariantMap();

    QTest::newRow("reply code, no content type") <<
        "http://localhost/resp.html?code=c0d3" <<
        int(Error::OperationFailed) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        int(200) <<
        "" <<
        "something else" <<
        QVariantMap();

    QTest::newRow("reply code, unsupported content type") <<
        "http://localhost/resp.html?code=c0d3" <<
        int(Error::OperationFailed) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        int(200) <<
        "image/jpeg" <<
        "something else" <<
        QVariantMap();

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    QTest::newRow("reply code, valid token") <<
        "http://localhost/resp.html?code=c0d3" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;

    response.clear();
    QTest::newRow("reply code, facebook, no token") <<
        "http://localhost/resp.html?code=c0d3" <<
        int(Error::NotAuthorized) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        int(200) <<
        "text/plain" <<
        "expires=3600" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    QTest::newRow("reply code, facebook, valid token") <<
        "http://localhost/resp.html?code=c0d3" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        int(200) <<
        "text/plain" <<
        "access_token=t0k3n&expires=3600" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    QTest::newRow("username-password, valid token") <<
        "http://localhost/resp.html?username=us3r&password=s3cr3t" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=user_basic&username=us3r&password=s3cr3t" <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    QTest::newRow("assertion, valid token") <<
        "http://localhost/resp.html?assertion_type=http://oauth.net/token/1.0"
        "&assertion=oauth1t0k3n" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=assertion&assertion_type=http://oauth.net/token/1.0&assertion=oauth1t0k3n" <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;
}

void OAuth2PluginTest::testPluginWebserverUserActionFinished()
{
    QFETCH(QString, urlResponse);
    QFETCH(int, errorCode);
    QFETCH(QString, postUrl);
    QFETCH(QString, postContents);
    QFETCH(int, replyStatusCode);
    QFETCH(QString, replyContentType);
    QFETCH(QString, replyContents);
    QFETCH(QVariantMap, response);

    SignOn::UiSessionData info;
    OAuth2PluginData data;
    data.setHost("localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRedirectUri("http://localhost/resp.html");

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this,  SLOT(result(const SignOn::SessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this,  SLOT(pluginError(const SignOn::Error &)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this,  SLOT(uiRequest(const SignOn::UiSessionData&)),Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(replyStatusCode);
    if (!replyContentType.isEmpty()) {
        reply->setContentType(replyContentType);
    }
    reply->setContent(replyContents.toUtf8());
    nam->setNextReply(reply);

    m_testPlugin->process(data, QString("web_server"));
    m_loop.exec();
    QCOMPARE(m_uiResponse.UrlResponse(), QString("UI request received"));

    if (!urlResponse.isEmpty()) {
        info.setUrlResponse(urlResponse);
    }

    m_testPlugin->userActionFinished(info);
    m_loop.exec();

    QCOMPARE(m_error.type(), errorCode);
    QCOMPARE(nam->m_lastRequest.url(), QUrl(postUrl));
    QCOMPARE(QString::fromUtf8(nam->m_lastRequestData), postContents);
    QCOMPARE(m_response.toMap(), response);

    delete nam;
}

void OAuth2PluginTest::testOAuth2Errors_data()
{
    QTest::addColumn<QString>("replyContents");
    QTest::addColumn<int>("expectedErrorCode");

    QTest::newRow("incorrect_client_credentials") <<
        "{ \"error\": \"incorrect_client_credentials\" }" <<
        int(Error::InvalidCredentials);

    QTest::newRow("redirect_uri_mismatch") <<
        "{ \"error\": \"redirect_uri_mismatch\" }" <<
        int(Error::InvalidCredentials);

    QTest::newRow("bad_authorization_code") <<
        "{ \"error\": \"bad_authorization_code\" }" <<
        int(Error::InvalidCredentials);

    QTest::newRow("invalid_client_credentials") <<
        "{ \"error\": \"invalid_client_credentials\" }" <<
        int(Error::InvalidCredentials);

    QTest::newRow("unauthorized_client") <<
        "{ \"error\": \"unauthorized_client\" }" <<
        int(Error::NotAuthorized);

    QTest::newRow("invalid_assertion") <<
        "{ \"error\": \"invalid_assertion\" }" <<
        int(Error::InvalidCredentials);

    QTest::newRow("unknown_format") <<
        "{ \"error\": \"unknown_format\" }" <<
        int(Error::InvalidQuery);

    QTest::newRow("authorization_expired") <<
        "{ \"error\": \"authorization_expired\" }" <<
        int(Error::InvalidCredentials);

    QTest::newRow("multiple_credentials") <<
        "{ \"error\": \"multiple_credentials\" }" <<
        int(Error::InvalidQuery);

    QTest::newRow("invalid_user_credentials") <<
        "{ \"error\": \"invalid_user_credentials\" }" <<
        int(Error::InvalidCredentials);
}

void OAuth2PluginTest::testOAuth2Errors()
{
    QFETCH(QString, replyContents);
    QFETCH(int, expectedErrorCode);

    SignOn::UiSessionData info;
    OAuth2PluginData data;
    data.setHost("localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRedirectUri("http://localhost/resp.html");

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this, SLOT(result(const SignOn::SessionData&)),
                  Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this, SLOT(pluginError(const SignOn::Error &)),
                  Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this, SLOT(uiRequest(const SignOn::UiSessionData&)),
                  Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(401);
    reply->setContentType("application/json");
    reply->setContent(replyContents.toUtf8());
    nam->setNextReply(reply);

    m_testPlugin->process(data, QString("web_server"));
    m_loop.exec();

    info.setUrlResponse("http://localhost/resp.html?code=c0d3");
    m_testPlugin->userActionFinished(info);
    m_loop.exec();

    QCOMPARE(m_error.type(), expectedErrorCode);

    delete nam;
}

void OAuth2PluginTest::testRefreshToken()
{
    SignOn::UiSessionData info;
    OAuth2PluginData data;
    data.setHost("localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRedirectUri("http://localhost/resp.html");

    /* Pretend that we have stored an expired access token, but have a refresh
     * token */
    QVariantMap tokens;
    QVariantMap token;
    token.insert("Token", QLatin1String("tokenfromtest"));
    token.insert("timestamp", QDateTime::currentDateTime().toTime_t() - 10000);
    token.insert("Expiry", 1000);
    token.insert("refresh_token", QString("r3fr3sh"));
    tokens.insert(data.ClientId(), QVariant::fromValue(token));
    data.m_data.insert("Tokens", tokens);

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this, SLOT(result(const SignOn::SessionData&)),
                  Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this, SLOT(pluginError(const SignOn::Error &)),
                  Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this, SLOT(uiRequest(const SignOn::UiSessionData&)),
                  Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(200);
    reply->setContentType("application/json");
    reply->setContent("{ \"access_token\":\"n3w-t0k3n\", \"expires_in\": 3600 }");
    nam->setNextReply(reply);

    m_testPlugin->process(data, QString("web_server"));
    m_loop.exec();

    QCOMPARE(m_error.type(), -1);
    QCOMPARE(nam->m_lastRequest.url(), QUrl("https://localhost/access_token"));
    QCOMPARE(QString::fromUtf8(nam->m_lastRequestData),
             QString("grant_type=refresh_token&refresh_token=r3fr3sh"));

    QVariantMap expectedResponse;
    expectedResponse.insert("AccessToken", "n3w-t0k3n");
    expectedResponse.insert("ExpiresIn", 3600);
    expectedResponse.insert("RefreshToken", QString());
    QCOMPARE(m_response.toMap(), expectedResponse);

    delete nam;
}

void OAuth2PluginTest::testClientAuthentication_data()
{
    QTest::addColumn<QString>("clientSecret");
    QTest::addColumn<bool>("forceAuthViaRequestBody");
    QTest::addColumn<QString>("postContents");
    QTest::addColumn<QString>("postAuthorization");

    QTest::newRow("no secret, std auth") <<
        "" << false <<
        "grant_type=authorization_code&code=c0d3"
        "&redirect_uri=http://localhost/resp.html&client_id=104660106251471" <<
        "";
    QTest::newRow("no secret, auth in body") <<
        "" << true <<
        "grant_type=authorization_code&code=c0d3"
        "&redirect_uri=http://localhost/resp.html&client_id=104660106251471" <<
        "";

    QTest::newRow("with secret, std auth") <<
        "s3cr3t" << false <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        "Basic MTA0NjYwMTA2MjUxNDcxOnMzY3IzdA==";
    QTest::newRow("with secret, auth in body") <<
        "s3cr3t" << true <<
        "grant_type=authorization_code&code=c0d3"
        "&redirect_uri=http://localhost/resp.html"
        "&client_id=104660106251471&client_secret=s3cr3t" <<
        "";
}

void OAuth2PluginTest::testClientAuthentication()
{
    QFETCH(QString, clientSecret);
    QFETCH(bool, forceAuthViaRequestBody);
    QFETCH(QString, postContents);
    QFETCH(QString, postAuthorization);

    SignOn::UiSessionData info;
    OAuth2PluginData data;
    data.setHost("localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret(clientSecret);
    data.setRedirectUri("http://localhost/resp.html");
    data.setForceClientAuthViaRequestBody(forceAuthViaRequestBody);

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this, SLOT(result(const SignOn::SessionData&)),
                  Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this, SLOT(pluginError(const SignOn::Error &)),
                  Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this, SLOT(uiRequest(const SignOn::UiSessionData&)),
                  Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(200);
    reply->setContentType("application/json");
    reply->setContent("{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }");
    nam->setNextReply(reply);

    m_testPlugin->process(data, QString("web_server"));
    m_loop.exec();

    info.setUrlResponse("http://localhost/resp.html?code=c0d3");
    m_testPlugin->userActionFinished(info);
    m_loop.exec();

    QCOMPARE(m_error.type(), -1);
    QCOMPARE(nam->m_lastRequest.url(), QUrl("https://localhost/access_token"));
    QCOMPARE(QString::fromUtf8(nam->m_lastRequestData), postContents);
    QCOMPARE(QString::fromUtf8(nam->m_lastRequest.rawHeader("Authorization")),
             postAuthorization);

    delete nam;
}

//end test cases

QTEST_MAIN(OAuth2PluginTest)
#include "oauth2plugintest.moc"
