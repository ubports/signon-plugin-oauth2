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

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>
#include <QRegExp>
#include <QSignalSpy>
#include <QTimer>
#include <QtTest/QtTest>

#include "plugin.h"
#include "oauth1data.h"
#include "oauth2data.h"
#include "oauth2tokendata.h"

#include "oauth2plugintest.h"

using namespace OAuth2PluginNS;
using namespace SignOn;

namespace QTest {
template<>
char *toString(const QVariantMap &map)
{
    QJsonDocument doc(QJsonObject::fromVariantMap(map));
    return qstrdup(doc.toJson(QJsonDocument::Compact).data());
}
} // QTest namespace

static QString parseState(const QSignalSpy &userActionRequired)
{
    UiSessionData data = userActionRequired.at(0).at(0).value<UiSessionData>();
    QUrlQuery query(data.OpenUrl());
    return query.queryItemValue("state");
}

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

    void setError(NetworkError errorCode, const QString &errorString,
                  int delay = -1) {
        QNetworkReply::setError(errorCode, errorString);
        if (delay > 0) {
            QTimer::singleShot(delay, this, SLOT(fail()));
        }
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
    void fail() { Q_EMIT error(error()); }

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
}

//finnish each test by deleting plugin
void OAuth2PluginTest::cleanup()
{
    delete m_testPlugin;
    m_testPlugin=NULL;
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
    //does nothing as no active connections
    m_testPlugin->cancel();

    //then real cancel
    QSignalSpy pluginError(m_testPlugin, SIGNAL(error(const SignOn::Error &)));

    OAuth2PluginData userAgentData;
    userAgentData.setHost("https://localhost");
    userAgentData.setAuthPath("access_token");
    userAgentData.setClientId("104660106251471");
    userAgentData.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    userAgentData.setRedirectUri("http://localhost/connect/login_success.html");

    m_testPlugin->process(userAgentData, QString("user_agent"));
    m_testPlugin->cancel();
    QTRY_COMPARE(pluginError.count(), 1);
    Error error = pluginError.at(0).at(0).value<Error>();
    QCOMPARE(error.type(), int(Error::SessionCanceled));
}

void OAuth2PluginTest::testPluginProcess_data()
{
    QTest::addColumn<QString>("mechanism");
    QTest::addColumn<QVariantMap>("sessionData");
    QTest::addColumn<int>("errorCode");
    QTest::addColumn<bool>("uiExpected");
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
        false << QVariantMap() << QVariantMap();

    QTest::newRow("without params, user_agent") <<
        "user_agent" <<
        userAgentData.toMap() <<
        int(Error::MissingData) <<
        false << QVariantMap() << QVariantMap();

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
        false << QVariantMap() << QVariantMap();

    userAgentData.setAuthPath("authorize");
    QTest::newRow("ui-request, user_agent") <<
        "user_agent" <<
        userAgentData.toMap() <<
        -1 <<
        true << QVariantMap() << QVariantMap();

    webServerData.setTokenPath("token");
    QTest::newRow("ui-request, web_server") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        true << QVariantMap() << QVariantMap();

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
        true << QVariantMap() << QVariantMap();

    tokens.insert(webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);

    QTest::newRow("stored response, missing cached scopes") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        true << QVariantMap() << QVariantMap();

    token.insert("Scopes", QStringList("scope2"));
    tokens.insert(webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);

    QTest::newRow("stored response, incomplete cached scopes") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        true << QVariantMap() << QVariantMap();

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
        false << response << QVariantMap();

    webServerData.setForceTokenRefresh(true);
    QTest::newRow("force token refresh, without refresh token") <<
        "web_server" <<
        webServerData.toMap() <<
        -1 <<
        true << QVariantMap() << QVariantMap();

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
        false << providedTokens << stored;
}

void OAuth2PluginTest::testPluginProcess()
{
    QFETCH(QString, mechanism);
    QFETCH(QVariantMap, sessionData);
    QFETCH(int, errorCode);
    QFETCH(bool, uiExpected);
    QFETCH(QVariantMap, response);
    QFETCH(QVariantMap, stored);

    QSignalSpy result(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)));
    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));
    QSignalSpy store(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)));

    m_testPlugin->process(sessionData, mechanism);
    if (errorCode < 0) {
        QCOMPARE(error.count(), 0);
        QTRY_COMPARE(userActionRequired.count(), uiExpected ? 1 : 0);
        if (!response.isEmpty()) {
            QCOMPARE(result.count(), 1);
            QVariantMap resp = result.at(0).at(0).value<SessionData>().toMap();
            /* Round the expiration time, because some seconds might have passed */
            if (resp.contains("ExpiresIn")) {
                resp["ExpiresIn"] = qRound(resp["ExpiresIn"].toInt() / 10.0) * 10;
                response["ExpiresIn"] = qRound(response["ExpiresIn"].toInt() / 10.0) * 10;
            }
            QCOMPARE(resp, response);
        }
        if (!stored.isEmpty()) {
            QCOMPARE(store.count(), 1);
            QVariantMap storedData =
                store.at(0).at(0).value<SessionData>().toMap();
            QVERIFY(mapIsSubset(stored, storedData));
        }
    } else {
        QTRY_COMPARE(error.count(), 1);
        Error err = error.at(0).at(0).value<Error>();
        QCOMPARE(err.type(), errorCode);
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
    QTest::addColumn<bool>("uiExpected");
    QTest::addColumn<QVariantMap>("response");
    QTest::addColumn<QVariantMap>("stored");

    OAuth1PluginData hmacSha1Data;
    hmacSha1Data.setRequestEndpoint("https://localhost/oauth/request_token");
    hmacSha1Data.setTokenEndpoint("https://localhost/oauth/access_token");
    hmacSha1Data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    hmacSha1Data.setCallback("https://localhost/connect/login_success.html");
    hmacSha1Data.setConsumerKey("104660106251471");
    hmacSha1Data.setConsumerSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    hmacSha1Data.setRealm("MyHost");

    QTest::newRow("invalid mechanism") <<
        "ANONYMOUS" <<
        hmacSha1Data.toMap() <<
        int(200) << "" << "" <<
        int(Error::MechanismNotAvailable) <<
        false << QVariantMap() << QVariantMap();

    // Try without params
    hmacSha1Data.setAuthorizationEndpoint(QString());
    QTest::newRow("without params, HMAC-SHA1") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "" << "" <<
        int(Error::MissingData) <<
        false << QVariantMap() << QVariantMap();

    // Check for signon UI request for HMAC-SHA1
    hmacSha1Data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    QTest::newRow("ui-request, HMAC-SHA1") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        -1 <<
        true << QVariantMap() << QVariantMap();

    QTest::newRow("ui-request, PLAINTEXT") <<
        "PLAINTEXT" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        -1 <<
        true << QVariantMap() << QVariantMap();

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
        true << QVariantMap() << QVariantMap();

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
        false << response << QVariantMap();

    hmacSha1Data.m_data.insert("UiPolicy", RequestPasswordPolicy);
    QTest::newRow("cached tokens, request password policy") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        -1 <<
        true << QVariantMap() << QVariantMap();
    hmacSha1Data.m_data.remove("UiPolicy");

    hmacSha1Data.setForceTokenRefresh(true);
    QTest::newRow("cached tokens, force refresh") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        -1 <<
        true << QVariantMap() << QVariantMap();
    hmacSha1Data.setForceTokenRefresh(false);

    token.insert("timestamp", QDateTime::currentDateTime().toTime_t() - 50000);
    token.insert("Expiry", (uint)100);
    tokens.insert(hmacSha1Data.ConsumerKey(), QVariant::fromValue(token));
    hmacSha1Data.m_data.insert(QLatin1String("Tokens"), tokens);
    QTest::newRow("cached tokens, expired") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        -1 <<
        true << QVariantMap() << QVariantMap();

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
    providedTokens.insert("UserId", "providedUserId");

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
        false << providedTokens << stored;

    QTest::newRow("http error 401") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(401) << "text/plain" <<
        "oauth_token=HiThere&oauth_token_secret=BigSecret" <<
        int(Error::OperationFailed) <<
        false << QVariantMap() << QVariantMap();

    QTest::newRow("no content returned") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "" << "" <<
        int(Error::OperationFailed) <<
        false << QVariantMap() << QVariantMap();

    QTest::newRow("no token returned") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(200) << "text/plain" <<
        "oauth_token=HiThere" <<
        int(Error::OperationFailed) <<
        false << QVariantMap() << QVariantMap();

    /* Test handling of oauth_problem; this is a non standard extension:
     * http://wiki.oauth.net/w/page/12238543/ProblemReporting
     * https://developer.yahoo.com/oauth/guide/oauth-errors.html
     */
    QTest::newRow("problem user_refused") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(400) << "text/plain" <<
        "oauth_problem=user_refused" <<
        int(Error::PermissionDenied) <<
        false << QVariantMap() << QVariantMap();
    QTest::newRow("problem permission_denied") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(400) << "text/plain" <<
        "oauth_problem=permission_denied" <<
        int(Error::PermissionDenied) <<
        false << QVariantMap() << QVariantMap();
    QTest::newRow("problem signature_invalid") <<
        "HMAC-SHA1" <<
        hmacSha1Data.toMap() <<
        int(400) << "text/plain" <<
        "oauth_problem=signature_invalid" <<
        int(Error::OperationFailed) <<
        false << QVariantMap() << QVariantMap();
}

void OAuth2PluginTest::testPluginHmacSha1Process()
{
    QFETCH(QString, mechanism);
    QFETCH(QVariantMap, sessionData);
    QFETCH(int, replyStatusCode);
    QFETCH(QString, replyContentType);
    QFETCH(QString, replyContents);
    QFETCH(int, errorCode);
    QFETCH(bool, uiExpected);
    QFETCH(QVariantMap, response);
    QFETCH(QVariantMap, stored);

    QSignalSpy result(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)));
    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));
    QSignalSpy store(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)));

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

    QTRY_COMPARE(result.count(), response.isEmpty() ? 0 : 1);
    /* In the test data sometimes we don't specify the expected stored data,
     * but this doesn't mean that store() shouldn't be emitted. */
    if (!stored.isEmpty()) { QTRY_COMPARE(store.count(), 1); }
    QTRY_COMPARE(userActionRequired.count(), uiExpected ? 1 : 0);
    QTRY_COMPARE(error.count(), errorCode < 0 ? 0 : 1);

    if (errorCode < 0) {
        QCOMPARE(error.count(), 0);

        QVariantMap resp = result.count() > 0 ?
            result.at(0).at(0).value<SessionData>().toMap() : QVariantMap();
        QVariantMap storedData = store.count() > 0 ?
            store.at(0).at(0).value<SessionData>().toMap() : QVariantMap();
        /* We don't check the network request if a response was received,
         * because a response can only be received if a cached token was
         * found -- and that doesn't cause any network request to be made. */
        if (resp.isEmpty()) {
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

        QVERIFY(mapIsSubset(response, resp));
        QVERIFY(mapIsSubset(stored, storedData));
    } else {
        Error err = error.at(0).at(0).value<Error>();
        QCOMPARE(err.type(), errorCode);
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

    QSignalSpy resultSpy(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)));
    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));
    QSignalSpy store(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)));

    m_testPlugin->process(data, QString("user_agent"));

    QTRY_COMPARE(userActionRequired.count(), 1);
    QString state = parseState(userActionRequired);

    //empty data
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(error.count(), 1);
    QCOMPARE(error.at(0).at(0).value<Error>().type(), int(Error::NotAuthorized));
    error.clear();

    //invalid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html#access_token=&expires_in=4776"));
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(error.count(), 1);
    QCOMPARE(error.at(0).at(0).value<Error>().type(), int(Error::NotAuthorized));
    error.clear();

    //Invalid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html"));
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(error.count(), 1);
    QCOMPARE(error.at(0).at(0).value<Error>().type(), int(Error::NotAuthorized));
    error.clear();

    // Wrong state
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html"
                                "#access_token=123&expires_in=456&state=%1").
                        arg(state + "Boo"));
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(error.count(), 1);
    QCOMPARE(error.at(0).at(0).value<Error>().type(), int(Error::NotAuthorized));
    error.clear();

    //valid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html#access_token=testtoken.&expires_in=4776&state=%1").
                        arg(state));
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(resultSpy.count(), 1);
    SessionData response = resultSpy.at(0).at(0).value<SessionData>();
    OAuth2PluginTokenData result = response.data<OAuth2PluginTokenData>();
    QCOMPARE(result.AccessToken(), QString("testtoken."));
    QCOMPARE(result.ExpiresIn(), 4776);
    QCOMPARE(result.Scope(), QStringList() << "scope1" << "scope2");
    resultSpy.clear();
    QTRY_COMPARE(store.count(), 1);
    SessionData storedData = store.at(0).at(0).value<SessionData>();
    QVariantMap storedTokenData = storedData.data<OAuth2TokenData>().Tokens();
    QVariantMap storedClientData =
        storedTokenData.value(data.ClientId()).toMap();
    QVERIFY(!storedClientData.isEmpty());
    QCOMPARE(storedClientData["Scopes"].toStringList(), scopes);
    store.clear();

    //valid data, got scopes
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html#access_token=testtoken.&expires_in=4776&state=%1&scope=scope2").
                        arg(state));
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(resultSpy.count(), 1);
    response = resultSpy.at(0).at(0).value<SessionData>();
    result = response.data<OAuth2PluginTokenData>();
    QCOMPARE(result.AccessToken(), QString("testtoken."));
    QCOMPARE(result.ExpiresIn(), 4776);
    QCOMPARE(result.Scope(), QStringList() << "scope2");
    resultSpy.clear();
    store.clear();

    //valid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html"
                                "#state=%1&access_token=testtoken.").
                        arg(state));
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(resultSpy.count(), 1);
    response = resultSpy.at(0).at(0).value<SessionData>();
    result = response.data<OAuth2PluginTokenData>();
    QCOMPARE(result.AccessToken(), QString("testtoken."));
    QCOMPARE(result.ExpiresIn(), 0);
    resultSpy.clear();
    /* Check that the expiration time has not been stored, since the expiration
     * time was not given (https://bugs.launchpad.net/bugs/1316021)
     */
    QTRY_COMPARE(store.count(), 1);
    storedData = store.at(0).at(0).value<SessionData>();
    storedTokenData = storedData.data<OAuth2TokenData>().Tokens();
    storedClientData = storedTokenData.value(data.ClientId()).toMap();
    QVERIFY(!storedClientData.isEmpty());
    QCOMPARE(storedClientData["Token"].toString(), QString("testtoken."));
    QVERIFY(!storedClientData.contains("Expiry"));
    store.clear();

    //Permission denied
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html?error=user_denied"));
    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(error.count(), 1);
    QCOMPARE(error.at(0).at(0).value<Error>().type(), int(Error::NotAuthorized));
    error.clear();
}

void OAuth2PluginTest::testPluginWebserverUserActionFinished_data()
{
    QTest::addColumn<QString>("urlResponse");
    QTest::addColumn<int>("errorCode");
    QTest::addColumn<QString>("postUrl");
    QTest::addColumn<QString>("postContents");
    QTest::addColumn<bool>("disableStateParameter");
    QTest::addColumn<int>("replyStatusCode");
    QTest::addColumn<QString>("replyContentType");
    QTest::addColumn<QString>("replyContents");
    QTest::addColumn<QVariantMap>("response");

    QVariantMap response;

    QTest::newRow("empty data") <<
        "" <<
        int(Error::NotAuthorized) <<
        "" << "" << false << 0 << "" << "" << QVariantMap();

    QTest::newRow("no query data") <<
        "http://localhost/resp.html" <<
        int(Error::NotAuthorized) <<
        "" << "" << false << 0 << "" << "" << QVariantMap();

    QTest::newRow("permission denied") <<
        "http://localhost/resp.html?error=user_denied&$state" <<
        int(Error::NotAuthorized) <<
        "" << "" << false << 0 << "" << "" << QVariantMap();

    QTest::newRow("invalid data") <<
        "http://localhost/resp.html?sdsdsds=access.grant." <<
        int(Error::NotAuthorized) <<
        "" << "" << false << 0 << "" << "" << QVariantMap();

    QTest::newRow("reply code, http error 401") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(Error::OperationFailed) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(401) <<
        "application/json" <<
        "something else" <<
        QVariantMap();

    QTest::newRow("reply code, empty reply") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(Error::NotAuthorized) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "application/json" <<
        "something else" <<
        QVariantMap();

    QTest::newRow("reply code, no access token") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(Error::NotAuthorized) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "application/json" <<
        "{ \"expires_in\": 3600 }" <<
        QVariantMap();

    QTest::newRow("reply code, no content type") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(Error::OperationFailed) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "" <<
        "something else" <<
        QVariantMap();

    QTest::newRow("reply code, unsupported content type") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(Error::OperationFailed) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "image/jpeg" <<
        "something else" <<
        QVariantMap();

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    QTest::newRow("reply code, valid token, wrong state") <<
        "http://localhost/resp.html?code=c0d3&$wrongstate" <<
        int(Error::NotAuthorized) <<
        "" <<
        "" <<
        false <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList() << "one" << "two");
    QTest::newRow("reply code, valid token, wrong state ignored") <<
        "http://localhost/resp.html?code=c0d3&$wrongstate" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        true <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600, "
        "\"scope\": \"one two\" }" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList() << "one" << "two" << "three");
    QTest::newRow("reply code, valid token, no scope") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList());
    QTest::newRow("reply code, valid token, empty scope") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600, \"scope\": \"\" }" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList() << "one" << "two");
    QTest::newRow("reply code, valid token, other scope") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600, "
        "\"scope\": \"one two\" }" <<
        response;

    response.clear();
    QTest::newRow("reply code, facebook, no token") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(Error::NotAuthorized) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "text/plain" <<
        "expires=3600" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList() << "one" << "two" << "three");
    QTest::newRow("reply code, facebook, valid token") <<
        "http://localhost/resp.html?code=c0d3&$state" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=authorization_code&code=c0d3&redirect_uri=http://localhost/resp.html" <<
        false <<
        int(200) <<
        "text/plain" <<
        "access_token=t0k3n&expires=3600" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList() << "one" << "two" << "three");
    QTest::newRow("username-password, valid token") <<
        "http://localhost/resp.html?username=us3r&password=s3cr3t" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=user_basic&username=us3r&password=s3cr3t" <<
        false <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList() << "one" << "two" << "three");
    QTest::newRow("assertion, valid token") <<
        "http://localhost/resp.html?assertion_type=http://oauth.net/token/1.0"
        "&assertion=oauth1t0k3n" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=assertion&assertion_type=http://oauth.net/token/1.0&assertion=oauth1t0k3n" <<
        false <<
        int(200) <<
        "application/json" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;

    response.clear();
    response.insert("AccessToken", "t0k3n");
    response.insert("ExpiresIn", int(3600));
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList() << "one" << "two" << "three");
    QTest::newRow("username-password, valid token, wrong content type") <<
        "http://localhost/resp.html?username=us3r&password=s3cr3t" <<
        int(-1) <<
        "https://localhost/access_token" <<
        "grant_type=user_basic&username=us3r&password=s3cr3t" <<
        false <<
        int(200) <<
        "text/plain" <<
        "{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }" <<
        response;
}

void OAuth2PluginTest::testPluginWebserverUserActionFinished()
{
    QFETCH(QString, urlResponse);
    QFETCH(int, errorCode);
    QFETCH(QString, postUrl);
    QFETCH(QString, postContents);
    QFETCH(bool, disableStateParameter);
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
    data.setScope(QStringList() << "one" << "two" << "three");
    data.setDisableStateParameter(disableStateParameter);

    QSignalSpy result(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)));
    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));

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
    QTRY_COMPARE(userActionRequired.count(), 1);
    QString state = parseState(userActionRequired);

    if (!urlResponse.isEmpty()) {
        urlResponse.replace("$state", QString("state=") + state);
        urlResponse.replace("$wrongstate", QString("state=12") + state);
        info.setUrlResponse(urlResponse);
    }

    m_testPlugin->userActionFinished(info);

    QTRY_COMPARE(error.count(), errorCode < 0 ? 0 : 1);
    QTRY_COMPARE(result.count(), errorCode < 0 ? 1 : 0);
    if (errorCode >= 0) {
        QCOMPARE(error.at(0).at(0).value<Error>().type(), errorCode);
    } else {
        QCOMPARE(result.at(0).at(0).value<SessionData>().toMap(), response);
    }
    QCOMPARE(nam->m_lastRequest.url(), QUrl(postUrl));
    QCOMPARE(QString::fromUtf8(nam->m_lastRequestData), postContents);

    delete nam;
}

void OAuth2PluginTest::testOauth1UserActionFinished_data()
{
    QTest::addColumn<QString>("mechanism");
    QTest::addColumn<QString>("urlResponse");
    QTest::addColumn<int>("errorCode");
    QTest::addColumn<QVariantMap>("expectedAuthMap");
    QTest::addColumn<int>("replyStatusCode");
    QTest::addColumn<QString>("replyContentType");
    QTest::addColumn<QString>("replyContents");
    QTest::addColumn<QVariantMap>("response");

    QTest::newRow("empty data") <<
        "HMAC-SHA1" <<
        "" <<
        int(Error::NotAuthorized) <<
        QVariantMap() << 0 << "" << "" << QVariantMap();

    QTest::newRow("auth error") <<
        "HMAC-SHA1" <<
        "http://localhost/resp.html?error=permission_denied" <<
        int(Error::NotAuthorized) <<
        QVariantMap() << 0 << "" << "" << QVariantMap();

    QTest::newRow("auth problem") <<
        "HMAC-SHA1" <<
        "http://localhost/resp.html?oauth_problem=permission_denied" <<
        int(Error::PermissionDenied) <<
        QVariantMap() << 0 << "" << "" << QVariantMap();

    QVariantMap authMap;
    authMap.insert("oauth_verifier", QString("v3r1f13r"));
    authMap.insert("oauth_token", QString("HiThere"));
    QTest::newRow("http error 401") <<
        "HMAC-SHA1" <<
        "http://localhost/resp.html?oauth_verifier=v3r1f13r" <<
        int(Error::OperationFailed) <<
        authMap <<
        int(401) <<
        "text/plain" <<
        "something else" <<
        QVariantMap();

    QTest::newRow("empty reply") <<
        "HMAC-SHA1" <<
        "http://localhost/resp.html?oauth_verifier=v3r1f13r" <<
        int(Error::OperationFailed) <<
        authMap <<
        int(200) <<
        "text/plain" <<
        "" <<
        QVariantMap();

    QTest::newRow("missing secret") <<
        "HMAC-SHA1" <<
        "http://localhost/resp.html?oauth_verifier=v3r1f13r" <<
        int(Error::OperationFailed) <<
        authMap <<
        int(200) <<
        "text/plain" <<
        "oauth_token=t0k3n" <<
        QVariantMap();

    QVariantMap response;
    response.insert("AccessToken", QString("t0k3n"));
    response.insert("TokenSecret", QString("t0k3nS3cr3t"));

    QTest::newRow("success") <<
        "HMAC-SHA1" <<
        "http://localhost/resp.html?oauth_verifier=v3r1f13r" <<
        int(-1) <<
        authMap <<
        int(200) <<
        "text/plain" <<
        "oauth_token=t0k3n&oauth_token_secret=t0k3nS3cr3t" <<
        response;

    response.insert("ExtraField", QString("v4lu3"));
    QTest::newRow("success with data") <<
        "HMAC-SHA1" <<
        "http://localhost/resp.html?oauth_verifier=v3r1f13r" <<
        int(-1) <<
        authMap <<
        int(200) <<
        "text/plain" <<
        "oauth_token=t0k3n&oauth_token_secret=t0k3nS3cr3t"
        "&ExtraField=v4lu3" <<
        response;
}

void OAuth2PluginTest::testOauth1UserActionFinished()
{
    QFETCH(QString, mechanism);
    QFETCH(QString, urlResponse);
    QFETCH(int, errorCode);
    QFETCH(QVariantMap, expectedAuthMap);
    QFETCH(int, replyStatusCode);
    QFETCH(QString, replyContentType);
    QFETCH(QString, replyContents);
    QFETCH(QVariantMap, response);

    SignOn::UiSessionData info;
    OAuth1PluginData data;
    data.setRequestEndpoint("https://localhost/oauth/request_token");
    data.setTokenEndpoint("https://localhost/oauth/access_token");
    data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    data.setCallback("http://localhost/resp.html");
    data.setConsumerKey("104660106251471");
    data.setConsumerSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRealm("MyHost");

    QSignalSpy result(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)));
    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(200);
    reply->setContentType("text/plain");
    reply->setContent("oauth_token=HiThere&oauth_token_secret=BigSecret");
    nam->setNextReply(reply);

    m_testPlugin->process(data, mechanism);
    QTRY_COMPARE(userActionRequired.count(), 1);

    nam->m_lastRequest = QNetworkRequest();
    nam->m_lastRequestData = QByteArray();

    reply = new TestNetworkReply(this);
    reply->setStatusCode(replyStatusCode);
    if (!replyContentType.isEmpty()) {
        reply->setContentType(replyContentType);
    }
    reply->setContent(replyContents.toUtf8());
    nam->setNextReply(reply);

    if (!urlResponse.isEmpty()) {
        info.setUrlResponse(urlResponse);
    }

    m_testPlugin->userActionFinished(info);
    QTRY_COMPARE(error.count(), errorCode < 0 ? 0 : 1);
    QTRY_COMPARE(result.count(), errorCode < 0 ? 1 : 0);
    QVariantMap resp;
    if (errorCode >= 0) {
        QCOMPARE(error.at(0).at(0).value<Error>().type(), errorCode);
    } else {
        resp = result.at(0).at(0).value<SessionData>().toMap();
        QVERIFY(mapIsSubset(response, resp));
    }

    if (!expectedAuthMap.isEmpty()) {
        QCOMPARE(nam->m_lastRequest.url().toString(), data.TokenEndpoint());
        QVERIFY(nam->m_lastRequestData.isEmpty());

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
        QVERIFY(mapIsSubset(expectedAuthMap, authMap));
    }

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

    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(401);
    reply->setContentType("application/json");
    reply->setContent(replyContents.toUtf8());
    nam->setNextReply(reply);

    m_testPlugin->process(data, QString("web_server"));
    QTRY_COMPARE(userActionRequired.count(), 1);
    QString state = parseState(userActionRequired);

    info.setUrlResponse("http://localhost/resp.html?code=c0d3&state=" + state);
    m_testPlugin->userActionFinished(info);

    QTRY_COMPARE(error.count(), 1);
    QCOMPARE(error.at(0).at(0).value<Error>().type(), expectedErrorCode);

    delete nam;
}

void OAuth2PluginTest::testRefreshToken_data()
{
    QTest::addColumn<QVariantMap>("sessionData");
    QTest::addColumn<QVariantMap>("expectedResponse");

    OAuth2PluginData data;
    data.setHost("localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRedirectUri("http://localhost/resp.html");

    QVariantMap tokens;
    QVariantMap token;
    token.insert("Token", QLatin1String("tokenfromtest"));
    token.insert("timestamp", QDateTime::currentDateTime().toTime_t() - 10000);
    token.insert("Expiry", 1000);
    token.insert("refresh_token", QString("r3fr3sh"));
    tokens.insert(data.ClientId(), QVariant::fromValue(token));
    data.m_data.insert("Tokens", tokens);

    QVariantMap response;
    response.insert("AccessToken", "n3w-t0k3n");
    response.insert("ExpiresIn", 3600);
    response.insert("RefreshToken", QString());
    response.insert("Scope", QStringList());

    QTest::newRow("expired access token") << data.toMap() << response;

    token.insert("timestamp", QDateTime::currentDateTime().toTime_t());
    token.insert("Expiry", 50000);
    tokens.insert(data.ClientId(), QVariant::fromValue(token));
    data.m_data.insert("Tokens", tokens);
    data.setForceTokenRefresh(true);
    QTest::newRow("valid access token, force refresh") << data.toMap() << response;
}

void OAuth2PluginTest::testRefreshToken()
{
    QFETCH(QVariantMap, sessionData);
    QFETCH(QVariantMap, expectedResponse);

    SignOn::UiSessionData info;

    QSignalSpy result(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)));
    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(200);
    reply->setContentType("application/json");
    reply->setContent("{ \"access_token\":\"n3w-t0k3n\", \"expires_in\": 3600 }");
    nam->setNextReply(reply);

    m_testPlugin->process(sessionData, QString("web_server"));
    QTRY_COMPARE(result.count(), 1);
    QCOMPARE(error.count(), 0);

    QCOMPARE(nam->m_lastRequest.url(), QUrl("https://localhost/access_token"));
    QCOMPARE(QString::fromUtf8(nam->m_lastRequestData),
             QString("grant_type=refresh_token&refresh_token=r3fr3sh"));

    QCOMPARE(result.at(0).at(0).value<SessionData>().toMap(), expectedResponse);

    delete nam;
}

void OAuth2PluginTest::testRefreshTokenError_data()
{
    QTest::addColumn<int>("replyErrorCode");
    QTest::addColumn<int>("replyStatusCode");
    QTest::addColumn<QString>("replyContents");
    QTest::addColumn<int>("expectedError");

    QTest::newRow("invalid grant, 400") <<
        int(QNetworkReply::ProtocolInvalidOperationError) <<
        int(400) <<
        "{ \"error\":\"invalid_grant\" }" <<
        int(-1);

    QTest::newRow("invalid grant, 401") <<
        int(QNetworkReply::ContentAccessDenied) <<
        int(401) <<
        "{ \"error\":\"invalid_grant\" }" <<
        int(-1);

    QTest::newRow("invalid grant, 401, no error signal") <<
        int(-1) <<
        int(401) <<
        "{ \"error\":\"invalid_grant\" }" <<
        int(-1);

    QTest::newRow("temporary network failure") <<
        int(QNetworkReply::TemporaryNetworkFailureError) <<
        int(-1) <<
        "" <<
        int(Error::NoConnection);
}

void OAuth2PluginTest::testRefreshTokenError()
{
    QFETCH(int, replyErrorCode);
    QFETCH(int, replyStatusCode);
    QFETCH(QString, replyContents);
    QFETCH(int, expectedError);

    OAuth2PluginData data;
    data.setHost("localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRedirectUri("http://localhost/resp.html");

    QVariantMap tokens;
    QVariantMap token;
    token.insert("Token", QLatin1String("tokenfromtest"));
    token.insert("timestamp", QDateTime::currentDateTime().toTime_t() - 10000);
    token.insert("Expiry", 1000);
    token.insert("refresh_token", QString("r3fr3sh"));
    tokens.insert(data.ClientId(), QVariant::fromValue(token));
    data.m_data.insert("Tokens", tokens);

    SignOn::UiSessionData info;

    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    if (replyErrorCode >= 0) {
        reply->setError(QNetworkReply::NetworkError(replyErrorCode),
                        "Dummy error", 5);
    }
    reply->setStatusCode(replyStatusCode);
    reply->setContentType("application/json");
    reply->setContent(replyContents.toUtf8());
    nam->setNextReply(reply);

    m_testPlugin->process(data, QString("web_server"));

    if (expectedError < 0) {
        QTRY_COMPARE(userActionRequired.count(), 1);
        QCOMPARE(error.count(), 0);
    } else {
        QTRY_COMPARE(error.count(), 1);
        QCOMPARE(error.at(0).at(0).value<Error>().type(), expectedError);
    }

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

    QSignalSpy result(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)));
    QSignalSpy error(m_testPlugin, SIGNAL(error(const SignOn::Error &)));
    QSignalSpy userActionRequired(m_testPlugin,
                                  SIGNAL(userActionRequired(const SignOn::UiSessionData&)));

    TestNetworkAccessManager *nam = new TestNetworkAccessManager;
    m_testPlugin->m_networkAccessManager = nam;
    TestNetworkReply *reply = new TestNetworkReply(this);
    reply->setStatusCode(200);
    reply->setContentType("application/json");
    reply->setContent("{ \"access_token\":\"t0k3n\", \"expires_in\": 3600 }");
    nam->setNextReply(reply);

    m_testPlugin->process(data, QString("web_server"));
    QTRY_COMPARE(userActionRequired.count(), 1);
    QString state = parseState(userActionRequired);

    info.setUrlResponse("http://localhost/resp.html?code=c0d3&state=" + state);
    m_testPlugin->userActionFinished(info);

    QTRY_COMPARE(result.count(), 1);
    QCOMPARE(error.count(), 0);
    QCOMPARE(nam->m_lastRequest.url(), QUrl("https://localhost/access_token"));
    QCOMPARE(QString::fromUtf8(nam->m_lastRequestData), postContents);
    QCOMPARE(QString::fromUtf8(nam->m_lastRequest.rawHeader("Authorization")),
             postAuthorization);

    delete nam;
}

//end test cases

QTEST_MAIN(OAuth2PluginTest)
#include "oauth2plugintest.moc"
