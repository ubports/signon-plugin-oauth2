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

#include <QtTest/QtTest>

#include "plugin.h"
#include "oauth1data.h"
#include "oauth2data.h"
#include "oauth2tokendata.h"

#include "oauth2plugintest.h"

using namespace OAuth2PluginNS;
using namespace SignOn;

#define TEST_START qDebug("\n\n\n\n ----------------- %s ----------------\n\n",  __func__);
#define TEST_DONE  qDebug("\n\n ----------------- %s DONE ----------------\n\n",  __func__);

void OAuth2PluginTest::initTestCase()
{
    TEST_START
    qRegisterMetaType<SignOn::SessionData>();
    qRegisterMetaType<SignOn::UiSessionData>();
    qRegisterMetaType<SignOn::Error>();
    TEST_DONE
}

void OAuth2PluginTest::cleanupTestCase()
{
    TEST_START

    TEST_DONE
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

//slot for receiving result
void OAuth2PluginTest::result(const SignOn::SessionData& data)
{
    qDebug() << "got result";
    m_response = data;
    m_loop.exit();
}

//slot for receiving error
void OAuth2PluginTest::pluginError(const SignOn::Error &err)
{
    qDebug() << "got error" << err.type() << ": " << err.message();
    m_error = err;
    m_loop.exit();
}

//slot for receiving result
void OAuth2PluginTest::uiRequest(const SignOn::UiSessionData& data)
{
    Q_UNUSED(data);
    qDebug() << "got ui request";
    m_uiResponse.setUrlResponse(QString("UI request received"));
    m_loop.exit();
}

//slot for store
void OAuth2PluginTest::store(const SignOn::SessionData &data)
{
    qDebug() << "got store";
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
    TEST_START

    qDebug() << "Checking plugin integrity.";
    QVERIFY(m_testPlugin);

    TEST_DONE
}

void OAuth2PluginTest::testPluginType()
{
    TEST_START

    qDebug() << "Checking plugin type.";
    QCOMPARE(m_testPlugin->type(), QString("oauth2"));

    TEST_DONE
}

void OAuth2PluginTest::testPluginMechanisms()
{
    TEST_START

    qDebug() << "Checking plugin mechanisms.";
    QStringList mechs = m_testPlugin->mechanisms();
    QVERIFY(!mechs.isEmpty());
    QVERIFY(mechs.contains(QString("user_agent")));
    QVERIFY(mechs.contains(QString("web_server")));
    qDebug() << mechs;

    TEST_DONE
}

void OAuth2PluginTest::testPluginCancel()
{
    TEST_START
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

    TEST_DONE
}

void OAuth2PluginTest::testPluginProcess()
{
    TEST_START

    OAuth2PluginData userAgentData;
    userAgentData.setHost("https://localhost");
    userAgentData.setTokenPath("access_token");
    userAgentData.setClientId("104660106251471");
    userAgentData.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    userAgentData.setRedirectUri("http://localhost/connect/login_success.html");

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this,  SLOT(result(const SignOn::SessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this,  SLOT(pluginError(const SignOn::Error &)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this,  SLOT(uiRequest(const SignOn::UiSessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)),
                  this,  SLOT(store(const SignOn::SessionData&)),Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    // Invalid mechanism
    m_testPlugin->process(userAgentData, QString("ANONYMOUS"));
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::MechanismNotAvailable));

    //try without params
    m_testPlugin->process(userAgentData, QString("user_agent"));
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::MissingData));

    OAuth2PluginData webServerData;
    webServerData.setHost("https://localhost");
    webServerData.setAuthPath("authorize");
    webServerData.setClientId("104660106251471");
    webServerData.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    webServerData.setRedirectUri("http://localhost/connect/login_success.html");
    webServerData.setScope(QStringList() << "scope1" << "scope2");

    //try without params
    m_testPlugin->process(webServerData, QString("web_server"));
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::MissingData));

    // Check for signon UI request for user_agent
    userAgentData.setAuthPath("authorize");
    m_testPlugin->process(userAgentData, QString("user_agent"));
    m_loop.exec();
    qDebug() << "Data = " << m_uiResponse.UrlResponse();
    QCOMPARE(m_uiResponse.UrlResponse(), QString("UI request received"));

    // Check for signon UI request for web_server
    m_uiResponse.setUrlResponse(QString(""));
    webServerData.setTokenPath("token");
    m_testPlugin->process(userAgentData, QString("web_server"));
    m_loop.exec();
    qDebug() << "Data = " << m_uiResponse.UrlResponse();
    QCOMPARE(m_uiResponse.UrlResponse(), QString("UI request received"));

    // Check using stored responses
    QVariantMap tokens;
    QVariantMap token;
    token.insert("Token", QLatin1String("tokenfromtest"));
    token.insert("Token2", QLatin1String("token2fromtest"));
    token.insert("timestamp", QDateTime::currentDateTime().toTime_t());
    token.insert("Expiry", 10000);
    tokens.insert( QLatin1String("invalidid"), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);

    //try without params
    m_testPlugin->process(webServerData, QString("web_server"));
    m_loop.exec();
    OAuth2PluginTokenData resp = m_response.data<OAuth2PluginTokenData>();
    QVERIFY(resp.AccessToken() != QLatin1String("tokenfromtest"));
    QCOMPARE(m_error.type(), int(Error::MissingData));

    tokens.insert( webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);

    /* try with missing cached scopes */
    m_testPlugin->process(webServerData, QString("web_server"));
    m_loop.exec();
    resp = m_response.data<OAuth2PluginTokenData>();
    QVERIFY(resp.AccessToken() != QLatin1String("tokenfromtest"));
    QCOMPARE(m_error.type(), int(Error::MissingData));

    /* try with incomplete cached scopes */
    token.insert("Scopes", QStringList("scope2"));
    tokens.insert(webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);
    m_testPlugin->process(webServerData, QString("web_server"));
    m_loop.exec();
    resp = m_response.data<OAuth2PluginTokenData>();
    QVERIFY(resp.AccessToken() != QLatin1String("tokenfromtest"));
    QCOMPARE(m_error.type(), int(Error::MissingData));

    /* try with sufficient cached scopes */
    token.insert("Scopes",
                 QStringList() << "scope1" << "scope3" << "scope2");
    tokens.insert(webServerData.ClientId(), QVariant::fromValue(token));
    webServerData.m_data.insert(QLatin1String("Tokens"), tokens);
    m_testPlugin->process(webServerData, QString("web_server"));
    m_loop.exec();
    resp = m_response.data<OAuth2PluginTokenData>();
    QCOMPARE(resp.AccessToken(), QLatin1String("tokenfromtest"));

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
    m_stored = SignOn::SessionData(QVariantMap());
    m_response = SignOn::SessionData(QVariantMap());
    providedTokensWebServerData.m_data.insert("ProvidedTokens", providedTokens);
    m_testPlugin->process(providedTokensWebServerData, QString("web_server"));
    m_loop.exec();
    resp = m_response.data<OAuth2PluginTokenData>();
    QCOMPARE(resp.AccessToken(), QLatin1String("providedtokenfromtest"));
    QVariantMap storedTokens = m_stored.getProperty("Tokens").toMap();
    QVariantMap storedTokensForKey = storedTokens.value(providedTokensWebServerData.ClientId()).toMap();
    QCOMPARE(storedTokensForKey.value("Token"), providedTokens.value("AccessToken"));
    QCOMPARE(storedTokensForKey.value("refresh_token"), providedTokens.value("RefreshToken"));

    /* ensure that subsequent requests return the provided tokens */
    m_response = SignOn::SessionData(QVariantMap());
    providedTokensWebServerData.m_data.insert("ProvidedTokens", QVariantMap());
    providedTokensWebServerData.m_data.insert("Tokens", storedTokens);
    m_testPlugin->process(providedTokensWebServerData, QString("web_server"));
    m_loop.exec();
    resp = m_response.data<OAuth2PluginTokenData>();
    QCOMPARE(resp.AccessToken(), QLatin1String("providedtokenfromtest"));

    TEST_DONE
}

void OAuth2PluginTest::testPluginHmacSha1Process()
{
    TEST_START

    OAuth1PluginData hmacSha1Data;
    hmacSha1Data.setRequestEndpoint("https://localhost/oauth/request_token");
    hmacSha1Data.setTokenEndpoint("https://localhost/oauth/access_token");
    hmacSha1Data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    hmacSha1Data.setCallback("https://localhost/connect/login_success.html");
    hmacSha1Data.setConsumerKey("104660106251471");
    hmacSha1Data.setConsumerSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this,  SLOT(result(const SignOn::SessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this,  SLOT(pluginError(const SignOn::Error &)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this,  SLOT(uiRequest(const SignOn::UiSessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(store(const SignOn::SessionData&)),
                  this,  SLOT(store(const SignOn::SessionData&)),Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    // Invalid mechanism
    m_testPlugin->process(hmacSha1Data, QString("ANONYMOUS"));
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::MechanismNotAvailable));

    // Try without params
    hmacSha1Data.setAuthorizationEndpoint(QString());
    m_testPlugin->process(hmacSha1Data, QString("HMAC-SHA1"));
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::MissingData));

    // Check for signon UI request for HMAC-SHA1
    hmacSha1Data.setAuthorizationEndpoint("https://localhost/oauth/authorize");
    m_testPlugin->process(hmacSha1Data, QString("HMAC-SHA1"));
    m_loop.exec();
    qDebug() << "Data = " << m_uiResponse.UrlResponse();
    QCOMPARE(m_uiResponse.UrlResponse(), QString("UI request received"));

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
    m_response = SignOn::SessionData(QVariantMap());
    m_testPlugin->process(hmacSha1Data, QString("HMAC-SHA1"));
    m_loop.exec();
    OAuth1PluginTokenData resp = m_response.data<OAuth1PluginTokenData>();
    QVERIFY(resp.AccessToken() != QLatin1String("hmactokenfromtest"));

    // Ensure that the cached token is returned as required
    m_response = SignOn::SessionData(QVariantMap());
    tokens.insert(hmacSha1Data.ConsumerKey(), QVariant::fromValue(token));
    hmacSha1Data.m_data.insert(QLatin1String("Tokens"), tokens);
    m_testPlugin->process(hmacSha1Data, QString("HMAC-SHA1"));
    m_loop.exec();
    resp = m_response.data<OAuth1PluginTokenData>();
    QCOMPARE(resp.AccessToken(), QLatin1String("hmactokenfromtest"));

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
    m_stored = SignOn::SessionData(QVariantMap());
    m_response = SignOn::SessionData(QVariantMap());
    providedTokensHmacSha1Data.m_data.insert("ProvidedTokens", providedTokens);
    m_testPlugin->process(providedTokensHmacSha1Data, QString("HMAC-SHA1"));
    m_loop.exec();
    resp = m_response.data<OAuth1PluginTokenData>();
    QCOMPARE(resp.AccessToken(), QLatin1String("providedhmactokenfromtest"));
    QVariantMap storedTokens = m_stored.getProperty("Tokens").toMap();
    QVariantMap storedTokensForKey = storedTokens.value(providedTokensHmacSha1Data.ConsumerKey()).toMap();
    QCOMPARE(storedTokensForKey.value("oauth_token"), providedTokens.value("AccessToken"));
    QCOMPARE(storedTokensForKey.value("oauth_token_secret"), providedTokens.value("TokenSecret"));

    // ensure that subsequent requests return the provided tokens
    m_response = SignOn::SessionData(QVariantMap());
    providedTokensHmacSha1Data.m_data.insert("UiPolicy", NoUserInteractionPolicy);
    providedTokensHmacSha1Data.m_data.insert("ProvidedTokens", QVariantMap());
    providedTokensHmacSha1Data.m_data.insert("Tokens", storedTokens);
    m_testPlugin->process(providedTokensHmacSha1Data, QString("HMAC-SHA1"));
    m_loop.exec();
    resp = m_response.data<OAuth1PluginTokenData>();
    QCOMPARE(resp.AccessToken(), QLatin1String("providedhmactokenfromtest"));

    TEST_DONE
}

void OAuth2PluginTest::testPluginUseragentUserActionFinished()
{
    TEST_START

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
    qDebug() << "Data = " << m_uiResponse.UrlResponse();
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

    TEST_DONE
}

void OAuth2PluginTest::testPluginWebserverUserActionFinished()
{
    TEST_START

    SignOn::UiSessionData info;
    OAuth2PluginData data;
    data.setHost("https://localhost");
    data.setAuthPath("authorize");
    data.setTokenPath("access_token");
    data.setClientId("104660106251471");
    data.setClientSecret("fa28f40b5a1f8c1d5628963d880636fbkjkjkj");
    data.setRedirectUri("http://localhost/connect/login_success.html");

    QObject::connect(m_testPlugin, SIGNAL(result(const SignOn::SessionData&)),
                  this,  SLOT(result(const SignOn::SessionData&)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(error(const SignOn::Error & )),
                  this,  SLOT(pluginError(const SignOn::Error &)),Qt::QueuedConnection);
    QObject::connect(m_testPlugin, SIGNAL(userActionRequired(const SignOn::UiSessionData&)),
                  this,  SLOT(uiRequest(const SignOn::UiSessionData&)),Qt::QueuedConnection);
    QTimer::singleShot(10*1000, &m_loop, SLOT(quit()));

    m_testPlugin->process(data, QString("web_server"));
    m_loop.exec();
    qDebug() << "Data = " << m_uiResponse.UrlResponse();
    QCOMPARE(m_uiResponse.UrlResponse(), QString("UI request received"));

    //empty data
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));

    //invalid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html"));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));

    //Permission denied
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html?error=user_denied"));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));

    //invalid data
    info.setUrlResponse(QString("http://www.facebook.com/connect/login_success.html?sdsdsds=access.grant."));
    m_testPlugin->userActionFinished(info);
    m_loop.exec();
    QCOMPARE(m_error.type(), int(Error::NotAuthorized));

    TEST_DONE
}

//end test cases

QTEST_MAIN(OAuth2PluginTest)

