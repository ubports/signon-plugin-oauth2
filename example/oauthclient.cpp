/*
 * This file is part of signon
 *
 * Copyright (C) 2011 Nokia Corporation.
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

#include "oauthclient.h"
#include "oauth2data.h"

#include <QCoreApplication>
#include <QDebug>

using namespace OAuth2PluginNS;

OAuthClient::OAuthClient(const QString &clientId,
                         const QString &clientSecret,
                         QObject *parent):
    QObject(parent),
    m_clientId(clientId),
    m_clientSecret(clientSecret),
    m_identity(0),
    m_session(0)
{
    m_identity = SignOn::Identity::newIdentity(SignOn::IdentityInfo(), this);
}

OAuthClient::~OAuthClient()
{
}

void OAuthClient::authenticate()
{
    SignOn::AuthSession *m_session = m_identity->createSession("oauth2");
    QObject::connect(m_session, SIGNAL(response(const SignOn::SessionData &)),
                     this, SLOT(onResponse(const SignOn::SessionData &)));
    QObject::connect(m_session, SIGNAL(error(const SignOn::Error &)),
                     this, SLOT(onError(const SignOn::Error &)));

    OAuth2PluginData data;
    data.setHost("www.facebook.com");
    data.setAuthPath("/dialog/oauth");
    data.setRedirectUri("https://www.facebook.com/connect/login_success.html");
    data.setClientId(m_clientId);
    data.setClientSecret(m_clientSecret);

    m_session->process(data, "user_agent");
}

void OAuthClient::onResponse(const SignOn::SessionData &sessionData)
{
    OAuth2PluginTokenData response = sessionData.data<OAuth2PluginTokenData>();
    qDebug() << "Access token:" << response.AccessToken();
    qDebug() << "Expires in:" << response.ExpiresIn();

    QCoreApplication::quit();
}

void OAuthClient::onError(const SignOn::Error &error)
{
    qDebug() << "Got error:" << error.message();

    QCoreApplication::quit();
}

