/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
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
#ifndef OAUTHCLIENT_H
#define OAUTHCLIENT_H

#include <SignOn/Identity>
#include <SignOn/AuthSession>

#include <QObject>

class OAuthClient: public QObject
{
    Q_OBJECT

public:
    OAuthClient(const QString &clientId,
                const QString &clientSecret,
                QObject *parent = 0);
    ~OAuthClient();

public Q_SLOTS:
    void authenticate();

private Q_SLOTS:
    void onResponse(const SignOn::SessionData &sessionData);
    void onError(const SignOn::Error &error);

private:
    QString m_clientId;
    QString m_clientSecret;
    SignOn::Identity *m_identity;
    SignOn::AuthSession *m_session;
};

#endif // OAUTHCLIENT_H

