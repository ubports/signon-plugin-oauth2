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

#ifndef SIGNON_PLUGIN_OAUTH2
#define SIGNON_PLUGIN_OAUTH2

#include <QtCore>

#include <SignOn/AuthPluginInterface>
#include <SignOn/SessionData>
#include <SignOn/Error>

#include "base-plugin.h"
#include "oauth2data.h"

namespace OAuth2PluginNS {

namespace GrantType {
    enum e {
        Undefined = 0,
        RefreshToken,
        UserBasic,
        Assertion,
        AuthorizationCode,
    };
};

/*!
 * @class OAuth2Plugin
 * OAuth 2.0 authentication plugin.
 */
class OAuth2PluginPrivate;
class OAuth2Plugin: public BasePlugin
{
    Q_OBJECT

public:
    OAuth2Plugin(QObject *parent = 0);
    ~OAuth2Plugin();

    static QStringList mechanisms();

    void process(const SignOn::SessionData &inData, const QString &mechanism);
    void userActionFinished(const SignOn::UiSessionData &data);

protected:
    void serverReply(QNetworkReply *);
    bool handleNetworkError(QNetworkReply *reply,
                            QNetworkReply::NetworkError err);

private:
    void sendOAuth2AuthRequest();
    bool validateInput(const SignOn::SessionData &inData, const QString &mechanism);
    bool respondWithStoredToken(const QVariantMap &token,
                                const QStringList &scopes);
    void refreshOAuth2Token(const QString &refreshToken);
    void sendOAuth2PostRequest(QUrl &postData,
                               GrantType::e grantType);
    void storeResponse(const OAuth2PluginTokenData &response);
    QVariantMap parseReply(const QByteArray &contentType,
                           const QByteArray &replyContent);
    QVariantMap parseJSONReply(const QByteArray &reply);
    QVariantMap parseTextReply(const QByteArray &reply);
    void handleOAuth2Error(const QByteArray &reply);
    QString urlEncode(QString strData);

    OAuth2PluginPrivate *d_ptr;
    Q_DECLARE_PRIVATE(OAuth2Plugin)
};

} //namespace OAuth2PluginNS

#endif // SIGNON_PLUGIN_OAUTH2
