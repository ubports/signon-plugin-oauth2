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

#ifndef SIGNON_PLUGIN_OAUTH1
#define SIGNON_PLUGIN_OAUTH1

#include <QtCore>

#include "base-plugin.h"
#include "oauth1data.h"

namespace OAuth2PluginNS {

/*!
 * @class OAuth1Plugin
 * OAuth 1.0a authentication plugin.
 */
class OAuth1PluginPrivate;
class OAuth1Plugin: public BasePlugin
{
    Q_OBJECT

public:
    OAuth1Plugin(QObject *parent = 0);
    ~OAuth1Plugin();

    static QStringList mechanisms();

    void process(const SignOn::SessionData &inData, const QString &mechanism = 0);
    void userActionFinished(const SignOn::UiSessionData &data);

protected:
    void serverReply(QNetworkReply *reply);

private:
    void sendOAuth1AuthRequest();
    bool validateInput(const SignOn::SessionData &inData, const QString &mechanism);
    bool respondWithStoredToken(const QVariantMap &token,
                                const QString &mechanism);
    void sendOAuth1PostRequest();
    const QMap<QString, QString> parseTextReply(const QByteArray &reply);
    void handleOAuth1ProblemError(const QString &errorString);
    void handleOAuth1Error(const QByteArray &reply);
    QByteArray constructSignatureBaseString(const QString &aUrl,
                                            const OAuth1PluginData &inData,
                                            const QString &timestamp,
                                            const QString &nonce);
    QString urlEncode(QString strData);
    QString createOAuth1Header(const QString &aUrl, OAuth1PluginData inData);
    QByteArray hashHMACSHA1(const QByteArray &keyForHash ,const QByteArray &secret);
    OAuth1PluginTokenData oauth1responseFromMap(const QVariantMap &map);

    OAuth1PluginPrivate *d_ptr;
    Q_DECLARE_PRIVATE(OAuth1Plugin)
};

} //namespace OAuth2PluginNS

#endif // SIGNON_PLUGIN_OAUTH1
