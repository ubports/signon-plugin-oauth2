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

#ifndef OAUTH2PLUGIN_H
#define OAUTH2PLUGIN_H

#include <QtCore>
#include <QSslError>
#include <QNetworkReply>

#include <SignOn/AuthPluginInterface>
#include <SignOn/SessionData>
#include <SignOn/Error>

#include "oauth2data.h"
#include "oauth1data.h"

class OAuth2PluginTest;
namespace OAuth2PluginNS {

/*!
 * @class oauthPlugin
 * OAuth authentication plugin.
 */
    class OAuth2Plugin : public AuthPluginInterface
    {
        Q_OBJECT
        Q_INTERFACES(AuthPluginInterface);
        friend class ::OAuth2PluginTest;
    public:
        OAuth2Plugin(QObject *parent = 0);
        ~OAuth2Plugin();

    public Q_SLOTS:
        QString type() const;
        QStringList mechanisms() const;
        void cancel();
        void process(const SignOn::SessionData &inData, const QString &mechanism = 0);
        void userActionFinished(const SignOn::UiSessionData &data);
        void refresh(const SignOn::UiSessionData &data);
        void replyOAuth2RequestFinished();
        void replyOAuth1RequestFinished();
        bool handleNetworkError(QNetworkReply::NetworkError err);
        void handleSslErrors(QList<QSslError> errorList);

    private:
        void sendOAuth2AuthRequest();
        void sendOAuth1AuthRequest(const QString &captchaUrl = 0);
        bool validateInput(const SignOn::SessionData &inData, const QString &mechanism);
        void sendOAuth2PostRequest(const QByteArray &postData);
        void sendOAuth1PostRequest();
        const QVariantMap parseJSONReply(const QByteArray &reply);
        const QMap<QString, QString> parseTextReply(const QByteArray &reply);
        void handleOAuth1ProblemError(const QByteArray &errorString);
        void handleOAuth1Error(const QByteArray &reply);
        void handleOAuth2Error(const QByteArray &reply);
        QByteArray constructSignatureBaseString(const QString &aUrl,
                                                const OAuth1PluginData &inData,
                                                const QString &timestamp,
                                                const QString &nonce);
        QString urlEncode(QString strData);
        QString createOAuth1Header(const QString &aUrl, OAuth1PluginData inData);
        QByteArray hashHMACSHA1(const QByteArray &keyForHash ,const QByteArray &secret);

        class Private;
        Private *d; // Owned.
    };

} //namespace OAuth2PluginNS

#endif // OAUTH2PLUGIN_H
