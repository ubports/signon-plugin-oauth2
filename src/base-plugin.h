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

#ifndef SIGNON_PLUGIN_BASE
#define SIGNON_PLUGIN_BASE

#include <QtCore>
#include <QSslError>
#include <QNetworkReply>

#include <SignOn/AuthPluginInterface>
#include <SignOn/Error>
#include <SignOn/SessionData>
#include <SignOn/UiSessionData>

class QNetworkAccessManager;

namespace OAuth2PluginNS {

/*!
 * @class BasePlugin
 * Base class for OAuth-based plugins.
 */
class BasePluginPrivate;
class BasePlugin: public QObject
{
    Q_OBJECT

public:
    BasePlugin(QObject *parent = 0);
    ~BasePlugin();

    virtual void cancel();
    virtual void process(const SignOn::SessionData &inData,
                         const QString &mechanism) = 0;
    virtual void userActionFinished(const SignOn::UiSessionData &data) = 0;
    virtual void refresh(const SignOn::UiSessionData &data);

    void setNetworkAccessManager(QNetworkAccessManager *nam);
    QNetworkAccessManager *networkAccessManager() const;

protected:
    void postRequest(const QNetworkRequest &request,
                     const QByteArray &data);

    virtual void serverReply(QNetworkReply *reply);

protected Q_SLOTS:
    void onPostFinished();
    virtual bool handleNetworkError(QNetworkReply::NetworkError err);
    virtual void handleSslErrors(QList<QSslError> errorList);

Q_SIGNALS:
    void result(const SignOn::SessionData &data);
    void store(const SignOn::SessionData &data);
    void error(const SignOn::Error &err);
    void userActionRequired(const SignOn::UiSessionData &data);
    void refreshed(const SignOn::UiSessionData &data);
    void statusChanged(const AuthPluginState state, const QString &message);

private:
    BasePluginPrivate *d_ptr;
    Q_DECLARE_PRIVATE(BasePlugin)
};

} //namespace OAuth2PluginNS

#endif // SIGNON_PLUGIN_BASE
