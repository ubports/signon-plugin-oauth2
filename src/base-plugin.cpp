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

#include "common.h"

#include "base-plugin.h"
#include "oauth2tokendata.h"

#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkProxy>
#include <QDateTime>
#include <QCryptographicHash>

using namespace SignOn;
using namespace OAuth2PluginNS;

namespace OAuth2PluginNS {

class BasePluginPrivate
{
    Q_DECLARE_PUBLIC(BasePlugin)

public:
    BasePluginPrivate(BasePlugin *q);
    ~BasePluginPrivate();

    void disposeReply();

    QNetworkAccessManager *m_networkAccessManager;
    QNetworkReply *m_reply;
    mutable BasePlugin *q_ptr;
}; //Private

} //namespace OAuth2PluginNS

BasePluginPrivate::BasePluginPrivate(BasePlugin *q):
    m_networkAccessManager(0),
    m_reply(0),
    q_ptr(q)
{
}

BasePluginPrivate::~BasePluginPrivate()
{
    disposeReply();
}

void BasePluginPrivate::disposeReply()
{
    Q_Q(BasePlugin);

    if (m_reply != 0) {
        QObject::disconnect(m_reply, 0, q, 0);
        m_reply->deleteLater();
        m_reply = 0;
    }
}

BasePlugin::BasePlugin(QObject *parent):
    QObject(parent),
    d_ptr(new BasePluginPrivate(this))
{
}

BasePlugin::~BasePlugin()
{
    delete d_ptr;
    d_ptr = 0;
}

void BasePlugin::cancel()
{
    Q_D(BasePlugin);

    TRACE();
    emit error(Error(Error::SessionCanceled));
    if (d->m_reply)
        d->m_reply->abort();
}

void BasePlugin::refresh(const SignOn::UiSessionData &data)
{
    TRACE();
    emit refreshed(data);
}

void BasePlugin::setNetworkAccessManager(QNetworkAccessManager *nam)
{
    Q_D(BasePlugin);
    d->m_networkAccessManager = nam;
}

QNetworkAccessManager *BasePlugin::networkAccessManager() const
{
    Q_D(const BasePlugin);
    return d->m_networkAccessManager;
}

void BasePlugin::postRequest(const QNetworkRequest &request,
                             const QByteArray &data)
{
    Q_D(BasePlugin);

    d->m_reply = d->m_networkAccessManager->post(request, data);
    connect(d->m_reply, SIGNAL(finished()),
            this, SLOT(onPostFinished()));
    connect(d->m_reply, SIGNAL(error(QNetworkReply::NetworkError)),
            this, SLOT(onNetworkError(QNetworkReply::NetworkError)));
    connect(d->m_reply, SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(handleSslErrors(QList<QSslError>)));
}

void BasePlugin::serverReply(QNetworkReply *reply)
{
    Q_UNUSED(reply);
    // Implemented by subclasses
}

void BasePlugin::onPostFinished()
{
    Q_D(BasePlugin);

    QNetworkReply *reply = d->m_reply;

    TRACE() << "Finished signal received - reply object:" << reply;
    if (Q_UNLIKELY(!reply)) return;

    d->disposeReply();

    if (reply->error() != QNetworkReply::NoError) {
        if (handleNetworkError(reply, reply->error()))
            return;
    }

    serverReply(reply);
}

void BasePlugin::onNetworkError(QNetworkReply::NetworkError err)
{
    Q_D(BasePlugin);

    QNetworkReply *reply = d->m_reply;

    TRACE() << "Network error:" << err;
    if (Q_UNLIKELY(!reply)) return;

    handleNetworkError(reply, err);
    d->disposeReply();
}

bool BasePlugin::handleNetworkError(QNetworkReply *reply,
                                    QNetworkReply::NetworkError err)
{
    /* Has been handled by handleSslErrors already */
    if (err == QNetworkReply::SslHandshakeFailedError) {
        return true;
    }
    /* HTTP errors handled in slots attached to  signal */
    if ((err > QNetworkReply::UnknownProxyError)
        && (err <= QNetworkReply::UnknownContentError)) {
        return false;
    }
    Error::ErrorType type = Error::Network;
    if (err <= QNetworkReply::UnknownNetworkError)
        type = Error::NoConnection;
    QString errorString = "";
    errorString = reply->errorString();
    emit error(Error(type, errorString));
    return true;
}

void BasePlugin::handleSslErrors(QList<QSslError> errorList)
{
    Q_D(BasePlugin);

    TRACE() << "Error: " << errorList;
    QString errorString = "";
    foreach (QSslError error, errorList) {
        errorString += error.errorString() + ";";
    }
    d->disposeReply();

    emit error(Error(Error::Ssl, errorString));
}

bool BasePlugin::handleUiErrors(const SignOn::UiSessionData &data)
{
    int code = data.QueryErrorCode();
    if (code == QUERY_ERROR_NONE) {
        return false;
    }

    TRACE() << "userActionFinished with error: " << code;
    if (code == QUERY_ERROR_CANCELED) {
        Q_EMIT error(Error(Error::SessionCanceled,
                           QLatin1String("Cancelled by user")));
    } else if (code == QUERY_ERROR_NETWORK) {
        Q_EMIT error(Error(Error::Network, QLatin1String("Network error")));
    } else if (code == QUERY_ERROR_SSL) {
        Q_EMIT error(Error(Error::Ssl, QLatin1String("SSL error")));
    } else {
        Q_EMIT error(Error(Error::UserInteraction,
                           QString("userActionFinished error: ")
                           + QString::number(data.QueryErrorCode())));
    }
    return true;
}
