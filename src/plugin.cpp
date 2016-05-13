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

#include "common.h"
#include "oauth1plugin.h"
#include "oauth2plugin.h"
#include "plugin.h"

#include <QNetworkAccessManager>
#include <QNetworkProxy>

using namespace SignOn;
using namespace OAuth2PluginNS;

namespace OAuth2PluginNS {
SIGNON_DECL_AUTH_PLUGIN(Plugin)
} //namespace OAuth2PluginNS

Plugin::Plugin(QObject *parent):
    AuthPluginInterface(parent),
    impl(0),
    m_networkAccessManager(0)
{
    TRACE();
}

Plugin::~Plugin()
{
    TRACE();
    delete impl;
    impl = 0;
}

QString Plugin::type() const
{
    TRACE();
    return QString("oauth2");
}

QStringList Plugin::mechanisms() const
{
    TRACE();
    return OAuth1Plugin::mechanisms() +
        OAuth2Plugin::mechanisms();
}

void Plugin::cancel()
{
    TRACE();
    if (impl != 0) impl->cancel();
}

void Plugin::process(const SignOn::SessionData &inData,
                           const QString &mechanism)
{
    if (impl != 0) delete impl;

    if (!m_networkAccessManager) {
        m_networkAccessManager = new QNetworkAccessManager(this);
    }

    if (OAuth1Plugin::mechanisms().contains(mechanism)) {
        impl = new OAuth1Plugin(this);
    } else if (OAuth2Plugin::mechanisms().contains(mechanism)) {
        impl = new OAuth2Plugin(this);
    } else {
        emit error(Error(Error::MechanismNotAvailable));
        return;
    }

    QNetworkProxy networkProxy = QNetworkProxy::applicationProxy();
    // Override proxy, if given in the parameters
    QString proxy = inData.NetworkProxy();
    if (!proxy.isEmpty()) {
        QUrl proxyUrl(proxy);
        if (!proxyUrl.host().isEmpty()) {
            networkProxy = QNetworkProxy(QNetworkProxy::HttpProxy,
                                         proxyUrl.host(),
                                         proxyUrl.port(),
                                         proxyUrl.userName(),
                                         proxyUrl.password());
            TRACE() << proxyUrl.host() << ":" <<  proxyUrl.port();
        }
    }

    m_networkAccessManager->setProxy(networkProxy);
    impl->setNetworkAccessManager(m_networkAccessManager);

    // Forward the signals from the implementation
    connect(impl, SIGNAL(result(const SignOn::SessionData &)),
            SIGNAL(result(const SignOn::SessionData &)));
    connect(impl, SIGNAL(store(const SignOn::SessionData &)),
            SIGNAL(store(const SignOn::SessionData &)));
    connect(impl, SIGNAL(error(const SignOn::Error &)),
            SIGNAL(error(const SignOn::Error &)));
    connect(impl, SIGNAL(userActionRequired(const SignOn::UiSessionData &)),
            SIGNAL(userActionRequired(const SignOn::UiSessionData &)));
    connect(impl, SIGNAL(refreshed(const SignOn::UiSessionData &)),
            SIGNAL(refreshed(const SignOn::UiSessionData &)));
    connect(impl, SIGNAL(statusChanged(const AuthPluginState, const QString&)),
            SIGNAL(statusChanged(const AuthPluginState, const QString&)));

    impl->process(inData, mechanism);
}

void Plugin::userActionFinished(const SignOn::UiSessionData &data)
{
    TRACE();
    if (impl != 0) impl->userActionFinished(data);
}

void Plugin::refresh(const SignOn::UiSessionData &data)
{
    TRACE();
    if (impl != 0) impl->refresh(data);
}
