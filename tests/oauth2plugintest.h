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

#ifndef OAUTH2PLUGINTEST_H
#define OAUTH2PLUGINTEST_H

#include <QNetworkReply>
#include <QString>
#include "plugin.h"
#include "SignOn/AuthPluginInterface"

using namespace OAuth2PluginNS;

class OAuth2PluginTest : public QObject
{
    Q_OBJECT

public slots:
    void result(const SignOn::SessionData &data);
    void pluginError(const SignOn::Error &err);
    void uiRequest(const SignOn::UiSessionData &data);
    void store(const SignOn::SessionData &data);
    void aborted(QNetworkReply *reply);

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    //test cases
    void testPlugin();
    void testPluginType();
    void testPluginMechanisms();
    void testPluginCancel();
    void testPluginProcess_data();
    void testPluginProcess();
    void testPluginHmacSha1Process_data();
    void testPluginHmacSha1Process();
    void testPluginUseragentUserActionFinished();
    void testPluginWebserverUserActionFinished_data();
    void testPluginWebserverUserActionFinished();
    void testOauth1UserActionFinished_data();
    void testOauth1UserActionFinished();
    void testOAuth2Errors_data();
    void testOAuth2Errors();
    void testRefreshToken();
    void testClientAuthentication_data();
    void testClientAuthentication();

private:
    Plugin *m_testPlugin;
    SignOn::Error m_error;
    SignOn::SessionData m_response;
    SignOn::UiSessionData m_uiResponse;
    SignOn::SessionData m_stored;
    QEventLoop m_loop;
};

#endif // OAUTH2PLUGINTEST_H
