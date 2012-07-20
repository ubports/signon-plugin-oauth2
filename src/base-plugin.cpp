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

#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkProxy>
#include <QDateTime>
#include <QCryptographicHash>

#include <qjson/parser.h>

#include "base-plugin.h"
#include "common.h"
#include "oauth2tokendata.h"

using namespace SignOn;
using namespace OAuth2PluginNS;

namespace OAuth2PluginNS {

class BasePluginPrivate
{
public:
    BasePluginPrivate()
    {
    }

    ~BasePluginPrivate()
    {
    }
}; //Private

} //namespace OAuth2PluginNS

BasePlugin::BasePlugin(QObject *parent):
    QObject(parent),
    d_ptr(new BasePluginPrivate())
{
}

BasePlugin::~BasePlugin()
{
    delete d_ptr;
    d_ptr = 0;
}

void BasePlugin::cancel()
{
    emit error(Error(Error::SessionCanceled));
}

void BasePlugin::refresh(const SignOn::UiSessionData &data)
{
    TRACE();
    emit refreshed(data);
}
