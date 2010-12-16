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

#ifndef OAUTH2TOKENDATA_H
#define OAUTH2TOKENDATA_H

#include <QDataStream>
#include <QDebug>

#include <SignOn/SessionData>

class OAuth2PluginTest;
namespace OAuth2PluginNS {

/*!
 * Data container to hold values for storing Token.
 */
class OAuth2TokenData : public SignOn::SessionData
{
public:
friend class ::OAuth2PluginTest;
    /*!
     * Declare property Tokens setter and getter
     * Received tokens are stored in this map
     */
    SIGNON_SESSION_DECLARE_PROPERTY(QVariantMap, Tokens);
};

}  // namespace

#endif // OAUTH2TOKENDATA_H
