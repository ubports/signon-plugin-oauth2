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

#ifndef OAUTH1DATA_H
#define OAUTH1DATA_H

#include <sessiondata.h>

namespace OAuth2PluginNS {

    /*!
 * @class OAuth1PluginData
 * Data container to hold values for OAuth 1.0a authentication session.
 */
    class OAuth1PluginData : public SignOn::SessionData
    {
    public:
        /*!
         * Request token endpoint of the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, RequestEndpoint);

        /*!
         * Access token endpoint of the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, TokenEndpoint);
        SIGNON_SESSION_DECLARE_PROPERTY(QString, AuthorizationEndpoint);

        /*!
         * Application client ID and secret
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, ConsumerKey);
        SIGNON_SESSION_DECLARE_PROPERTY(QString, ConsumerSecret);

        /*!
         * redirection URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, Callback);
        SIGNON_SESSION_DECLARE_PROPERTY(QString, Realm);
    };

    class OAuth1PluginTokenData : public SignOn::SessionData
    {
    public:
        /*!
         * Access token received from the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, AccessToken);

        /*!
         * Token secret received from the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, TokenSecret);
    };

} // namespace OAuth2PluginNS


#endif // OAUTH1DATA_H
