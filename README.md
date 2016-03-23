node-jwt-auth
===================

Authenticated JSON API with Node.js, Express, JWT


###Default resource routes

METHOD    |URI                                   |MIDDLEWARE  |FAILCODE   |SUCCESSCODE  |INPUT                                                             |OUTPUT
----------|--------------------------------------|------------|-----------|-------------|------------------------------------------------------------------|-----------------------------------------------------------------
POST      |/session                              |-           |500/403    |200          |email, password, (remember)                                       |{user: {id, email, name, role}, auth: {token, (code, id)}}
POST      |/session/refresh                      |user        |500        |200          |-                                                                 |{user: {id, email, name, role}, auth: {token, (code, id)}}
DELETE    |/session                              |user        |500        |200          |-                                                                 |{message}
GET       |/users                                |admin       |500/400    |200          |?q=<name>&startFrom=<number>&limit=100 (15 default, max is 100)   |[{name email role createdAt updatedAt id}, ... ]
GET       |/users/:id                            |admin       |500        |200          |-                                                                 |{email, name, id, role}
POST      |/users/:id                            |admin       |422        |200          |email, role, name                                                 |{email, name, phone, id, role}
POST      |/users/invites                        |admin       |500/400    |201          |email, name                                                       |{email, name, phone, id, role}
POST      |/users/password/:invitecode/activate  |-           |500/422    |200          |password (8-100 chars)                                            |{email, name, phone, id, role}
POST      |/users/password                       |-           |500        |200          |email                                                             |{message: 'Password change request sent'}
