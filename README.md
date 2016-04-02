node-jwt-auth
===================
#### Authenticated JSON API with Node.js, Express, JWT

### Test
Run all unit tests with `npm test`.

Run specific unit test with `mocha test/<testfile>.js` (if mocha is globally available).

### Front end
Gets along well with [React-JWT-Authentication-Redux-Router](https://github.com/JohanGustafsson91/React-JWT-Authentication-Redux-Router) which is a React.js boilerplate front end with Redux.

### Resource routes

#### Authentication resources
|METHOD    |URI                           |MIDDLEWARE  |FAILCODE   |SUCCESSCODE  INPUT                         |OUTPUT
|----------|------------------------------|------------|-----------|-------------------------------------------|-----------------------------------------------------------------
|POST      |/session                      |-           |500/403    |200          email, password, (remember)   |{user: {id, email, name, role}, auth: {token, (code, id)}}
|POST      |/session/refresh              |user        |500        |200          -                             |{user: {id, email, name, role}, auth: {token, (code, id)}}
|DELETE    |/session                      |user        |500        |200          -                             |{message}

#### User resources
|METHOD    |URI                                   |MIDDLEWARE  |FAILCODE   |SUCCESSCODE  |INPUT                                                             |OUTPUT
|----------|--------------------------------------|------------|-----------|-------------|------------------------------------------------------------------|-----------------------------------------------------------------
|GET       |/users                                |user        |500/400    |200          |?q=<name>&startFrom=<number>&limit=100 (15 default, max is 100)   |[{name email role category createdAt updatedAt id}, ... ]
|GET       |/users/:id                            |admin       |500        |200          |-                                                                 |{email, name, phone, id, role, category: {id, name, parent}}
|POST      |/users/:id                            |admin       |422        |200          |email, role, name, phone category                                 |{email, name, phone, id, role, category: {id, name, parent}}
|POST      |/users/invites                        |admin       |500/400    |201          |email, name, phone, category                                      |{email, name, phone, id, role, category: {id, name, parent}}
|POST      |/users/password/:invitecode/activate  |-           |500/422    |200          |password (8-100 chars)                                            |{email, name, phone, id, role, category: {id, name, parent}}
|POST      |/users/password                       |-           |500        |200          |email                                                             |{message: 'Password change request sent'}
|DELETE    |/users/:id                            |admin       |500        |200          |The user ID to 'remove'                                           |{message: 'The user has been inactivated'}
