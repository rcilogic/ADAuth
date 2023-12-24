# ADAuth
`ASP.NET Core 6.0`, `C#`, `Windows`, `Active Directory`

## Description
This application is a part of [REM](https://github.com/rcilogic/rem) project. It provides windows-authentication for specified services. It generates signed JWT with user's data.

### System requirements
- `MS Windows`
- `MS Active Directory`
- `.NET Core 6.0 SDK`

**Note** - The host name URL must be added to SPN for account that is used to start the app.
CMD:  `SETSPN -s HTTPS/adauth.example.com DOMAIN\ACCOUNTNAME`.
To check if SPN record is added, use CMD: `SETSPN -L DOMAIN\ACCOUNTNAME`.
URL **aduth.example.com** must be added in to **Intranet** scope in IE settings (directly or via GPO) on the client side for "transparent" windows authentication.

### Routes:

**/publickey** [`GET`]
Returns RSA public key that is a part of RSA pair used for signing JWT. Application generates new RSA pair duiring each startup.

**/auth**  [`POST`]
This route authenticates user with Windows Authentication (Kerberos) and fetches user data from AD: Name,Email,Groups etc...
If User is authenticated and he is member of one or more of requested security groups, authenticator will create JWT.
If  form's POST data are correct and authTarget exists user will be redirected to authTarget's 'redirectURL' with 'POST' method.
Route recieves POST with form-data with fields:
- `groupPrefix` - prefix of Active Directory security group. Prefix will be removed from result group name.
Example: For AD Security Group `ACL_WebApp1_Admins`" prefix should be `ACL_WebApp1_` (that means: Access control list for resource `WebApp1`). Result group name is "Admins".
- `requestID` - ID (UUID), used by service, requested authentication. Returns with claim: aud (Audience).
- `authTarget` - name of target where user must be redirected. List of authTargets is defined in config file: `config.json`.

### Configuration
Configuration must be specifed in the file `config.json` in app's working directory.

**config.json** (example):
```json
{
  "AuthTargets": {
    "app1": "http://app1.mycompany.local/api/auth/adauth",
    "app2": "https://app2.mycompany.local/auth/adauth"
  },
  "tokenExpireTimeInSecondes": "300",
  "host": "0.0.0.0",
  "port": "10443",
  "pfxPath": "C:\\ssl\\my-cert.pfx",
  "pfxPassword": "Password"
}
```
