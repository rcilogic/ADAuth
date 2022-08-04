using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Negotiate;
using System.Net;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using ADAuth;

[assembly: System.Runtime.Versioning.SupportedOSPlatformAttribute("windows")]

// Host name URL must be added to SPN for account which is used to start the app.
// CMD:  SETSPN -s HTTPS/adauth.example.com DOMAIN\ACCOUNTNAME
// To check if SPN record is added, use CMD: SETSPN -L DOMAIN\ACCOUNTNAME
// aduth.example.com must be added in to "Intranet" scope in IE settings

var builder = WebApplication.CreateBuilder(args);

// config.json must contain section 'AuthTargets' with Dictionary<string,string>
// "ClientName" : "URL_To_Redirect". Example:
// "AuthTargets" : {
//  "portal": "https://portal.mycompany.local/auth/adauth"
// }
builder.Configuration.AddJsonFile("config.json");

builder.Services.AddSingleton(
        new AppConfig(
                builder.Configuration.GetSection("AuthTargets").Get<Dictionary<string, string>>(),
                builder.Configuration.GetSection("tokenExpireTimeInSecondes").Get<int>()
            )
    );

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
   .AddNegotiate();

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = options.DefaultPolicy;
});

string host = builder.Configuration.GetSection("host").Get<string>() ?? "127.0.0.1"  ;
IPAddress hostIP = IPAddress.Parse(host);
int port = builder.Configuration.GetSection("port").Get<int>() ;
if (port == 0 ) { port = 443; }
string pfxPath = builder.Configuration.GetSection("pfxPath").Get<string>();
string pfxPassword = builder.Configuration.GetSection("pfxPassword").Get<string>();

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.Listen(hostIP, port, listenOptions => 
    {       
        if (pfxPath != null && pfxPassword != null)
        {            
            listenOptions.UseHttps(pfxPath, pfxPassword);
        } else
        { 
            listenOptions.UseHttps();
        }
    });
});


var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// POST: /auth
// This route authenticates user with Windows Authentication (Kerberos) and fetches user data from AD: Name,Email,Groups etc...
// If User is authenticated and he is member of one or more of requested security groups, authenticator will create JWT.
// If  form's POST data are correct and authTarget exists user will be redirected to authTarget's 'redirectURL' with 'POST' method
// Route recieves POST with form-data with fields:
// - groupPrefix - prefix of Active Directory security group. Prefix will be removed from result group name.
// Example: For AD Security Group "ACL_WebApp1_Admins" prefix should be "ACL_WebApp1_" (that means: Access control list for resource 'WebApp1'). Result group name is "Admins"
// - requestID - ID (UUID), used by service, requested authentication. Returns with claim: aud (Audience).
// - authTarget - name of target where user must be redirected. List of authTargets is defined in config file: 'config.json'
app.MapPost("/", async (HttpContext context, AppConfig appConfig) =>
{
    
    string groupPrefix = context.Request.Form["groupPrefix"].ToString();
    string requestID = context.Request.Form["requestID"].ToString();
    string authTarget = context.Request.Form["authTarget"].ToString();        
    
    if (groupPrefix == "" || requestID == "" || authTarget == "")
    {
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await context.Response.WriteAsync("Bad request.");
        return;
    }

    if (!appConfig.authTargets.ContainsKey(authTarget))
    {
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await context.Response.WriteAsync("Bad request. Invalid Auth Target");
        return;
    }

    string redirectPath = appConfig.authTargets[authTarget];

    var currentUser = context.User?.Identity?.Name?.ToString();
    if (currentUser == null)
    {
        await context.Response.WriteAsync(    
            HTTPHelper.MakePostBodyWithRedirect("Unauthorized", new Dictionary<string, string> { ["result"] = "Unauthorized" }, redirectPath)
            );
        return;
    }

    using (var principalContext = new PrincipalContext(ContextType.Domain))
    {
        UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, currentUser);
        if (user == null)
        { 
            await context.Response.WriteAsync(
                HTTPHelper.MakePostBodyWithRedirect("Unauthorized", new Dictionary<string, string> { ["result"] = $"User '{currentUser}' not found in Active Directory" }, redirectPath)    
                );
            return ;
        } 

        var groups = user.GetGroups()
        .Where(group => group.Name.StartsWith(groupPrefix, StringComparison.OrdinalIgnoreCase))
        .Select(group => group.Name.Remove(0, groupPrefix.Length));

        if (groups.Count() < 1)
        {
            await context.Response.WriteAsync(
                HTTPHelper.MakePostBodyWithRedirect("Unauthorized", new Dictionary<string, string> { ["result"] = $"Access denied for user: { user.DisplayName }({ currentUser })." }, redirectPath)
                );
            return;
        }

        var tokenHandler = new JwtSecurityTokenHandler() { SetDefaultTimesOnTokenCreation = false };
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.SamAccountName),
                new Claim("name", user.DisplayName),
                new Claim(ClaimTypes.Email, user.EmailAddress),
                new Claim("groups", string.Join(",", groups)),                

            }),
            Issuer = "AdAuth",
            Audience = requestID,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(appConfig.rsa), SecurityAlgorithms.RsaSha256),
            Expires = DateTime.UtcNow.AddSeconds(appConfig.tokenExpireTimeInSecondes),      
            
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        
        await context.Response.WriteAsync(
               HTTPHelper.MakePostBodyWithRedirect(
                   "Access granted", 
                   new Dictionary<string, string> { 
                       ["result"] = $"Access granted for user: { user.DisplayName }({ currentUser }). Groups: { string.Join(", ", groups) }.",
                       ["token"] = tokenHandler.WriteToken(token),
       
                   }, 
                   redirectPath)
               );    

    }

});

app.MapGet("/", async (HttpContext context, AppConfig appConfig) =>
{
    context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
    await context.Response.WriteAsync("Forbidden");
    return;
});

app.MapGet("/publickey", [AllowAnonymous] async (HttpContext context, AppConfig appConfig) =>
{
    await context.Response.WriteAsync(appConfig.getRSAPublicKeyInBase64());
});

app.Run();

