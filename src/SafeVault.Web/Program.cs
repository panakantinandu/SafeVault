using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Web.Data;
using SafeVault.Web.Security;
using SafeVault.Web.Validation;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? "Data Source=safevault.db";

builder.Services.AddSingleton(new UserRepository(connectionString));

const string jwtIssuer = "SafeVault";
const string jwtAudience = "SafeVault.Clients";

// Production must supply Jwt:SigningKey via configuration/environment/user-secrets.
// Without one, an ephemeral key is generated per process start (dev/test only) —
// tokens issued before a restart simply stop validating, nothing is persisted insecurely.
var signingKeyBytes = Encoding.UTF8.GetBytes(
    builder.Configuration["Jwt:SigningKey"]
    ?? Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));

builder.Services.AddSingleton(new JwtTokenService(signingKeyBytes, jwtIssuer, jwtAudience, TimeSpan.FromHours(1)));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
});

var app = builder.Build();

app.Services.GetRequiredService<UserRepository>().InitializeDatabase();

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/submit", async (HttpRequest request, UserRepository repository) =>
{
    var form = await request.ReadFormAsync();
    var username = form["username"].ToString();
    var email = form["email"].ToString();
    var password = form["password"].ToString();

    if (!InputValidator.IsValidUsername(username))
    {
        return Results.BadRequest("Username must be 3-30 characters: letters, numbers, underscore, hyphen, or period only.");
    }

    if (!InputValidator.IsValidEmail(email))
    {
        return Results.BadRequest("Email address is not valid.");
    }

    if (!InputValidator.IsValidPassword(password))
    {
        return Results.BadRequest("Password must be 8-128 characters.");
    }

    try
    {
        // Self-registration always yields the "user" role; no HTTP-reachable path grants admin.
        var user = repository.AddUser(username, email, password);
        var safeUsername = InputValidator.EncodeForHtml(user.Username);
        return Results.Content($"<p>Registered user: {safeUsername}</p>", "text/html");
    }
    catch (DuplicateUserException ex)
    {
        return Results.Conflict(ex.Message);
    }
});

app.MapPost("/login", async (HttpRequest request, UserRepository repository, JwtTokenService tokenService) =>
{
    var form = await request.ReadFormAsync();
    var username = form["username"].ToString();
    var password = form["password"].ToString();

    if (!InputValidator.IsValidUsername(username) || string.IsNullOrEmpty(password))
    {
        return Results.Unauthorized();
    }

    var user = repository.AuthenticateUser(username, password);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    var token = tokenService.IssueToken(user.Username, user.Role);
    return Results.Ok(new { token, role = user.Role });
});

app.MapGet("/search", (string q, UserRepository repository) =>
{
    var sanitizedTerm = InputValidator.SanitizeSearchTerm(q);
    var matches = repository.SearchUsersByUsername(sanitizedTerm)
        .Select(u => InputValidator.EncodeForHtml(u.Username));

    return Results.Ok(matches);
});

app.MapGet("/account/profile", (ClaimsPrincipal user) =>
        Results.Ok(new { username = user.Identity!.Name, role = user.FindFirstValue(ClaimTypes.Role) }))
    .RequireAuthorization();

app.MapGet("/admin/dashboard", () => Results.Ok("Welcome to the Admin Dashboard."))
    .RequireAuthorization("AdminOnly");

app.Run();

public partial class Program { }
