using SafeVault.Web.Data;
using SafeVault.Web.Validation;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? "Data Source=safevault.db";

builder.Services.AddSingleton(new UserRepository(connectionString));

var app = builder.Build();

app.Services.GetRequiredService<UserRepository>().InitializeDatabase();

app.UseStaticFiles();

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
        var user = repository.AddUser(username, email, password);
        var safeUsername = InputValidator.EncodeForHtml(user.Username);
        return Results.Content($"<p>Registered user: {safeUsername}</p>", "text/html");
    }
    catch (DuplicateUserException ex)
    {
        return Results.Conflict(ex.Message);
    }
});

app.MapPost("/login", async (HttpRequest request, UserRepository repository) =>
{
    var form = await request.ReadFormAsync();
    var username = form["username"].ToString();
    var password = form["password"].ToString();

    if (!InputValidator.IsValidUsername(username) || string.IsNullOrEmpty(password))
    {
        return Results.Unauthorized();
    }

    return repository.VerifyLogin(username, password) ? Results.Ok("Login successful.") : Results.Unauthorized();
});

app.MapGet("/search", (string q, UserRepository repository) =>
{
    var sanitizedTerm = InputValidator.SanitizeSearchTerm(q);
    var matches = repository.SearchUsersByUsername(sanitizedTerm)
        .Select(u => InputValidator.EncodeForHtml(u.Username));

    return Results.Ok(matches);
});

app.Run();
