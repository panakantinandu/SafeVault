using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Web.Data;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuthorization
{
    private const string Password = "Str0ngPassw0rd!";

    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;
    private string _dbPath = null!;

    [SetUp]
    public void SetUp()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"safevault_authz_{Guid.NewGuid():N}.db");

        var repository = new UserRepository($"Data Source={_dbPath}");
        repository.InitializeDatabase();
        repository.AddUser("alice_admin", "alice@example.com", Password, "admin");
        repository.AddUser("bob_user", "bob@example.com", Password, "user");

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(webHost =>
        {
            webHost.ConfigureServices(services =>
            {
                services.RemoveAll<UserRepository>();
                services.AddSingleton(repository);
            });
        });

        _client = _factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath))
        {
            File.Delete(_dbPath);
        }
    }

    private static FormUrlEncodedContent LoginForm(string username, string password) =>
        new(new Dictionary<string, string> { ["username"] = username, ["password"] = password });

    private async Task<string> LoginAndGetTokenAsync(string username, string password)
    {
        var response = await _client.PostAsync("/login", LoginForm(username, password));
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        return json.RootElement.GetProperty("token").GetString()!;
    }

    [Test]
    public async Task Login_ValidCredentials_ReturnsOkWithToken()
    {
        var response = await _client.PostAsync("/login", LoginForm("bob_user", Password));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Does.Contain("token"));
    }

    [TestCase("bob_user", "WrongPassword1")]
    [TestCase("nonexistent_user", Password)]
    [TestCase("bob_user' --", Password)]
    [TestCase("bob_user", "")]
    public async Task Login_InvalidCredentials_ReturnsUnauthorized(string username, string password)
    {
        var response = await _client.PostAsync("/login", LoginForm(username, password));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminDashboard_NoToken_ReturnsUnauthorized()
    {
        var response = await _client.GetAsync("/admin/dashboard");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminDashboard_UserRoleToken_ReturnsForbidden()
    {
        var token = await LoginAndGetTokenAsync("bob_user", Password);
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/admin/dashboard");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task AdminDashboard_AdminRoleToken_ReturnsOk()
    {
        var token = await LoginAndGetTokenAsync("alice_admin", Password);
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/admin/dashboard");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task AdminDashboard_TamperedToken_ReturnsUnauthorized()
    {
        var token = await LoginAndGetTokenAsync("alice_admin", Password);
        var tampered = token[..^1] + (token[^1] == 'A' ? 'B' : 'A');
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tampered);

        var response = await _client.GetAsync("/admin/dashboard");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AccountProfile_AnyAuthenticatedRole_ReturnsOk()
    {
        var token = await LoginAndGetTokenAsync("bob_user", Password);
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/account/profile");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task AccountProfile_NoToken_ReturnsUnauthorized()
    {
        var response = await _client.GetAsync("/account/profile");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
}
