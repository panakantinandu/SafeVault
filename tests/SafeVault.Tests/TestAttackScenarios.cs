using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NUnit.Framework;
using SafeVault.Web.Data;

namespace SafeVault.Tests;

// End-to-end attack simulations against the live HTTP pipeline (routing, model binding,
// validation, and the database layer together) rather than any single class in isolation.
[TestFixture]
public class TestAttackScenarios
{
    private static readonly string[] SqlInjectionPayloads =
    {
        "admin' --",
        "' OR '1'='1",
        "'; DROP TABLE Users; --",
        "1; SELECT * FROM Users",
        "' UNION SELECT Username, PasswordHash FROM Users --"
    };

    private static readonly string[] XssPayloads =
    {
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "javascript:alert('xss')",
        "<a href=\"javascript:alert(1)\">click</a>"
    };

    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;
    private string _dbPath = null!;

    [SetUp]
    public void SetUp()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"safevault_attack_{Guid.NewGuid():N}.db");

        var repository = new UserRepository($"Data Source={_dbPath}");
        repository.InitializeDatabase();

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

    private static FormUrlEncodedContent RegisterForm(string username, string email, string password) =>
        new(new Dictionary<string, string> { ["username"] = username, ["email"] = email, ["password"] = password });

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public async Task Submit_SqlInjectionInUsername_RejectedNotExecuted(string payload)
    {
        var response = await _client.PostAsync("/submit", RegisterForm(payload, "attacker@example.com", "Str0ngPassw0rd!"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCaseSource(nameof(XssPayloads))]
    public async Task Submit_XssInUsername_RejectedNotStored(string payload)
    {
        var response = await _client.PostAsync("/submit", RegisterForm(payload, "attacker@example.com", "Str0ngPassw0rd!"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCaseSource(nameof(XssPayloads))]
    public async Task Submit_XssInEmail_RejectedByEmailValidation(string payload)
    {
        var response = await _client.PostAsync("/submit", RegisterForm("legit_user", $"{payload}@example.com", "Str0ngPassw0rd!"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Submit_AttackPayloadsDoNotDamageTable_LegitimateRegistrationStillWorks()
    {
        foreach (var payload in SqlInjectionPayloads.Concat(XssPayloads))
        {
            await _client.PostAsync("/submit", RegisterForm(payload, "attacker@example.com", "Str0ngPassw0rd!"));
        }

        var response = await _client.PostAsync("/submit", RegisterForm("real_user", "real@example.com", "Str0ngPassw0rd!"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Does.Contain("real_user"));
    }

    [Test]
    public async Task Submit_ValidRegistration_ResponseReflectsUsernameSafely()
    {
        var response = await _client.PostAsync("/submit", RegisterForm("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Does.Not.Contain("<script"));
    }

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public async Task Login_SqlInjectionInUsername_ReturnsUnauthorizedNotServerError(string payload)
    {
        var response = await _client.PostAsync("/login", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["username"] = payload, ["password"] = "anything123" }));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public async Task Search_SqlInjectionPayload_ReturnsEmptyResultsNot500(string payload)
    {
        var response = await _client.GetAsync($"/search?q={Uri.EscapeDataString(payload)}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Is.EqualTo("[]"));
    }

    [TestCaseSource(nameof(XssPayloads))]
    public async Task Search_XssPayload_ResponseNeverContainsRawScriptTag(string payload)
    {
        var response = await _client.GetAsync($"/search?q={Uri.EscapeDataString(payload)}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Does.Not.Contain("<script"));
        Assert.That(body, Does.Not.Contain("<img"));
        Assert.That(body, Does.Not.Contain("<svg"));
    }

    [Test]
    public async Task Search_AfterAttackAttempts_StillFindsLegitimateUsers()
    {
        await _client.PostAsync("/submit", RegisterForm("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!"));

        foreach (var payload in SqlInjectionPayloads.Concat(XssPayloads))
        {
            await _client.GetAsync($"/search?q={Uri.EscapeDataString(payload)}");
        }

        var response = await _client.GetAsync("/search?q=nandu");
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(body, Does.Contain("nandu_p"));
    }
}
